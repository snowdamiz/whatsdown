#!/usr/bin/env node
// morse-relay submit <evidence.frk> --wallet <keypair.json> [options]
// morse-relay serve [--port 8787] --wallet <keypair.json> [options]
//
// Options (or environment): --rpc URL (MORSE_RELAY_RPC), --judge PROGRAM_ID
// (MORSE_JUDGE_PROGRAM_ID), --log NAME=DIRECTORY_ORIGIN, repeatable
// (MORSE_RELAY_LOGS, comma-separated), --per-minute N (MORSE_RELAY_PER_MINUTE),
// --trust-proxy (MORSE_RELAY_TRUST_PROXY=1: rate-limit by X-Forwarded-For).
import { readFileSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { address, hex, loadKeypair, solanaChain } from './judge.mjs';
import { prepareEvidence, relayServer, submitEvidence } from './relay.mjs';

const USAGE = 'usage: morse-relay submit <evidence.frk> --wallet <keypair.json> [--rpc URL] [--judge ID] [--log NAME=ORIGIN ...]\n'
  + '       morse-relay serve [--port N] --wallet <keypair.json> [--rpc URL] [--judge ID] [--log NAME=ORIGIN ...] [--per-minute N] [--trust-proxy]';

export function relayConfig(argv, env = process.env) {
  const { values, positionals } = parseArgs({ args: argv, allowPositionals: true, options: {
    wallet: { type: 'string' }, rpc: { type: 'string' }, judge: { type: 'string' }, log: { type: 'string', multiple: true },
    port: { type: 'string' }, 'per-minute': { type: 'string' }, 'trust-proxy': { type: 'boolean' },
  } });
  const [command, file] = positionals;
  if (!['submit', 'serve'].includes(command) || (command === 'submit' && !file)) throw new Error(USAGE);
  const wallet = values.wallet ?? env.MORSE_RELAY_WALLET;
  const rpc = values.rpc ?? env.MORSE_RELAY_RPC;
  const judge = values.judge ?? env.MORSE_JUDGE_PROGRAM_ID;
  const logs = (values.log ?? (env.MORSE_RELAY_LOGS ? env.MORSE_RELAY_LOGS.split(',') : ['morse-main'])).map(item => {
    const [name, directory = null] = item.split('=');
    if (!/^[a-z0-9-]{1,32}$/.test(name)) throw new Error(`bad log name ${name}`);
    if (directory && new URL(directory).protocol !== 'https:' && !/^http:\/\/(127\.0\.0\.1|localhost)(:\d+)?\/?$/.test(directory)) {
      throw new Error('directory origins must be https');
    }
    return { name, directory };
  });
  if (!wallet || !rpc || !judge) throw new Error(`--wallet, --rpc and --judge are required\n${USAGE}`);
  return { command, file, wallet, rpc, judge: address(judge), logs,
    port: Number(values.port ?? env.PORT ?? 8787), perMinute: Number(values['per-minute'] ?? env.MORSE_RELAY_PER_MINUTE ?? 6),
    trustProxy: values['trust-proxy'] ?? env.MORSE_RELAY_TRUST_PROXY === '1' };
}

async function main() {
  const config = relayConfig(process.argv.slice(2));
  const chain = solanaChain({ url: config.rpc });
  const wallet = await loadKeypair(readFileSync(config.wallet, 'utf8'));
  if (config.command === 'serve') {
    const server = relayServer({ chain, judge: config.judge, logs: config.logs, wallet, perMinute: config.perMinute, trustProxy: config.trustProxy });
    server.listen(config.port, () => console.log(`morse-relay: listening on ${config.port} for ${config.logs.map(x => x.name).join(', ')}, wallet ${wallet.address}`));
    return;
  }
  const prepared = await prepareEvidence(new Uint8Array(readFileSync(config.file)), { chain, judge: config.judge, logs: config.logs });
  console.log(`morse-relay: ${prepared.target.name} kind ${prepared.frk.kind} proof ${hex(prepared.proofHash)}, implicated ${prepared.implicated.map(x => x.id).join(', ') || 'none'}; finder ${prepared.finder ?? 'none (this wallet keeps the share)'}`);
  const result = await submitEvidence(prepared, { chain, judge: config.judge, wallet });
  console.log(`morse-relay: ${result.status}${result.signature ? ` in ${result.signature}` : ''}${result.proof ? `, paid to ${result.proof.paidTo}` : ''}`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`morse-relay: ${error.code ?? ''} ${error.message}`.trim()); process.exit(1); });
}

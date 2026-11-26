// Runs the bootstrap acceptance suite (plan §4.3) against the configured system.
//
//   node ops/acceptance/run.mjs --checks 1,3,4,5 [--out results.json]
//   node ops/acceptance/run.mjs --drill-witness        # this week's outage drill witness
//   node ops/acceptance/run.mjs --create-canaries      # once: register morse-canary-1…3
//
// Configuration is environment only (README.md lists every variable). Exit 1
// when a check failed, 0 when every check passed or skipped.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { canaryProcess } from './canary.mjs';
import { CHECK_NAMES, parseSecurityConfig, runChecks, securityFrame, weeklyDrillWitness } from './checks.mjs';
import { outageDrill } from './witness-outage.mjs';
import { decodeLog, judgeAddresses, solanaChain } from '../cloudflare/judge.mjs';

function capture(command, args) {
  return new Promise(resolve => {
    const child = spawn(command, args, { stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '';
    child.stdout.on('data', chunk => { output += chunk; });
    child.stderr.on('data', chunk => { output += chunk; });
    child.on('error', error => resolve({ code: 1, output: String(error.message) }));
    child.on('close', code => resolve({ code: code ?? 1, output }));
  });
}

async function healthJson(env) {
  const response = await fetch(env.MORSE_DIRECTORY_HEALTH_URL ?? `${env.MORSE_DIRECTORY_URL}/v1/transparency/health`, { signal: AbortSignal.timeout(15_000) });
  if (!response.ok) throw new Error(`directory health answered ${response.status}`);
  return response.json();
}

export function context(env) {
  const frame = securityFrame(env);
  const workdir = env.MORSE_ACCEPTANCE_WORKDIR ?? mkdtempSync(join(tmpdir(), 'morse-acceptance-'));
  const configFile = join(workdir, 'security-config.txt');
  if (frame) writeFileSync(configFile, frame);
  const directory = env.MORSE_DIRECTORY_URL ?? '';
  const canary = (role, extra = {}) => canaryProcess({ role, directory, frame, workdir, accounts: env.MORSE_CANARY_ACCOUNTS, env: extra, meshc: env.MESHC ?? 'meshc' });
  return {
    env, directory, config: frame ? parseSecurityConfig(frame) : null, configFile, workdir, now: Date.now, http: fetch, canary,
    chain: url => solanaChain({ url }),
    monitorOnce: args => capture(env.MORSE_MONITOR_BIN, args),
    canaryLog: async ({ judge, log, rpc }) => {
      const account = await solanaChain({ url: rpc }).account(await judgeAddresses(judge).log(log));
      if (!account || account.owner !== judge) throw new Error(`${log} is not a log under ${judge}`);
      return decodeLog(account.data);
    },
    // The drill signs with the canary keys and files through a relay (ops/drills; needs `npm ci` in ops/relay).
    forkDrill: async options => {
      const { canaryForkDrill } = await import('../drills/canary-fork.mjs');
      const relayJudge = await import('../relay/judge.mjs');
      return canaryForkDrill({ chain: relayJudge.solanaChain({ url: options.rpc }), judge: options.judge, log: options.log,
        serviceSeed: relayJudge.fromHex(options.serviceSeedHex), witnesses: options.witnesses.map(w => ({ id: w.id, seed: relayJudge.fromHex(w.seedHex) })),
        anchor: await relayJudge.loadKeypair(options.anchorKeypair), payer: await relayJudge.loadKeypair(options.payerKeypair),
        relay: options.relay.url ? { url: options.relay.url } : { wallet: await relayJudge.loadKeypair(options.relay.walletKeypair) },
        finder: options.finder });
    },
    outageDrill: options => outageDrill({ ...options, health: () => healthJson(env), token: env.CLOUDFLARE_API_TOKEN,
      watch: () => canary('watch', { MORSE_CANARY_ACCOUNTS: (env.MORSE_CANARY_ACCOUNTS ?? 'morse-canary-1').split(',')[0], MORSE_CANARY_INTERVAL_MS: '60000' }) }),
    // The extras run on the drill device: the canary device's `extras` role, given the tokens.
    creditsDrill: async options => (await import('./credits-drill.mjs')).creditsDrill({ ...options, env, device: ({ tokens }) => {
      const file = join(workdir, 'drill-tokens.txt');
      writeFileSync(file, tokens.map(t => Buffer.from(t).toString('hex')).join('\n'), { mode: 0o600 });
      return canary('extras', { MORSE_CANARY_TOKENS: file, MORSE_CANARY_EDGE: env.MORSE_CREDITS_EDGE_URL }).done;
    } }),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { checks: { type: 'string' }, out: { type: 'string' }, 'drill-witness': { type: 'boolean' },
    'create-canaries': { type: 'boolean' } } });
  // An unset GitHub variable arrives as an empty string: treat it as unset.
  const ctx = context(Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== '')));
  if (values['drill-witness']) {
    console.log(weeklyDrillWitness(ctx) ?? '');
  } else if (values['create-canaries']) {
    const lines = await ctx.canary('create').done;
    for (const line of lines) console.log(JSON.stringify(line));
    process.exitCode = lines.every(line => line.kind === 'created' && [201, 409].includes(line.status)) ? 0 : 1;
  } else {
    const ids = (values.checks ?? '1,2,3,4,5,6,7,8').split(',').map(Number);
    if (ids.some(id => !CHECK_NAMES[id])) throw new Error('--checks takes numbers 1 to 8');
    const results = await runChecks(ids, ctx);
    for (const r of results) console.log(`${r.status.toUpperCase().padEnd(4)} ${r.id}. ${r.name}: ${r.detail}`);
    if (values.out) writeFileSync(values.out, JSON.stringify({ generated_at: new Date().toISOString(), results }, null, 1));
    process.exitCode = results.some(r => r.status === 'fail') ? 1 : 0;
  }
}

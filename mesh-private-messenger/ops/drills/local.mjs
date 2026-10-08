// A throwaway local chain for the drills and the integration test: starts
// solana-test-validator with morse-judge and morse-rewards deployed (like
// programs/scripts/smoke.sh, on its own port) and sets up logs, bonded
// witnesses and directory bonds, with a local key standing in for governance.
//
//   node ops/drills/local.mjs [--port 18990] [--dir DIR]
// starts a validator, sets up morse-main and morse-canary, writes the key files
// the drills take into DIR, prints the drill command lines, and runs until
// interrupted.
import { spawn, execFileSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import {
  LOG_CANARY, LOG_MAIN, RING_LEN, addressBytes, ata, bytes, concat, createAtaIdempotent, ed25519FromSeed, ed25519Instruction, hex, judgeAddresses,
  judgeInstructions, keypairFromSeed, loadKeypair, pause, rewardsAddresses, rewardsInstructions, solanaChain, token,
} from '../relay/judge.mjs';

export const PROGRAMS = fileURLToPath(new URL('../../programs/', import.meta.url));
const TOOLS = [join(process.env.HOME ?? '', '.cargo/bin'), join(process.env.HOME ?? '', '.local/share/solana/install/active_release/bin')];
const toolEnv = { ...process.env, PATH: [...TOOLS, process.env.PATH].join(':') };

// A key whose seed is kept, so it can be written as a solana-keygen file.
export async function newKey(seed = crypto.getRandomValues(new Uint8Array(32))) {
  return { seed, ...(await keypairFromSeed(seed)) };
}
export const keyFile = async key => JSON.stringify([...concat(key.seed, (await ed25519FromSeed(key.seed)).publicKey)]);

export function solanaToolsAvailable() {
  try {
    execFileSync('solana-test-validator', ['--version'], { env: toolEnv, stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

// The .so files, built with cargo-build-sbf when missing (programs/README.md).
export function programBinaries() {
  const deploy = join(PROGRAMS, 'target/deploy');
  for (const name of ['morse-judge', 'morse-rewards']) {
    if (!existsSync(join(deploy, `${name.replace('-', '_')}.so`))) {
      execFileSync('cargo-build-sbf', ['--manifest-path', join(PROGRAMS, name, 'Cargo.toml')],
        { env: { ...toolEnv, CARGO_BUILD_JOBS: toolEnv.CARGO_BUILD_JOBS ?? '4' }, stdio: 'inherit' });
    }
  }
  return { judgeSo: join(deploy, 'morse_judge.so'), rewardsSo: join(deploy, 'morse_rewards.so'),
    judgeKey: join(deploy, 'morse_judge-keypair.json'), rewardsKey: join(deploy, 'morse_rewards-keypair.json') };
}

export async function airdrop(chain, target, sol) {
  const signature = await chain.rpc.requestAirdrop(target, BigInt(sol) * 1_000_000_000n, { commitment: 'confirmed' }).send();
  for (let i = 0; i < 120; i++) {
    const { value: [status] } = await chain.rpc.getSignatureStatuses([signature]).send();
    if (['confirmed', 'finalized'].includes(status?.confirmationStatus)) return;
    await pause(250);
  }
  throw new Error('airdrop not confirmed');
}

// Starts the validator; `stop()` kills only the process it started.
export async function startValidator({ port = 18990, dir = mkdtempSync(join(tmpdir(), 'morse-drill-')) } = {}) {
  const bin = programBinaries();
  const deployer = await newKey();
  const deployerFile = join(dir, 'deployer.json');
  writeFileSync(deployerFile, await keyFile(deployer), { mode: 0o600 });
  const judge = (await loadKeypair(readFileSync(bin.judgeKey, 'utf8'))).address;
  const rewards = (await loadKeypair(readFileSync(bin.rewardsKey, 'utf8'))).address;
  const child = spawn('solana-test-validator', ['--reset', '--quiet', '--ledger', join(dir, 'ledger'), '--rpc-port', String(port),
    '--faucet-port', String(port + 1001), '--gossip-port', String(port + 1002), '--dynamic-port-range', `${port + 1010}-${port + 1040}`,
    '--upgradeable-program', judge, bin.judgeSo, deployerFile, '--upgradeable-program', rewards, bin.rewardsSo, deployerFile],
  { env: toolEnv, stdio: 'ignore' });
  const url = `http://127.0.0.1:${port}`;
  const chain = solanaChain({ url, pollMs: 200 });
  for (let i = 0; ; i++) {
    if (child.exitCode !== null) throw new Error('solana-test-validator exited');
    try { if (await chain.rpc.getHealth().send() === 'ok') break; } catch { /* still starting */ }
    if (i > 120) throw new Error('validator did not start');
    await pause(500);
  }
  const stop = async () => {
    if (child.exitCode === null) {
      child.kill('SIGTERM');
      await Promise.race([new Promise(resolve => child.once('exit', resolve)), pause(10_000).then(() => child.kill('SIGKILL'))]);
    }
  };
  return { url, chain, judge, rewards, deployer, dir, stop };
}

const send = (chain, instructions, payer, signers = []) => chain.send(instructions, { payer, signers });

// Grows a log's ring to full size (42 reallocs, 8 per transaction).
export async function growRing({ chain, judge, payer, name }) {
  const ring = await judgeAddresses(judge).ring(name);
  const grow = await judgeInstructions(judge).growRing({ log: name, payer: payer.address });
  for (;;) {
    const length = (await chain.account(ring))?.data.length ?? 0;
    if (length === RING_LEN) return ring;
    await send(chain, Array(length === 0 ? 1 : Math.min(8, Math.ceil((RING_LEN - length) / 10_240))).fill(grow), payer);
  }
}

// register_witness (the operator, proving the witness key), governance's
// admit_witness (appended to the list), then the operator's bond.
export async function addWitness({ chain, judge, gov, payer, usdc, name, id, seed, excluded = false, bond }) {
  const ix = judgeInstructions(judge);
  const key = await ed25519FromSeed(seed);
  const operator = await newKey();
  await airdrop(chain, operator.address, 2);
  const message = concat(bytes('morse-witness-register-v1'), bytes(id), addressBytes(operator.address), addressBytes(operator.address));
  await send(chain, [ed25519Instruction([{ publicKey: key.publicKey, message, signature: await key.sign(message) }]),
    await ix.registerWitness({ log: name, operator: operator.address, id, signingKey: key.publicKey, payout: operator.address, excluded })], operator);
  await send(chain, [await ix.admitWitness({ log: name, authority: gov.address, id })], payer, [gov]);
  await send(chain, [await createAtaIdempotent(payer.address, operator.address, usdc),
    await token.mintTo({ mint: usdc, owner: operator.address, authority: gov.address, amount: bond })], payer, [gov]);
  await send(chain, [await ix.bond({ log: name, operator: operator.address, id, mint: usdc, amount: bond })], operator);
  return { id, seed, key, operator, excluded };
}

// A registered log with its ring, bonded witnesses and bonded directory.
export async function setupLog({ chain, judge, gov, payer, usdc, name, witnesses, directoryBond, witnessBond, excluded = false, kind = LOG_MAIN }) {
  const serviceSeed = crypto.getRandomValues(new Uint8Array(32));
  const service = await ed25519FromSeed(serviceSeed);
  const anchor = await newKey();
  await send(chain, [await judgeInstructions(judge).registerLog({ log: name, authority: gov.address, payer: payer.address,
    serviceKey: service.publicKey, anchorAuthority: anchor.address, usdc, kind })], payer, [gov]);
  await growRing({ chain, judge, payer, name });
  const listed = [];
  for (const id of witnesses) {
    listed.push(await addWitness({ chain, judge, gov, payer, usdc, name, id, seed: crypto.getRandomValues(new Uint8Array(32)), excluded, bond: witnessBond }));
  }
  await send(chain, [await createAtaIdempotent(payer.address, gov.address, usdc),
    await token.mintTo({ mint: usdc, owner: gov.address, authority: gov.address, amount: directoryBond })], payer, [gov]);
  await send(chain, [await judgeInstructions(judge).bondDirectory({ log: name, authority: gov.address, mint: usdc, amount: directoryBond })], payer, [gov]);
  return { name, service, serviceSeed, anchor, witnesses: listed };
}

// The whole local environment: judge and rewards initialized, a USDC mint,
// morse-main (main kind; Morse-run, excluded witnesses; $50,000 + $10,000 bonds)
// and morse-canary (canary kind, closable after a slash; t1-t3; $100 bonds), and
// a funded rewards pool.
export async function setupLocal(validator) {
  const { chain, judge, rewards, deployer } = validator;
  const gov = await newKey();
  const payer = await newKey();
  await airdrop(chain, payer.address, 300);
  for (const k of [gov, deployer]) await airdrop(chain, k.address, 20);
  const mint = await newKey();
  await send(chain, await token.createMint({ payer: payer.address, mint: mint.address, authority: gov.address, rent: await chain.rent(82) }), payer, [mint]);
  const usdc = mint.address;
  await send(chain, [await judgeInstructions(judge).initialize({ deployer: deployer.address, authority: gov.address, usdc, rewards,
    minUsdc: 1_000_000n, minToken: 1_000_000n })], payer, [deployer]);
  const logs = {
    'morse-main': await setupLog({ chain, judge, gov, payer, usdc, name: 'morse-main', witnesses: ['witness-a', 'witness-b'], excluded: true,
      directoryBond: 50_000_000_000n, witnessBond: 10_000_000_000n }),
    'morse-canary': await setupLog({ chain, judge, gov, payer, usdc, name: 'morse-canary', witnesses: ['t1', 't2', 't3'], kind: LOG_CANARY,
      directoryBond: 100_000_000n, witnessBond: 100_000_000n }),
  };
  // The canary drill re-bonds T3 afterwards: its operator holds a second bond.
  const t3 = logs['morse-canary'].witnesses.find(w => w.id === 't3');
  await send(chain, [await token.mintTo({ mint: usdc, owner: t3.operator.address, authority: gov.address, amount: 100_000_000n })], payer, [gov]);
  const r = rewardsInstructions(rewards);
  const pool = await rewardsAddresses(rewards).pool();
  await send(chain, [await r.initialize({ deployer: deployer.address, authority: gov.address, judge, log: await judgeAddresses(judge).log('morse-main'), usdc }),
    await createAtaIdempotent(payer.address, pool, usdc)], payer, [deployer]);
  await send(chain, [await token.mintTo({ mint: usdc, owner: gov.address, authority: gov.address, amount: 3_000_000n }),
    await r.fundPool({ funder: gov.address, usdc, amount: 3_000_000n })], payer, [gov]);
  return { ...validator, gov, payer, usdc, logs, poolVault: await ata(pool, usdc) };
}

// Writes the files the drill command lines take.
export async function writeKeyFiles(local) {
  const canary = local.logs['morse-canary'];
  const t3 = canary.witnesses.find(w => w.id === 't3');
  const files = { 'payer.json': await keyFile(local.payer), 'governance.json': await keyFile(local.gov),
    'canary-anchor.json': await keyFile(canary.anchor), 'canary-service.hex': hex(canary.serviceSeed), 't3.hex': hex(t3.seed),
    't3-operator.json': await keyFile(t3.operator) };
  for (const [name, content] of Object.entries(files)) writeFileSync(join(local.dir, name), content, { mode: 0o600 });
  return files;
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  const { values } = parseArgs({ options: { port: { type: 'string' }, dir: { type: 'string' } } });
  if (!solanaToolsAvailable()) throw new Error('solana-test-validator not found (Solana CLI 4.1, see programs/README.md)');
  const validator = await startValidator({ port: Number(values.port ?? 18990), ...(values.dir ? { dir: values.dir } : {}) });
  const local = await setupLocal(validator);
  await writeKeyFiles(local);
  const d = local.dir;
  console.log(`local chain ${local.url}: judge ${local.judge}, rewards ${local.rewards}, usdc ${local.usdc}; keys in ${d}
  node ops/drills/canary-fork.mjs --rpc ${local.url} --judge ${local.judge} --service-key ${d}/canary-service.hex --witness t3 --witness-key ${d}/t3.hex \\
    --anchor ${d}/canary-anchor.json --payer ${d}/payer.json --relay-wallet ${d}/payer.json --governance ${d}/governance.json --operator ${d}/t3-operator.json
  node ops/drills/rewards.mjs --rpc ${local.url} --rewards ${local.rewards} --payer ${d}/payer.json`);
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.on(signal, async () => { await validator.stop(); if (!values.dir) rmSync(d, { recursive: true, force: true }); process.exit(0); });
  }
}

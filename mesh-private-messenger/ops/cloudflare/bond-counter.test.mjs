import assert from 'node:assert/strict';
import test from 'node:test';
import { bondSnapshot } from './bond-counter.mjs';
import {
  TOKEN, addressFrom, encodeJudgeConfig, encodeLog, encodeProof, encodeRingHeader, encodeTokenAccount, encodeWitness,
  judgeAddresses, memoryChain,
} from './judge.mjs';

const judge = addressFrom(new Uint8Array(32).fill(7));
const usdc = addressFrom(new Uint8Array(32).fill(9));
const at = judgeAddresses(judge);
const memory = () => { const m = new Map(); return { get: k => m.get(k), set: (k, v) => m.set(k, v) }; };

// morse-main and morse-canary on one provider; `serviceSlashed` flips the main log.
async function provider({ serviceSlashed = false, directoryBond = 50_000_000_000n, lastSlot = 900n } = {}) {
  const chain = memoryChain();
  const reads = [];
  const read = chain.account;
  chain.account = async (target, slice) => { reads.push(target); return read(target, slice); };
  for (const log of ['morse-main', 'morse-canary']) {
    const vault = await at.directoryVault(log);
    const witness = { id: 'witness-a', key: new Uint8Array(32).fill(1), account: await at.witness(log, 'witness-a') };
    chain.set(await at.log(log), encodeLog({ log, serviceKey: new Uint8Array(32), ring: await at.ring(log), directoryVault: vault,
      serviceSlashed: log === 'morse-canary' || serviceSlashed, directoryStatus: serviceSlashed ? 3 : 1, witnesses: [witness] }), judge);
    chain.set(await at.ring(log), encodeRingHeader({ log, head: 3, count: 3, lastSequence: 41n, lastSize: 12n, lastSlot }), judge);
    chain.set(vault, encodeTokenAccount({ mint: usdc, owner: vault, amount: directoryBond }), TOKEN);
    const wvault = await at.witnessVault(log, 'witness-a');
    chain.set(witness.account, encodeWitness({ id: 'witness-a', key: witness.key, vault: wvault, excluded: true, listIndex: 0 }), judge);
    chain.set(wvault, encodeTokenAccount({ mint: usdc, owner: wvault, amount: 10_000_000_000n }), TOKEN);
  }
  chain.set(await at.config(), encodeJudgeConfig({ usdc }), judge);
  chain.times.set(lastSlot, 1_790_000_000n);
  return { chain, reads };
}

test('two agreeing providers give numbers with explorer links, read from morse-main only', async () => {
  const a = await provider();
  const b = await provider();
  const state = memory();
  const snapshot = await bondSnapshot({ chains: [a.chain, b.chain], judge, cluster: 'devnet', state, nowMs: 1_790_000_040_000 });
  assert.equal(snapshot.status, 'ok');
  assert.deepEqual(snapshot.last_public_checkpoint, { slot: '900', sequence: '41', tree_size: '12', time: new Date(1_790_000_000_000).toISOString(),
    age_seconds: 40, link: 'https://explorer.solana.com/block/900?cluster=devnet' });
  assert.equal(snapshot.bonded.directory.usd, '50000.00');
  assert.equal(snapshot.bonded.witnesses[0].usd, '10000.00');
  assert.match(snapshot.bonded.directory.link, /^https:\/\/explorer\.solana\.com\/address\/.+\?cluster=devnet$/);
  assert.deepEqual(snapshot.slashed, { service: false, witnesses: 0, never: true, link: snapshot.log_account.link });
  const canary = new Set([await at.log('morse-canary'), await at.ring('morse-canary'), await at.directoryVault('morse-canary')]);
  assert.ok(![...a.reads, ...b.reads].some(x => canary.has(x)), 'the canary log is never counted');
});

test('providers that disagree give "unavailable" and no numbers, and a slash stays in the history for good', async () => {
  const state = memory();
  const alerts = [];
  const a = await provider({ directoryBond: 50_000_000_000n });
  const b = await provider({ directoryBond: 49_000_000_000n });
  const split = await bondSnapshot({ chains: [a.chain, b.chain], judge, cluster: 'mainnet', state, alert: x => alerts.push(x) });
  assert.deepEqual(Object.keys(split).sort(), ['generated_at', 'last_good_at', 'log', 'reason', 'slash_history', 'status']);
  assert.equal(split.reason, 'rpc_disagree');
  assert.deepEqual(alerts, ['WARN bond_counter_rpc_disagree']);

  const slashedA = await provider({ serviceSlashed: true });
  const slashedB = await provider({ serviceSlashed: true });
  const proof = addressFrom(new Uint8Array(32).fill(0x33));
  const record = encodeProof({ log: await at.log('morse-main'), proofHash: new Uint8Array(32).fill(4), paidTo: usdc, slot: 950n });
  slashedA.chain.programAccounts = async (program, filters) => {
    assert.equal(program, judge);
    assert.deepEqual(filters[0], { dataSize: 112n });
    return [{ address: proof, data: record, owner: judge }];
  };
  slashedA.chain.signaturesFor = async () => [{ signature: 'later-failed', err: { Custom: 1 } }, { signature: 'slash-tx', err: null }];
  slashedB.chain.set(proof, record, judge);
  const slashed = await bondSnapshot({ chains: [slashedA.chain, slashedB.chain], judge, cluster: 'mainnet', state });
  assert.deepEqual(slashed.slashed, { service: true, witnesses: 0, never: false, link: slashed.log_account.link });
  assert.deepEqual(slashed.slash_history, [{ proof, kind: 1, slot: '950', paid_to: usdc, tx_signature: 'slash-tx',
    link: 'https://explorer.solana.com/tx/slash-tx', account_link: `https://explorer.solana.com/address/${proof}` }]);
  const later = await bondSnapshot({ chains: [slashedA.chain, b.chain], judge, cluster: 'mainnet', state, alert: () => {} });
  assert.equal(later.status, 'unavailable');
  assert.equal(later.slash_history.length, 1, 'RPC trouble never hides a slash');
});

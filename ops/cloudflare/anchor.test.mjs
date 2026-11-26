import assert from 'node:assert/strict';
import test from 'node:test';
import { checkFeePayer, crankCosigns, postAnchor, settleEpochs } from './anchor.mjs';
import {
  ChainError, LOG_CANARY, addressFrom, bytes, checkpointHash, concat, encodeLog, encodeWitness, hex, memoryChain, rewardsAddresses, witnessMessage,
} from './judge.mjs';
import { at, authority, directory, judge, judgeChain, ktk, memory, payer } from './test-chain.mjs';

test('the anchor poster posts each new checkpoint once, at most once a minute, and records it', async () => {
  const { chain } = await judgeChain();
  const served = { checkpoint: await ktk(5n, 10n) };
  const { call, records } = directory(served);
  const state = memory();
  const args = { chain, judge, logName: 'morse-main', payer, authority, call, state };
  const first = await postAnchor({ ...args, nowMs: 1_000_000 });
  assert.equal(first.status, 'posted');
  const sent = chain.sent[0];
  assert.deepEqual(sent.signers.map(s => s.address), [authority.address], 'the anchor authority signs; the fee payer pays');
  assert.equal(sent.payer.address, payer.address);
  assert.equal(sent.instructions[0].programAddress, 'Ed25519SigVerify111111111111111111111111111');
  assert.deepEqual([...sent.instructions[1].data.subarray(0, 2)], [6, 0], 'post_anchor with ed_ix 0');
  assert.deepEqual(records, [{ sequence: 5, tree_size: 10, checkpoint_hash: hex(checkpointHash(served.checkpoint)), ring_index: 0, tx_signature: 'sig1', slot: 5000 }]);
  assert.equal((await postAnchor({ ...args, nowMs: 1_010_000 })).status, 'unchanged');
  served.checkpoint = await ktk(6n, 11n, 2);
  assert.deepEqual(await postAnchor({ ...args, nowMs: 1_030_000 }), { status: 'deferred', deferUntil: 1_060_000 });
  assert.equal(chain.sent.length, 1);
  const second = await postAnchor({ ...args, nowMs: 1_061_000 });
  assert.equal(second.anchor.ringIndex, 1);
  assert.equal(records.length, 2);
});

test('a slashed canary log takes no anchors, so the poster stops without sending', async () => {
  const { chain } = await judgeChain();
  chain.set(await at.log('morse-main'), encodeLog({ serviceKey: new Uint8Array(32), kind: LOG_CANARY, serviceSlashed: true, directoryStatus: 3 }), judge);
  const { call } = directory({ checkpoint: await ktk(5n, 10n) });
  assert.deepEqual(await postAnchor({ chain, judge, logName: 'morse-main', payer, authority, call, state: memory(), nowMs: 1 }), { status: 'log_slashed' });
  assert.equal(chain.sent.length, 0);
});

test('DuplicateAnchor means an earlier attempt landed: it is recorded with that attempt\'s signature', async () => {
  const { chain } = await judgeChain();
  const served = { checkpoint: await ktk(5n, 10n) };
  const { call, records } = directory(served);
  const state = memory();
  const args = { chain, judge, logName: 'morse-main', payer, authority, call, state, nowMs: 1_000_000 };
  const send = chain.send;
  chain.send = async (...params) => { await send(...params); throw new ChainError('not confirmed in time', { signature: 'landed-sig' }); };
  await assert.rejects(postAnchor(args), /not confirmed/);
  chain.send = send;
  const retried = await postAnchor({ ...args, nowMs: 1_100_000 });
  assert.equal(retried.status, 'posted');
  assert.equal(records[0].tx_signature, 'landed-sig');
  assert.equal(records[0].ring_index, 0);
});

test('the cosign crank batches four cosigns per transaction and skips bad, set, slashed or late signatures', async () => {
  const ids = ['witness-a', 'witness-b', 'witness-c', 'witness-d', 'witness-e', 'witness-f', 'witness-g'];
  const { chain, witnesses } = await judgeChain(ids);
  const served = { checkpoint: await ktk(5n, 10n) };
  const { call } = directory(served);
  const state = memory();
  await postAnchor({ chain, judge, logName: 'morse-main', payer, authority, call, state, nowMs: 1_000_000 });
  const hash = checkpointHash(served.checkpoint);
  // g is slashed; f's signature is forged.
  chain.set(witnesses[6].account, encodeWitness({ id: 'witness-g', key: witnesses[6].key, status: 3, listIndex: 6 }), judge);
  const entries = await Promise.all(witnesses.map(async (w, i) => {
    const signature = await w.sign(witnessMessage(w.id, hash));
    if (i === 5) signature[0] ^= 1;
    return concat(Uint8Array.of(1), u32(w.id.length), bytes(w.id), hash, signature);
  }));
  // The directory has moved on to a newer checkpoint: the anchored one's
  // attestations are read by its sequence.
  served.checkpoint = await ktk(6n, 11n, 2);
  served.attestations = { 5: concat(Uint8Array.of(2), bytes('KTW'), Uint8Array.of(0, entries.length), ...entries) };
  const result = await crankCosigns({ chain, judge, logName: 'morse-main', payer, call, state });
  assert.deepEqual(result, { cosigned: 5, open: 1 });
  const batches = chain.sent.slice(1).map(t => t.instructions.filter(ix => ix.programAddress === judge).length);
  assert.deepEqual(batches, [4, 1]);
  assert.equal(chain.sent[1].instructions[0].data[0], 4, 'one Ed25519 instruction carries all four entries');
  // Nothing new to submit; after 1,500 slots the anchor leaves the crank.
  assert.deepEqual(await crankCosigns({ chain, judge, logName: 'morse-main', payer, call, state }), { cosigned: 0, open: 1 });
  chain.slotNow += 1501n;
  assert.deepEqual(await crankCosigns({ chain, judge, logName: 'morse-main', payer, call, state }), { cosigned: 0, open: 0 });
  assert.equal(chain.sent.length, 3);
  // A checkpoint the directory no longer holds leaves the crank.
  const again = await postAnchor({ chain, judge, logName: 'morse-main', payer, authority, call, state, nowMs: 2_000_000 });
  assert.equal(again.status, 'posted');
  assert.deepEqual(await crankCosigns({ chain, judge, logName: 'morse-main', payer, call, state }), { cosigned: 0, open: 0 });
});
const u32 = n => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n); return b; };

test('weekly settlement runs once per epoch after its boundary, with every listed witness, and warns when late', async () => {
  const rewards = addressFrom(new Uint8Array(32).fill(8));
  const { chain, witnesses } = await judgeChain(['witness-a', 'witness-b']);
  const r = rewardsAddresses(rewards);
  const config = new Uint8Array(904);
  config.set([1, 1]);
  config.set(new Uint8Array(32).fill(7), 40);
  const { addressBytes } = await import('./judge.mjs');
  config.set(addressBytes(await at.log('morse-main')), 72);
  config.set(new Uint8Array(32).fill(9), 104);
  chain.set(await r.config(), config, rewards);
  const state = memory();
  state.set('settled', 2938);
  const boundary = 2940 * 604800;
  assert.deepEqual(await settleEpochs({ chain, rewards, payer, state, nowMs: (boundary + 600) * 1000 }), []);
  const settled = await settleEpochs({ chain, rewards, payer, state, nowMs: (boundary + 901) * 1000 });
  assert.deepEqual(settled, [{ epoch: 2939, status: 'settled' }]);
  const ix = chain.sent.at(-1).instructions[0];
  assert.deepEqual([...ix.data.subarray(0, 1)], [3]);
  assert.deepEqual(ix.accounts.slice(7).map(a => a.address), [witnesses[0].account, witnesses[0].vault, witnesses[1].account, witnesses[1].vault]);
  assert.deepEqual(await settleEpochs({ chain, rewards, payer, state, nowMs: (boundary + 2000) * 1000 }), []);
  const alerts = [];
  chain.onSend = async () => { throw new ChainError('rpc down'); };
  const next = boundary + 604800;
  await settleEpochs({ chain, rewards, payer, state, nowMs: (next + 1000) * 1000, alert: x => alerts.push(x) });
  assert.deepEqual(alerts, []);
  await settleEpochs({ chain, rewards, payer, state, nowMs: (next + 3700) * 1000, alert: x => alerts.push(x) });
  await settleEpochs({ chain, rewards, payer, state, nowMs: (next + 3800) * 1000, alert: x => alerts.push(x) });
  assert.equal(alerts.length, 1);
  assert.match(alerts[0], /^WARN settle_epoch_late epoch=2940/);
});

test('the fee payer warns at 0.2 SOL and pages at 0.05 SOL', async () => {
  const chain = memoryChain();
  const state = memory();
  const alerts = [];
  const level = async lamports => {
    chain.set(payer.address, new Uint8Array(), undefined, lamports);
    return checkFeePayer({ chain, payer, state, nowMs: 0, alert: x => alerts.push(x) });
  };
  assert.equal(await level(900_000_000n), 'ok');
  assert.equal(await level(150_000_000n), 'warn');
  assert.equal(await level(40_000_000n), 'page');
  assert.equal(await level(40_000_000n), 'page');
  assert.equal(await level(2_000_000_000n), 'over_limit');
  assert.equal(alerts.length, 3);
  assert.match(alerts[1], /^PAGE fee_payer_page/);
});

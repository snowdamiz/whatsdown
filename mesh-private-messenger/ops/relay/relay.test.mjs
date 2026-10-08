import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { decodeFrk, encodeFrk } from './frk.mjs';
import {
  ChainError, ERROR, addressFrom, ata, bytes, concat, decodeLog, encodeJudgeConfig, encodeLog, encodeProof, encodeRingEntry,
  encodeRingHeader, encodeTokenAccount, encodeWitness, fromHex, hex, judgeAddresses, keypairFromSeed, memoryChain, u64be, u8,
} from './judge.mjs';
import { prepareEvidence, rateLimiter, relayServer, submitEvidence } from './relay.mjs';

const judge = addressFrom(new Uint8Array(32).fill(7));
const usdc = addressFrom(new Uint8Array(32).fill(9));
const vector = name => JSON.parse(readFileSync(new URL(`../../tests/fixtures/frk/${name}.json`, import.meta.url), 'utf8'));
const at = judgeAddresses(judge);
const wallet = await keypairFromSeed(new Uint8Array(32).fill(3));

// A chain holding morse-main as the fixture log: directory and every witness
// Active with a USDC bond, and the vector's ring entry when it has one.
async function fixtureChain(fixture, onSend) {
  const chain = memoryChain({ onSend });
  const ring = await at.ring('morse-main');
  const witnesses = await Promise.all(fixture.log.witnesses.map(async x => ({
    id: x.witness_id, key: fromHex(x.public_key), account: await at.witness('morse-main', x.witness_id),
    vault: await at.witnessVault('morse-main', x.witness_id) })));
  chain.set(await at.log('morse-main'), encodeLog({ serviceKey: fromHex(fixture.log.service_public_key), ring,
    directoryVault: await at.directoryVault('morse-main'), locked: await at.locked('morse-main'), witnesses }), judge);
  chain.set(await at.config(), encodeJudgeConfig({ usdc }), judge);
  for (const [i, w] of witnesses.entries()) {
    chain.set(w.account, encodeWitness({ id: w.id, key: w.key, listIndex: i, vault: w.vault }), judge);
    chain.set(w.vault, encodeTokenAccount({ mint: usdc, owner: w.vault, amount: 1_000_000n }));
  }
  const header = new Uint8Array(64 + 104 * 32);
  header.set(encodeRingHeader({ head: 21, count: 21 }));
  if (fixture.ring) {
    const r = fixture.ring;
    header.set(encodeRingEntry({ sequence: BigInt(r.sequence), treeSize: BigInt(r.tree_size), root: fromHex(r.root),
      checkpointHash: fromHex(r.checkpoint_hash), bitmap: r.cosign_bitmap, timestampMs: BigInt(Date.now()) }), 64 + 104 * r.ring_index);
  }
  chain.set(ring, header, judge);
  return { chain, witnesses };
}
const logs = [{ name: 'morse-main', directory: 'https://directory.test' }];

test('a staged proof passes the finder through, creates its token account and lists implicated witnesses in list order', async () => {
  const fixture = vector('f1-same-size-finder');
  const { chain, witnesses } = await fixtureChain(fixture);
  const prepared = await prepareEvidence(fromHex(fixture.frk), { chain, judge, logs, nowMs: 0 });
  assert.equal(hex(prepared.proofHash), fixture.proof_hash);
  assert.equal(prepared.changed, false);
  const alerts = [];
  const proofAddress = await at.proof(prepared.proofHash);
  chain.onSend = async (instructions, _options, c) => {
    const prove = instructions.find(ix => ix.programAddress === judge && [17, 18, 19].includes(ix.data[0]));
    if (prove) c.set(proofAddress, encodeProof({ log: await at.log('morse-main'), proofHash: prepared.proofHash, paidTo: prepared.finder }), judge);
  };
  const result = await submitEvidence(prepared, { chain, judge, wallet, alert: line => alerts.push(line) });
  assert.equal(result.status, 'landed');
  const kinds = chain.sent.map(t => t.instructions.filter(ix => ix.programAddress === judge).map(ix => ix.data[0]));
  assert.deepEqual(kinds[0], [13], 'stage_init first');
  assert.ok(kinds.some(k => k[0] === 14) && kinds.some(k => k[0] === 15), 'staged writes and verifications');
  const last = chain.sent.at(-1).instructions;
  const prove = last.at(-1);
  assert.deepEqual([...prove.data], [17, 1], 'staged same-size proof');
  const finderAta = await ata(prepared.finder, usdc);
  assert.equal(prove.accounts[11].address, finderAta, 'the finder named in the evidence is paid, not the relay');
  assert.ok(last.some(ix => ix.data.length === 1 && ix.data[0] === 1 && ix.accounts[1].address === finderAta), 'its token account is created idempotently');
  assert.deepEqual(prove.accounts.slice(14).map(a => a.address), [witnesses[0].account, witnesses[0].vault, witnesses[1].account, witnesses[1].vault]);
  assert.deepEqual(alerts, []);
});

test('a landed proof paying someone other than the evidence finder raises a P0 line', async () => {
  const fixture = vector('f1-same-size-finder');
  const { chain } = await fixtureChain(fixture);
  const prepared = await prepareEvidence(fromHex(fixture.frk), { chain, judge, logs, nowMs: 0 });
  chain.set(await at.proof(prepared.proofHash), encodeProof({ log: await at.log('morse-main'), proofHash: prepared.proofHash, paidTo: wallet.address }), judge);
  const alerts = [];
  const result = await submitEvidence(prepared, { chain, judge, wallet, alert: line => alerts.push(line) });
  assert.equal(result.status, 'superseded');
  assert.equal(chain.sent.length, 0);
  assert.match(alerts[0], /^P0 relay_finder_mismatch/);
});

test('a contradiction against a ring entry is completed from the directory and checked against the ring root', async () => {
  const fixture = vector('f2-ring');
  const { chain } = await fixtureChain(fixture);
  const complete = decodeFrk(fromHex(fixture.frk));
  const partial = decodeFrk(fromHex(fixture.frk));
  partial.contradiction.secondPath = [];
  partial.contradiction.secondLeaf = new Uint8Array(32);
  const kti = path => concat(u8(2), bytes('KTI'), u64be(complete.contradiction.leafIndex), u64be(BigInt(fixture.ring.tree_size)), u8(path.length), ...path);
  const ktl = (leaf, path) => { const inner = kti(path); const n = new Uint8Array(4); new DataView(n.buffer).setUint32(0, inner.length); return concat(u8(2), bytes('KTL'), leaf, n, inner); };
  const requests = [];
  const directory = body => async (url, init) => { requests.push([String(url), init.body]); return new Response(body); };
  const good = directory(ktl(complete.contradiction.secondLeaf, complete.contradiction.secondPath));
  const prepared = await prepareEvidence(encodeFrk(partial), { chain, judge, logs, fetcher: good, nowMs: 0 });
  assert.equal(prepared.changed, true);
  assert.equal(hex(prepared.bytes), fixture.frk, 'the completed proof is the complete vector byte for byte');
  assert.deepEqual(prepared.implicated.map(x => x.id), fixture.implicated);
  assert.equal(requests[0][0], 'https://directory.test/v1/transparency/leaf');
  assert.deepEqual([...requests[0][1].subarray(0, 4)], [2, ...bytes('KTP')]);
  const forged = directory(ktl(complete.contradiction.firstLeaf, complete.contradiction.secondPath));
  await assert.rejects(prepareEvidence(encodeFrk(partial), { chain, judge, logs, fetcher: forged, nowMs: 0 }), /completion_invalid/);
  await assert.rejects(prepareEvidence(encodeFrk(partial), { chain, judge, logs, fetcher: async () => new Response(null, { status: 503 }), nowMs: 0 }), /completion_unavailable/);
});

test('attestations the judge would refuse are dropped so the proof can land, never the finder', async () => {
  const fixture = vector('f1-same-size-finder');
  const { chain } = await fixtureChain(fixture);
  const frk = decodeFrk(fromHex(fixture.frk));
  frk.attestations[0].signature = frk.attestations[0].signature.map(x => x ^ 1);
  const prepared = await prepareEvidence(encodeFrk(frk), { chain, judge, logs, nowMs: 0 });
  assert.equal(prepared.changed, true);
  assert.equal(prepared.frk.attestations.length, frk.attestations.length - 1);
  assert.equal(hex(prepared.frk.finder), fixture.finder);
});

test('transient failures are retried; another proof of the same fork landing first ends the submission', async () => {
  const fixture = vector('f1-same-size');
  const { chain } = await fixtureChain(fixture);
  const prepared = await prepareEvidence(fromHex(fixture.frk), { chain, judge, logs, nowMs: 0 });
  let failures = 1;
  chain.onSend = async (instructions, _options, c) => {
    if (failures-- > 0) throw new ChainError('blockhash expired');
    const init = instructions.find(ix => ix.programAddress === judge && ix.data[0] === 13);
    if (init) c.set(init.accounts[2].address, new Uint8Array(96 + prepared.bytes.length), judge);
    if (instructions.some(ix => ix.programAddress === judge && ix.data[0] === 17)) throw new ChainError('x', { code: ERROR.NothingToSlash });
  };
  const result = await submitEvidence(prepared, { chain, judge, wallet, backoffMs: 1, alert: () => {} });
  assert.equal(result.status, 'superseded');
  assert.ok(chain.sent.some(t => t.instructions.some(ix => ix.data[0] === 16)), 'the abandoned stage is closed for its rent');
  const slashed = decodeLog((await chain.account(await at.log('morse-main'))).data);
  assert.equal(slashed.serviceSlashed, false);
});

test('the HTTP endpoint verifies before answering, caps bodies, rate-limits per address and submits in the background', async () => {
  const fixture = vector('f1-same-size');
  const { chain } = await fixtureChain(fixture);
  const submitted = [];
  const alerts = [];
  const server = relayServer({ chain, judge, logs, wallet, perMinute: 3, alert: line => alerts.push(line),
    submit: async prepared => { submitted.push(hex(prepared.proofHash)); return { status: 'landed' }; } });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const post = body => fetch(`http://127.0.0.1:${server.address().port}/v1/fork-evidence`, { method: 'POST', body });
  try {
    assert.equal((await post(new Uint8Array(8193))).status, 413);
    assert.equal((await post(new Uint8Array(10))).status, 400);
    const accepted = await post(fromHex(fixture.frk));
    assert.equal(accepted.status, 202);
    assert.deepEqual(await accepted.json(), { status: 'submitting', proof_hash: fixture.proof_hash, completed: false });
    assert.equal((await post(fromHex(fixture.frk))).status, 429);
    assert.deepEqual(submitted, [fixture.proof_hash]);
    assert.match(alerts[0], /^P0 fork_evidence_received log=morse-main kind=1/);
  } finally {
    server.close();
  }
  const honest = relayServer({ chain, judge, logs, wallet, alert: () => {} });
  await new Promise(resolve => honest.listen(0, '127.0.0.1', resolve));
  try {
    const response = await fetch(`http://127.0.0.1:${honest.address().port}/v1/fork-evidence`, { method: 'POST', body: fromHex(vector('honest-f3-extension').frk) });
    assert.equal(response.status, 422);
    assert.deepEqual(await response.json(), { error: 'not_a_fork' });
  } finally {
    honest.close();
  }
});

test('the rate limiter refills over a minute', () => {
  let now = 0;
  const allow = rateLimiter(2, () => now);
  assert.deepEqual([allow('a'), allow('a'), allow('a'), allow('b')], [true, true, false, true]);
  now = 30_000;
  assert.equal(allow('a'), true);
  assert.equal(allow('a'), false);
});

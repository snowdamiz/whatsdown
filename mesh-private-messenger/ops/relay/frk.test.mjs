import assert from 'node:assert/strict';
import test from 'node:test';
import { readdirSync, readFileSync } from 'node:fs';
import { decodeFrk, encodeFrk, judgeFrk, proofHash } from './frk.mjs';
import { fromHex, hex } from './judge.mjs';

const directory = new URL('../../tests/fixtures/frk/', import.meta.url);
const vectors = readdirSync(directory).filter(name => name.endsWith('.json'))
  .map(name => JSON.parse(readFileSync(new URL(name, directory), 'utf8')));

export const fixtureLog = vector => ({
  serviceKey: fromHex(vector.log.service_public_key),
  witnesses: vector.log.witnesses.map((x, index) => ({ index, id: x.witness_id, key: fromHex(x.public_key), sinceSlot: 0n })),
});
export const fixtureRing = ring => ring && {
  sequence: BigInt(ring.sequence), treeSize: BigInt(ring.tree_size), root: fromHex(ring.root),
  checkpointHash: fromHex(ring.checkpoint_hash), timestampMs: 0n, slot: 0n, bitmap: ring.cosign_bitmap,
};

test('every shared FRK vector decodes, hashes and judges as the Mesh module and the judge do', async () => {
  assert.equal(vectors.length, 24);
  for (const vector of vectors) {
    const bytes = fromHex(vector.frk);
    if (!vector.decodes) {
      assert.throws(() => decodeFrk(bytes), /frk_malformed/, vector.name);
      continue;
    }
    const frk = decodeFrk(bytes);
    assert.equal(hex(encodeFrk(frk)), vector.frk, `${vector.name} re-encodes byte for byte`);
    assert.equal(hex(proofHash(bytes)), vector.proof_hash, vector.name);
    const judged = judgeFrk(frk, fixtureLog(vector), fixtureRing(vector.ring));
    if (vector.valid) {
      assert.deepEqual((await judged).implicated.map(x => x.id), vector.implicated, vector.name);
    } else {
      await assert.rejects(judged, /not_a_fork|checkpoint_unsigned|wrong_log_key/, vector.name);
    }
  }
});

test('the proof hash ignores the finder address and a listed witness with a bad signature is reported', async () => {
  const vector = vectors.find(x => x.name === 'f1-same-size');
  const named = vectors.find(x => x.name === 'f1-same-size-finder');
  assert.equal(vector.proof_hash, named.proof_hash);
  const frk = decodeFrk(fromHex(vector.frk));
  frk.attestations[0].signature = frk.attestations[0].signature.map(x => x ^ 1);
  const judged = await judgeFrk(frk, fixtureLog(vector));
  assert.deepEqual(judged.unverified, [0]);
  assert.ok(!judged.implicated.some(x => x.id === frk.attestations[0].id));
  await assert.rejects(judgeFrk(frk, fixtureLog(vector), null, { nowMs: 10n ** 15n }), /proof_window_closed/);
});

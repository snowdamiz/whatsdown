// Public, deterministic test keys only. This is an independent Node/OpenSSL
// implementation of FRK v1/v3; the checked-in JSON is shared with Mesh and the judge.
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';

const concat = (...values) => Buffer.concat(values);
const utf8 = value => Buffer.from(value, 'utf8');
const byte = value => Buffer.from([value]);
const hash = (...values) => createHash('sha256').update(concat(...values)).digest();
const u64 = value => { const out = Buffer.alloc(8); out.writeBigUInt64BE(BigInt(value)); return out; };
const u32 = value => { const out = Buffer.alloc(4); out.writeUInt32BE(value); return out; };
const key = seed => {
  const privateKey = createPrivateKey({ key: concat(Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, seed)), format: 'der', type: 'pkcs8' });
  return { privateKey, publicKey: createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32) };
};
const zero = Buffer.alloc(32);
const split = count => { let n = 1; while (n * 2 < count) n *= 2; return n; };
const node = (a, b, version = 1) => hash(version === 1 ? utf8('mesh-msg/v1/transparency-node') : byte(1), a, b);
const root = (leaves, version = 1) => leaves.length === 0 ? hash(version === 1 ? utf8('mesh-msg/v1/transparency-empty') : Buffer.alloc(0)) : leaves.length === 1 ? leaves[0] : node(root(leaves.slice(0, split(leaves.length)), version), root(leaves.slice(split(leaves.length)), version), version);
const audit = (leaves, index, version = 1) => {
  if (leaves.length === 1) return [];
  const k = split(leaves.length);
  return index < k ? [...audit(leaves.slice(0, k), index, version), root(leaves.slice(k), version)] : [...audit(leaves.slice(k), index - k, version), root(leaves.slice(0, k), version)];
};
const checkpoint = (signer, sequence, leaves, timestamp, previous = zero, version = 1) => {
  const fields = concat(u64(sequence), u64(leaves.length), root(leaves, version), previous, u64(timestamp), signer.publicKey);
  const statement = concat(utf8('mesh-key-transparency-v1'), Buffer.from([0, version]), fields);
  const signature = sign(null, statement, signer.privateKey);
  return { wire: concat(byte(version), utf8('KTK'), fields, signature), hash: hash(utf8('mesh-msg/v1/transparency-checkpoint'), statement, signature) };
};
const attest = (id, signer, checkpoint) => concat(byte(Buffer.byteLength(id)), utf8(id), checkpoint.hash, sign(null, concat(utf8('mesh-msg/v1/transparency-witness'), utf8(id), checkpoint.hash), signer.privateKey));
const proof = (kind, signer, first, second, attestations = [], paths = Buffer.alloc(0), finder = zero, version = 1) => concat(byte(version), utf8('FRK'), byte(kind), finder, signer.publicKey, first.wire, second.wire ? concat(byte(0), second.wire) : concat(byte(1), u32(second.index)), byte(attestations.length), ...attestations, paths);
const paths = (a, b, index, version = 1) => concat(u64(index), byte(audit(a, index, version).length), ...audit(a, index, version), a[index], byte(audit(b, index, version).length), ...audit(b, index, version), b[index]);
export const proofHash = wire => hash(wire.subarray(0, 5), wire.subarray(37)).toString('hex');
export function vectors() {
  const log = key(11), both = key(12), left = key(13), right = key(14), foreign = key(15);
  const leaf = text => hash(utf8('mesh-msg/v1/transparency-leaf'), utf8(text));
  const a = [leaf('a'), leaf('b'), leaf('c')], b = [leaf('a'), leaf('d'), leaf('c')], c = [...b, leaf('e')];
  const first = checkpoint(log, 10, a, 1000), second = checkpoint(log, 12, b, 2000, first.hash);
  const later = checkpoint(log, 13, c, 3000, second.hash), smaller = checkpoint(log, 14, a.slice(0, 1), 4000, later.hash);
  const restated = checkpoint(log, 10, a, 2000), honest = checkpoint(log, 11, [...a, leaf('e')], 2000, first.hash);
  const attestations = [attest('both', both, first), attest('both', both, second), attest('left', left, first), attest('right', right, second)];
  const f1 = proof(1, log, first, second, attestations);
  const f2 = proof(2, log, first, later, [attest('both', both, first), attest('both', both, later)], paths(a, c, 1));
  const f3 = proof(3, log, later, smaller, [attest('both', both, later), attest('both', both, smaller)]);
  const cases = [];
  const add = (name, wire, valid, witnesses = [], decode = true) => { const value = { name, wire_hex: wire.toString('hex'), proof_hash: proofHash(wire), decode, valid, witnesses }; cases.push(value); return value; };
  add('same-size-different-sequences', f1, true, ['both']);
  add('same-size-finder-does-not-change-hash', proof(1, log, first, second, attestations, Buffer.alloc(0), Buffer.alloc(32, 42)), true, ['both']);
  add('same-size-service-only', proof(1, log, first, second), true);
  add('contradictory-leaf-different-sizes', f2, true, ['both']);
  add('rollback', f3, true, ['both']);
  add('rollback-reversed', proof(3, log, smaller, later), true);
  add('equal-sequence-different-timestamp', proof(3, log, first, restated), true);
  add('honest-growth', proof(3, log, first, honest), false);
  add('identical-checkpoint', proof(3, log, first, first), false);
  add('same-size-identical-root', proof(1, log, first, restated), false);
  add('contradiction-identical-leaf', proof(2, log, first, later, [], paths(a, c, 0)), false);
  add('wrong-log', proof(1, foreign, checkpoint(foreign, 1, a, 1000), checkpoint(foreign, 2, b, 2000)), false);
  const badSignature = Buffer.from(f1); badSignature[256] ^= 1; add('bad-checkpoint-signature', badSignature, false);
  const badWitness = Buffer.from(attestations[1]); badWitness[badWitness.length - 1] ^= 1;
  add('bad-witness-signature-does-not-accuse', proof(1, log, first, second, [attestations[0], badWitness]), true);
  add('invalid-duplicate-cannot-hide-a-valid-double-signature', proof(1, log, first, second, [badWitness, attestations[0], attestations[1]]), true, ['both']);
  const wrongPath = paths(a, c, 1); wrongPath[9] ^= 1;
  add('bad-inclusion-path', proof(2, log, first, later, [], wrongPath), false);
  add('anchor-requires-authenticated-resolution', proof(1, log, first, { index: 4095 }, [attestations[0]]), false);
  const trustedAnchor = (checkpoint, cosigners) => ({ ring_index: 4095, service_public_key: log.publicKey.toString('hex'),
    sequence: checkpoint.wire.readBigUInt64BE(4).toString(), tree_size: checkpoint.wire.readBigUInt64BE(12).toString(),
    tree_root: checkpoint.wire.subarray(20, 52).toString('hex'), checkpoint_hash: checkpoint.hash.toString('hex'),
    cosigners: cosigners.map(([witness_id, signer]) => ({ witness_id, public_key: signer.publicKey.toString('hex') })) });
  const anchoredF1 = proof(1, log, first, { index: 4095 }, [attestations[0], attestations[2]]);
  add('anchored-same-size', anchoredF1, true, ['both']).anchor = trustedAnchor(second, [['both', both], ['right', right]]);
  add('anchored-contradiction', proof(2, log, first, { index: 4095 }, [attestations[0]], paths(a, c, 1)), true, ['both']).anchor = trustedAnchor(later, [['both', both]]);
  add('anchored-rollback', proof(3, log, later, { index: 4095 }), true).anchor = trustedAnchor(smaller, []);
  add('anchor-wrong-index', anchoredF1, false).anchor = { ...trustedAnchor(second, []), ring_index: 0 };
  add('anchor-wrong-log', anchoredF1, false).anchor = { ...trustedAnchor(second, []), service_public_key: foreign.publicKey.toString('hex') };
  add('anchor-does-not-accuse-a-replaced-key', anchoredF1, true).anchor = trustedAnchor(second, [['both', foreign]]);
  const mutate = (wire, offset, value) => { const out = Buffer.from(wire); out[offset] = value; return out; };
  add('bad-version', mutate(f1, 0, 2), false, [], false);
  add('unknown-kind', mutate(f1, 4, 4), false, [], false);
  add('unknown-target', mutate(f1, 257, 2), false, [], false);
  add('too-many-attestations', mutate(f1, 446, 17), false, [], false);
  add('truncated', f1.subarray(0, -1), false, [], false);
  add('trailing', concat(f1, byte(0)), false, [], false);
  add('anchor-outside-ring', proof(1, log, first, { index: 4096 }), false, [], false);
  const oversizedPath = paths(a, c, 1); oversizedPath[8] = 33;
  add('oversized-path', proof(2, log, first, later, [], oversizedPath), false, [], false);
  add('empty-attestation-id', mutate(f1, 447, 0), false, [], false);
  add('oversized-wire', Buffer.alloc(5146), false, [], false);
  const maximalPaths = concat(u64(1), byte(32), ...Array(32).fill(zero), a[1], byte(32), ...Array(32).fill(zero), c[1]);
  const maximal = proof(2, log, first, later, Array.from({ length: 16 }, (_, i) => attest(String(i).padStart(64, 'a'), both, first)), maximalPaths);
  if (maximal.length !== 5145) throw new Error('FRK maximum bound changed');
  add('maximal-framing-invalid-paths', maximal, false);
  const all = Array.from({ length: 16 }, (_, i) => ({ id: 'witness-' + i, signer: key(40 + i) }));
  const tagged = value => concat(value.subarray(0, value.length - 64), byte(0), value.subarray(-64));
  const allSignatures = all.flatMap(({ id, signer }) => [tagged(attest(id, signer, first)), tagged(attest(id, signer, second))]);
  const v3 = proof(1, log, first, second, allSignatures, Buffer.alloc(0), zero, 3);
  const allPins = all.map(({ id, signer }) => ({ witness_id: id, public_key: signer.publicKey.toString('hex') }));
  add('v3-sixteen-double-signers', v3, true, all.map(({ id }) => id)).pins = allPins;
  add('v3-finder-does-not-change-hash', proof(1, log, first, second, allSignatures, Buffer.alloc(0), Buffer.alloc(32, 42), 3), true, all.map(({ id }) => id)).pins = allPins;
  add('v3-only-fifteen-double-signers', proof(1, log, first, second, allSignatures.slice(0, 31), Buffer.alloc(0), zero, 3), true, all.slice(0, 15).map(({ id }) => id)).pins = allPins;
  add('v3-too-few-attestations', proof(1, log, first, second, allSignatures.slice(0, 16), Buffer.alloc(0), zero, 3), false, [], false);
  add('v3-too-many-attestations', proof(1, log, first, second, [...allSignatures, allSignatures[0]], Buffer.alloc(0), zero, 3), false, [], false);
  add('v3-downgrade-to-v2', mutate(v3, 0, 2), false, [], false);
  add('v3-truncated', v3.subarray(0, -1), false, [], false);
  add('v3-trailing', concat(v3, byte(0)), false, [], false);
  const maximalC2sp = Array.from({ length: 32 }, (_, i) => concat(byte(64), utf8(String(i).padStart(64, 'a')), first.hash, byte(4), Buffer.alloc(72)));
  const maxV3 = proof(2, log, first, later, maximalC2sp, maximalPaths, zero, 3);
  if (maxV3.length !== 8009) throw new Error('FRK v3 maximum bound changed');
  add('v3-maximal-framing-invalid-paths', maxV3, false);
  add('v3-oversized-wire', concat(maxV3, byte(0)), false, [], false);
  const rfcLeaves = Array.from({ length: 9 }, (_, i) => hash(byte(0), utf8('rfc-' + i)));
  const rfcForked = [...rfcLeaves]; rfcForked[6] = hash(byte(0), utf8('private-replacement'));
  const rfcFirst = checkpoint(log, 30, rfcLeaves.slice(0, 7), 1000, zero, 2);
  const rfcSecond = checkpoint(log, 31, rfcForked.slice(0, 7), 2000, rfcFirst.hash, 2);
  const rfcLater = checkpoint(log, 32, rfcForked, 3000, rfcSecond.hash, 2);
  add('rfc-same-size', proof(1, log, rfcFirst, rfcSecond), true);
  add('rfc-contradiction-uneven-trees', proof(2, log, rfcFirst, rfcLater, [], paths(rfcLeaves.slice(0, 7), rfcForked, 6, 2)), true);
  add('rfc-wrong-hash-profile-path', proof(2, log, rfcFirst, rfcLater, [], paths(rfcLeaves.slice(0, 7), rfcForked, 6)), false);
  add('different-log-profiles-cannot-conflict', proof(3, log, first, rfcFirst), false);
  const rfcSignatures = all.flatMap(({ id, signer }) => [tagged(attest(id, signer, rfcFirst)), tagged(attest(id, signer, rfcSecond))]);
  add('rfc-v3-sixteen-double-signers', proof(1, log, rfcFirst, rfcSecond, rfcSignatures, Buffer.alloc(0), zero, 3), true, all.map(({ id }) => id)).pins = allPins;
  return { version: 1, service_public_key: log.publicKey.toString('hex'), pins: [ ['both', both], ['left', left], ['right', right] ].map(([witness_id, key]) => ({ witness_id, public_key: key.publicKey.toString('hex') })), cases };
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (process.argv[2] !== '--write') throw new Error('Use --write to regenerate the public test fixtures');
  writeFileSync(fileURLToPath(new URL('../tests/fixtures/fork-v1/vectors.json', import.meta.url)), JSON.stringify(vectors(), null, 2) + '\n');
}

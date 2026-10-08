// Fork evidence FRK v1 (INTERFACES §5, protocol/witness-network-v1.md): decode,
// encode, proof hash, and the judge's acceptance rules (morse-judge-v1.md §7.1,
// §7.3) so a relay only spends fees on proofs the judge will accept.
import {
  bytes, checkpointHash, concat, ed25519Verify, equalBytes, ktkStatement, parseKtk, readU64be, sha256, u64be, witnessMessage,
} from './judge.mjs';

export const FRK_LIMIT = 8192;
export const PROOF_WINDOW_MS = 2_419_200_000n;

export class FrkError extends Error {
  constructor(code) { super(code); this.code = code; }
  get name() { return 'FrkError'; }
}
const fail = code => { throw new FrkError(code); };

// Strict decode: any other version, kind, form, count or length is refused.
export function decodeFrk(input) {
  const data = Uint8Array.from(input);
  if (data.length > FRK_LIMIT) fail('frk_malformed');
  let at = 0;
  const take = n => { if (at + n > data.length) fail('frk_malformed'); const out = data.slice(at, at + n); at += n; return out; };
  const one = () => take(1)[0];
  if (one() !== 1 || new TextDecoder().decode(take(3)) !== 'FRK') fail('frk_malformed');
  const kind = one();
  if (kind < 1 || kind > 3) fail('frk_malformed');
  const finder = take(32);
  const serviceKey = take(32);
  const c1 = take(188);
  const form = one();
  let c2 = null;
  let ringIndex = null;
  if (form === 0) c2 = take(188);
  else if (form === 1) ringIndex = new DataView(take(4).buffer).getUint32(0, false);
  else fail('frk_malformed');
  for (const ktk of [c1, c2].filter(Boolean)) {
    try { parseKtk(ktk); } catch { fail('frk_malformed'); }
  }
  const count = one();
  if (count > 16) fail('frk_malformed');
  const attestations = [];
  for (let j = 0; j < count; j++) {
    const length = one();
    if (length < 1 || length > 64) fail('frk_malformed');
    let id;
    try { id = new TextDecoder('utf-8', { fatal: true }).decode(take(length)); } catch { fail('frk_malformed'); }
    attestations.push({ id, hash: take(32), signature: take(64) });
  }
  let contradiction = null;
  if (kind === 2) {
    const leafIndex = readU64be(take(8), 0);
    const path = () => { const p = one(); if (p > 64) fail('frk_malformed'); return Array.from({ length: p }, () => take(32)); };
    const firstPath = path();
    const firstLeaf = take(32);
    const secondPath = path();
    const secondLeaf = take(32);
    contradiction = { leafIndex, firstPath, firstLeaf, secondPath, secondLeaf };
  }
  if (at !== data.length) fail('frk_malformed');
  return { kind, finder, serviceKey, c1, c2, ringIndex, attestations, contradiction };
}

export function encodeFrk(frk) {
  const ring = new Uint8Array(4);
  if (!frk.c2) new DataView(ring.buffer).setUint32(0, frk.ringIndex, false);
  const second = frk.c2 ? [Uint8Array.of(0), frk.c2] : [Uint8Array.of(1), ring];
  const parts = [Uint8Array.of(1), bytes('FRK'), Uint8Array.of(frk.kind), frk.finder, frk.serviceKey, frk.c1, ...second,
    Uint8Array.of(frk.attestations.length),
    ...frk.attestations.flatMap(a => [Uint8Array.of(bytes(a.id).length), bytes(a.id), a.hash, a.signature])];
  if (frk.kind === 2) {
    const c = frk.contradiction;
    parts.push(u64be(c.leafIndex), Uint8Array.of(c.firstPath.length), ...c.firstPath, c.firstLeaf,
      Uint8Array.of(c.secondPath.length), ...c.secondPath, c.secondLeaf);
  }
  const out = concat(...parts);
  if (out.length > FRK_LIMIT) fail('frk_malformed');
  return out;
}

// Keys the judge's pay-once record: every byte except the finder address.
export function proofHash(input) {
  if (input.length < 69) fail('frk_malformed');
  return sha256(bytes('morse-frk-v1/proof'), input.subarray(0, 5), input.subarray(37));
}

const node = (left, right) => sha256(bytes('mesh-msg/v1/transparency-node'), left, right);

// RFC 9162 §2.1.3.2 with Morse node hashing; the leaf is given as its hash.
export function verifyInclusion(leaf, index, size, path, root) {
  let fn = BigInt(index);
  let sn = BigInt(size) - 1n;
  if (fn > sn) return false;
  let hash = leaf;
  for (const sibling of path) {
    if (sn === 0n) return false;
    if ((fn & 1n) === 1n || fn === sn) {
      hash = node(sibling, hash);
      if ((fn & 1n) === 0n) while ((fn & 1n) === 0n && fn !== 0n) { fn >>= 1n; sn >>= 1n; }
    } else {
      hash = node(hash, sibling);
    }
    fn >>= 1n; sn >>= 1n;
  }
  return sn === 0n && equalBytes(hash, root);
}

function side(ktk) {
  const c = parseKtk(ktk);
  return { sequence: c.sequence, treeSize: c.treeSize, root: c.root, timestampMs: c.timestampMs, hash: checkpointHash(ktk) };
}

export function forkHolds(kind, first, second, contradiction) {
  if (kind === 1) return first.treeSize === second.treeSize && !equalBytes(first.root, second.root);
  if (kind === 3) {
    return (first.sequence < second.sequence && first.treeSize > second.treeSize)
      || (first.sequence > second.sequence && first.treeSize < second.treeSize)
      || (first.sequence === second.sequence && !equalBytes(first.hash, second.hash));
  }
  const c = contradiction;
  const i = c.leafIndex;
  return i < first.treeSize && i < second.treeSize && !equalBytes(c.firstLeaf, c.secondLeaf)
    && verifyInclusion(c.firstLeaf, i, first.treeSize, c.firstPath, first.root)
    && verifyInclusion(c.secondLeaf, i, second.treeSize, c.secondPath, second.root);
}

// Judges `frk` (decoded) against `log` ({serviceKey, witnesses: [{index, id, key,
// sinceSlot}]}) and, for a ring reference, the ring entry ({sequence, treeSize,
// root, checkpointHash, timestampMs, slot, bitmap}). Returns the implicated list
// entries (ascending index) and `unverified`: attestations the judge would refuse
// (a listed witness's attestation on C1 or C2 whose signature fails, §7.1 rule 5).
export async function judgeFrk(frk, log, ringEntry = null, { nowMs = null } = {}) {
  if (!equalBytes(frk.serviceKey, log.serviceKey)) fail('wrong_log_key');
  for (const ktk of [frk.c1, frk.c2].filter(Boolean)) {
    if (!(await ed25519Verify(log.serviceKey, ktkStatement(ktk), ktk.subarray(124, 188)))) fail('checkpoint_unsigned');
  }
  const first = side(frk.c1);
  let second;
  if (frk.c2) second = side(frk.c2);
  else if (ringEntry) second = { ...ringEntry, hash: ringEntry.checkpointHash };
  else fail('ring_index_invalid');
  if (!forkHolds(frk.kind, first, second, frk.contradiction)) fail('not_a_fork');
  if (nowMs !== null) {
    const older = first.timestampMs < second.timestampMs ? first.timestampMs : second.timestampMs;
    if (BigInt(nowMs) > older + PROOF_WINDOW_MS) fail('proof_window_closed');
  }
  const signed = [new Set(), new Set()];
  const unverified = [];
  for (const [j, a] of frk.attestations.entries()) {
    const entry = log.witnesses.find(x => x.id === a.id);
    const which = equalBytes(a.hash, first.hash) ? 0 : equalBytes(a.hash, second.hash) ? 1 : -1;
    if (!entry || which < 0) continue;
    if (await ed25519Verify(entry.key, witnessMessage(a.id, a.hash), a.signature)) signed[which].add(entry.index);
    else unverified.push(j);
  }
  const implicated = log.witnesses.filter(entry => signed[0].has(entry.index) && (signed[1].has(entry.index)
    || (!frk.c2 && ((second.bitmap >> entry.index) & 1) === 1 && BigInt(second.slot ?? 0) >= BigInt(entry.sinceSlot ?? 0))));
  return { implicated, unverified, first, second };
}

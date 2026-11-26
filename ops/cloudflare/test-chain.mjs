// Test support (not a test file): a judge-shaped in-memory chain and a signed
// checkpoint maker, shared by the jobs tests.
import assert from 'node:assert/strict';
import {
  ChainError, ERROR, addressFrom, bytes, checkpointHash, concat, decodeRingEntry, decodeRingHeader, ed25519FromSeed, encodeJudgeConfig,
  encodeLog, encodeRingEntry, encodeRingHeader, encodeWitness, hex, judgeAddresses, keypairFromSeed, memoryChain, parseKtk, readU32, u64be,
} from './judge.mjs';

export const judge = addressFrom(new Uint8Array(32).fill(7));
export const usdc = addressFrom(new Uint8Array(32).fill(9));
export const at = judgeAddresses(judge);
export const service = await ed25519FromSeed(new Uint8Array(32).fill(0x51));
export const payer = await keypairFromSeed(new Uint8Array(32).fill(1));
export const authority = await keypairFromSeed(new Uint8Array(32).fill(2));
export const memory = () => { const m = new Map(); return { get: k => m.get(k), set: (k, v) => m.set(k, v) }; };
export async function ktk(sequence, size, rootByte = 1, timestampMs = 1_790_000_000_000n) {
  const body = concat(u64be(sequence), u64be(size), new Uint8Array(32).fill(rootByte), new Uint8Array(32), u64be(timestampMs), service.publicKey);
  const signature = await service.sign(concat(bytes('mesh-key-transparency-v1'), Uint8Array.of(0, 1), body));
  return concat(Uint8Array.of(1), bytes('KTK'), body, signature);
}

// morse-main with `ids` listed, and a chain that applies post_anchor and cosign
// to the ring the way the judge does (enough for the writers under test).
export async function judgeChain(ids = []) {
  const chain = memoryChain({ slot: 5000n });
  const ring = await at.ring('morse-main');
  const witnesses = await Promise.all(ids.map(async (id, i) => {
    const key = await ed25519FromSeed(new Uint8Array(32).fill(0xa0 + i));
    return { id, key: key.publicKey, sign: key.sign, account: await at.witness('morse-main', id), vault: await at.witnessVault('morse-main', id) };
  }));
  chain.set(await at.log('morse-main'), encodeLog({ serviceKey: service.publicKey, ring, witnesses }), judge);
  chain.set(await at.config(), encodeJudgeConfig({ usdc }), judge);
  for (const [i, w] of witnesses.entries()) chain.set(w.account, encodeWitness({ id: w.id, key: w.key, listIndex: i, vault: w.vault }), judge);
  const data = new Uint8Array(64 + 104 * 64);
  data.set(encodeRingHeader({}));
  chain.set(ring, data, judge);
  chain.onSend = async instructions => {
    for (const ix of instructions.filter(x => x.programAddress === judge)) {
      const header = decodeRingHeader(data);
      if (ix.data[0] === 6) {
        const k = ix.data.subarray(2);
        const tip = header.count && decodeRingEntry(data.slice(64 + 104 * (header.head - 1), 64 + 104 * header.head));
        if (tip && hex(tip.checkpointHash) === hex(checkpointHash(k))) throw new ChainError('dup', { code: ERROR.DuplicateAnchor });
        const c = parseKtk(k);
        data.set(encodeRingEntry({ sequence: c.sequence, treeSize: c.treeSize, root: c.root, checkpointHash: checkpointHash(k), slot: chain.slotNow }), 64 + 104 * header.head);
        data.set(encodeRingHeader({ head: header.head + 1, count: header.count + 1, lastSequence: c.sequence, lastSize: c.treeSize, lastSlot: chain.slotNow }));
      }
      if (ix.data[0] === 7) {
        const index = readU32(ix.data, 1);
        data[64 + 104 * index + 96 + (ix.data[5] >> 3)] |= 1 << (ix.data[5] & 7);
      }
    }
  };
  return { chain, witnesses, ring };
}

// A directory serving a current checkpoint and attestations, recording anchors.
export function directory(state) {
  const records = [];
  const call = async (path, init = {}) => {
    if (path === '/v1/transparency/checkpoint') return { status: 200, bytes: state.checkpoint };
    // The current checkpoint's attestations (none: the log has moved on), and
    // each earlier checkpoint's by sequence, 404 once it is gone.
    if (path === '/v1/transparency/witnesses') return { status: 200, bytes: Uint8Array.of(2, 75, 84, 87, 0, 0) };
    const sequence = /^\/v1\/transparency\/witnesses\/([0-9]+)$/.exec(path)?.[1];
    if (sequence) return state.attestations?.[sequence] ? { status: 200, bytes: state.attestations[sequence] } : { status: 404, bytes: new Uint8Array() };
    if (path === '/internal/v1/transparency/anchors') {
      assert.equal(init.internal, true);
      records.push(JSON.parse(init.body));
      return { status: 201 };
    }
    return { status: 404, bytes: new Uint8Array() };
  };
  return { call, records };
}


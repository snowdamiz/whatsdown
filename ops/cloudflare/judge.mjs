// Client for the on-chain judge and rewards programs (protocol/morse-judge-v1.md):
// addresses, account decoders, instruction builders and a small transaction
// sender on @solana/kit. Shared by the relay, the drills and the jobs Worker
// (ops/cloudflare/judge.mjs is a byte-for-byte copy; a test keeps them equal).
import { createHash } from 'node:crypto';
import {
  AccountRole, address, appendTransactionMessageInstructions, compileTransaction,
  compressTransactionMessageUsingAddressLookupTables, createKeyPairFromBytes, createSolanaRpc,
  createTransactionMessage, getAddressDecoder, getAddressEncoder, getAddressFromPublicKey,
  getBase58Decoder, getBase64EncodedWireTransaction,
  getProgramDerivedAddress, getSignatureFromTransaction, getTransactionSize, partiallySignTransaction,
  pipe, setTransactionMessageFeePayer, setTransactionMessageLifetimeUsingBlockhash,
} from '@solana/kit';

export const SYSTEM = address('11111111111111111111111111111111');
export const TOKEN = address('TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA');
export const ATA_PROGRAM = address('ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL');
export const ED25519_PROGRAM = address('Ed25519SigVerify111111111111111111111111111');
export const COMPUTE_BUDGET = address('ComputeBudget111111111111111111111111111111');
export const SYSVAR_INSTRUCTIONS = address('Sysvar1nstructions1111111111111111111111111');
export const UPGRADEABLE_LOADER = address('BPFLoaderUpgradeab1e11111111111111111111111');
export const LOOKUP_TABLE_PROGRAM = address('AddressLookupTab1e1111111111111111111111111');

export const TRANSACTION_LIMIT = 1232;
export const RING_ENTRIES = 4096;
export const RING_LEN = 64 + 104 * RING_ENTRIES;
export const COSIGN_WINDOW_SLOTS = 1500;
export const EPOCH_SECONDS = 604800;
export const STATUS = ['Registered', 'Active', 'Unbonding', 'Slashed', 'Withdrawn'];
export const SLASHED = 3;
export const LOG_MAIN = 0;
export const LOG_CANARY = 1;

export const JUDGE_ERRORS = ['WrongAccount', 'Unauthorized', 'InvalidData', 'TimelockActive', 'NoPendingChange',
  'InvalidParameter', 'RingNotReady', 'RingAlreadyGrown', 'InvalidCheckpoint', 'SignatureNotVerified',
  'DuplicateAnchor', 'StaleAnchor', 'RingIndexInvalid', 'CosignWindowClosed', 'InvalidStatus', 'WitnessListFull',
  'SlotNotReusable', 'DuplicateSigningKey', 'InvalidWitnessId', 'MintNotAllowed', 'BondBelowMinimum',
  'UnbondingNotElapsed', 'StageInvalid', 'FrkMalformed', 'WrongLogKey', 'NotAFork', 'ProofWindowClosed',
  'AttestationNotVerified', 'AlreadyProven', 'ImplicatedAccountsMismatch', 'FinderAccountMismatch',
  'NothingToSlash', 'KindMismatch', 'AmountZero', 'WrongDestination', 'NotClosable', 'CloseTooEarly'];
export const REWARDS_ERRORS = ['WrongAccount', 'Unauthorized', 'InvalidData', 'EpochNotOver', 'AlreadySettled',
  'AlreadyClaimed', 'WrongDestination', 'WitnessAccountsMismatch', 'NoTokenMint'];
export const ERROR = Object.fromEntries(JUDGE_ERRORS.map((name, index) => [name, 6000 + index]));

const encoder = new TextEncoder();
const addressEncoder = getAddressEncoder();
const addressDecoder = getAddressDecoder();

// ---- bytes ----

export const bytes = value => typeof value === 'string' ? encoder.encode(value) : Uint8Array.from(value);
export const concat = (...values) => {
  const parts = values.map(bytes);
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
};
export const hex = value => Buffer.from(value).toString('hex');
export const fromHex = value => {
  if (!/^([0-9a-f]{2})*$/.test(value)) throw new Error('expected lowercase hex');
  return Uint8Array.from(Buffer.from(value, 'hex'));
};
export const equalBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);
export const sha256 = (...parts) => new Uint8Array(createHash('sha256').update(concat(...parts)).digest());
export const u8 = n => Uint8Array.of(n);
export const u16le = n => { const b = new Uint8Array(2); new DataView(b.buffer).setUint16(0, n, true); return b; };
export const u32le = n => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n, true); return b; };
export const u64le = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), true); return b; };
export const i64le = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigInt64(0, BigInt(n), true); return b; };
export const u64be = n => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, BigInt(n), false); return b; };
const view = data => new DataView(data.buffer, data.byteOffset, data.byteLength);
export const readU32 = (data, at) => view(data).getUint32(at, true);
export const readU64 = (data, at) => view(data).getBigUint64(at, true);
export const readI64 = (data, at) => view(data).getBigInt64(at, true);
export const readU64be = (data, at) => view(data).getBigUint64(at, false);
export const addressBytes = value => new Uint8Array(addressEncoder.encode(address(value)));
export const addressFrom = data => addressDecoder.decode(data);
export const isZero = data => data.every(x => x === 0);

// ---- addresses (protocol/morse-judge-v1.md §3) ----

export function logId(name) {
  const id = encoder.encode(name);
  if (!id.length || id.length > 32) throw new Error('log_id is 1-32 ASCII bytes');
  return concat(id, new Uint8Array(32 - id.length));
}
const idOf = log => typeof log === 'string' ? logId(log) : log;
const pda = async (program, seeds) => (await getProgramDerivedAddress({ programAddress: address(program), seeds }))[0];

export const judgeAddresses = judge => ({
  config: () => pda(judge, ['config']),
  log: log => pda(judge, ['log', idOf(log)]),
  ring: log => pda(judge, ['ring', idOf(log)]),
  directoryVault: log => pda(judge, ['bond', idOf(log), 'directory']),
  witness: (log, id) => pda(judge, ['witness', idOf(log), sha256(id)]),
  witnessVault: (log, id) => pda(judge, ['bond', idOf(log), sha256(id)]),
  locked: log => pda(judge, ['locked', idOf(log)]),
  stage: (submitter, nonce) => pda(judge, ['stage', addressBytes(submitter), u64le(nonce)]),
  proof: proofHash => pda(judge, ['proof', proofHash]),
});
export const rewardsAddresses = rewards => ({
  config: () => pda(rewards, ['config']),
  pool: () => pda(rewards, ['pool']),
  burn: () => pda(rewards, ['burn']),
  epoch: epoch => pda(rewards, ['epoch', u64le(epoch)]),
});
export const programData = program => pda(UPGRADEABLE_LOADER, [addressBytes(program)]);
export const ata = (owner, mint) => pda(ATA_PROGRAM, [addressBytes(owner), addressBytes(TOKEN), addressBytes(mint)]);

// ---- account decoders (§4, §10) ----

function tagged(data, tag, length) {
  if (!data || data.length !== length || data[0] !== tag || data[1] !== 1) throw new Error('unexpected account layout');
}

export function decodeLog(data) {
  tagged(data, 2, 2584);
  const count = data[4];
  const witnesses = [];
  for (let index = 0; index < count; index++) {
    const at = 280 + 144 * index;
    witnesses.push({
      index,
      id: new TextDecoder().decode(data.subarray(at + 1, at + 1 + data[at])),
      key: data.slice(at + 72, at + 104),
      account: addressFrom(data.subarray(at + 104, at + 136)),
      sinceSlot: readU64(data, at + 136),
    });
  }
  const anchorCounts = [0, 1, 2, 3].map(i => ({ epoch: readU64(data, 216 + 16 * i), count: readU64(data, 224 + 16 * i) }));
  return {
    serviceSlashed: data[3] === 1, witnessCount: count, directoryStatus: data[5], kind: data[6],
    logId: data.slice(16, 48), serviceKey: data.slice(48, 80), anchorAuthority: addressFrom(data.subarray(80, 112)),
    ring: addressFrom(data.subarray(112, 144)), directoryVault: addressFrom(data.subarray(144, 176)),
    locked: addressFrom(data.subarray(176, 208)), withdrawableAt: readI64(data, 208), anchorCounts, witnesses,
  };
}

export function decodeRingHeader(data) {
  if (!data || data.length < 64) throw new Error('unexpected ring layout');
  return { logId: data.slice(0, 32), head: readU32(data, 32), count: readU32(data, 36),
    lastSequence: readU64(data, 40), lastSize: readU64(data, 48), lastSlot: readU64(data, 56) };
}
export const ringEntryOffset = index => 64 + 104 * index;
export function decodeRingEntry(data) {
  if (!data || data.length !== 104) throw new Error('unexpected ring entry');
  return { sequence: readU64(data, 0), treeSize: readU64(data, 8), root: data.slice(16, 48),
    checkpointHash: data.slice(48, 80), timestampMs: readU64(data, 80), slot: readU64(data, 88),
    bitmap: data[96] | (data[97] << 8), evidence: data[98], epoch: readU32(data, 100) };
}

export function decodeWitness(data) {
  tagged(data, 3, 336);
  return {
    status: data[3], excluded: data[4] === 1, listIndex: data[5],
    id: new TextDecoder().decode(data.subarray(8, 8 + data[7])), log: addressFrom(data.subarray(72, 104)),
    key: data.slice(104, 136), operator: addressFrom(data.subarray(136, 168)), payout: addressFrom(data.subarray(168, 200)),
    vault: addressFrom(data.subarray(232, 264)), withdrawableAt: readI64(data, 264),
  };
}

export function decodeProof(data) {
  tagged(data, 5, 112);
  return { kind: data[3], log: addressFrom(data.subarray(8, 40)), proofHash: data.slice(40, 72),
    paidTo: addressFrom(data.subarray(72, 104)), slot: readU64(data, 104) };
}

export function decodeJudgeConfig(data) {
  tagged(data, 1, 192);
  return { authority: addressFrom(data.subarray(8, 40)), usdc: addressFrom(data.subarray(40, 72)),
    token: isZero(data.subarray(72, 104)) ? null : addressFrom(data.subarray(72, 104)) };
}

export function decodeRewardsConfig(data) {
  tagged(data, 1, 904);
  const optional = at => isZero(data.subarray(at, at + 32)) ? null : addressFrom(data.subarray(at, at + 32));
  return { authority: addressFrom(data.subarray(8, 40)), judge: addressFrom(data.subarray(40, 72)),
    log: addressFrom(data.subarray(72, 104)), usdc: addressFrom(data.subarray(104, 136)), token: optional(136),
    oracle: optional(168), priceFeed: optional(200) };
}

export function decodeEpoch(data) {
  tagged(data, 2, 1320);
  const allocations = [];
  for (let i = 0; i < data[3]; i++) {
    const at = 40 + 80 * i;
    allocations.push({ witness: addressFrom(data.subarray(at, at + 32)), amount: readU64(data, at + 64), claimed: data[at + 72] === 1 });
  }
  return { epoch: readU64(data, 8), budget: readU64(data, 16), allocated: readU64(data, 24), anchors: readU64(data, 32), allocations };
}

// SPL token account: mint 0..32, owner 32..64, amount 64..72.
export function decodeTokenAccount(data) {
  if (!data || data.length !== 165) throw new Error('unexpected token account');
  return { mint: addressFrom(data.subarray(0, 32)), owner: addressFrom(data.subarray(32, 64)), amount: readU64(data, 64) };
}

// Price feed (§10.4): i64 price, i32 exponent, i64 publish time.
export function decodePriceFeed(data) {
  if (!data || data.length < 20) throw new Error('unexpected price feed');
  return { price: readI64(data, 0), exponent: view(data).getInt32(8, true), publishTime: readI64(data, 12) };
}

// ---- checkpoints and statements (INTERFACES §1) ----

export function parseKtk(ktk) {
  if (ktk?.length !== 188 || ktk[0] !== 1 || new TextDecoder().decode(ktk.subarray(1, 4)) !== 'KTK') throw new Error('not a KTK checkpoint');
  return { sequence: readU64be(ktk, 4), treeSize: readU64be(ktk, 12), root: ktk.slice(20, 52), previous: ktk.slice(52, 84),
    timestampMs: readU64be(ktk, 84), serviceKey: ktk.slice(92, 124), signature: ktk.slice(124, 188) };
}
export const ktkStatement = ktk => concat(bytes('mesh-key-transparency-v1'), Uint8Array.of(0, 1), ktk.subarray(4, 124));
export const checkpointHash = ktk => sha256(bytes('mesh-msg/v1/transparency-checkpoint'), ktkStatement(ktk), ktk.subarray(124, 188));
export const witnessMessage = (id, hash) => concat(bytes('mesh-msg/v1/transparency-witness'), bytes(id), hash);

// ---- Ed25519 (WebCrypto: runs in Node and in Workers) ----

const PKCS8_PREFIX = fromHex('302e020100300506032b657004220420');
export async function ed25519FromSeed(seed) {
  const key = await crypto.subtle.importKey('pkcs8', concat(PKCS8_PREFIX, seed), { name: 'Ed25519' }, true, ['sign']);
  const jwk = await crypto.subtle.exportKey('jwk', key);
  const publicKey = new Uint8Array(Buffer.from(jwk.x, 'base64url'));
  return { publicKey, sign: async message => new Uint8Array(await crypto.subtle.sign('Ed25519', key, message)) };
}
export async function ed25519Verify(publicKey, message, signature) {
  try {
    const key = await crypto.subtle.importKey('raw', publicKey, { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify('Ed25519', key, signature, message);
  } catch {
    return false;
  }
}

// ---- instructions ----

const meta = (value, role) => ({ address: address(value), role });
const r = value => meta(value, AccountRole.READONLY);
const w = value => meta(value, AccountRole.WRITABLE);
const rs = value => meta(value, AccountRole.READONLY_SIGNER);
const ws = value => meta(value, AccountRole.WRITABLE_SIGNER);
const instruction = (program, accounts, ...data) => ({ programAddress: address(program), accounts, data: concat(...data) });

// Native Ed25519 program: one entry per signature, all pointing into this
// instruction's own data (instruction index 0xFFFF), per §5.
export function ed25519Instruction(entries) {
  if (!entries.length || entries.length > 255) throw new Error('1-255 Ed25519 entries');
  const header = 2 + 14 * entries.length;
  const offsets = [];
  const payload = [];
  let at = header;
  for (const { publicKey, signature, message } of entries) {
    const keyAt = at; const sigAt = keyAt + 32; const messageAt = sigAt + 64;
    payload.push(publicKey, signature, message);
    at = messageAt + message.length;
    offsets.push(u16le(sigAt), u16le(0xffff), u16le(keyAt), u16le(0xffff), u16le(messageAt), u16le(message.length), u16le(0xffff));
  }
  if (at > 0xffff) throw new Error('Ed25519 instruction too large');
  return instruction(ED25519_PROGRAM, [], Uint8Array.of(entries.length, 0), ...offsets, ...payload);
}
export const checkpointEntry = ktk => ({ publicKey: ktk.subarray(92, 124), message: ktkStatement(ktk), signature: ktk.subarray(124, 188) });

export const computeUnitLimit = units => instruction(COMPUTE_BUDGET, [], Uint8Array.of(2), u32le(units));

export const createAtaIdempotent = async (payer, owner, mint) =>
  instruction(ATA_PROGRAM, [ws(payer), w(await ata(owner, mint)), r(owner), r(mint), r(SYSTEM), r(TOKEN)], Uint8Array.of(1));

// Judge (§6). `judge` is the program id; `log` a name or 32-byte log_id.
export function judgeInstructions(judge) {
  const at = judgeAddresses(judge);
  return {
    async initialize({ deployer, authority, usdc, token = null, rewards = null, minUsdc, minToken }) {
      const zero = new Uint8Array(32);
      return instruction(judge, [ws(deployer), w(await at.config()), r(await programData(judge)), r(SYSTEM)], u8(0),
        addressBytes(authority), addressBytes(usdc), token ? addressBytes(token) : zero, rewards ? addressBytes(rewards) : zero,
        u64le(minUsdc), u64le(minToken));
    },
    // kind: LOG_MAIN (never closable) or LOG_CANARY (closable after a slash).
    async registerLog({ log, authority, payer, serviceKey, anchorAuthority, usdc, kind = LOG_MAIN }) {
      return instruction(judge, [rs(authority), ws(payer), r(await at.config()), w(await at.log(log)), w(await at.locked(log)),
        r(usdc), r(SYSTEM), r(TOKEN)], u8(3), idOf(log), serviceKey, addressBytes(anchorAuthority), u8(kind));
    },
    // Governance reclaims a slashed canary log's ring rent, 28 days after the
    // slash; `stages`: [{stage, submitter}] left behind for this log.
    async closeLog({ log, authority, destination, stages = [] }) {
      return instruction(judge, [rs(authority), r(await at.config()), r(await at.log(log)), w(await at.ring(log)), w(destination),
        ...stages.flatMap(x => [w(x.stage), w(x.submitter)])], u8(21));
    },
    async growRing({ log, payer }) {
      return instruction(judge, [ws(payer), r(await at.log(log)), w(await at.ring(log)), r(SYSTEM)], u8(5));
    },
    async postAnchor({ log, anchorAuthority, ktk, edIndex = 0 }) {
      return instruction(judge, [rs(anchorAuthority), w(await at.log(log)), w(await at.ring(log)), r(SYSVAR_INSTRUCTIONS)],
        u8(6), u8(edIndex), ktk);
    },
    async cosign({ log, ringIndex, listIndex, witnessAccount, edIndex = 0 }) {
      return instruction(judge, [r(await at.log(log)), w(await at.ring(log)), w(witnessAccount), r(SYSVAR_INSTRUCTIONS)],
        u8(7), u32le(ringIndex), u8(listIndex), u8(edIndex));
    },
    async registerWitness({ log, operator, id, signingKey, payout, operatorHash = new Uint8Array(32), excluded = false, edIndex = 0 }) {
      return instruction(judge, [ws(operator), r(await at.log(log)), w(await at.witness(log, id)), r(SYSVAR_INSTRUCTIONS), r(SYSTEM)],
        u8(8), signingKey, addressBytes(payout), operatorHash, u8(excluded ? 1 : 0), u8(edIndex), u8(bytes(id).length), bytes(id));
    },
    async admitWitness({ log, authority, id, replace = 0xff, replacedId = null, excluded = false }) {
      const replaced = replacedId ? w(await at.witness(log, replacedId)) : r(judge);
      return instruction(judge, [rs(authority), r(await at.config()), w(await at.log(log)), w(await at.witness(log, id)), replaced],
        u8(20), u8(replace), u8(excluded ? 1 : 0));
    },
    async bond({ log, operator, id, mint, amount }) {
      return instruction(judge, [ws(operator), r(await at.config()), r(await at.log(log)), w(await at.witness(log, id)),
        w(await at.witnessVault(log, id)), r(mint), w(await ata(operator, mint)), r(SYSTEM), r(TOKEN)], u8(10), u64le(amount));
    },
    async bondDirectory({ log, authority, mint, amount }) {
      return instruction(judge, [ws(authority), r(await at.config()), w(await at.log(log)), w(await at.directoryVault(log)),
        r(mint), w(await ata(authority, mint)), r(SYSTEM), r(TOKEN)], u8(9), u64le(amount));
    },
    async stageInit({ log, submitter, nonce, length }) {
      return instruction(judge, [ws(submitter), r(await at.log(log)), w(await at.stage(submitter, nonce)), r(SYSTEM)],
        u8(13), u64le(nonce), u16le(length));
    },
    async stageWrite({ submitter, nonce, offset, chunk }) {
      return instruction(judge, [rs(submitter), w(await at.stage(submitter, nonce))], u8(14), u16le(offset), chunk);
    },
    async stageVerify({ log, submitter, nonce, edIndex = 0 }) {
      return instruction(judge, [w(await at.stage(submitter, nonce)), r(await at.log(log)), r(SYSVAR_INSTRUCTIONS)], u8(15), u8(edIndex));
    },
    async stageClose({ submitter, nonce }) {
      return instruction(judge, [ws(submitter), w(await at.stage(submitter, nonce))], u8(16));
    },
    // §6.5. `frk` inline (mode 0, with the Ed25519 instruction at `edIndex`) or
    // `nonce` for a complete stage (mode 1). `implicated` = [{account, vault}]
    // in ascending list index.
    async prove({ log, kind, submitter, proofHash, frk = null, edIndex = 0, nonce = null, locked, directoryVault,
      tokenMint = null, usdcMint, finderUsdc, finderToken = null, implicated }) {
      const stage = nonce === null ? r(judge) : w(await at.stage(submitter, nonce));
      const accounts = [ws(submitter), r(await at.config()), w(await at.log(log)), r(await at.ring(log)), w(await at.proof(proofHash)),
        stage, r(SYSVAR_INSTRUCTIONS), r(SYSTEM), r(TOKEN), w(locked), tokenMint ? w(tokenMint) : r(usdcMint),
        w(finderUsdc), w(finderToken ?? finderUsdc), w(directoryVault),
        ...implicated.flatMap(x => [w(x.account), w(x.vault)])];
      const data = nonce === null ? [u8(0), u8(edIndex), frk] : [u8(1)];
      return instruction(judge, accounts, u8(16 + kind), ...data);
    },
  };
}

// Rewards (§10.2).
export function rewardsInstructions(rewards) {
  const at = rewardsAddresses(rewards);
  return {
    async initialize({ deployer, authority, judge, log, usdc, floor = 0, floorUntil = 0 }) {
      return instruction(rewards, [ws(deployer), w(await at.config()), r(await programData(rewards)), r(SYSTEM)], u8(0),
        addressBytes(authority), addressBytes(judge), addressBytes(log), addressBytes(usdc), u64le(floor), i64le(floorUntil));
    },
    async fundPool({ funder, usdc, amount }) {
      return instruction(rewards, [rs(funder), w(await ata(funder, usdc)), w(await ata(await at.pool(), usdc)),
        r(await at.config()), r(TOKEN)], u8(2), u64le(amount));
    },
    // `witnesses` = the Log's list in order: [{account, vault}].
    async settleEpoch({ payer, epoch, log, usdc, priceFeed = null, witnesses }) {
      return instruction(rewards, [ws(payer), w(await at.config()), r(log), r(await ata(await at.pool(), usdc)),
        w(await at.epoch(epoch)), r(SYSTEM), r(priceFeed ?? SYSTEM), ...witnesses.flatMap(x => [r(x.account), r(x.vault)])],
      u8(3), u64le(epoch));
    },
    async burn({ tokenMint }) {
      const authority = await at.burn();
      return instruction(rewards, [r(await at.config()), r(authority), w(await ata(authority, tokenMint)), w(tokenMint), r(TOKEN)], u8(5));
    },
  };
}

// SPL token and system helpers for local setups and drills.
export const token = {
  async createMint({ payer, mint, authority, rent, decimals = 6 }) {
    return [
      instruction(SYSTEM, [ws(payer), ws(mint)], u32le(0), u64le(rent), u64le(82), addressBytes(TOKEN)),
      instruction(TOKEN, [w(mint)], Uint8Array.of(20, decimals), addressBytes(authority), u8(0)),
    ];
  },
  async mintTo({ mint, owner, authority, amount }) {
    return instruction(TOKEN, [w(mint), w(await ata(owner, mint)), rs(authority)], u8(7), u64le(amount));
  },
  async transfer({ owner, mint, to, amount }) {
    return instruction(TOKEN, [w(await ata(owner, mint)), w(to), rs(owner)], u8(3), u64le(amount));
  },
};

// Address lookup tables (for proofs implicating more than nine witnesses).
export const lookupTable = {
  async create({ authority, payer, recentSlot }) {
    const [table, bump] = await getProgramDerivedAddress({ programAddress: LOOKUP_TABLE_PROGRAM, seeds: [addressBytes(authority), u64le(recentSlot)] });
    return { table, instruction: instruction(LOOKUP_TABLE_PROGRAM, [w(table), rs(authority), ws(payer), r(SYSTEM)], u32le(0), u64le(recentSlot), u8(bump)) };
  },
  extend({ table, authority, payer, addresses }) {
    return instruction(LOOKUP_TABLE_PROGRAM, [w(table), rs(authority), ws(payer), r(SYSTEM)], u32le(2), u64le(addresses.length),
      ...addresses.map(addressBytes));
  },
};

// ---- keys ----

// A solana-keygen JSON file's contents (64 numbers), or 64 raw bytes.
export async function loadKeypair(value) {
  const secret = Uint8Array.from(typeof value === 'string' ? JSON.parse(value) : value);
  if (secret.length !== 64) throw new Error('expected a 64-byte Solana keypair');
  const keyPair = await createKeyPairFromBytes(secret);
  return { address: await getAddressFromPublicKey(keyPair.publicKey), keyPair };
}

export async function keypairFromSeed(seed) {
  return loadKeypair(concat(seed, (await ed25519FromSeed(seed)).publicKey));
}

// ---- errors ----

export class ChainError extends Error {
  constructor(message, { code = null, signature = null, logs = [] } = {}) {
    super(message);
    this.code = code;
    this.signature = signature;
    this.logs = logs;
  }
  get name() { return 'ChainError'; }
}
export const errorName = code => code >= 7000 ? REWARDS_ERRORS[code - 7000] : JUDGE_ERRORS[code - 6000];

// The custom program error in a kit SolanaError chain or a raw RPC status error.
export function customCode(error) {
  for (let e = error, depth = 0; e && depth < 8; e = e.cause, depth++) {
    if (typeof e.code === 'number' && e.name === 'ChainError') return e.code;
    if (typeof e.context?.code === 'number' && e.context.__code === 4615026) return e.context.code;
    const custom = e.InstructionError?.[1]?.Custom;
    if (custom !== undefined) return Number(custom);
    const match = /custom program error: (0x[0-9a-f]+|#\d+)/i.exec(e.message ?? '');
    if (match) return Number(match[1].replace('#', ''));
  }
  return null;
}
const logsOf = error => {
  for (let e = error, depth = 0; e && depth < 8; e = e.cause, depth++) if (Array.isArray(e.context?.logs)) return e.context.logs;
  return [];
};

// ---- chain access ----

export const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
const NO_BLOCKHASH = { blockhash: '11111111111111111111111111111111', lastValidBlockHeight: 0n };

function buildMessage(instructions, feePayer, blockhash, lookupTables = null) {
  const message = pipe(createTransactionMessage({ version: lookupTables ? 0 : 'legacy' }),
    m => setTransactionMessageFeePayer(address(feePayer), m),
    m => setTransactionMessageLifetimeUsingBlockhash(blockhash, m),
    m => appendTransactionMessageInstructions(instructions, m));
  return lookupTables ? compressTransactionMessageUsingAddressLookupTables(message, lookupTables) : message;
}

// `rpc` defaults to createSolanaRpc(url); tests pass a fake with the same shape.
export function solanaChain({ url, rpc = createSolanaRpc(url), commitment = 'confirmed', confirmTimeoutMs = 60_000, pollMs = 400 }) {
  const b64 = value => new Uint8Array(Buffer.from(value, 'base64'));
  const info = value => value ? { data: b64(value.data[0]), owner: value.owner, lamports: value.lamports } : null;
  const chain = {
    url, rpc,
    async account(target, slice) {
      const { value } = await rpc.getAccountInfo(address(target), { encoding: 'base64', commitment, ...(slice ? { dataSlice: slice } : {}) }).send();
      return info(value);
    },
    async accounts(targets) {
      const out = [];
      for (let i = 0; i < targets.length; i += 100) {
        const { value } = await rpc.getMultipleAccounts(targets.slice(i, i + 100).map(x => address(x)), { encoding: 'base64', commitment }).send();
        out.push(...value.map(info));
      }
      return out;
    },
    async balance(target) { return (await rpc.getBalance(address(target), { commitment }).send()).value; },
    async slot() { return await rpc.getSlot({ commitment }).send(); },
    async blockTime(slot) { return await rpc.getBlockTime(BigInt(slot)).send(); },
    async rent(length) { return await rpc.getMinimumBalanceForRentExemption(BigInt(length)).send(); },
    async signaturesFor(target, limit = 20) {
      return await rpc.getSignaturesForAddress(address(target), { limit, commitment }).send();
    },
    async programAccounts(program, filters) {
      const list = await rpc.getProgramAccounts(address(program), { encoding: 'base64', commitment, filters }).send();
      return list.map(x => ({ address: x.pubkey, ...info(x.account) }));
    },
    // Signs with the fee payer and `signers` ({address, keyPair}), sends, and
    // waits for `commitment`. Throws ChainError with the custom error code.
    async send(instructions, { payer, signers = [], lookupTables = null }) {
      const { value: blockhash } = await rpc.getLatestBlockhash({ commitment }).send();
      const transaction = compileTransaction(buildMessage(instructions, payer.address, blockhash, lookupTables));
      const keys = new Map([payer, ...signers].map(s => [s.address, s.keyPair]));
      return chain.sendSigned(await partiallySignTransaction([...keys.values()], transaction));
    },
    // Sends a signed kit transaction and waits for `commitment`.
    async sendSigned(signed) {
      const size = getTransactionSize(signed);
      if (size > TRANSACTION_LIMIT) throw new ChainError(`transaction too large: ${size} bytes`);
      const signature = getSignatureFromTransaction(signed);
      try {
        await rpc.sendTransaction(getBase64EncodedWireTransaction(signed), { encoding: 'base64', preflightCommitment: commitment }).send();
      } catch (error) {
        const code = customCode(error);
        throw new ChainError(code === null ? `send failed: ${error.message}` : `program error ${code} ${errorName(code) ?? ''}`.trim(),
          { code, signature, logs: logsOf(error) });
      }
      const deadline = Date.now() + confirmTimeoutMs;
      for (;;) {
        const { value: [status] } = await rpc.getSignatureStatuses([signature]).send();
        if (status?.err) {
          const code = customCode(status.err);
          throw new ChainError(`transaction failed: ${code ?? JSON.stringify(status.err)}`, { code, signature });
        }
        if (status && ['confirmed', 'finalized'].includes(status.confirmationStatus)) return { signature, slot: status.slot };
        if (Date.now() > deadline) throw new ChainError('transaction not confirmed in time', { signature });
        await pause(pollMs);
      }
    },
  };
  return chain;
}

// A legacy message with the given fee payer, for a Squads vault transaction or
// another signer to sign offline (never signed here). Base58, like morse-admin.
export function unsignedMessage(instructions, feePayer) {
  return getBase58Decoder().decode(compileTransaction(buildMessage(instructions, feePayer, NO_BLOCKHASH)).messageBytes);
}

// Wire size with signatures, for packing transactions under the 1,232-byte limit.
export const transactionSize = (instructions, feePayer, lookupTables = null) =>
  getTransactionSize(compileTransaction(buildMessage(instructions, feePayer, NO_BLOCKHASH, lookupTables)));
export const instructionJson = ix => ({
  programId: ix.programAddress,
  accounts: ix.accounts.map(a => ({ pubkey: a.address, isSigner: a.role >= 2, isWritable: (a.role & 1) === 1 })),
  data: Buffer.from(ix.data).toString('base64'),
});
export { address };

// ---- account encoders and an in-memory chain (tests and local dry runs) ----

const put = (data, at, value) => data.set(value, at);
const tag = (length, value) => { const data = new Uint8Array(length); data[0] = value; data[1] = 1; return data; };

export function encodeLog({ serviceSlashed = false, directoryStatus = 1, kind = LOG_MAIN, log = 'morse-main', serviceKey, anchorAuthority = SYSTEM,
  ring = SYSTEM, directoryVault = SYSTEM, locked = SYSTEM, witnesses = [], anchorCounts = [] }) {
  const data = tag(2584, 2);
  data[3] = serviceSlashed ? 1 : 0; data[4] = witnesses.length; data[5] = directoryStatus; data[6] = kind;
  put(data, 16, idOf(log)); put(data, 48, serviceKey); put(data, 80, addressBytes(anchorAuthority)); put(data, 112, addressBytes(ring));
  put(data, 144, addressBytes(directoryVault)); put(data, 176, addressBytes(locked));
  for (const { epoch, count } of anchorCounts) { put(data, 216 + 16 * Number(BigInt(epoch) % 4n), concat(u64le(epoch), u64le(count))); }
  witnesses.forEach(({ id, key, account, sinceSlot = 0n }, i) => {
    const at = 280 + 144 * i;
    data[at] = bytes(id).length; put(data, at + 1, bytes(id)); put(data, at + 72, key); put(data, at + 104, addressBytes(account));
    put(data, at + 136, u64le(sinceSlot));
  });
  return data;
}
export function encodeRingHeader({ log = 'morse-main', head = 0, count = 0, lastSequence = 0n, lastSize = 0n, lastSlot = 0n }) {
  return concat(idOf(log), u32le(head), u32le(count), u64le(lastSequence), u64le(lastSize), u64le(lastSlot));
}
export function encodeRingEntry({ sequence, treeSize, root, checkpointHash: hash, timestampMs = 0n, slot = 0n, bitmap = 0, evidence = 0, epoch = 0 }) {
  return concat(u64le(sequence), u64le(treeSize), root, hash, u64le(timestampMs), u64le(slot), u16le(bitmap), u8(evidence), u8(0), u32le(epoch));
}
export function encodeWitness({ status = 1, excluded = false, listIndex = 255, id, log = SYSTEM, key, operator = SYSTEM, payout = SYSTEM,
  vault = SYSTEM, cosignCounts = [] }) {
  const data = tag(336, 3);
  data[3] = status; data[4] = excluded ? 1 : 0; data[5] = listIndex; data[7] = bytes(id).length;
  put(data, 8, bytes(id)); put(data, 72, addressBytes(log)); put(data, 104, key); put(data, 136, addressBytes(operator));
  put(data, 168, addressBytes(payout)); put(data, 232, addressBytes(vault));
  for (const { epoch, count } of cosignCounts) { put(data, 272 + 16 * Number(BigInt(epoch) % 4n), concat(u64le(epoch), u64le(count))); }
  return data;
}
export function encodeTokenAccount({ mint, owner, amount }) {
  const data = new Uint8Array(165);
  put(data, 0, addressBytes(mint)); put(data, 32, addressBytes(owner)); put(data, 64, u64le(amount)); data[108] = 1;
  return data;
}
export function encodeProof({ kind = 1, log, proofHash: hash, paidTo, slot = 0n }) {
  const data = tag(112, 5);
  data[3] = kind; put(data, 8, addressBytes(log)); put(data, 40, hash); put(data, 72, addressBytes(paidTo)); put(data, 104, u64le(slot));
  return data;
}
export function encodeJudgeConfig({ authority = SYSTEM, usdc, token = null }) {
  const data = tag(192, 1);
  put(data, 8, addressBytes(authority)); put(data, 40, addressBytes(usdc)); if (token) put(data, 72, addressBytes(token));
  return data;
}

// Accounts in a Map; `send` records every transaction and asks `onSend`
// (instructions, options, chain) for a result or throws what it throws.
export function memoryChain({ slot = 1000n, onSend = null } = {}) {
  const store = new Map();
  const chain = {
    store, sent: [], slotNow: BigInt(slot), onSend, times: new Map(),
    set(target, data, owner = SYSTEM, lamports = 1_000_000n) { store.set(target, { data, owner, lamports }); },
    async account(target, slice) {
      const found = store.get(target);
      if (!found) return null;
      if (!slice) return found;
      const data = new Uint8Array(slice.length);
      data.set(found.data.subarray(slice.offset, slice.offset + slice.length));
      return { ...found, data };
    },
    async accounts(targets) { return Promise.all(targets.map(t => chain.account(t))); },
    async balance(target) { return store.get(target)?.lamports ?? 0n; },
    async slot() { return chain.slotNow; },
    async blockTime(at) { return chain.times.get(BigInt(at)) ?? null; },
    async rent(length) { return BigInt(length) * 6960n; },
    async signaturesFor() { return []; },
    async programAccounts() { return []; },
    async sendSigned(transaction) {
      chain.sent.push({ transaction });
      const result = await chain.onSend?.([], { transaction }, chain);
      return result ?? { signature: `sig${chain.sent.length}`, slot: chain.slotNow };
    },
    async send(instructions, options) {
      chain.sent.push({ instructions, ...options });
      const result = await chain.onSend?.(instructions, options, chain);
      return result ?? { signature: `sig${chain.sent.length}`, slot: chain.slotNow };
    },
  };
  return chain;
}

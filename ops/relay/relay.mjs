// The fork-evidence relay (plan §6.9, morse-judge-v1.md §9 "Relay"): verify an
// FRK off-chain, complete a contradiction proof against a ring reference, and
// land it on-chain from the relay's own wallet, passing the finder address
// through unchanged. Retries until this proof or another proof of the fork lands.
import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { FRK_LIMIT, FrkError, decodeFrk, encodeFrk, judgeFrk, proofHash, verifyInclusion } from './frk.mjs';
import {
  ERROR, SLASHED, TRANSACTION_LIMIT, addressFrom, ata, bytes, checkpointEntry, checkpointHash, computeUnitLimit, concat,
  createAtaIdempotent, decodeJudgeConfig, decodeLog, decodeProof, decodeRingEntry, decodeRingHeader, decodeTokenAccount,
  decodeWitness, ed25519Instruction, equalBytes, errorName, hex, isZero, judgeAddresses, judgeInstructions, lookupTable,
  pause, readU64be, ringEntryOffset, transactionSize, u64be, u8, witnessMessage,
} from './judge.mjs';

const WITHDRAWN = 4;
const STAGE_CHUNK = 1000;
const PROVE_UNITS = 400_000;

// {name, directory} per log this relay serves; each is matched by service key.
export async function loadLogs(chain, judge, logs) {
  const at = judgeAddresses(judge);
  return Promise.all(logs.map(async ({ name, directory }) => {
    const address = await at.log(name);
    const account = await chain.account(address);
    if (!account || account.owner !== judge) throw new Error(`log ${name} not found under ${judge}`);
    return { name, directory, address, log: decodeLog(account.data) };
  }));
}

async function ringEntry(chain, log, index) {
  const header = decodeRingHeader((await chain.account(log.ring, { offset: 0, length: 64 }))?.data);
  if (index >= Math.min(header.count, 4096)) throw new FrkError('ring_index_invalid');
  return decodeRingEntry((await chain.account(log.ring, { offset: ringEntryOffset(index), length: 104 })).data);
}

// Fills in the public version's leaf and audit path for a kind-2 proof against a
// ring entry (a phone only holds its own side), from the directory's KTP v2 leaf
// query, checked against the ring root rather than trusted.
export async function completeContradiction(frk, entry, directory, fetcher = fetch) {
  const c = frk.contradiction;
  if (verifyInclusion(c.secondLeaf, c.leafIndex, entry.treeSize, c.secondPath, entry.root)) return false;
  if (!directory) throw new FrkError('completion_unavailable');
  let body;
  try {
    const response = await fetcher(new URL('/v1/transparency/leaf', directory), {
      method: 'POST', redirect: 'manual', signal: AbortSignal.timeout(30_000),
      headers: { 'Content-Type': 'application/octet-stream' },
      body: concat(u8(2), bytes('KTP'), u64be(c.leafIndex), u64be(entry.treeSize), u8(1)),
    });
    if (response.status !== 200) throw new Error(String(response.status));
    body = new Uint8Array(await response.arrayBuffer());
  } catch {
    throw new FrkError('completion_unavailable');
  }
  // KTL v2: u8 2 ‖ "KTL" ‖ leaf32 ‖ vector32(KTI v2 = u8 2 ‖ "KTI" ‖ u64 index ‖ u64 size ‖ u8 p ‖ p × 32).
  const text = x => new TextDecoder().decode(x);
  const kti = body.subarray(40);
  const length = body.length >= 40 ? new DataView(body.buffer, body.byteOffset + 36, 4).getUint32(0) : -1;
  if (body[0] !== 2 || text(body.subarray(1, 4)) !== 'KTL' || length !== kti.length || kti.length < 21
    || kti[0] !== 2 || text(kti.subarray(1, 4)) !== 'KTI' || kti.length !== 21 + 32 * kti[20]
    || readU64be(kti, 4) !== c.leafIndex || readU64be(kti, 12) !== entry.treeSize) throw new FrkError('completion_invalid');
  const leaf = body.slice(4, 36);
  const path = Array.from({ length: kti[20] }, (_, i) => kti.slice(21 + 32 * i, 53 + 32 * i));
  if (!verifyInclusion(leaf, c.leafIndex, entry.treeSize, path, entry.root)) throw new FrkError('completion_invalid');
  c.secondLeaf = leaf;
  c.secondPath = path;
  return true;
}

// Everything short of spending fees: decode, find the log, resolve the ring
// reference, complete, judge, and drop attestations the judge would refuse
// (they implicate nobody). Throws FrkError with a stable code.
export async function prepareEvidence(input, { chain, judge, logs, fetcher = fetch, nowMs = Date.now() }) {
  if (input.length > FRK_LIMIT) throw new FrkError('too_large');
  const frk = decodeFrk(input);
  const served = await loadLogs(chain, judge, logs);
  const target = served.find(x => equalBytes(x.log.serviceKey, frk.serviceKey));
  if (!target) throw new FrkError('unknown_log');
  const entry = frk.ringIndex === null ? null : await ringEntry(chain, target.log, frk.ringIndex);
  let changed = frk.kind === 2 && entry ? await completeContradiction(frk, entry, target.directory, fetcher) : false;
  const first = await judgeFrk(frk, target.log, entry, { nowMs });
  if (first.unverified.length) {
    frk.attestations = frk.attestations.filter((_, j) => !first.unverified.includes(j));
    changed = true;
  }
  const bytesOut = changed ? encodeFrk(frk) : Uint8Array.from(input);
  return { frk, bytes: bytesOut, proofHash: proofHash(bytesOut), target, entry, implicated: first.implicated,
    finder: isZero(frk.finder) ? null : addressFrom(frk.finder), changed };
}

// Ed25519 entries the judge needs: C1, inline C2, and every listed witness's
// attestation on C1 or C2 (after preparation all of them verify).
function signatureEntries({ frk, target, entry }) {
  const hashes = [checkpointHash(frk.c1), frk.c2 ? checkpointHash(frk.c2) : entry.checkpointHash];
  const listed = new Map(target.log.witnesses.map(x => [x.id, x]));
  return [
    ...[frk.c1, frk.c2].filter(Boolean).map(checkpointEntry),
    ...frk.attestations.filter(a => listed.has(a.id) && hashes.some(h => equalBytes(h, a.hash)))
      .map(a => ({ publicKey: listed.get(a.id).key, message: witnessMessage(a.id, a.hash), signature: a.signature })),
  ];
}

async function proofAccounts(prepared, { chain, judge, wallet }) {
  const at = judgeAddresses(judge);
  const config = decodeJudgeConfig((await chain.account(await at.config())).data);
  const { log } = prepared.target;
  const witnesses = await chain.accounts(prepared.implicated.map(x => x.account));
  const implicated = prepared.implicated.map((x, i) => ({ ...x, witness: decodeWitness(witnesses[i].data) }));
  const directorySlashes = log.directoryStatus !== SLASHED && log.directoryStatus !== WITHDRAWN;
  const slashed = implicated.filter(x => x.witness.status !== SLASHED && x.witness.status !== WITHDRAWN);
  if (!directorySlashes && !slashed.length) return null;
  const vaults = [...(directorySlashes ? [log.directoryVault] : []), ...slashed.map(x => x.witness.vault)];
  const tokenVault = config.token && (await chain.accounts(vaults)).some(a => {
    if (!a || a.data.length !== 165) return false;
    const account = decodeTokenAccount(a.data);
    return account.mint === config.token && account.amount > 0n;
  });
  const payee = prepared.finder ?? wallet.address;
  const create = [await createAtaIdempotent(wallet.address, payee, config.usdc)];
  if (tokenVault) create.push(await createAtaIdempotent(wallet.address, payee, config.token));
  return {
    config, create,
    base: { log: prepared.target.name, kind: prepared.frk.kind, submitter: wallet.address, proofHash: prepared.proofHash,
      locked: log.locked, directoryVault: log.directoryVault, tokenMint: config.token, usdcMint: config.usdc,
      finderUsdc: await ata(payee, config.usdc), finderToken: tokenVault ? await ata(payee, config.token) : null,
      implicated: implicated.map(x => ({ account: x.account, vault: x.witness.vault })) },
  };
}

// Packs Ed25519 entries into as few stage_verify transactions as fit.
async function verifyStage(entries, { chain, judge, wallet, log, nonce }) {
  const ix = judgeInstructions(judge);
  const verify = await ix.stageVerify({ log, submitter: wallet.address, nonce });
  let batch = [];
  const flush = async () => {
    if (batch.length) await chain.send([ed25519Instruction(batch), verify], { payer: wallet });
    batch = [];
  };
  for (const e of entries) {
    if (batch.length && transactionSize([ed25519Instruction([...batch, e]), verify], wallet.address) > TRANSACTION_LIMIT) await flush();
    batch.push(e);
  }
  await flush();
}

async function sendProve(instructions, lookupAddresses, { chain, wallet }) {
  if (transactionSize(instructions, wallet.address) <= TRANSACTION_LIMIT) return chain.send(instructions, { payer: wallet });
  // More than nine implicated witnesses: put the witness accounts in a lookup table.
  const recentSlot = await chain.slot() - 1n;
  const { table, instruction } = await lookupTable.create({ authority: wallet.address, payer: wallet.address, recentSlot });
  await chain.send([instruction], { payer: wallet });
  for (let i = 0; i < lookupAddresses.length; i += 20) {
    await chain.send([lookupTable.extend({ table, authority: wallet.address, payer: wallet.address, addresses: lookupAddresses.slice(i, i + 20) })], { payer: wallet });
  }
  const ready = await chain.slot();
  while (await chain.slot() <= ready) await pause(400);
  return chain.send(instructions, { payer: wallet, lookupTables: { [table]: lookupAddresses } });
}

// One submission attempt: inline when it fits one transaction, else staged.
async function submitOnce(prepared, context, nonce) {
  const { chain, judge, wallet } = context;
  const accounts = await proofAccounts(prepared, context);
  if (!accounts) return { status: 'nothing_to_slash' };
  const ix = judgeInstructions(judge);
  const entries = signatureEntries(prepared);
  const edIndex = 1 + accounts.create.length;
  const inline = [computeUnitLimit(PROVE_UNITS), ...accounts.create, ed25519Instruction(entries),
    await ix.prove({ ...accounts.base, frk: prepared.bytes, edIndex })];
  if (transactionSize(inline, wallet.address) <= TRANSACTION_LIMIT) return { status: 'landed', ...(await chain.send(inline, { payer: wallet })) };
  const log = prepared.target.name;
  const at = judgeAddresses(judge);
  const stage = await at.stage(wallet.address, nonce);
  let written = 0;
  const existing = await chain.account(stage);
  if (!existing) {
    await chain.send([await ix.stageInit({ log, submitter: wallet.address, nonce, length: prepared.bytes.length })], { payer: wallet });
  } else {
    written = new DataView(existing.data.buffer, existing.data.byteOffset + 82, 2).getUint16(0, true);
  }
  for (let offset = written; offset < prepared.bytes.length; offset += STAGE_CHUNK) {
    const chunk = prepared.bytes.subarray(offset, offset + STAGE_CHUNK);
    await chain.send([await ix.stageWrite({ submitter: wallet.address, nonce, offset, chunk })], { payer: wallet });
  }
  await verifyStage(entries, { ...context, log, nonce });
  const prove = await ix.prove({ ...accounts.base, nonce });
  const lookup = accounts.base.implicated.flatMap(x => [x.account, x.vault]);
  return { status: 'landed', ...(await sendProve([computeUnitLimit(PROVE_UNITS), ...accounts.create, prove], lookup, context)) };
}

// Whoever landed a proof of this hash, and the P0 check on the payee.
async function landedProof(prepared, { chain, judge, alert }) {
  const account = await chain.account(await judgeAddresses(judge).proof(prepared.proofHash));
  if (!account) return null;
  const proof = decodeProof(account.data);
  if (prepared.finder && proof.paidTo !== prepared.finder) {
    alert(`P0 relay_finder_mismatch proof=${hex(prepared.proofHash)} expected=${prepared.finder} paid=${proof.paidTo}`);
  }
  return proof;
}

const permanent = new Set([ERROR.NotAFork, ERROR.WrongLogKey, ERROR.FrkMalformed, ERROR.KindMismatch, ERROR.ProofWindowClosed,
  ERROR.RingIndexInvalid, ERROR.AttestationNotVerified, ERROR.ImplicatedAccountsMismatch, ERROR.FinderAccountMismatch]);

// Lands the prepared proof, retrying transient failures until it or another
// proof of the same fork is on-chain. `attempts` bounds the loop (Infinity for
// the server). Returns {status: landed | superseded | nothing_to_slash, ...}.
export async function submitEvidence(prepared, { chain, judge, wallet, attempts = Infinity, alert = console.error, backoffMs = 2000 }) {
  const context = { chain, judge, wallet, alert };
  const nonce = new DataView(randomBytes(8).buffer).getBigUint64(0);
  for (let attempt = 1; ; attempt++) {
    const already = await landedProof(prepared, context).catch(() => null);
    if (already) return { status: already.paidTo === (prepared.finder ?? wallet.address) ? 'landed' : 'superseded', proof: already };
    try {
      const result = await submitOnce(prepared, context, nonce);
      if (result.status === 'landed') return { ...result, proof: await landedProof(prepared, context) };
      return result;
    } catch (error) {
      const code = error?.name === 'ChainError' ? error.code : null;
      if (code === ERROR.AlreadyProven) { await pause(backoffMs); continue; }
      if (code === ERROR.NothingToSlash) {
        await closeStage(context, nonce);
        return { status: 'superseded' };
      }
      if (permanent.has(code)) {
        await closeStage(context, nonce);
        throw new FrkError(`rejected_${errorName(code)}`);
      }
      if (attempt >= attempts) throw error;
      console.error(`relay: attempt ${attempt} failed: ${String(error.message).slice(0, 200)}`);
      await pause(Math.min(60_000, backoffMs * 2 ** Math.min(attempt - 1, 5)));
    }
  }
}

async function closeStage({ chain, judge, wallet }, nonce) {
  try {
    if (await chain.account(await judgeAddresses(judge).stage(wallet.address, nonce))) {
      await chain.send([await judgeInstructions(judge).stageClose({ submitter: wallet.address, nonce })], { payer: wallet });
    }
  } catch { /* rent stays recoverable with stage_close later */ }
}

const STATUS = { frk_malformed: 400, too_large: 413, unknown_log: 422, wrong_log_key: 422, checkpoint_unsigned: 422,
  not_a_fork: 422, ring_index_invalid: 422, proof_window_closed: 422, completion_invalid: 422, completion_unavailable: 503 };

// Per-IP token bucket: `perMinute` evidence posts, refilled continuously.
export function rateLimiter(perMinute, now = () => Date.now()) {
  const buckets = new Map();
  return key => {
    const t = now();
    const bucket = buckets.get(key) ?? { tokens: perMinute, at: t };
    bucket.tokens = Math.min(perMinute, bucket.tokens + ((t - bucket.at) / 60_000) * perMinute);
    bucket.at = t;
    buckets.set(key, bucket);
    if (buckets.size > 10_000) buckets.delete(buckets.keys().next().value);
    if (bucket.tokens < 1) return false;
    bucket.tokens -= 1;
    return true;
  };
}

// POST /v1/fork-evidence (FRK body ≤ 8 KB): 202 while landing, 200 once landed.
export function relayServer({ chain, judge, logs, wallet, fetcher = fetch, perMinute = 6, trustProxy = false, alert = console.error, submit = submitEvidence }) {
  const allow = rateLimiter(perMinute);
  const inflight = new Map();
  const json = (response, status, body) => response.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }).end(JSON.stringify(body));
  return createServer(async (request, response) => {
    try {
      const url = new URL(request.url, 'http://relay');
      if (request.method === 'GET' && url.pathname === '/health') return json(response, 200, { ok: true });
      if (request.method !== 'POST' || url.pathname !== '/v1/fork-evidence' || url.search) return json(response, 404, { error: 'not_found' });
      const ip = (trustProxy && request.headers['x-forwarded-for']?.split(',')[0].trim()) || request.socket.remoteAddress;
      if (!allow(ip)) return json(response, 429, { error: 'rate_limited' });
      const chunks = [];
      let size = 0;
      for await (const chunk of request) {
        size += chunk.length;
        if (size > FRK_LIMIT) return json(response, 413, { error: 'too_large' });
        chunks.push(chunk);
      }
      const prepared = await prepareEvidence(new Uint8Array(Buffer.concat(chunks)), { chain, judge, logs, fetcher });
      const hash = hex(prepared.proofHash);
      alert(`P0 fork_evidence_received log=${prepared.target.name} kind=${prepared.frk.kind} proof=${hash}`);
      const landed = await landedProof(prepared, { chain, judge, alert });
      if (landed) return json(response, 200, { status: 'landed', proof_hash: hash, paid_to: landed.paidTo, slot: String(landed.slot) });
      if (!inflight.has(hash)) {
        const job = submit(prepared, { chain, judge, wallet, alert })
          .then(result => console.log(`relay: proof ${hash} ${result.status}`))
          .catch(error => alert(`relay: proof ${hash} failed: ${String(error.message).slice(0, 300)}`))
          .finally(() => inflight.delete(hash));
        inflight.set(hash, job);
      }
      return json(response, 202, { status: 'submitting', proof_hash: hash, completed: prepared.changed });
    } catch (error) {
      if (error instanceof FrkError) return json(response, STATUS[error.code] ?? 422, { error: error.code });
      console.error('relay: request failed', String(error.message).slice(0, 300));
      return json(response, 503, { error: 'unavailable' });
    }
  });
}

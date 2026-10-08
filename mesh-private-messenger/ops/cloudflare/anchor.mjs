// Chain writers of the jobs Worker (plan Phase 1 and §6.11, morse-judge-v1.md §9):
// the anchor poster, the cosign crank, weekly settlement, and the fee payer watch.
// Each takes its chain, keys and state explicitly so tests run without a network.
import { currentCheckpoint } from './directory.mjs';
import {
  COSIGN_WINDOW_SLOTS, EPOCH_SECONDS, ERROR, LOG_CANARY, SLASHED, TRANSACTION_LIMIT, checkpointEntry, checkpointHash,
  decodeLog, decodeRewardsConfig, decodeRingEntry, decodeRingHeader, decodeWitness, ed25519Instruction, ed25519Verify, equalBytes,
  hex, judgeAddresses, judgeInstructions, parseKtk, rewardsAddresses, rewardsInstructions, ringEntryOffset, transactionSize,
  witnessMessage,
} from './judge.mjs';

export const ANCHOR_INTERVAL_MS = 60_000;
export const ANCHOR_GAP_MS = 3_600_000;
const SOL = 1_000_000_000n;
const REWARDS_ALREADY_SETTLED = 7004;

async function readLog(chain, judge, logName) {
  const address = await judgeAddresses(judge).log(logName);
  const account = await chain.account(address);
  if (!account || account.owner !== judge) throw new Error(`Log ${logName} not found under the judge`);
  return { address, log: decodeLog(account.data) };
}
const readEntry = async (chain, ring, index) => decodeRingEntry((await chain.account(ring, { offset: ringEntryOffset(index), length: 104 })).data);

// The newest ring entries first, looking for a checkpoint hash (a retry whose
// first attempt landed).
async function findEntry(chain, ring, head, hash, depth = 16) {
  for (let back = 1; back <= depth; back++) {
    const index = (head - back + 4096) % 4096;
    const entry = await readEntry(chain, ring, index);
    if (equalBytes(entry.checkpointHash, hash)) return { index, entry };
  }
  return null;
}

// Posts the directory's current checkpoint unless it is already the anchored
// tip, at most once a minute (`deferUntil` says when to come back). Records the
// anchor with the directory, retrying the record on later calls until stored.
export async function postAnchor({ chain, judge, logName, payer, authority, call, state, nowMs = Date.now() }) {
  const ktk = await currentCheckpoint(call);
  const checkpoint = parseKtk(ktk);
  const hash = hex(checkpointHash(ktk));
  const last = state.get('anchor:last');
  if (last?.hash === hash) {
    if (!last.recorded) await recordAnchor(call, state, last);
    return { status: 'unchanged', anchor: last };
  }
  if (last && nowMs - last.postedMs < ANCHOR_INTERVAL_MS) return { status: 'deferred', deferUntil: last.postedMs + ANCHOR_INTERVAL_MS };
  const { log } = await readLog(chain, judge, logName);
  // A slashed canary log takes no more anchors; the drill re-provisions a new one.
  if (log.kind === LOG_CANARY && log.serviceSlashed) return { status: 'log_slashed' };
  if (!equalBytes(log.serviceKey, checkpoint.serviceKey)) throw new Error('The checkpoint is not signed by the Log service key');
  const { head } = decodeRingHeader((await chain.account(log.ring, { offset: 0, length: 64 })).data);
  const instructions = [ed25519Instruction([checkpointEntry(ktk)]),
    await judgeInstructions(judge).postAnchor({ log: logName, anchorAuthority: authority.address, ktk })];
  let signature;
  try {
    signature = (await chain.send(instructions, { payer, signers: [authority] })).signature;
  } catch (error) {
    // By name: the relay's and the Worker's copies of judge.mjs are separate modules.
    if (error?.name !== 'ChainError') throw error;
    if (error.signature && error.code === null) state.set('anchor:pending', { hash, signature: error.signature });
    if (error.code === ERROR.StaleAnchor) {
      state.set('anchor:last', { ...last, hash, stale: true, postedMs: nowMs, recorded: true });
      return { status: 'stale' };
    }
    if (error.code !== ERROR.DuplicateAnchor) throw error;
    const pending = state.get('anchor:pending');
    signature = pending?.hash === hash ? pending.signature : null;
  }
  const found = await findEntry(chain, log.ring, (head + 1) % 4096, checkpointHash(ktk), 17);
  if (!found) throw new Error('Anchored checkpoint not found in the ring');
  if (!signature) {
    const listed = await chain.signaturesFor(log.ring, 50);
    signature = listed.find(x => !x.err && BigInt(x.slot) === found.entry.slot)?.signature;
    if (!signature) throw new Error('Anchoring transaction not found');
  }
  const anchor = { sequence: String(checkpoint.sequence), treeSize: String(checkpoint.treeSize), hash, ringIndex: found.index,
    slot: String(found.entry.slot), signature, postedMs: nowMs, recorded: false };
  state.set('anchor:last', anchor);
  state.set('anchors:open', [...(state.get('anchors:open') ?? []).filter(x => x.hash !== hash), anchor].slice(-32));
  await recordAnchor(call, state, anchor);
  return { status: 'posted', anchor };
}

// POST /internal/v1/transparency/anchors (INTERFACES §7).
async function recordAnchor(call, state, anchor) {
  const body = JSON.stringify({ sequence: Number(anchor.sequence), tree_size: Number(anchor.treeSize), checkpoint_hash: anchor.hash,
    ring_index: anchor.ringIndex, tx_signature: anchor.signature, slot: Number(anchor.slot) });
  const { status } = await call('/internal/v1/transparency/anchors', { method: 'POST', body, internal: true, headers: { 'Content-Type': 'application/json' } });
  if (![200, 201].includes(status)) {
    console.error(`Anchor record for sequence ${anchor.sequence} refused (${status})`);
    return;
  }
  const last = state.get('anchor:last');
  if (last?.hash === anchor.hash) state.set('anchor:last', { ...last, recorded: true });
}

// KTW v1 or v2 from GET /v1/transparency/witnesses: the kind-1 (Morse) entries.
export function morseAttestations(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  if (bytes.length < 6 || ![1, 2].includes(bytes[0]) || new TextDecoder().decode(bytes.subarray(1, 4)) !== 'KTW') throw new Error('not a KTW frame');
  const out = [];
  let at = 6;
  for (let i = 0; i < view.getUint16(4); i++) {
    const kind = bytes[0] === 2 ? bytes[at++] : 1;
    const length = view.getUint32(at);
    const id = new TextDecoder().decode(bytes.subarray(at + 4, at + 4 + length));
    at += 4 + length;
    if (kind === 1) { out.push({ id, hash: bytes.slice(at, at + 32), signature: bytes.slice(at + 32, at + 96) }); at += 96; } else at += 72;
    if (at > bytes.length) throw new Error('truncated KTW frame');
  }
  return out;
}

// Submits `cosign` for every Morse witness signature on an anchored checkpoint
// still inside its 1,500-slot window, four (or as many as fit) per transaction.
// Signatures are read per checkpoint (GET /v1/transparency/witnesses/{sequence}),
// so those arriving after the directory moved to a newer checkpoint still count.
export async function crankCosigns({ chain, judge, logName, payer, call, state }) {
  const slotNow = BigInt(await chain.slot());
  const open = (state.get('anchors:open') ?? []).filter(a => BigInt(a.slot) + BigInt(COSIGN_WINDOW_SLOTS) >= slotNow);
  if (!open.length) { state.set('anchors:open', []); return { cosigned: 0, open: 0 }; }
  const { log } = await readLog(chain, judge, logName);
  const accounts = await chain.accounts(log.witnesses.map(x => x.account));
  const usable = log.witnesses.filter((_, i) => accounts[i] && decodeWitness(accounts[i].data).status < SLASHED);
  const candidates = [];
  const remaining = [];
  for (const anchor of open) {
    const entry = await readEntry(chain, log.ring, anchor.ringIndex);
    if (hex(entry.checkpointHash) !== anchor.hash) continue;
    // This checkpoint's attestations, even after the directory has moved on.
    const response = await call(`/v1/transparency/witnesses/${anchor.sequence}`, { headers: { Accept: 'application/x-morse-attestation-v2' } });
    if (response.status === 404) continue; // the checkpoint is gone
    const attestations = response.status === 200 ? morseAttestations(response.bytes) : [];
    let missing = usable.filter(w => ((entry.bitmap >> w.index) & 1) === 0 && entry.slot >= w.sinceSlot);
    for (const a of attestations.filter(x => hex(x.hash) === anchor.hash)) {
      const w = missing.find(x => x.id === a.id);
      if (!w || !(await ed25519Verify(w.key, witnessMessage(a.id, a.hash), a.signature))) continue;
      candidates.push({ ringIndex: anchor.ringIndex, listIndex: w.index, witnessAccount: w.account,
        entry: { publicKey: w.key, message: witnessMessage(a.id, a.hash), signature: a.signature } });
      missing = missing.filter(x => x !== w);
    }
    if (missing.length) remaining.push(anchor);
  }
  const ix = judgeInstructions(judge);
  let cosigned = 0;
  const build = async batch => [ed25519Instruction(batch.map(c => c.entry)),
    ...(await Promise.all(batch.map(c => ix.cosign({ log: logName, ...c }))))];
  const send = async batch => {
    try {
      await chain.send(await build(batch), { payer });
      cosigned += batch.length;
    } catch (error) {
      if (error.code !== ERROR.CosignWindowClosed) throw error;
    }
  };
  let batch = [];
  for (const candidate of candidates) {
    if (batch.length === 4 || (batch.length && transactionSize(await build([...batch, candidate]), payer.address) > TRANSACTION_LIMIT)) {
      await send(batch);
      batch = [];
    }
    batch.push(candidate);
  }
  if (batch.length) await send(batch);
  state.set('anchors:open', remaining);
  return { cosigned, open: remaining.length };
}

// settle_epoch for the latest finished epochs (at or after boundary + 900 s),
// once each; warns when an epoch is still unsettled an hour after its boundary.
export async function settleEpochs({ chain, rewards, payer, state, nowMs = Date.now(), alert = console.error }) {
  const now = Math.floor(nowMs / 1000);
  const latest = Math.floor((now - 900) / EPOCH_SECONDS) - 1;
  const at = rewardsAddresses(rewards);
  const results = [];
  for (const epoch of [latest - 1, latest]) {
    if ((state.get('settled') ?? -1) >= epoch) continue;
    if (await chain.account(await at.epoch(epoch))) { state.set('settled', epoch); continue; }
    try {
      const config = decodeRewardsConfig((await chain.account(await at.config())).data);
      const log = decodeLog((await chain.account(config.log)).data);
      const witnesses = await chain.accounts(log.witnesses.map(x => x.account));
      await chain.send([await rewardsInstructions(rewards).settleEpoch({ payer: payer.address, epoch, log: config.log, usdc: config.usdc,
        priceFeed: config.priceFeed, witnesses: log.witnesses.map((x, i) => ({ account: x.account, vault: decodeWitness(witnesses[i].data).vault })) })],
      { payer });
      state.set('settled', epoch);
      results.push({ epoch, status: 'settled' });
    } catch (error) {
      if (error.code === REWARDS_ALREADY_SETTLED) { state.set('settled', epoch); continue; }
      results.push({ epoch, status: 'failed', error: String(error.message).slice(0, 200) });
      if (now > (epoch + 1) * EPOCH_SECONDS + 3600 && state.get('settle:warned') !== epoch) {
        alert(`WARN settle_epoch_late epoch=${epoch}: ${String(error.message).slice(0, 200)}`);
        state.set('settle:warned', epoch);
      }
    }
  }
  return results;
}

// Warn at 0.2 SOL, page at 0.05 SOL, and flag more than the 1 SOL it may hold.
export async function checkFeePayer({ chain, payer, state, nowMs = Date.now(), alert = console.error }) {
  const lamports = BigInt(await chain.balance(payer.address));
  const level = lamports < SOL / 20n ? 'page' : lamports < SOL / 5n ? 'warn' : lamports > SOL ? 'over_limit' : 'ok';
  const previous = state.get('fee_payer');
  if (level !== 'ok' && (previous?.level !== level || nowMs - (previous?.alertedMs ?? 0) >= 3_600_000)) {
    alert(`${level === 'page' ? 'PAGE' : 'WARN'} fee_payer_${level} address=${payer.address} lamports=${lamports}`);
    state.set('fee_payer', { address: payer.address, lamports: String(lamports), level, checkedMs: nowMs, alertedMs: nowMs });
  } else {
    state.set('fee_payer', { address: payer.address, lamports: String(lamports), level, checkedMs: nowMs, alertedMs: previous?.alertedMs ?? 0 });
  }
  return level;
}

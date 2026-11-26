// The phone's check against the public record (mobile-core Mobile.Anchor,
// plan §6.7, §6.17, §10): what Settings -> Network and the banners show, when
// the check runs, and the request/answer frames the app carries for it. The
// core decides everything; this file only reads its frames and words them.
import type { NetworkStatus } from './witnesses.ts';

export type AnchorOutcome =
  | 'never' | 'ok' | 'stale' | 'rpc_disagree' | 'rpc_unavailable' | 'mismatch'
  | 'service_slashed' | 'off' | 'directory_unavailable' | 'chain_invalid';

export type AnchorStatus = {
  outcome: AnchorOutcome;
  checkedAt: number;
  // When the newest anchor landed on chain; 0 when unknown.
  anchorAt: number;
  anchorSlot: number;
  publicTreeSize: number;
};

export type BondAsset = 'none' | 'usdc' | 'token' | 'other';
export type Bond = { asset: BondAsset; amount: number; usdMicros: number | null };
export type WitnessStatus = 'registered' | 'active' | 'unbonding' | 'slashed' | 'withdrawn' | 'unlisted';
export type WitnessBond = { id: string; status: WitnessStatus; bond: Bond };
export type BondCounter = {
  // False when the providers did not agree: never a guessed number.
  available: boolean;
  // Only the pinned morse-main log is counted.
  counted: boolean;
  serviceSlashed: boolean;
  slashedWitnesses: number;
  directory: Bond;
  witnesses: WitnessBond[];
};

export type TrustAlarmKind = 'anchor_mismatch' | 'service_slashed' | 'contact_fork';
export type TrustAlarmNotice = { kind: TrustAlarmKind; raisedAt: number };

const outcomes: readonly AnchorOutcome[] = [
  'never', 'ok', 'stale', 'rpc_disagree', 'rpc_unavailable', 'mismatch',
  'service_slashed', 'off', 'directory_unavailable', 'chain_invalid',
];
const assets: readonly BondAsset[] = ['none', 'usdc', 'token', 'other'];
const statuses: readonly WitnessStatus[] = ['registered', 'active', 'unbonding', 'slashed', 'withdrawn'];
const alarmKinds: readonly TrustAlarmKind[] = ['anchor_mismatch', 'service_slashed', 'contact_fork'];
const decoder = new TextDecoder('utf-8', { fatal: true });

const hour = 3_600_000;
const STALE_AFTER = 2 * hour;

// A bounded big-endian reader over one frame.
function reader(input: Uint8Array) {
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  let offset = 0;
  const take = (length: number): Uint8Array => {
    if (length < 0 || offset + length > input.length) throw new Error('Truncated frame');
    const value = input.slice(offset, offset + length);
    offset += length;
    return value;
  };
  return {
    take,
    byte: (): number => take(1)[0]!,
    u16: (): number => { take(2); return view.getUint16(offset - 2); },
    u64: (): number => { take(8); return Number(view.getBigUint64(offset - 8)); },
    vector: (maximum: number): Uint8Array => {
      take(4);
      const length = view.getUint32(offset - 4);
      if (length > maximum) throw new Error('Invalid frame');
      return take(length);
    },
    done: (): boolean => offset === input.length,
  };
}

const pick = <T>(values: readonly T[], index: number): T => {
  const value = values[index];
  if (value === undefined) throw new Error('Invalid frame');
  return value;
};

// Network status tag 2.
export function parseAnchorSection(body: Uint8Array): AnchorStatus {
  const read = reader(body);
  const value = {
    outcome: pick(outcomes, read.byte()),
    checkedAt: read.u64(),
    anchorAt: read.u64(),
    anchorSlot: read.u64(),
    publicTreeSize: read.u64(),
  };
  if (!read.done()) throw new Error('Invalid anchor status');
  return value;
}

function readBond(read: ReturnType<typeof reader>): Bond {
  const asset = pick(assets, read.byte());
  const amount = read.u64();
  const known = read.byte() === 1;
  const usd = read.u64();
  return { asset, amount, usdMicros: known ? usd : null };
}

// Network status tag 3 (Mobile.BondCounter).
export function parseBondSection(body: Uint8Array): BondCounter {
  const read = reader(body);
  const available = read.byte() === 1;
  const counted = read.byte() === 1;
  const serviceSlashed = read.byte() === 1;
  const slashedWitnesses = read.byte();
  const directory = readBond(read);
  const count = read.byte();
  const witnesses: WitnessBond[] = [];
  for (let index = 0; index < count; index += 1) {
    const id = decoder.decode(read.vector(64));
    const status = read.byte();
    witnesses.push({ id, status: status === 255 ? 'unlisted' : pick(statuses, status), bond: readBond(read) });
  }
  if (!read.done()) throw new Error('Invalid bond counter');
  return { available, counted, serviceSlashed, slashedWitnesses, directory, witnesses };
}

// Network status tag 4.
export function parseAlarmSection(body: Uint8Array): TrustAlarmNotice {
  const read = reader(body);
  const value = { kind: pick(alarmKinds, read.byte() - 1), raisedAt: read.u64() };
  if (!read.done()) throw new Error('Invalid trust alarm');
  return value;
}

const plural = (count: number, one: string, many: string): string => `${count} ${count === 1 ? one : many}`;

export function ago(milliseconds: number): string {
  const seconds = Math.max(0, Math.floor(milliseconds / 1000));
  if (seconds < 60) return `${plural(seconds, 'second', 'seconds')} ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${plural(minutes, 'minute', 'minutes')} ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${plural(hours, 'hour', 'hours')} ago`;
  return `${plural(Math.floor(hours / 24), 'day', 'days')} ago`;
}

const whole = (value: number): string => Math.floor(value).toLocaleString('en-US');

// Base units have 6 decimals for both USDC and the Morse token.
export function formatBond(bond: Bond): string {
  if (bond.usdMicros !== null) return `$${whole(bond.usdMicros / 1_000_000)}`;
  return `${whole(bond.amount / 1_000_000)} ${bond.asset === 'token' ? 'MORSE' : 'tokens'}`;
}

export function lastPublicCheckpointLine(anchor: AnchorStatus | undefined, now: number): string | null {
  if (!anchor || anchor.outcome === 'off' || anchor.outcome === 'never') return null;
  return anchor.anchorAt > 0
    ? `Last public checkpoint: ${ago(now - anchor.anchorAt)}.`
    : 'Last public checkpoint: unavailable.';
}

function slashedText(bonds: BondCounter): string {
  const parts = [
    ...(bonds.serviceSlashed ? ['Morse’s key'] : []),
    ...(bonds.slashedWitnesses > 0 ? [plural(bonds.slashedWitnesses, 'witness', 'witnesses')] : []),
  ];
  return parts.length ? parts.join(' and ') : 'never';
}

// "$50,000 bonded. Slashed: never. Last public checkpoint: 40 seconds ago."
// Bond lines show once the bonds exist on chain; a slash always shows.
export function bondCounterLine(
  bonds: BondCounter | undefined,
  anchor: AnchorStatus | undefined,
  now: number,
): string | null {
  const parts: string[] = [];
  if (bonds?.counted) {
    if (!bonds.available) {
      parts.push('Bonds unavailable: the providers disagree.');
      if (bonds.serviceSlashed || bonds.slashedWitnesses > 0) parts.push(`Slashed: ${slashedText(bonds)}.`);
    } else if (bonds.directory.asset !== 'none' || bonds.serviceSlashed || bonds.slashedWitnesses > 0) {
      if (bonds.directory.asset !== 'none') parts.push(`${formatBond(bonds.directory)} bonded.`);
      parts.push(`Slashed: ${slashedText(bonds)}.`);
    }
  }
  const checkpoint = lastPublicCheckpointLine(anchor, now);
  if (checkpoint) parts.push(checkpoint);
  return parts.length ? parts.join(' ') : null;
}

// A pinned witness's row: its bond and whether the judge slashed it.
export function witnessBondLine(value: WitnessBond | undefined): string | null {
  if (!value || value.status === 'unlisted') return null;
  const bonded = value.bond.asset === 'none' ? null : `${formatBond(value.bond)} bonded`;
  const state = value.status === 'slashed' ? 'Slashed' : value.status === 'unbonding' ? 'Unbonding' : null;
  const parts = [state, bonded].filter((part): part is string => Boolean(part));
  return parts.length ? parts.join(' · ') : null;
}

const results: Record<AnchorOutcome, string | null> = {
  never: 'Not checked against the public record yet.',
  ok: 'Matches the public record.',
  stale: 'Public record is behind.',
  rpc_disagree: 'Couldn’t check: the public record’s providers disagree.',
  rpc_unavailable: 'Couldn’t reach the public record.',
  mismatch: 'Doesn’t match the public record.',
  service_slashed: 'Morse’s key was slashed on the public record.',
  off: null,
  directory_unavailable: 'Couldn’t reach the directory to check.',
  chain_invalid: 'This build can’t read the public record.',
};

export function checkResultLine(anchor: AnchorStatus | undefined, now: number): string | null {
  if (!anchor) return null;
  const result = results[anchor.outcome];
  if (!result || anchor.outcome === 'never') return result;
  return `${result} Checked ${ago(now - anchor.checkedAt)}.`;
}

export function publicRecordBehind(anchor: AnchorStatus | undefined, now: number): boolean {
  if (!anchor || anchor.outcome === 'off' || anchor.outcome === 'never') return false;
  return anchor.anchorAt > 0 ? now - anchor.anchorAt > STALE_AFTER : anchor.outcome === 'stale';
}

const alarmTexts: Record<TrustAlarmKind, string> = {
  anchor_mismatch: 'Morse’s key log doesn’t match the public record.',
  service_slashed: 'Morse’s key log was caught signing two versions.',
  contact_fork: 'A contact’s phone was shown a different key log.',
};

export type TrustBanner = { text: string; blocking: boolean };

// Blocking while an alarm is active (new chats and key changes are paused);
// otherwise a quiet notice when the public record is behind.
export function trustBanner(status: NetworkStatus | null, now: number): TrustBanner | null {
  if (!status) return null;
  if (status.alarm) return { text: alarmTexts[status.alarm.kind], blocking: true };
  if (publicRecordBehind(status.anchor, now)) return { text: 'Public record is behind', blocking: false };
  return null;
}

export type CheckReason = 'daily' | 'key-change' | 'network-screen';

const intervals: Record<CheckReason, number> = {
  daily: 24 * hour,
  'key-change': hour,
  'network-screen': 5 * 60_000,
};
const retryable: readonly AnchorOutcome[] = ['rpc_unavailable', 'rpc_disagree', 'directory_unavailable'];

// Daily, and after a contact's keys change at most hourly (plan §7); a check
// that could not reach an answer is tried again after an hour. A build with no
// anchor pinned still runs daily: the check is off, but evidence checkpoint
// gossip kept is filed with the relays.
export function anchorCheckDue(anchor: AnchorStatus | undefined, reason: CheckReason, now: number): boolean {
  if (!anchor) return false;
  if (anchor.outcome === 'never') return true;
  const interval = retryable.includes(anchor.outcome) ? Math.min(hour, intervals[reason]) : intervals[reason];
  return now - anchor.checkedAt >= interval;
}

// Mobile.AnchorSteps frames.
export type AnchorRequest = { kind: number; tag: string; target: string; body: Uint8Array; raw: Uint8Array };

export function parseAnchorRequest(raw: Uint8Array): AnchorRequest {
  const read = reader(raw);
  const kind = read.byte();
  const tag = decoder.decode(read.vector(1024));
  const target = decoder.decode(read.vector(2048));
  const body = read.vector(65_536);
  if (!read.done() || kind < 1 || kind > 4) throw new Error('Invalid anchor request');
  return { kind, tag, target, body, raw };
}

export function parseAnchorStep(input: Uint8Array): { done: boolean; requests: AnchorRequest[] } {
  const read = reader(input);
  if (read.byte() !== 1 || decoder.decode(read.take(3)) !== 'ACS') throw new Error('Invalid anchor step');
  const done = read.byte() === 1;
  const count = read.u16();
  const requests: AnchorRequest[] = [];
  for (let index = 0; index < count; index += 1) requests.push(parseAnchorRequest(read.vector(65_536 + 4_096)));
  if (!read.done()) throw new Error('Invalid anchor step');
  return { done, requests };
}

const frame = (value: Uint8Array): Uint8Array => {
  const output = new Uint8Array(4 + value.length);
  new DataView(output.buffer).setUint32(0, value.length);
  output.set(value, 4);
  return output;
};

const joined = (parts: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};

// vector(request) || u16 status (0: no answer) || vector(body).
export function encodeAnchorExchange(request: AnchorRequest, status: number, body: Uint8Array): Uint8Array {
  return joined([frame(request.raw), Uint8Array.of((status >> 8) & 255, status & 255), frame(body)]);
}

export function encodeAnchorExchanges(exchanges: Uint8Array[]): Uint8Array {
  return joined([Uint8Array.of(exchanges.length >> 8, exchanges.length & 255), ...exchanges]);
}

const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let text = '';
  while (value > 0n) { text = alphabet[Number(value % 58n)] + text; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; text = `1${text}`; }
  return text;
}

export type Version = { sequence: number; treeSize: number; root: Uint8Array };
export type RelayFiling = { url: string; status: 'pending' | 'sent' | 'refused' };
export type FiledProof = {
  bytes: Uint8Array;
  forkKind: number;
  proofHash: Uint8Array;
  finder: Uint8Array | null;
  complete: boolean;
  landed: boolean;
  paidTo: Uint8Array | null;
  // The slot the judge's pay-once record was written in: where the payout
  // transaction is, once landed.
  landedSlot: number | null;
  // Landed, but paid to an address this proof did not name (plan §6.9).
  paidElsewhere: boolean;
  relays: RelayFiling[];
};
export type TrustDetails = {
  kind: TrustAlarmKind;
  active: boolean;
  raisedAt: number;
  yours: Version | null;
  other: Version | null;
  proofs: FiledProof[];
};

// Which phone a contact fork targeted (plan §6.16 step 6): the one whose view
// also disagrees with the public record. This phone's own check raises an
// anchor_mismatch alarm when its view is at odds with it; a check that passed
// after the fork was raised puts this phone's view on record, so the contact
// was shown the other version. With no anchor pinned nobody can tell.
export type ForkTarget = 'this-phone' | 'contact' | 'unknown' | 'off';

export function forkTarget(alarm: TrustDetails, all: TrustDetails[], anchor: AnchorStatus | undefined): ForkTarget {
  if (all.some((other) => other.kind === 'anchor_mismatch' && other.active)) return 'this-phone';
  if (!anchor || anchor.outcome === 'off') return 'off';
  if ((anchor.outcome === 'ok' || anchor.outcome === 'stale') && anchor.checkedAt >= alarm.raisedAt) return 'contact';
  return 'unknown';
}

const forkTargetLines: Record<ForkTarget, string> = {
  'this-phone': 'Your phone was shown the other version: it doesn’t match the public record either.',
  contact: 'Your contact’s phone was shown the other version: yours matches the public record.',
  unknown: 'The next check against the public record says which phone was shown the other version.',
  off: 'This build doesn’t check the public record, so it can’t say which phone was shown the other version.',
};

export function forkTargetLine(target: ForkTarget): string {
  return forkTargetLines[target];
}

const relayStates: readonly RelayFiling['status'][] = ['pending', 'sent', 'refused'];
const zero = (bytes: Uint8Array): boolean => bytes.every((byte) => byte === 0);
const same = (left: Uint8Array, right: Uint8Array): boolean =>
  left.length === right.length && left.every((byte, index) => byte === right[index]);

function readVersion(read: ReturnType<typeof reader>): Version | null {
  const present = read.byte() === 1;
  const value = { sequence: read.u64(), treeSize: read.u64(), root: read.take(32) };
  return present ? value : null;
}

function readProof(input: Uint8Array): FiledProof {
  const read = reader(input);
  const bytes = read.vector(8_192);
  const proofHash = read.take(32);
  const complete = read.byte() === 1;
  const landed = read.byte() === 1;
  const paidTo = read.take(32);
  const slot = read.u64();
  const count = read.byte();
  const relays: RelayFiling[] = [];
  for (let index = 0; index < count; index += 1) {
    const url = decoder.decode(read.vector(2_048));
    relays.push({ url, status: pick(relayStates, read.byte()) });
    read.take(32);
  }
  if (!read.done() || bytes.length < 37) throw new Error('Invalid trust alarm details');
  const finder = bytes.slice(5, 37);
  return {
    bytes,
    forkKind: bytes[4]!,
    proofHash,
    finder: zero(finder) ? null : finder,
    complete,
    landed,
    paidTo: landed ? paidTo : null,
    landedSlot: landed ? slot : null,
    paidElsewhere: landed && !(!zero(finder) && same(finder, paidTo)),
    relays,
  };
}

// mesh_messenger_trust_alarm_details: every alarm on record for the pinned key.
export function parseTrustDetails(input: Uint8Array): TrustDetails[] {
  const read = reader(input);
  if (read.byte() !== 1 || decoder.decode(read.take(3)) !== 'TAD') throw new Error('Invalid trust alarm details');
  const count = read.byte();
  const alarms: TrustDetails[] = [];
  for (let index = 0; index < count; index += 1) {
    const record = reader(read.vector(1_048_576));
    const kind = pick(alarmKinds, record.byte() - 1);
    const active = record.byte() === 1;
    const raisedAt = record.u64();
    const yours = readVersion(record);
    const other = readVersion(record);
    const proofs: FiledProof[] = [];
    const proofCount = record.byte();
    for (let position = 0; position < proofCount; position += 1) proofs.push(readProof(record.vector(65_536)));
    if (!record.done()) throw new Error('Invalid trust alarm details');
    alarms.push({ kind, active, raisedAt, yours, other, proofs });
  }
  if (!read.done()) throw new Error('Invalid trust alarm details');
  return alarms;
}

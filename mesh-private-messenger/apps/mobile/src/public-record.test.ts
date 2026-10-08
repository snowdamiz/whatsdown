import assert from 'node:assert/strict';
import test from 'node:test';

import { utf8, vector } from './codec.ts';
import {
  anchorCheckDue,
  bondCounterLine,
  checkResultLine,
  encodeAnchorExchange,
  forkTarget,
  forkTargetLine,
  lastPublicCheckpointLine,
  parseAnchorStep,
  parseTrustDetails,
  publicRecordBehind,
  trustBanner,
  witnessBondLine,
  type AnchorStatus,
  type TrustDetails,
} from './public-record.ts';
import { parseNetworkStatus } from './witnesses.ts';

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};
const u16 = (value: number): Uint8Array => Uint8Array.of(value >> 8, value & 255);
const u64 = (value: number): Uint8Array => {
  const output = new Uint8Array(8);
  new DataView(output.buffer).setBigUint64(0, BigInt(value));
  return output;
};

// What mobile-core's network status export writes, with sections.
function status(sections: [number, Uint8Array][]): Uint8Array {
  return concat(
    Uint8Array.of(1), utf8('NST'), vector(utf8('bootstrap')),
    Uint8Array.of(2, 2, 2), new Uint8Array(32).fill(9),
    vector(utf8('witness-a')), vector(utf8('Morse')), Uint8Array.of(1),
    vector(utf8('witness-b')), vector(utf8('Morse')), Uint8Array.of(1),
    Uint8Array.of(sections.length),
    ...sections.map(([tag, body]) => concat(u16(tag), vector(body))),
  );
}

const check = (outcome: number, checkedAt: number, anchorAt: number): [number, Uint8Array] =>
  [2, concat(Uint8Array.of(outcome), u64(checkedAt), u64(anchorAt), u64(500), u64(5))];
// asset 1 = USDC; amounts in 6-decimal base units.
const bond = (asset: number, amount: number, usd: number | null): Uint8Array =>
  concat(Uint8Array.of(asset), u64(amount), Uint8Array.of(usd === null ? 0 : 1), u64(usd ?? 0));
const bonds = (available: boolean, slashed: boolean, slashedWitnesses: number): [number, Uint8Array] => [3, concat(
  Uint8Array.of(available ? 1 : 0, 1, slashed ? 1 : 0, slashedWitnesses),
  bond(1, 50_000_000_000, 50_000_000_000),
  Uint8Array.of(2),
  vector(utf8('witness-a')), Uint8Array.of(1), bond(1, 10_000_000_000, 10_000_000_000),
  vector(utf8('witness-b')), Uint8Array.of(3), bond(2, 1_200_000_000, null),
)];
const alarm = (kind: number): [number, Uint8Array] => [4, concat(Uint8Array.of(kind), u64(1_000))];

const now = 1_800_000_000_000;

test('network status carries the last check, the bond counter and the blocking alarm', () => {
  const parsed = parseNetworkStatus(status([check(1, now - 60_000, now - 40_000), bonds(true, false, 0), alarm(1)]));
  assert.deepEqual(parsed.anchor, { outcome: 'ok', checkedAt: now - 60_000, anchorAt: now - 40_000, anchorSlot: 500, publicTreeSize: 5 });
  assert.equal(parsed.bonds?.directory.usdMicros, 50_000_000_000);
  assert.equal(parsed.bonds?.witnesses[1]?.status, 'slashed');
  assert.deepEqual(parsed.alarm, { kind: 'anchor_mismatch', raisedAt: 1_000 });
  // Older builds without these sections still parse.
  const plain = parseNetworkStatus(status([]));
  assert.equal(plain.anchor, undefined);
  assert.equal(plain.alarm, undefined);
});

test('Settings -> Network: the bond counter line, read from the chain', () => {
  const parsed = parseNetworkStatus(status([check(1, now - 60_000, now - 40_000), bonds(true, false, 0)]));
  assert.equal(
    bondCounterLine(parsed.bonds, parsed.anchor, now),
    '$50,000 bonded. Slashed: never. Last public checkpoint: 40 seconds ago.',
  );
  // Before bonds exist on chain only the checkpoint line shows.
  assert.equal(bondCounterLine(undefined, parsed.anchor, now), 'Last public checkpoint: 40 seconds ago.');
  // A slash is never hidden, even when the bond reads disagree.
  const slashed = parseNetworkStatus(status([check(6, now, now - 7_200_000), bonds(false, true, 1)]));
  assert.equal(
    bondCounterLine(slashed.bonds, slashed.anchor, now),
    'Bonds unavailable: the providers disagree. Slashed: Morse’s key and 1 witness. Last public checkpoint: 2 hours ago.',
  );
  const witnesses = parsed.bonds?.witnesses ?? [];
  assert.equal(witnessBondLine(witnesses[0]), '$10,000 bonded');
  assert.equal(witnessBondLine(witnesses[1]), 'Slashed · 1,200 MORSE bonded');
  assert.equal(witnessBondLine(undefined), null);
});

test('the last check says what the phone found', () => {
  const at = (outcome: AnchorStatus['outcome']): AnchorStatus => ({ outcome, checkedAt: now - 3 * 3_600_000, anchorAt: 0, anchorSlot: 0, publicTreeSize: 0 });
  assert.equal(checkResultLine(at('ok'), now), 'Matches the public record. Checked 3 hours ago.');
  assert.equal(checkResultLine(at('rpc_disagree'), now), 'Couldn’t check: the public record’s providers disagree. Checked 3 hours ago.');
  assert.equal(checkResultLine(at('mismatch'), now), 'Doesn’t match the public record. Checked 3 hours ago.');
  assert.equal(checkResultLine({ ...at('never'), checkedAt: 0 }, now), 'Not checked against the public record yet.');
  assert.equal(checkResultLine(at('off'), now), null);
  assert.equal(lastPublicCheckpointLine(at('rpc_disagree'), now), 'Last public checkpoint: unavailable.');
});

test('banners: blocking for an alarm, quiet when the public record is behind', () => {
  const behind = parseNetworkStatus(status([check(2, now, now - 3 * 3_600_000)]));
  assert.equal(publicRecordBehind(behind.anchor, now), true);
  assert.deepEqual(trustBanner(behind, now), { text: 'Public record is behind', blocking: false });
  const fresh = parseNetworkStatus(status([check(1, now, now - 60_000)]));
  assert.equal(trustBanner(fresh, now), null);
  const texts = [1, 2, 3].map((kind) => trustBanner(parseNetworkStatus(status([check(5, now, now), alarm(kind)])), now));
  assert.deepEqual(texts, [
    { text: 'Morse’s key log doesn’t match the public record.', blocking: true },
    { text: 'Morse’s key log was caught signing two versions.', blocking: true },
    { text: 'A contact’s phone was shown a different key log.', blocking: true },
  ]);
  // The alarm wins over the quiet notice.
  assert.equal(trustBanner(parseNetworkStatus(status([check(2, now, now - 3 * 3_600_000), alarm(2)])), now)?.blocking, true);
});

test('the check runs daily, after a key change at most hourly, and sooner after a failure', () => {
  const at = (outcome: AnchorStatus['outcome'], age: number): AnchorStatus => ({ outcome, checkedAt: now - age, anchorAt: 0, anchorSlot: 0, publicTreeSize: 0 });
  assert.equal(anchorCheckDue(at('never', 0), 'daily', now), true);
  assert.equal(anchorCheckDue(at('ok', 23 * 3_600_000), 'daily', now), false);
  assert.equal(anchorCheckDue(at('ok', 24 * 3_600_000), 'daily', now), true);
  assert.equal(anchorCheckDue(at('ok', 59 * 60_000), 'key-change', now), false);
  assert.equal(anchorCheckDue(at('ok', 60 * 60_000), 'key-change', now), true);
  assert.equal(anchorCheckDue(at('rpc_unavailable', 60 * 60_000), 'daily', now), true);
  assert.equal(anchorCheckDue(at('ok', 6 * 60_000), 'network-screen', now), true);
  assert.equal(anchorCheckDue(at('off', 23 * 3_600_000), 'daily', now), false);
  assert.equal(anchorCheckDue(at('off', 48 * 3_600_000), 'daily', now), true);
  assert.equal(anchorCheckDue(undefined, 'daily', now), false);
});

test('anchor check steps: requests out, exchanges back', () => {
  const request = concat(Uint8Array.of(1), vector(utf8('log')), vector(utf8('https://rpc-1.test')), vector(utf8('{}')));
  const step = parseAnchorStep(concat(Uint8Array.of(1), utf8('ACS'), Uint8Array.of(0), u16(1), vector(request)));
  assert.equal(step.done, false);
  assert.deepEqual(step.requests.map(({ kind, tag, target }) => ({ kind, tag, target })), [{ kind: 1, tag: 'log', target: 'https://rpc-1.test' }]);
  assert.deepEqual(new TextDecoder().decode(step.requests[0]!.body), '{}');
  assert.deepEqual(
    encodeAnchorExchange(step.requests[0]!, 200, utf8('ok')),
    concat(vector(request), u16(200), vector(utf8('ok'))),
  );
  assert.equal(parseAnchorStep(concat(Uint8Array.of(1), utf8('ACS'), Uint8Array.of(1), u16(0))).done, true);
  assert.throws(() => parseAnchorStep(concat(Uint8Array.of(1), utf8('ACX'), Uint8Array.of(1), u16(0))));
});

test('Details: the evidence, where each proof went and who was paid', () => {
  const finder = new Uint8Array(32).fill(7);
  const frk = concat(Uint8Array.of(1), utf8('FRK'), Uint8Array.of(2), finder, new Uint8Array(40));
  const summary = (size: number, fill: number) => concat(Uint8Array.of(1), u64(size), u64(size), new Uint8Array(32).fill(fill));
  const relay = (url: string, state: number) => concat(vector(utf8(url)), Uint8Array.of(state), new Uint8Array(32));
  const proof = concat(
    vector(frk), new Uint8Array(32).fill(3), Uint8Array.of(1, 1), new Uint8Array(32).fill(8), u64(777), Uint8Array.of(3),
    relay('https://relay-a.test', 1), relay('https://relay-b.test', 2), relay('https://relay-c.test', 0),
  );
  const record = concat(Uint8Array.of(1, 1), u64(1_000), summary(2, 1), summary(5, 2), Uint8Array.of(1), vector(proof));
  const details = parseTrustDetails(concat(Uint8Array.of(1), utf8('TAD'), Uint8Array.of(1), vector(record)));
  assert.equal(details.length, 1);
  const [only] = details;
  assert.equal(only?.kind, 'anchor_mismatch');
  assert.equal(only?.yours?.treeSize, 2);
  assert.equal(only?.other?.treeSize, 5);
  const filed = only?.proofs[0];
  assert.equal(filed?.forkKind, 2);
  assert.deepEqual(filed?.relays.map((value) => value.status), ['sent', 'refused', 'pending']);
  assert.equal(filed?.landed, true);
  assert.equal(filed?.landedSlot, 777);
  // Paid to an address the proof did not name: someone else's proof landed first.
  assert.equal(filed?.paidElsewhere, true);
  assert.deepEqual(filed?.bytes, frk);
});

test('a contact fork names the phone that was targeted: the one the public record disagrees with', () => {
  const alarm = (kind: TrustDetails['kind'], active: boolean, raisedAt: number): TrustDetails =>
    ({ kind, active, raisedAt, yours: null, other: null, proofs: [] });
  const fork = alarm('contact_fork', true, 1_000);
  const checked = (outcome: AnchorStatus['outcome'], checkedAt: number): AnchorStatus =>
    ({ outcome, checkedAt, anchorAt: 0, anchorSlot: 0, publicTreeSize: 0 });
  // This phone's own view is at odds with the public record.
  assert.equal(forkTarget(fork, [fork, alarm('anchor_mismatch', true, 900)], checked('mismatch', 1_100)), 'this-phone');
  // A check after the fork found this phone's view public: the contact was shown the other one.
  assert.equal(forkTarget(fork, [fork], checked('ok', 1_100)), 'contact');
  assert.equal(forkTarget(fork, [fork, alarm('anchor_mismatch', false, 500)], checked('stale', 1_100)), 'contact');
  // A pass from before the fork, or a check that could not finish, says nothing yet.
  assert.equal(forkTarget(fork, [fork], checked('ok', 900)), 'unknown');
  assert.equal(forkTarget(fork, [fork], checked('rpc_disagree', 1_100)), 'unknown');
  // With no anchor pinned the phone can't tell; gossip alone still built the proof.
  assert.equal(forkTarget(fork, [fork], checked('off', 1_100)), 'off');
  assert.match(forkTargetLine('contact'), /contact’s phone/);
  assert.match(forkTargetLine('this-phone'), /Your phone/);
});

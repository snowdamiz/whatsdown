import assert from 'node:assert/strict';
import test from 'node:test';
import { utf8, vectors, writeU32 } from './codec.ts';
import { parseAnchorObservation, describeAnchorObservation, checkpointAgeSeconds } from './anchor.ts';

const frame = (fields: string[]) => vectors(writeU32(fields.length), ...fields.map(utf8));

test('checkpoint age uses the public posting time and never invents an age for missing or future clocks', () => {
  assert.equal(checkpointAgeSeconds('8000', 8040999), 40);
  assert.equal(checkpointAgeSeconds('8000', 8000000), 0);
  assert.equal(checkpointAgeSeconds('8000', 15200000), 7200);
  for (const value of ['0', '8001', '18446744073709551615', '-1', '1e3', '01', '']) {
    assert.equal(checkpointAgeSeconds(value, 8000000), null);
  }
  for (const now of [NaN, Infinity, -1, 1.5, Number.MAX_SAFE_INTEGER + 1]) {
    assert.equal(checkpointAgeSeconds('1', now), null);
  }
});

test('anchor UI preserves full-width native counters and distinguishes observation from consistency', () => {
  const value = parseAnchorObservation(frame(['observed', '9000000', '18446744073709551615', '500', '8000']));
  assert.equal(value.contextSlot, '18446744073709551615');
  assert.equal(describeAnchorObservation(value.status).title, 'Public checkpoint observed');
  assert.match(describeAnchorObservation(value.status).detail, /Consistency.*not.*verified/i);
  assert.equal(describeAnchorObservation('service_slashed').blocking, true);
  assert.equal(parseAnchorObservation(frame(['consistent', '1', '2', '3', '4'])).status, 'consistent');
  assert.equal(describeAnchorObservation('consistent').blocking, false);
  assert.equal(describeAnchorObservation('mismatch').blocking, true);
  assert.match(describeAnchorObservation('mismatch').detail, /New chats and key changes are paused/);
  assert.equal(describeAnchorObservation('proof_unavailable').blocking, false);
  for (const status of ['off', 'pending', 'observed', 'stale', 'rpc_unavailable', 'rpc_disagree', 'clock_unavailable', 'empty'] as const) {
    assert.equal(describeAnchorObservation(status).blocking, false);
    assert.equal(parseAnchorObservation(frame([status, '0', '0', '0', '0'])).status, status);
  }
});

test('anchor UI rejects malformed native output instead of displaying an invented verdict', () => {
  for (const fields of [
    [], ['ok', '0', '0', '0', '0'], ['observed', '0', '0', '0'],
    ['observed', '0', '0', '0', '0', 'extra'],
    ...['-1', '1e3', '1.0', '00', '18446744073709551616', ''].map(value => ['observed', value, '0', '0', '0']),
  ]) assert.throws(() => parseAnchorObservation(frame(fields)));
});

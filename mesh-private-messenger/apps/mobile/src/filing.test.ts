import assert from 'node:assert/strict';
import test from 'node:test';
import { utf8, vectors, writeU32 } from './codec.ts';
import { parseFilingObservation, describeFilingObservation } from './filing.ts';

const frame = (fields: string[]) => vectors(writeU32(fields.length), ...fields.map(utf8));
const finder = '11111111111111111111111111111112';
const other = '11111111111111111111111111111113';
const fields = (status = 'accepted') => [status, 'ab'.repeat(32), finder, '', '0', other, '2', '3', '1', '60001', '18446744073709551615', '0'];

test('filing UI distinguishes acknowledgment, verified payment and another finder without losing integer precision', () => {
  const accepted = parseFilingObservation(frame(fields()));
  assert.equal(accepted.contextSlot, '18446744073709551615');
  assert.match(describeFilingObservation(accepted).detail, /not.*confirmed/i);
  assert.match(describeFilingObservation(accepted).acknowledgments, /2 of 3/);
  const paid = fields('settled'); paid[3] = finder; paid[4] = '18446744073709551615';
  const view = describeFilingObservation(parseFilingObservation(frame(paid)));
  assert.match(view.detail, /confirms/i);
  assert.equal(view.payment, '18446744073709551615 token base units');
  paid[0] = 'paid_elsewhere'; paid[3] = other;
  assert.match(describeFilingObservation(parseFilingObservation(frame(paid))).detail, /another phone or monitor/i);
  paid[0] = 'settled'; paid[2] = '1'.repeat(32);
  assert.match(describeFilingObservation(parseFilingObservation(frame(paid))).detail, /did not name a bounty address/i);
  for (const status of ['none', 'disabled', 'invalid_evidence']) {
    assert.equal(parseFilingObservation(frame([status, '', '', '', '0', '', '0', '0', '0', '0', '0', '0'])).status, status);
  }
  for (const status of ['pending', 'rpc_unavailable', 'rpc_disagree']) {
    assert.equal(describeFilingObservation(parseFilingObservation(frame(fields(status)))).payment, '');
  }
});

test('filing UI refuses malformed or contradictory native payout views', () => {
  assert.throws(() => parseFilingObservation(frame([])));
  assert.throws(() => parseFilingObservation(frame([...fields(), 'extra'])));
  for (const [index, value] of [[0, 'paid'], [1, 'AB'.repeat(32)], [2, '0'.repeat(32)], [3, other],
    [4, '1'], [6, '4'], [7, '9'], [8, '-1'], [9, '01'], [10, '18446744073709551616'], [11, '2']] as const) {
    const bad = fields(); bad[index] = value;
    assert.throws(() => parseFilingObservation(frame(bad)), `${index}: ${value}`);
  }
  const wrong = fields('settled'); wrong[3] = other;
  assert.throws(() => parseFilingObservation(frame(wrong)));
  wrong[0] = 'paid_elsewhere'; wrong[3] = finder;
  assert.throws(() => parseFilingObservation(frame(wrong)));
  wrong[2] = '1'.repeat(32); wrong[3] = other;
  assert.throws(() => parseFilingObservation(frame(wrong)));
  wrong[0] = 'disabled';
  assert.throws(() => parseFilingObservation(frame(wrong)));
});

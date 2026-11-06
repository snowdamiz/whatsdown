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

const zeroAddress = '1'.repeat(32);
const usdcMint = '1'.repeat(31) + '4';
const morseMint = '1'.repeat(31) + '5';
const maximumUnits = '18446744073709551615';
const versionedFields = (status = 'accepted', receiptFormat = '0') => {
  const value = fields(status);
  value[5] = usdcMint;
  if (['prepared', 'settled', 'paid_elsewhere'].includes(status)) value[3] = status === 'paid_elsewhere' ? other : finder;
  return [...value, '2', '0', morseMint, receiptFormat];
};

test('legacy twelve-field views retain their exact shape, address checks and payment wording', () => {
  const legacy = fields('settled');
  legacy[2] = zeroAddress;
  legacy[3] = 'z'.repeat(44); // Shape-only legacy validation must not be tightened.
  legacy[4] = maximumUnits;
  legacy[5] = '1'.repeat(33);
  const parsed = parseFilingObservation(frame(legacy));
  assert.deepEqual(parsed, {
    status: 'settled', proofHash: 'ab'.repeat(32), expectedFinder: zeroAddress,
    paidFinder: 'z'.repeat(44), paidUnits: maximumUnits, mint: '1'.repeat(33),
    accepted: 2, targets: 3, checkedAt: '1', nextAttempt: '60001', contextSlot: maximumUnits, working: false,
  });
  assert.deepEqual(describeFilingObservation(parsed), {
    detail: 'A public receipt confirms the payout. This proof did not name a bounty address, so the submitter received the finder share.',
    acknowledgments: '', payment: `${maximumUnits} token base units`,
  });
  legacy[0] = 'prepared';
  assert.throws(() => parseFilingObservation(frame(legacy)));
});

test('sixteen-field settled receipts name both currencies at full U64 precision and both finder addresses', () => {
  for (const status of ['settled', 'paid_elsewhere']) {
    for (const receiptFormat of ['1', '2']) {
      const value = versionedFields(status, receiptFormat);
      value[4] = maximumUnits;
      value[13] = receiptFormat === '2' ? maximumUnits : '0';
      const parsed = parseFilingObservation(frame(value));
      assert.ok('viewVersion' in parsed && parsed.viewVersion === '2');
      assert.equal(parsed.receiptFormat, receiptFormat);
      assert.equal(parsed.morsePaidUnits, value[13]);
      assert.equal(parsed.morseMint, morseMint);
      const description = describeFilingObservation(parsed);
      assert.equal(description.payment, `${maximumUnits} USDC base units; ${value[13]} MORSE base units`);
      assert.match(description.detail, new RegExp(`Actual finder: ${value[3]}`));
      assert.match(description.detail, new RegExp(`Requested finder: ${finder}`));
      assert.equal(description.acknowledgments, '');
    }
  }
  for (const [usdc, morse] of [['0', maximumUnits], [maximumUnits, '0'], ['0', '0']] satisfies [string, string][]) {
    const value = versionedFields('settled', '2');
    value[4] = usdc; value[13] = morse;
    assert.equal(describeFilingObservation(parseFilingObservation(frame(value))).payment, `${usdc} USDC base units; ${morse} MORSE base units`);
  }
  const noRequestedFinder = versionedFields('settled', '2');
  noRequestedFinder[2] = zeroAddress;
  assert.match(describeFilingObservation(parseFilingObservation(frame(noRequestedFinder))).detail, /did not name a bounty address/i);
  const fullWidthAddresses = versionedFields('settled', '2');
  fullWidthAddresses[2] = fullWidthAddresses[3] = 'So11111111111111111111111111111111111111112';
  fullWidthAddresses[5] = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
  fullWidthAddresses[14] = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
  assert.equal(parseFilingObservation(frame(fullWidthAddresses)).paidFinder, fullWidthAddresses[3]);
});

test('prepared MPR2 receipts show the actual and requested finder without claiming payment', () => {
  for (const requestedFinder of [finder, other, zeroAddress]) {
    for (const working of ['0', '1']) {
      const value = versionedFields('prepared', '2');
      value[2] = requestedFinder; value[11] = working;
      const parsed = parseFilingObservation(frame(value));
      const description = describeFilingObservation(parsed);
      assert.equal(parsed.status, 'prepared');
      assert.match(description.detail, /prepared/i);
      assert.match(description.detail, /payment has not been confirmed/i);
      assert.match(description.detail, new RegExp(`Actual finder: ${finder}`));
      assert.match(description.detail, new RegExp(`Requested finder: ${requestedFinder}`));
      assert.doesNotMatch(description.detail, /\bpaid\b|confirms (?:the payout|payment)|received/i);
      assert.equal(description.payment, '');
    }
  }
});

test('unconfirmed sixteen-field views require no receipt and expose no payment', () => {
  for (const status of ['pending', 'accepted', 'rpc_unavailable', 'rpc_disagree']) {
    const value = versionedFields(status);
    const parsed = parseFilingObservation(frame(value));
    assert.equal(parsed.status, status);
    assert.equal(describeFilingObservation(parsed).payment, '');
    assert.match(describeFilingObservation(parsed).acknowledgments, /2 of 3/);
    for (const [index, replacement] of [[3, finder], [4, '1'], [13, '1'], [15, '1'], [15, '2']] satisfies [number, string][]) {
      const bad = [...value]; bad[index] = replacement;
      assert.throws(() => parseFilingObservation(frame(bad)), `${status}: ${index}=${replacement}`);
    }
  }
});

test('sixteen-field prepared and settled views reject contradictory receipt formats, amounts and finder identities', () => {
  for (const status of ['prepared', 'settled', 'paid_elsewhere']) {
    const value = versionedFields(status, '2');
    const replacements: [number, string][] = [
      [3, ''], [3, zeroAddress], [3, '1'.repeat(33)], [3, 'z'.repeat(44)],
      [4, '-1'], [4, '01'], [4, '18446744073709551616'],
      [4, '1\n'], [13, '-1'], [13, '01'], [13, '18446744073709551616'], [13, '1\n'], [15, '0'],
    ];
    if (status === 'prepared') replacements.push([4, '1'], [13, '1'], [15, '1']);
    else replacements.push([11, '1'], [3, status === 'settled' ? other : finder]);
    for (const [index, replacement] of replacements) {
      const bad = [...value]; bad[index] = replacement;
      assert.throws(() => parseFilingObservation(frame(bad)), `${status}: ${index}=${replacement}`);
    }
  }
  const legacyReceipt = versionedFields('settled', '1');
  legacyReceipt[13] = '1';
  assert.throws(() => parseFilingObservation(frame(legacyReceipt)));
  const wrongElsewhere = versionedFields('paid_elsewhere', '2');
  wrongElsewhere[2] = zeroAddress;
  assert.throws(() => parseFilingObservation(frame(wrongElsewhere)));
});

test('sixteen-field framing and distinct nonzero canonical mints are strict without changing legacy blanks', () => {
  const valid = versionedFields();
  for (const count of [0, 11, 13, 14, 15, 17]) {
    const bad = count < 16 ? valid.slice(0, count) : [...valid, 'extra'];
    assert.throws(() => parseFilingObservation(frame(bad)), `${count} fields`);
  }
  for (const [index, replacement] of [[0, 'unknown'], [12, '1'], [12, '02'], [15, '3'], [15, ''],
    [1, 'AB'.repeat(32)], [2, finder + '\n'], [6, '4'], [6, '2\n'], [7, '9'], [7, '3\n'],
    [8, '-1'], [8, '1\n'], [9, '01'], [9, '60001\n'], [10, '18446744073709551616'], [10, '1\n'], [11, '2'], [11, '0\n']] satisfies [number, string][]) {
    const bad = [...valid]; bad[index] = replacement;
    assert.throws(() => parseFilingObservation(frame(bad)), `${index}=${replacement}`);
  }
  const noAcknowledgments = [...valid]; noAcknowledgments[6] = '0';
  assert.throws(() => parseFilingObservation(frame(noAcknowledgments)));
  for (const index of [5, 14]) {
    for (const replacement of ['', zeroAddress, '1'.repeat(33), '1'.repeat(31) + '0', usdcMint + '\n', 'z'.repeat(44), '2'.repeat(32), 'é'.repeat(32), '1'.repeat(65)]) {
      const bad = [...valid]; bad[index] = replacement;
      assert.throws(() => parseFilingObservation(frame(bad)), `mint ${index}=${replacement}`);
    }
  }
  const sameMints = [...valid]; sameMints[14] = usdcMint;
  assert.throws(() => parseFilingObservation(frame(sameMints)));
  const encoded = frame(valid);
  assert.throws(() => parseFilingObservation(encoded.slice(0, -1)));
  assert.throws(() => parseFilingObservation(vectors(encoded, Uint8Array.of(0))));
  for (const status of ['none', 'disabled', 'invalid_evidence']) {
    const blank = [status, '', '', '', '0', '', '0', '0', '0', '0', '0', '0'];
    assert.equal(parseFilingObservation(frame(blank)).status, status);
    assert.throws(() => parseFilingObservation(frame([...blank, '2', '0', morseMint, '0'])));
  }
});

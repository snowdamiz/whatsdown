import assert from 'node:assert/strict';
import test from 'node:test';
import { safetyQrValue, safetyFromQr, safetyVerificationRequest } from './safety-qr.ts';
import { policyRequest, vectors, utf8, hex } from './codec.ts';
import { qrFrames, createQrCollector } from './qr.ts';

const safety = 'a3f91c2e77b00d4f9e215a6cb3d844100f7ac2e18b936d052c4ea917f30b5e68';

test('the safety QR carries one canonical public fingerprint and round-trips through the scanner', () => {
  const qr = safetyQrValue(safety);
  assert.equal(qr, `mesh://safety/v1/${safety}`);
  assert.deepEqual(qrFrames(qr), [qr]);
  assert.equal(safetyFromQr(createQrCollector().scan(qr)!), safety);
});

test('wrong kinds, noncanonical fingerprints and extra URL data are refused', () => {
  for (const value of ['', safety.slice(1), safety.toUpperCase(), safety + '0', 'z'.repeat(64)]) {
    assert.throws(() => safetyQrValue(value));
  }
  for (const value of [`mesh://contact/v1/${safety}`, `mesh://safety/v2/${safety}`, `mesh://safety/v1/${safety}?x=1`,
    `mesh://safety/v1/${safety}#extra`, ` mesh://safety/v1/${safety}`, `mesh://safety/v1/${safety.toUpperCase()}`]) {
    assert.throws(() => safetyFromQr(value));
  }
});

test('the native request carries the scanned number, rather than the old unconditional verification action', () => {
  const peer = new Uint8Array(32).fill(7);
  const expected = new Uint8Array([...policyRequest('/owned/test.db', peer, 6, 0), ...vectors(utf8(safety))]);
  assert.equal(hex(safetyVerificationRequest('/owned/test.db', peer, safety)), hex(expected));
  assert.notEqual(hex(expected), hex(policyRequest('/owned/test.db', peer, 4, 0)));
  assert.throws(() => safetyVerificationRequest('/owned/test.db', peer, 'bad'));
});

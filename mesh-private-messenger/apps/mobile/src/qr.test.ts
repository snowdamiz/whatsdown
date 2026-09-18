import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { createRequire } from 'node:module';
import test from 'node:test';

import { payloadQrValue, profileFromQr, profileQrValue } from './codec.ts';
import { createQrCollector, qrFrames } from './qr.ts';

const QRCode = createRequire(import.meta.url)('qrcode');

test('hybrid contact codes render and reassemble after repeated, out-of-order scans', () => {
  const profile = Uint8Array.from(randomBytes(3_100));
  const value = profileQrValue(profile);
  const frames = qrFrames(value);
  const collector = createQrCollector();
  for (const frame of frames) QRCode.create(frame, { errorCorrectionLevel: 'M' });
  assert.equal(collector.scan(frames.at(-1)!), null);
  assert.equal(collector.scan(frames.at(-1)!), null);
  let result: string | null = null;
  for (const frame of frames.slice(0, -1).reverse()) result = collector.scan(frame);
  assert.deepEqual(profileFromQr(result!), profile);
  assert.equal(collector.scan(frames[0]!), null);
  collector.reset();
  const small = payloadQrValue('group-key-package', randomBytes(369));
  assert.deepEqual(qrFrames(small), [small]);
  assert.equal(collector.scan(small), small);
  collector.reset();
  assert.throws(() => collector.scan('mesh://part/00000000/0/99/x'), /Invalid QR fragment/);
  assert.throws(() => qrFrames('x'.repeat(48_201)), /Invalid QR payload size/);
  collector.scan(frames[0]!);
  assert.throws(() => collector.scan(frames[0]!.slice(0, -1) + '!'), /Conflicting QR fragment/);
  collector.reset();
  for (const frame of frames.slice(0, -1)) collector.scan(frame);
  assert.throws(() => collector.scan(frames.at(-1)!.slice(0, -1) + '!'), /did not match/);
});

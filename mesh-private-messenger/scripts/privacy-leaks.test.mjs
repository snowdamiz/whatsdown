import assert from 'node:assert/strict';
import test from 'node:test';
import { assertPrivateMarkersAbsent } from './privacy-leaks.mjs';

test('privacy scanner detects planted leaks in every supported encoding', () => {
  const marker = 'synthetic-private-marker-91a0426d';
  const utf16 = Buffer.from(marker, 'utf16le');
  for (const leak of [Buffer.from(marker), utf16, Buffer.from(utf16).swap16(),
    Buffer.from(Buffer.from(marker).toString('hex')), Buffer.from(Buffer.from(marker).toString('hex').toUpperCase()), Buffer.from(Buffer.from(marker).toString('base64'))]) {
    assert.throws(() => assertPrivateMarkersAbsent({ planted: Buffer.concat([Buffer.from('prefix'), leak]) }, { message: marker }), /planted exposed private marker message/);
  }
  for (const prefix of ['', 'x', 'xx']) {
    const encoded = Buffer.from(prefix + marker + 'tail').toString('base64');
    assert.throws(() => assertPrivateMarkersAbsent({ encoded }, { message: marker }), /exposed private marker/);
  }
  assertPrivateMarkersAbsent({ clean: Buffer.from('opaque synthetic bytes') }, { message: marker });
});

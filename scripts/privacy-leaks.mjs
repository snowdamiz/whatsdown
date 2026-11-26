import assert from 'node:assert/strict';

// Inspect each role separately: public directory fields are not private message markers.
export function assertPrivateMarkersAbsent(captures, markers) {
  for (const [name, marker] of Object.entries(markers)) {
    const raw = Buffer.isBuffer(marker) ? marker : Buffer.from(marker);
    assert.ok(raw.length >= 16, 'use distinctive synthetic markers');
    const utf16 = Buffer.from(raw.toString('utf8'), 'utf16le');
    const variants = [raw, utf16, Buffer.from(utf16).swap16(),
      Buffer.from(raw.toString('hex')), Buffer.from(raw.toString('hex').toUpperCase()), Buffer.from(raw.toString('base64'))];
    // Base64 of a larger frame may start the marker at any of three alignments.
    for (let offset = 0; offset < 3; offset++) {
      const encoded = Buffer.concat([Buffer.alloc(offset), raw]).toString('base64').slice(4, -4);
      variants.push(Buffer.from(encoded), Buffer.from(encoded.replaceAll('+', '-').replaceAll('/', '_')));
    }
    for (const [surface, bytes] of Object.entries(captures)) {
      assert.ok(!variants.some(value => Buffer.from(bytes).includes(value)), `${surface} exposed private marker ${name}`);
    }
  }
}

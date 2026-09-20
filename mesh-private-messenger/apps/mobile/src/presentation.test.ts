import assert from 'node:assert/strict';
import { test } from 'node:test';
import { encodePresentation, parsePresentation, identityName } from './presentation.ts';
import { utf8, vectors } from './codec.ts';

test('names and optional photos round trip with size and image-source validation', () => {
  const value = { name: 'Weekend walks', avatar: 'data:image/jpeg;base64,/9j/2Q==' };
  assert.deepEqual(parsePresentation(encodePresentation(value)), value);
  assert.deepEqual(parsePresentation(encodePresentation({ name: '  Weekend walks  ' })), { name: 'Weekend walks', avatar: undefined });
  assert.throws(() => encodePresentation({ name: '   ' }));
  assert.throws(() => encodePresentation({ name: 'a'.repeat(97) }));
  assert.throws(() => encodePresentation({ name: 'alice', avatar: 'https://tracking.example/photo.jpg' }));
  assert.throws(() => parsePresentation(vectors(utf8('alice'), utf8('data:image/svg+xml;base64,AAAA'))));
  assert.throws(() => encodePresentation({ name: 'alice', avatar: 'data:image/jpeg;base64,' + 'A'.repeat(12288) }));
  assert.throws(() => parsePresentation(new Uint8Array([...encodePresentation(value), 1])));
});

test('private nicknames override shared display names with a username fallback', () => {
  assert.equal(identityName('maya_1987', { name: 'Maya Chen' }, { name: 'Mum' }), 'Mum');
  assert.equal(identityName('maya_1987', { name: 'Maya Chen' }), 'Maya Chen');
  assert.equal(identityName('maya_1987', { name: 'maya_1987' }), '@maya_1987');
  assert.equal(identityName('maya_1987'), '@maya_1987');
  assert.equal(identityName(null, { name: 'Maya Chen' }), 'Maya Chen');
  assert.equal(identityName(null), undefined);
});

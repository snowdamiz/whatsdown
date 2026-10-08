import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import test from 'node:test';

import { formatRecoveryCode, parseRecoveryCode } from './recovery-code.ts';

test('a recovery code reads back from its 13 groups of four however it is typed', () => {
  for (let round = 0; round < 50; round += 1) {
    const code = new Uint8Array(randomBytes(32));
    const shown = formatRecoveryCode(code);
    assert.match(shown, /^([0-9A-HJKMNP-TV-Z]{4} ){12}[0-9A-HJKMNP-TV-Z]{4}$/);
    assert.deepEqual(parseRecoveryCode(shown), code);
    const typed = shown.toLowerCase().replaceAll(' ', '-').replaceAll('0', 'o').replaceAll('1', 'l');
    assert.deepEqual(parseRecoveryCode(`  ${typed}\n`), code);
  }
});

test('a code of the wrong length or with a stray character opens nothing', () => {
  const shown = formatRecoveryCode(new Uint8Array(32).fill(7));
  assert.equal(parseRecoveryCode(shown.slice(0, -1)), null);
  assert.equal(parseRecoveryCode(`${shown}0`), null);
  assert.equal(parseRecoveryCode(shown.replace(/^./, 'U')), null);
  // The last character carries four bits of the code and one of nothing.
  const last = shown.at(-1)!;
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  assert.equal(parseRecoveryCode(shown.slice(0, -1) + alphabet[alphabet.indexOf(last) ^ 1]), null);
  assert.throws(() => formatRecoveryCode(new Uint8Array(31)));
});

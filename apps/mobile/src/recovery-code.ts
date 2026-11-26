// A recovery code is 32 random bytes the core makes when backups are turned on
// (protocol/backup-wire-v1.md). People see it as 52 Crockford base32 characters
// in groups of four; typing it back forgives case, spaces, dashes, and the
// letters that look like digits.

const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';

export function formatRecoveryCode(code: Uint8Array): string {
  if (code.length !== 32) throw new Error('invalid_recovery_code');
  let text = '';
  let value = 0;
  let bits = 0;
  for (const byte of code) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      text += alphabet[(value >> bits) & 31];
    }
    value &= (1 << bits) - 1;
  }
  text += alphabet[(value << (5 - bits)) & 31];
  return text.match(/.{4}/g)!.join(' ');
}

export function parseRecoveryCode(input: string): Uint8Array | null {
  const text = input.toUpperCase().replace(/[\s-]/g, '').replace(/O/g, '0').replace(/[IL]/g, '1');
  if (text.length !== 52) return null;
  const code = new Uint8Array(32);
  let value = 0;
  let bits = 0;
  let length = 0;
  for (const character of text) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) return null;
    value = (value << 5) | digit;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      code[length++] = (value >> bits) & 255;
      value &= (1 << bits) - 1;
    }
  }
  return value === 0 ? code : null;
}

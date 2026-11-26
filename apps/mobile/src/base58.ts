// Solana's base58 (Bitcoin alphabet), for addresses, keys and hashes.

const ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let text = '';
  while (value > 0n) { text = ALPHABET[Number(value % 58n)] + text; value /= 58n; }
  for (const byte of bytes) { if (byte !== 0) break; text = `1${text}`; }
  return text;
}

// A Solana address or hash: exactly 32 bytes.
export function fromBase58(text: string): Uint8Array {
  let value = 0n;
  for (const character of text) {
    const digit = ALPHABET.indexOf(character);
    if (digit < 0) throw new Error('bad_base58');
    value = value * 58n + BigInt(digit);
  }
  const bytes: number[] = [];
  for (; value > 0n; value /= 256n) bytes.unshift(Number(value % 256n));
  for (const character of text) { if (character !== '1') break; bytes.unshift(0); }
  if (bytes.length !== 32) throw new Error('bad_base58');
  return Uint8Array.from(bytes);
}

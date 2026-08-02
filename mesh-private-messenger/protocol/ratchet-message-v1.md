# Ratchet message v1

The Profile A ratchet wire message is canonical, big-endian, and bounded to
65,630 bytes. It is authenticated by the ratchet AEAD together with the
conversation-specific associated data; the delivery service stores the bytes
without interpreting them.

| Field | Encoding |
|---|---|
| Version | `u8`, value `1` |
| Magic | 3 bytes, ASCII `RAT` |
| Suite | `u16`, value `1` |
| Session ID | 32 bytes |
| Ratchet public key | 32-byte X25519 public key |
| Previous chain length | `u32` |
| Message number | `u32` |
| Nonce | 12 bytes |
| Ciphertext | `u32` length plus 16–65,536 bytes |

Decoders reject non-canonical lengths, unsupported version or suite, invalid
field sizes, oversized inputs, truncation, and trailing bytes before ratchet
state is touched. Decode then encode produces the same bytes.

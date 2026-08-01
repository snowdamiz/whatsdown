# messenger-protocol

Canonical Profile A (`version = 1`, `suite = 0x0001`) codecs. Integers are
unsigned, fixed-width, and big-endian. Vectors are a `u32` byte length followed
by exactly that many bytes. Decoders reject unsupported versions or suites,
oversized vectors, truncation, and trailing bytes.

## Outer envelope v1

| Field | Encoding |
|---|---|
| Version | `u8`, value `1` |
| Magic | 3 bytes, ASCII `MSG` |
| Envelope ID | 16 bytes |
| Destination mailbox token | 32 bytes |
| Suite | `u16`, value `1` |
| Expiration | `u64`, Unix milliseconds |
| Padding bucket | `u32`: 256 through 65,536 in powers of two |
| Ciphertext | `u32` length + bytes, at most the padding bucket |

The maximum encoded envelope is 65,606 bytes.

## Device credential v1

| Field | Encoding |
|---|---|
| Version | `u8`, value `1` |
| Suite | `u16`, value `1` |
| Account ID | 32 bytes |
| Device ID | 16 bytes |
| Ed25519 signing public key | 32 bytes |
| X25519 public key | 32 bytes |
| Post-quantum public key | `u32` length + bytes; empty in Profile A |
| Capabilities | `u32` bit set |
| Created at | `u64`, Unix milliseconds |
| Expires at | `u64`, Unix milliseconds; not before creation |
| Directory sequence | `u64` |
| Ed25519 signature | 64 bytes |

The Profile A credential is exactly 211 bytes. The vector remains bounded at
4,096 bytes so malformed future-profile input is rejected before allocation.
Golden and hostile fixtures live in `tests/fixtures/m1`.

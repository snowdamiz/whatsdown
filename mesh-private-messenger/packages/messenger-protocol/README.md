# messenger-protocol

Canonical Profile A (`version = 1`, `suite = 0x0001`) types, negotiation,
transcript hashing, and codecs implemented entirely in Mesh. Integers are
unsigned, fixed-width, and big-endian. Vectors are a `u32` byte length followed
by exactly that many bytes. Decoders reject unsupported versions or suites,
oversized vectors, truncation, duplicate extension IDs, unknown mandatory
extensions, and trailing bytes.

`Protocol.V1` exports codecs for `AccountIdentity`, `DeviceCredential`,
`PrekeyBundle`, `OuterEnvelope`, `InnerEnvelope`, `HandshakeTranscript`, and
`InitialMessage`.
`negotiate_profile_a` enforces the authenticated strongest-suite floor;
`hash_handshake_transcript` hashes the canonical transcript with the exact
`mesh-msg/v1/handshake` domain label.

Unknown optional extensions are retained byte-for-byte. Version 1 has no
registered mandatory extension, so every mandatory extension is rejected.
The complete field layouts and decoder ceilings are specified in
[`../../protocol/canonical-codecs-v1.md`](../../protocol/canonical-codecs-v1.md).

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
Golden and hostile fixtures live in `tests/fixtures/m1` and
`tests/fixtures/m5`.

## Decoder ceilings

| Value | Maximum encoded bytes |
|---|---:|
| Account identity | 16,582 |
| Device credential | 4,307 (211 is canonical in Profile A) |
| Prekey bundle | 16,942 |
| Outer envelope | 65,606 |
| Inner envelope | 65,536 |
| Handshake transcript | 16,684 |
| Initial message | 65,536 |

Every extension list has at most 16 entries, each value is at most 1,024
bytes, and protocol nesting is one extension-list level. Inner bodies are at
most 32,768 bytes and attachment manifests are at most 16,384 bytes.

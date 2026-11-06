# Inactive composite ratchet framing

`Session.TripleWire` defines development framing for an encrypted header that
contains both the existing classical ratchet header and a sparse post-quantum
fragment. It allocates no production capability or RAT version. Existing RAT4
messages are unchanged, and active conversations do not use this format.

Parsing establishes syntax, bounds and matching configuration/session bytes.
It does not authenticate a peer or body, authorize an acknowledgement or epoch
transition, or advance any ratchet. The later coordinator must authenticate the
body before committing any candidate state.

All integers are unsigned big-endian. The clear header is:

| Field | Bytes |
|---|---:|
| ASCII `CHP1`, profile 1 | 5 |
| Existing canonical classical header, restricted to suite 2 | 74 |
| PQ message number, 1 through u64 maximum | 8 |
| CBF1 fragment length | 2 |
| Exact CBF1 control or data fragment | 78 or 148 |

The clear header is exactly 167 or 237 bytes. Its classical session identifier
must equal the fragment session and the expected session supplied to decoding.
The existing CBF1 codec checks the configuration, nonzero epoch and kind-specific
fields. Decoding rejects truncation, trailing bytes and other profiles.

The outer frame is ASCII `CHF1`, a 24-byte header nonce, a u16 encrypted-header
length, the encrypted header, a 12-byte body nonce, a u32 ciphertext length and
the body ciphertext. The encrypted header must be exactly 183 or 253 bytes,
including its 16-byte authentication tag. Body ciphertext is 16–65,168 bytes.
The maximum frame is 65,467 bytes; adding the existing 13-byte RatchetPacket
framing reaches its 65,480-byte ceiling. This arithmetic does not establish
native transport or performance qualification.

Let `D = ASCII("mesh-msg/spqr/v1") || 0x00 || configuration32 || session32`.
This is 81 bytes. Associated data is exactly:

```
header: ASCII("mesh-msg/triple/v1/header-aad") || 0x00 || D || "CHF1"
        || encrypted_header_length:u16 || caller

body:   ASCII("mesh-msg/triple/v1/body-aad") || 0x00 || D || "CHF1"
        || header_nonce24 || encrypted_header_length:u16 || encrypted_header
        || body_nonce12 || caller
```

The lengths refer to the encrypted header. AAD construction validates framing
and caps its complete output at 131,072 bytes. Body AAD excludes its own
ciphertext/tag and accepts an empty ciphertext during encryption preparation.
The later cryptographic integration must use the actual classical and PQ keys
with one body AEAD operation. That integration is not implemented by this codec.

Independent byte literals cover both header/frame forms and AAD. Refusal checks
cover malformed nested and outer framing, configuration/session substitution,
counter boundaries, self-consistent unsupported header sizes, the exact body
ceiling and exact AAD bounds. Payload mutation remains valid syntax until the
later authentication step verifies it.

# messenger-protocol

Canonical classical (`version = 1`, `suite = 0x0001`) and experimental hybrid
(`suite = 0x0002`) types, negotiation, transcript hashing, and codecs
implemented entirely in Mesh. Integers are
unsigned, fixed-width, and big-endian. Vectors are a `u32` byte length followed
by exactly that many bytes. Decoders reject unsupported versions or suites,
oversized vectors, truncation, duplicate extension IDs, unknown mandatory
extensions, and trailing bytes.

`Protocol.V1` exports codecs for `AccountIdentity`, `DeviceCredential`,
`PrekeyBundle`, `OuterEnvelope`, `InnerEnvelope`, `HandshakeTranscript`, and
`InitialMessage`, plus the bounded directory, mailbox-fetch, delivery-batch,
and acknowledgement records used by the CLI services.
`negotiate_suites` prefers suite `0x0002` and enforces the authenticated
strongest-suite floor. `hash_handshake_transcript` hashes the canonical
transcript with the exact `mesh-msg/v1/handshake` domain label.

`Session.Snapshot` seals every private ratchet resource under a `StorageKey`
with account, device, session, purpose, and monotonic snapshot-version binding.
Restore preserves skipped message keys and counters; session replacement
accepts only a newer authenticated snapshot and otherwise returns the current
state unchanged. `StorageKey.ephemeral()` supports same-process CLI proofs only;
restart persistence requires a host-provisioned key and durable nonce counter.
`Session.Ratchet.encode_ratchet_message` and `decode_ratchet_message` provide
the bounded canonical binary form used by HTTP delivery; decoding rejects
wrong magic, unsupported profiles, oversized ciphertext, truncation, and
trailing bytes.

`Groups.Mls` exports the development-only suite `0x0003`: bounded immutable
membership trees, signed add/remove commits, HPKE welcomes, epoch messages,
delivery fanout, extension negotiation, and purpose-16 sealed snapshots.
Epoch secrets use storage purpose 16; TreeKEM leaf and direct-path private keys
use purpose 17.
Commit, welcome, message, and snapshot decoders are canonical and reject
trailing data. The exact limits and independent-review release gate are in
[`../../protocol/mls-groups-v1.md`](../../protocol/mls-groups-v1.md).

`Attachments.Protocol` exports a bounded encrypted manifest and authenticated
64 KiB chunks. Its exact labels, wire layouts, and 16 MiB development ceiling
are specified in
[`../../protocol/attachment-wire-v1.md`](../../protocol/attachment-wire-v1.md).

`Backups.Protocol` exports the fixed Argon2id v1.3 recovery profile, opaque
authenticated manifest, and bounded encrypted chunks used for opt-in client
backups. The exact profile and 16 MiB development ceiling are specified in
[`../../protocol/backup-wire-v1.md`](../../protocol/backup-wire-v1.md).

`Push.Token` seals Expo provider tokens directly to the push broker and exports
the bounded internal wake request. Directory and delivery services retain and
forward only opaque ciphertext. The exact boundary and wire ceilings are in
[`../../protocol/push-token-wire-v1.md`](../../protocol/push-token-wire-v1.md).

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
| Suite | `u16`, value `1` or `2` |
| Expiration | `u64`, Unix milliseconds |
| Padding bucket | `u32`: 256 through 65,536 in powers of two |
| Ciphertext | `u32` length + bytes, at most the padding bucket |

The maximum encoded envelope is 65,606 bytes.

Delivery fetches return at most eight envelopes (524,949 encoded bytes), and
acknowledgements accept at most eight 16-byte envelope IDs. Usernames are
1–64 lowercase ASCII letters, digits, dots, underscores, or hyphens.

## Device credential v1

| Field | Encoding |
|---|---|
| Version | `u8`, value `1` |
| Suite | `u16`, value `1` or `2` |
| Account ID | 32 bytes |
| Device ID | 16 bytes |
| Ed25519 signing public key | 32 bytes |
| X25519 public key | 32 bytes |
| Post-quantum public key | `u32` length + bytes; empty in suite 1, exactly 1,184 bytes in suite 2 |
| Capabilities | `u32` bit set |
| Created at | `u64`, Unix milliseconds |
| Expires at | `u64`, Unix milliseconds; not before creation |
| Directory sequence | `u64` |
| Ed25519 signature | 64 bytes |

The credential is exactly 211 bytes in suite 1 and 1,395 bytes in suite 2. The
vector remains bounded so malformed input is rejected before allocation.
Golden and hostile fixtures live in `tests/fixtures/m1` and
`tests/fixtures/m5`.

## Decoder ceilings

| Value | Maximum encoded bytes |
|---|---:|
| Account identity | 16,582 |
| Device credential | 1,395 |
| Prekey bundle | 18,126 |
| Outer envelope | 65,606 |
| Inner envelope | 65,536 |
| Handshake transcript | 17,868 |
| Initial message | 65,536 |
| Directory entry | 34,820 |
| Delivery batch | 524,949 |

Every extension list has at most 16 entries, each value is at most 1,024
bytes, and protocol nesting is one extension-list level. Inner bodies are at
most 32,768 bytes and attachment manifests are at most 16,384 bytes.

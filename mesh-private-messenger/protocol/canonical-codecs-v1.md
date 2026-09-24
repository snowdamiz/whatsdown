# Canonical Codecs, Profile A, Version 1

Status: development protocol. These rules are consensus and signature inputs;
changing one requires a new protocol version and new golden fixtures.

All integers are unsigned and big-endian. Every value starts with a one-byte
version. Variable byte strings use a canonical `u32` length followed by exactly
that many bytes. Decoders reject truncation, trailing bytes, unsupported
versions or suites, and input beyond the value-specific ceiling before
cryptographic work.

No field is implicitly UTF-8. The three-byte ASCII tags and the transcript
domain label below are protocol constants; every application value is `Bytes`.

## Extensions

An extension list is:

```text
count:u16
repeat count times:
  id:u16
  mandatory:u8
  value_length:u32
  value:bytes
```

The count is at most 16, values are at most 1,024 bytes, IDs are nonzero and
strictly increasing, and flags other than `0` or `1` are invalid. This fixes
field order and rejects duplicates without sorting attacker-controlled input.
Version 1 registers no mandatory extensions, so a flag of `1` is rejected as
`UnknownMandatoryExtension`. Unknown optional extensions use flag `0` and are
preserved byte-for-byte. Maximum nesting is one extension-list level.

## Suite negotiation

A suite advertisement is a `u8` count followed by `u16` suite IDs. It contains
one or two unique IDs. Version 1 recognizes classical `0x0001` and experimental
hybrid `0x0002`; any other ID returns `UnsupportedSuite` instead of falling
back.

`negotiate_suites(local, remote, strongest_authenticated_suite)` prefers
`0x0002`, then `0x0001`. A duplicate list fails with `DuplicateSuite`; selecting
below the remembered floor fails with `DowngradeDetected`. History outside
`0..2` fails with `InvalidSuiteHistory`. The selected suite is encoded in
credentials, prekey bundles, outer envelopes, handshakes, ratchet messages, and
snapshots.

## Account identity (`ACT`)

```text
version:u8 = 1
tag:3 = "ACT"
account_id:32
authorization_public_key:32
created_at:u64
directory_sequence:u64
extensions
```

Profile A chooses a 256-bit account ID. `directory_sequence` is the monotonic
directory/transparency position. Maximum encoded size: 16,582 bytes.

## Device credential

The credential layout is exactly 211 bytes in suite `0x0001` and 1,395 bytes in
suite `0x0002`. It
binds the account and device IDs, Ed25519 and X25519 public keys, capabilities,
creation and expiry times, directory sequence, selected suite, and signature.
The post-quantum key vector is empty in suite `0x0001` and is an exact
1,184-byte ML-KEM-768 encapsulation key in suite `0x0002`.

## Prekey bundle (`PKB`)

```text
version:u8 = 1
tag:3 = "PKB"
suite:u16 = 1 or 2
device_credential:vector (exactly 211 or 1,395 bytes)
identity_dh_public_key:32
signing_public_key:32
signed_prekey_id:u64 (nonzero)
signed_prekey:32
signed_prekey_signature:64
one_time_prekey_id:u64
one_time_prekey:vector (0 or 32 bytes)
post_quantum_prekey:0 bytes for suite 1; 1,184 bytes for suite 2
supported_suites
expires_at:u64
extensions
```

The embedded credential must itself decode canonically, use the same suite,
and contain the same signing and identity-DH public keys. A one-time prekey ID
is zero exactly when the one-time public key is absent; otherwise it is
nonzero. This makes prekey consumption addressable without ambiguity. A
maximal suite-2 bundle is 2,814 bytes through `expires_at` plus a 16,498-byte
extension list, for a maximum encoded size of 19,312 bytes.

The directory stores and logs a base bundle with `one_time_prekey_id = 0` and
an empty `one_time_prekey`. During device registration, a nonzero one-time
prekey from the submitted bundle is extracted into the device's consumable
pool in the same transaction. A successful pool claim returns a canonical
`PKB` made from that exact base bundle plus one claimed ID and public key. The
base bundle remains unchanged, so its transparency evidence remains valid.

## One-time prekey publication (`OTB`)

```text
version:u8 = 3
tag:3 = "OTB"
account_id:32
device_id:16
count:u8 (0..64)
repeat count times:
  prekey_id:u64 (1..2^63-1, strictly increasing)
  public_key:32
last_resort:u8 (0 or 1)
if last_resort = 1:
  prekey_id:u64 (1..2^63-1, not one of the batch IDs)
  public_key:32
contact_address:u8 (0 or 1)
if contact_address = 1:
  contact_address_hash:32
signature:64
```

The device Ed25519 signature covers:

```text
ASCII("mesh-msg/v3/one-time-prekey-batch") ||
canonical_OTB_fields_before_signature
```

The encoded size is `119 + 40 * count` bytes, plus 40 with a last-resort key
and 32 with a contact address, and is at most 2,751 bytes. Versions 1 and 2
lacked these fields and are refused. `contact_address_hash` is SHA-256 of the
device's secret second deposit address; see `contact-address-v1.md`.
An empty batch is an authenticated recovery query that inserts no one-time key
and asks for the current active set.

The last-resort key is the one reusable prekey of a device. The directory
returns it from an `OTQ` claim only when the one-time pool is empty and never
consumes it, so draining a pool cannot stop new sessions. Every publication
repeats the current key; repeating it is idempotent. Publishing a key with a
higher identifier retires the previous one. A lower identifier, or a known
identifier with different key bytes, is a conflict, so replaying a retired
publication cannot bring an old key back. Mobile identifiers start at
`2^62 + 1`, outside the range one-time identifiers count through. The key never
appears in an `OTA` active list. Decoders reject oversized batches, duplicate or unsorted IDs,
out-of-range IDs, wrong key or signature lengths, unsupported tags or
versions, truncation, and trailing bytes. Replaying an identical signed batch
is idempotent. Reusing an ID with different public-key bytes is a conflict and
never changes or reactivates the original row.

## One-time prekey active acknowledgement (`OTA`)

```text
version:u8 = 1
tag:3 = "OTA"
account_id:32
device_id:16
count:u8 (0..64)
repeat count times:
  active_prekey_id:u64 (1..2^63-1, strictly increasing)
```

The service returns this identity-bound body with every successful `OTB`
publication. It is encoded after the publication transaction has inserted any
new rows and lists exactly the device's unconsumed server IDs. The maximum size
is 565 bytes. Decoders reject unknown versions, wrong identity lengths,
duplicate or unsorted IDs, out-of-range IDs, truncation, and trailing bytes.

## One-time prekey bundle claim (`OTQ`)

```text
version:u8 = 1
tag:3 = "OTQ"
account_id:32
device_id:16
base_bundle_hash:32
reservation_id:16
```

This request is exactly 100 bytes. `base_bundle_hash` is
`SHA-256(canonical_base_PKB)` and binds the claim to the transparently verified
device bundle without revealing requester identity. `reservation_id` is random,
generated and durably persisted by Mesh before the HTTP request. The service
atomically marks at most one available key consumed and returns the reconstructed
`PKB`; replaying the same reservation returns that exact bundle without consuming
another key. Concurrent claims cannot receive the same key. Consumed IDs remain
tombstones and publication cannot reactivate them. An empty pool returns the
device's last-resort key in the one-time slot without reserving or consuming
anything; only a device that never published one returns no bundle. Device
revocation removes that device's pool, last-resort key included.

## Outer envelope (`MSG`)

The server-visible layout remains version, tag, 16-byte envelope ID, 32-byte
mailbox token, suite, expiry, padding bucket, and bounded ciphertext. Its
maximum encoded size is 65,606 bytes and it contains no sender, conversation,
or message-type field.

## Inner envelope (`PAY`)

```text
version:u8 = 1
tag:3 = "PAY"
sender_account_id:32
sender_device_id:16
recipient_device_id:16
conversation_id:16
client_message_id:16
client_timestamp:u64
message_type:u16 (nonzero)
body:vector (at most 32,768 bytes)
reply_reference:vector (0 or 16 bytes)
attachment_manifest:vector (at most 16,384 bytes)
receipt_policy:u8 (0..2)
disappearing_seconds:u32
extensions
```

The total encoded inner envelope is at most 65,536 bytes, even when individual
fields remain below their own ceilings. Larger content uses encrypted
attachments.

A direct conversation is named after the two accounts in it: `conversation_id`
is the first 16 bytes of SHA-256 over `mesh-msg/mobile/conversation/v2`
followed by both account IDs in ascending byte order. Every device of either
account derives the same name with nothing to coordinate, and a receiver
rejects any other name. A copy an account sends to its own other devices is
filed under `mesh-msg/mobile/self-sync/v1` over its account ID instead.

## Handshake transcript (`HST`)

```text
version:u8 = 1
tag:3 = "HST"
suite:u16 = 1 or 2
initiator_credential_hash:32
responder_prekey_bundle_hash:32
initiator_ephemeral_public_key:32
signed_prekey_id:u64 (nonzero)
responder_signed_prekey:32
one_time_prekey_id:u64
responder_one_time_prekey:vector (0 or 32 bytes)
responder_post_quantum_prekey:0 bytes for suite 1; 1,184 bytes for suite 2
extensions
```

The one-time ID/key rule is identical to the bundle rule. Maximum encoded size:
16,684 bytes. The authenticated transcript digest is exactly:

```text
SHA-256(ASCII("mesh-msg/v1/handshake") || canonical_handshake_transcript)
```

The selected suite and both prekey IDs are therefore authenticated. Golden
vectors for every new value and the transcript digest live under
`mesh-private-messenger/tests/fixtures/m5`.

## Initial message (`INI`)

```text
version:u8 = 1
tag:3 = "INI"
suite:u16 = 1 or 2
signed_prekey_id:u64 (nonzero)
one_time_prekey_id:u64 (nonzero)
initiator_credential:vector (exactly 211 or 1,395 bytes)
initiator_identity_public_key:32
initiator_ephemeral_public_key:32
post_quantum_ciphertext:0 bytes for suite 1; 1,088 bytes for suite 2
transcript_hash:32
nonce:12
ciphertext:vector (16..65,187 bytes)
```

The total is `349 + ciphertext_length` bytes for suite `0x0001` and
`2,621 + ciphertext_length` bytes for suite `0x0002`; neither may exceed
65,536 bytes.
Encoding uses the affine `BytesBuilder`; decoding uses `BinaryReader` and
rejects oversized input, truncation, invalid fixed lengths, malformed embedded
credentials, unsupported identifiers, and trailing bytes before cryptography.

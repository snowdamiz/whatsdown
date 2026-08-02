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
one to eight unique IDs. Profile A recognizes only `0x0001`; any higher or
otherwise unknown ID returns `UnsupportedSuite` instead of falling back.

`negotiate_profile_a(local, remote, strongest_authenticated_suite)` returns
`0x0001` only when both authenticated lists are valid and the remembered suite
floor is not stronger. A duplicate list fails with `DuplicateSuite`; a
remembered value above Profile A fails with `DowngradeDetected`. The selected
history below zero fails with `InvalidSuiteHistory`. The selected suite is also
encoded in credentials, prekey bundles, outer envelopes, and the handshake
transcript.

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

The existing credential layout remains exactly 211 bytes in Profile A. It
binds the account and device IDs, Ed25519 and X25519 public keys, capabilities,
creation and expiry times, directory sequence, selected suite, and signature.
The post-quantum key vector must be empty. See the package README for the exact
field table.

## Prekey bundle (`PKB`)

```text
version:u8 = 1
tag:3 = "PKB"
suite:u16 = 1
device_credential:vector (exactly 211 bytes)
identity_dh_public_key:32
signing_public_key:32
signed_prekey_id:u64 (nonzero)
signed_prekey:32
signed_prekey_signature:64
one_time_prekey_id:u64
one_time_prekey:vector (0 or 32 bytes)
supported_suites
expires_at:u64
extensions
```

The embedded credential must itself decode canonically, use the same suite,
and contain the same signing and identity-DH public keys. A one-time prekey ID
is zero exactly when the one-time public key is absent; otherwise it is
nonzero. This makes prekey consumption addressable without ambiguity. Maximum
encoded size: 16,942 bytes.

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

## Handshake transcript (`HST`)

```text
version:u8 = 1
tag:3 = "HST"
suite:u16 = 1
initiator_credential_hash:32
responder_prekey_bundle_hash:32
initiator_ephemeral_public_key:32
signed_prekey_id:u64 (nonzero)
responder_signed_prekey:32
one_time_prekey_id:u64
responder_one_time_prekey:vector (0 or 32 bytes)
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
suite:u16 = 1
signed_prekey_id:u64 (nonzero)
one_time_prekey_id:u64 (nonzero)
initiator_credential:vector (exactly 211 bytes)
initiator_identity_public_key:32
initiator_ephemeral_public_key:32
transcript_hash:32
nonce:12
ciphertext:vector (16..65,187 bytes)
```

The total is `349 + ciphertext_length` bytes and cannot exceed 65,536 bytes.
Encoding uses the affine `BytesBuilder`; decoding uses `BinaryReader` and
rejects oversized input, truncation, invalid fixed lengths, malformed embedded
credentials, unsupported identifiers, and trailing bytes before cryptography.

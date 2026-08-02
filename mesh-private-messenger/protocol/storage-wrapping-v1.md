# Storage Wrapping Format, Version 1

This document is the exact Profile A contract for sealing a Mesh secret before
it enters SQLite, a backup, or another durable byte store. An implementation
can encode and validate a blob using only the rules below.

The format identifier is `mesh-msg/storage-wrap/v1`. Algorithm `0x0001` is
ChaCha20-Poly1305 with a 32-byte platform-backed `StorageKey`, a unique 12-byte
nonce, and a 16-byte authentication tag.

## Context

Callers first encode the 123-byte context in this fixed order:

| Field | Encoding |
|---|---|
| Context version | unsigned 8-bit integer; `1` |
| Account ID | 32 bytes |
| Device ID | 16 bytes |
| Session ID | 32 bytes |
| Object ID | 32 bytes |
| Secret purpose | unsigned 16-bit big-endian identifier |
| Snapshot version | unsigned 64-bit big-endian integer |

Purpose identifiers are stable: `1` root key, `2` sending chain key, `3`
receiving chain key, `4` header key, `5` attachment key, `6` account
authorization key, `7` device signing key, `8` device DH key, `9` signed
prekey, `10` one-time prekey, and `11` skipped message key. Unknown
identifiers are rejected.

The Session ID is the canonical 32-byte session identifier for session,
ratchet, message, and header keys; other purposes use 32 zero bytes. The Object
ID prevents swapping values with the same purpose: use the 32-byte hash of the
corresponding public key for account/device keys and prekeys, the attachment ID
for attachment keys, and
`SHA-256(session_id || ratchet_public_key || message_number_u64_be)` for a
skipped message key. A singleton session key uses its session ID as Object ID;
a chain or header generation uses
`SHA-256(session_id || purpose_u16_be || generation_u64_be)`.

Snapshot version starts at `1` and increases for every committed reseal of an
object. The durable transaction reserves the next version before sealing and
never reuses a reserved value after failure. The account ID, device ID,
Session ID, Object ID, purpose, and version come from the authenticated local
state record, never from caller-entered text or unauthenticated server data.

The context binding stored in the blob is:

```text
SHA-256("mesh-msg/v1/storage-wrap" || context)
```

The supplied context is never inferred from database columns. Unsealing
recomputes this digest and rejects a mismatch before returning secret material.

Profile A wraps exactly 32 plaintext bytes. `seal_for_storage` reads them
directly from the live resource table; no ordinary `Bytes` plaintext is
created. `unseal_from_storage` authenticates the complete blob before checking
the 32-byte plaintext length and constructing the purpose-specific resource.

## Blob encoding

All integers are canonical big-endian values. Fields appear exactly once in
this order:

| Field | Encoding |
|---|---|
| Version | unsigned 8-bit integer; `1` |
| Algorithm | unsigned 16-bit integer; `0x0001` |
| Nonce | 12 bytes |
| Context binding | 32 bytes |
| Ciphertext length | unsigned 32-bit integer |
| Ciphertext | exactly the encoded length |
| Authentication tag | 16 bytes |

The fixed overhead is 67 bytes. Plaintext is limited to 65,536 bytes, so the
maximum version-1 blob is 65,603 bytes. Truncation, overflow, non-canonical
lengths, unsupported identifiers, and trailing bytes are rejected.

AEAD associated data is the ASCII domain label
`mesh-msg/v1/storage-wrap` followed by the encoded version, algorithm, context
binding, and ciphertext length. Callers cannot provide the nonce.

Each platform `StorageKey` record also holds a random 4-byte nonce prefix and a
monotonic 64-bit next-counter initialized to zero. A seal atomically returns
the current counter and increments the durable record, encodes the nonce as
`prefix || counter_u64_be`, and never reuses a reserved counter,
including after failure. Key bytes, prefix, and counter are backed up and
restored as one platform record; if atomic counter continuity cannot be proven,
the device creates a new `StorageKey` and reseals its live state. The key is
rotated before the counter is exhausted.

The native reservation callback and its context are host-owned and remain valid
and thread-safe until runtime shutdown. The callback atomically persists the
increment before reporting success, never re-enters Mesh, and treats every
successfully returned counter as consumed even when the seal later fails.

## Failure behavior

Validation order is fixed. First require the minimum size, read version and
algorithm, and return `UnsupportedOperation` for an unsupported identifier.
Next read the ciphertext length and require both the 65,536-byte bound and an
exact total blob length of `67 + ciphertext_length`; failure is a typed length
error. Then compare the supplied-context binding in constant time and perform
AEAD open. A wrong key or context, or any change to the supported authenticated
header, nonce, ciphertext, or tag, returns the same `AuthenticationFailed`
result and no plaintext. Errors and diagnostics never include secret bytes,
keys, resource handles, or decrypted values.

Production has no deterministic mode. Tests use a compile-time-only provider
to fix the nonce, assert one golden blob, round-trip every registered purpose,
and verify that changing each context field or authenticated blob field fails.

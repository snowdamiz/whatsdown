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
prekey, `10` one-time prekey, `11` skipped message key, `12` skipped-key map,
`13` ratchet DH key, `14` local data, `15` ML-KEM prekey seed, `16` group epoch
secret, and `17` group TreeKEM private key. Unknown identifiers are rejected.

The Session ID is the canonical 32-byte session identifier for session,
ratchet, message, and header keys; purposes `16` and `17` use the 32-byte group
ID and other purposes use 32 zero bytes. The Object ID prevents swapping values with
the same purpose: use the 32-byte hash of the corresponding public key for
account/device keys and prekeys, the attachment ID for attachment keys, the
hash of the complete canonical public group-snapshot header plus the purpose
and key-slot identifiers for purposes `16` and `17`, and
`SHA-256(session_id || ratchet_public_key || message_number_u64_be)` for a
skipped message key. A singleton session key uses its session ID as Object ID;
a chain or header generation uses
`SHA-256(session_id || purpose_u16_be || generation_u64_be)`.

Group snapshots use slot `0` for the purpose-`16` epoch secret, slot `1` for
the purpose-`17` leaf private key, and slots `2` through `7` for direct-path
levels `0` through `5`.

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

Private resources wrap exactly 32 plaintext bytes except purpose `15`, which
wraps the 64-byte ML-KEM-768 seed. `seal_for_storage` reads them directly from
the live resource table; no ordinary `Bytes` plaintext is created.
`unseal_from_storage` authenticates the complete blob before checking the exact
purpose-specific length and constructing the resource.

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
including after failure. The platform record `mesh/storage-key/v2` contains the 32-byte key, 4-byte
prefix, and 8-byte big-endian next-counter. Each reservation replaces that whole
record before sealing. Complete legacy key/counter pairs migrate without changing
the key or resetting the counter; the old key is deleted before its old counter,
after v2 is durable. Interrupted migration resumes from v2. Incomplete or
conflicting legacy records fail without being overwritten. An older application
cannot use the retired v1 key to restart its counter; rollback to such a binary
is unsupported.

Counter exhaustion fails before encryption. Complete rollback of all records
cannot be detected from the key store alone. Database continuity checks and
recovery/resealing remain open release work; the atomic
record does not by itself establish rollback resistance.

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

## Local record format 2

A device keeps its sealed records in one SQLite database. Format 2 decides where
each record sits and what its row shows, so that a copy of the file names no
label, and so no account, contact, group or conversation, and dates nothing.
SQLite's `user_version` is `2` in a database in this format; the core checks it
on every open.

```sql
CREATE TABLE storage_label_key (id INTEGER PRIMARY KEY CHECK(id = 1),
  sealed BLOB NOT NULL CHECK(length(sealed) > 0)) STRICT;
CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64),
  ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16)) STRICT;
```

**Label key.** `K` is 32 random bytes made with the database. It is sealed
under the platform `StorageKey` as local data, with the context: version `1`,
32 zero bytes of account ID, 16 zero bytes of device ID, Session ID
`SHA-256("mesh-msg/mobile/storage-session/v1")`, Object ID
`SHA-256("storage-label-key/v1")`, purpose `14`, snapshot `1`. The sealed blob
is the one row of `storage_label_key`. It is never replaced, never exported,
and never in a backup (see [secret-purpose-inventory.md](secret-purpose-inventory.md)).

**Row.** A record with label `L` (its UTF-8 bytes) is kept under

```text
R = lowercase hex of HMAC-SHA-256(K, "mesh-msg/mobile/storage-row/v1" || SHA-256(L))
```

A record stored under a caller's record key (`mesh_messenger_store_envelope`)
uses `SHA-256(record key)` in place of `SHA-256(L)`.

**Value.** A value `V` of at least one byte is stored as

```text
salt || (V[0..n] XOR M[0..n]) || V[n..]
n    = min(64, length(V))
M    = HMAC-SHA-256(K, D || R || salt || 0x01) || HMAC-SHA-256(K, D || R || salt || 0x02)
D    = "mesh-msg/mobile/storage-mask/v1"
```

where `salt` is 16 fresh random bytes for each write and `R` is the row's 64
ASCII characters. The mask covers a storage-wrap blob's version, algorithm,
nonce (its prefix and write counter), context binding, length, and the start of
its ciphertext. It adds no integrity: the blob's own authentication covers
every byte it unmasks to. Nothing else is stored with a row: no time, no
counter, no type.

**Moving a format 1 database.** Format 1 kept the same table under
`SHA-256(L)` in hex, with an `updated_at` time on each row, its values binary
or, in the first databases, base64 text. The first open of such a database
(`user_version` `0`) moves it in one transaction, with SQLite's `secure_delete`
on so the pages the old rows leave are zeroed:

1. Make `K` and `storage_label_key`, and an empty `encrypted_blobs_keyed` with
   the format 2 columns (dropping either table first if it exists).
2. Take the old rows 256 at a time in row order. For each, decode the old row
   ID (exactly 32 bytes of hex) and the value (a non-empty blob, or canonical
   base64 text), insert it under `R = lowercase hex of HMAC-SHA-256(K,
   "mesh-msg/mobile/storage-row/v1" || old row ID)` with its value masked as
   above, and delete the old row.
3. Drop the old table, rename `encrypted_blobs_keyed` to `encrypted_blobs`, set
   `user_version` to `2`, and commit.

Every record keeps its label; its time is dropped. An old row that cannot be
read (an ID that is not 32 bytes of hex, an empty value, base64 that is not
canonical) stops the move and rolls it back: the database stays in format 1,
unchanged, and the next open tries again. A move that stops for any other
reason, a crash included, leaves the same. A database already in format 2 is
never moved again. A new database is made in format 2 directly.

A backup never copies rows: restoring one writes each record through the
storage API, under the restoring device's own label key. A build from before
format 2 cannot open a format 2 database; going back to one is unsupported.

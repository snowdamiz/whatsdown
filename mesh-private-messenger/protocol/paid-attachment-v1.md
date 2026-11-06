# Paid large attachments, development profile

Current development writers use [padded attachment profile 4 and LAG2/LAR2](attachment-buckets-v4.md).
The version-2 attachment and LAG1/LAR1 wire sections below specify retained
legacy reads and exact recovery. In the new layout, the public size field is
rounded capacity and the original length remains encrypted. HTTP routes,
credit tiers and bounded completion/cancellation retain their existing rules.

The free attachment and opaque-object v1 protocols retain their existing limits.
This profile authorizes one attachment larger than 16 MiB and at most 512 MiB.
Its integer price is `floor((plaintext_size - 1) / 16777216)`, from 1 through
31 credits. It does not authorize backups or increase chat/crypto frame limits.
Paid creation is disabled unless `MORSE_PAID_LARGE_ATTACHMENTS=on` at both core
and object store (and at the public Cloudflare routing boundary).

The core/object-store, native receipt/recovery and bounded host file-range paths
have local integration evidence, including a 257-chunk paid transfer on iOS
Simulator and Android emulator. Deployment must select matching service readers,
native writers and host parsers. This document does not claim physical-device
acceptance, release approval or independent cryptographic review.

## Encrypted attachment version 2

AMF, EAM and ACH keep the layouts in [attachment-wire-v1.md](attachment-wire-v1.md),
with version byte 2 and the following constraints:

- plaintext size is 16,777,217 through 536,870,912 bytes;
- chunk size is exactly 65,536 and chunk count is `ceil(size / 65536)`, at most 8,192;
- the attachment identifier equals the paid opaque object identifier;
- HKDF and associated-data labels use `mesh-msg/v2/attachment-*`;
- an EAM is at most 514 bytes, an ACH at most 65,576 bytes, and the final chunk
  has its manifest-derived exact nonzero length.

Part 0 is the EAM; part `i + 1` is ACH chunk `i`. The total encoded budget is
`manifest_size + plaintext_size + 40 * chunk_count`, at most 537,199,106 bytes.
There is no array of 8,192 descriptors in a manifest or actor message. The
recipient decrypts each part independently using its device-wrapped ATR/ATG
reference. Inner and outer versions must agree; v1 and v2 authentication domains
are distinct. Filename, MIME type and attachment key remain encrypted. The paid
service learns the exact plaintext size, layout, expiry, opaque ID and access
timing; it must not be described as hiding those values.

## Canonical authorization

All integers below are unsigned big-endian. LAG is exactly 186 bytes:

```text
01 | "LAG" | operation_nonce:32 | object_id:32
upload_capability:32 | download_capability:32
plaintext_size:u32 | encrypted_manifest_size:u16 | encrypted_manifest_sha256:32
object_expires_at_ms:u64 | action_expires_at_seconds:u64
```

Nonces, identifiers, hashes and capabilities are nonzero. Upload and download
capabilities differ. The action is canonical kind 1, with the same nonce,
object-ID target, quantity equal to plaintext size, the same action expiry,
and request hash SHA-256(LAG). Action admission is bounded to fifteen minutes;
object expiry is future and at most seven days from authorization. The client
uses six days so transport delay does not extend a server-owned bound.

The public client sends canonical CAP (action + LAG + exact CRD frame) to
`POST /v1/attachments/paid-grant`. The object store forwards that exact CAP to
bearer-authenticated `POST /internal/credits/attachments/grant`. Only the core's
configured, witnessed issuer directory authenticates tokens; clients cannot
supply issuer keys or prices.

The core inserts every nullifier, immutable hold, unique object-to-hold mapping
and signed result in one PostgreSQL transaction. Any token conflict or effect
failure rolls back all inserts. Another nonce/frame cannot authorize the same
object. Hold/mapping/receipt retention lasts through the object expiry plus at
least seven recovery days, including when that exceeds issuer retention.

LAR is exactly 84 bytes:

```text
01 | "LAR" | object_id:32 | sha256(LAG):32
encoded_total_bytes:u32 | part_count:u32 | object_expires_at_ms:u64
```

The signed CAR is 290 bytes. It binds the exact action and CRD frame, stable
attachment effect ID, application time and entire LAR. Clients authenticate it
with their pinned core Ed25519 key. An edge's HTTP status alone never consumes
local reserved tokens. New authorization returns 201 and exact replay 200 with
byte-identical CAR. Malformed input is 400, changed replay or spent token is
409, unavailable proof/storage is 503. Core authorization is a durable upload
entitlement, not proof that object bytes have already been uploaded.

## Upload, completion and recovery

`GET/PUT /v2/objects/{64 lowercase hex ID}/parts/{canonical index}` uses the
existing `X-Object-Capability` header. Indices are 0 through 8,192 and bounded
again by the granted part count. Upload validates the EAM identifier/hash and
every ACH index/exact size before storage. A fresh part returns 201, an exact
body replay 200, and changed bytes at an accepted index 409. GET requires the
download capability and a completed, unexpired object. Wrong capability is 403;
missing part/object is 404; expired or deleting object is 410.

`POST /v2/attachments/complete` and `/v2/attachments/delete` use existing OCP
and ODL binary controls in this separate namespace. Completion first requires the exact total and all contiguous indices, then
verifies at most 128 part files/hashes per transaction using a durable cursor.
Repeat the same OCP after each 202; only the final 200 permits downloads. Deletion
and expiry remove at most 128 parts per transaction, recording a durable cursor;
explicit deletion returns 202 while work remains, then 204. Downloads and writes
fail closed during deletion. Cleanup tolerates already missing files.

A core commit followed by a lost object-store response or failed local commit
is recovered by resubmitting the exact CAP. The stored central CAR permits the
same local object grant to be created without a second charge. A changed CAP
cannot replace it. Local deletion followed by exact authorization replay can
recreate the same still-unexpired grant, with the same budget and capabilities;
it does not create a second central charge.

Native preparation seals the LAG, device-wrapped key/reference and capabilities
before reserving tokens. Unknown network outcomes retain the exact request and
selection. Each encrypted part must also be durably staged **before** its first
PUT: sealing identical plaintext again creates a different random nonce and is
not an exact replay. A staged index accepts only the original plaintext hash,
and concurrent staging returns the single committed ciphertext. This staging
is bounded per call; it never constructs a 512 MiB Bytes value. The host must
read and write bounded file ranges and preserve staged parts through uncertain
outcomes. The provided native prune operation advances a durable cursor by at most 128
sealed parts after object expiry plus seven days, then removes the prepared
material. It never releases an uncertain reservation. The host must schedule
that cleanup before a large-file UI is enabled.

## Evidence

`services/object-store/tests/paid-attachments-live.test.mjs` starts a disposable
PostgreSQL cluster, actual core and independent object-store processes. It
exercises shared-spend rollback, a lost local grant commit, concurrent exact
recovery, bounded encrypted streaming, capability and integrity checks, separate
free IDs, and cursor-based cleanup. Protocol and native tests additionally
cover the maximum 512 MiB layout using a single last chunk, without allocating
the whole file. These focused checks do not substitute for platform streaming
and release qualification.

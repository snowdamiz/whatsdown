# Portable text-archive codecs v1

The development `Backups.TextArchive` and `Backups.FileBundle` modules implement
bounded canonical payload and file framing. These codecs do not authenticate a
file, authorize an account, filter live history or import an archive. The
development `Mobile.BackupArchive` operations now perform those guarded tasks,
with protected listing, removal and read-only projections. Authenticated import
preview, pending export continuation, matching native bindings and the backup UI
are adopted locally. Authenticated whole-app provider flows and release
qualification remain open.
The encryption and recovery profile in [Backup Wire v1](backup-wire-v1.md)
is unchanged.

The locally adopted attachment-content successor and its remaining app/device
gates are described in [Portable attachment-content archive v1](backup-content-archive-v1.md).

All integers below are unsigned big-endian. A `vector` is a u32 byte length
followed by exactly that many bytes. Decoders reject unknown versions, kinds or
flags, invalid UTF-8, noncanonical ordering and trailing bytes.

## Encrypted file framing

```text
u8 version = 1
3 bytes "MBF"
vector sealed_manifest (exactly 182 bytes)
u16 chunk_count
vector sealed_chunk repeated chunk_count times
```

There are 1–256 chunks, each 73–65,608 bytes. Every chunk must have canonical
`BCH` framing, the manifest's clear backup ID, its exact zero-based index and a
consistent ciphertext length. The sum of ciphertext lengths minus AEAD tags
must not exceed 16,777,216 bytes. The complete file limit is 16,796,864 bytes.
The manifest's fixed public KDF profile is checked before copying chunk vectors.

The file has 192 fixed framing bytes plus 76 bytes per chunk beyond its
plaintext payload. At 256 chunks this adds 19,648 bytes to the 16 MiB payload
limit. A file adapter must admit the complete framed size and use bounded
range I/O; a 16 MiB file ceiling cannot represent every valid bundle. The
clear count and chunk lengths disclose the payload's byte extent, as described
in [Backup Wire v1](backup-wire-v1.md).

These are structural checks. A restore must still authenticate the manifest
and every chunk, compare their count and sizes with the opened manifest, and
verify the complete plaintext snapshot hash before publishing content. A
structurally valid file can contain invalid ciphertext.

## Encrypted payload

The payload has this 170-byte header followed by scope vectors:

```text
u8 version = 1
3 bytes "MTA"
32 bytes backup_id
32 bytes owner_account_id
32 bytes owner_authorization_public_key
32 bytes service_realm
u64 created_at_ms
u16 scope_count
u32 record_count
u32 candidate_count
u32 omitted_timed
u32 omitted_unknown_policy_or_kind
u32 omitted_nontext
u32 omitted_empty
u32 attachment_messages
vector scope repeated scope_count times
```

The limits are 1–32 scopes, 1–4,096 included records, at most 8,192 candidate
records and at most 16,777,216 payload bytes. `candidate_count` equals the
included record count plus the four exclusive omission counts.
`attachment_messages` is an independent count, bounded by the candidate count
and at least the number of included records carrying the attachment-omitted
flag. The decoder checks each scope's count against the remaining declared
record budget before reading its record vectors.

The owner fields are data until a caller authenticates the backup and compares
them with current account authority. The guarded operations derive the service
realm as SHA-256 of ASCII `morse-backup-service-realm/v1\n`, the exact UTF-8 pinned
core origin, and the pinned 32-byte service public key, concatenated in that
order. The captured transparency origin must equal that core origin. The pure
codec checks field sizes, not this derivation or account membership. Creation
times retain the full u64 range.

## Scopes and records

Each scope contains:

```text
u8 kind (1 direct, 2 group)
vector source_scope_id (16 bytes direct, 32 bytes group)
vector peer_account_id (32 bytes direct, empty for group)
vector display_name_utf8 (at most 96 bytes, no Unicode Cc characters)
u16 entry_count (1–256)
vector record repeated entry_count times
```

Scopes are strictly ordered by `(kind, source_scope_id)`, comparing ID bytes
lexicographically. Direct scopes may not repeat a peer account under another
conversation ID. Names are historical archive labels and grant no live contact
or group authority.

Each record contains:

```text
u16 source_ordinal (0–255)
u8 direction (1 sent, 2 received)
vector message_id (16 bytes direct; empty or 32 bytes group)
32 bytes sender_account_id
16 bytes sender_device_id
u64 timestamp_ms
u8 flags (only bit 0: attachment omitted)
vector text_utf8
```

Ordinals strictly increase within a scope. Nonempty message IDs may not repeat
within that scope; empty legacy group IDs remain absent and may repeat. Direct
sender accounts must equal the owner for sent records and the peer for received
records. This structural relation does not establish historical sender proof.

Direct text is bounded to 32,768 UTF-8 bytes and group text to 65,346 bytes.
Empty text requires the attachment-omitted flag. Exact maximum record lengths
are 32,852 bytes for direct records and 65,446 bytes for group records, plus
the outer four-byte vector prefix.

The intended export policy includes only supported permanent text and explicit
attachment placeholders. Timed or unknown ephemeral records, attachment bytes
and capabilities, active sessions, keys and financial state are excluded. The
codec has no access to source history and cannot enforce that filtering;
the guarded exporter must enforce it before encoding.

## Guarded development operations

Each create, import, list, remove or read operation captures its own current
account, device custody, native configuration and witnessed membership, then
checks the original authority and storage snapshots before publishing a result
or committing. The same owned platform key is used throughout. Import validates
the authenticated owner account, authorization key, service realm and confirmed
backup ID. It stores a separate read-only archive; it never restores active
sessions, keys, chats or financial state.

The encrypted account index holds at most eight archives and preserves their
original snapshot times. Re-importing an identical payload under the same ID is
idempotent; a conflicting payload refuses, and capacity never causes eviction.
Removal updates the selected row and index atomically. An authorized corrupt
payload within the storage capture limits can be removed without decoding it.
If both row and entry are absent, retry succeeds without writing; inconsistent
row/index states refuse. Listing does not use protected IDs to discover rows.

`Mobile.BackupArchiveReader` returns protected overview and message-page values
after a fresh guarded read on every request. Pages contain at most 16 complete
records and 131,072 text bytes. Cursors are record positions, not source ordinals;
attachment placeholders and absent legacy group message IDs remain intact.
The complete bounded archive is decoded for each projection, so these are not
streaming or peak-memory guarantees. The overview excludes message bodies,
authorization keys and the service realm. Native display must additionally
check the current app owner when delivering the result.

Current group snapshots authenticate account/device custody before export, and
sent group records must name the archive owner. Generic legacy group-history
wrapping cannot establish the historical local owner of old records. Keeping
legacy reads does not convert those records into historical sender proof.

## Pending export continuation

The development 175-export ABI includes the original seven backup operations
and four pending export operations. Matching Core libraries are installed for
iOS device/simulator and Android ARM64/x86_64. The portable file and recovery
profile stay unchanged. A pending export is separate from the eight imported
read-only archives.

There is one pending slot per account and device, with no expiry. Internal row
labels derive from SHA-256 of `morse-backup-pending-owner/v1\n`, account ID and
device ID. The slot stays the same when the authorization key or service realm
changes, so those changes cannot make an existing draft appear absent. The
descriptor's sealing context additionally binds both fields to the current
account and device. Callers supply no storage labels, keys or clock authority.

The slot contains the original portable ciphertext, at most 16,796,864 bytes,
and a platform-sealed descriptor bounded to 4,096 bytes. Its 225-byte plaintext
is `BPDM`, version 1, account ID, authorization key, service realm, device ID,
random draft ID, authenticated backup ID, wire digest, u32 wire length and u64
creation time, in that order. Draft IDs are 32 bytes and identify export work
independently of archive backup IDs. Creation time is display metadata, not an
expiry or grant.
Neither row stores a recovery code, recovery key, restored plaintext,
destination or app-lock scope. Both rows publish atomically.

Every operation captures fresh custody, native configuration and original row
states using one owned platform key. The final writer checks the same account,
device, authority freshness and captured rows before publication or deletion.
Crypto and portable restore run outside that writer. A valid existing draft
prevents another create. Concurrent creation preserves the first committed pair.

| Operation | Result and admission |
| --- | --- |
| Create | Returns its exact draft ID, original wire and newly generated code after the pair commits. The code is returned once and is never persisted. |
| State | Returns empty, repair-required, or a protected descriptor containing only draft ID, creation time and wire size. This validates the owner-bound descriptor, structural file and digest, not decryption with a recovery code. |
| Resume | Requires the exact draft ID and a newly entered saved code. It authenticates the retained file and current owner, then returns only the original ciphertext byte-for-byte. It never creates another code or returns restored plaintext. |
| Discard | Deletes the valid matching draft under the original-state fence. Absence is idempotent. A different draft or an invalid pair refuses. |
| Repair | Explicitly removes an empty, partial or invalid current slot. It accepts no fake ID and refuses a pair that has become valid. |

A wrong recovery code leaves the stored pair unchanged and does not make a
valid pair repairable. Bounded corrupt rows retain their exact bytes for the
final comparison. SQL type and length checks classify oversized or wrong-type
values without materializing them. The final writer rechecks those predicates
and preserves the captured state of any bounded companion. Repair cannot delete
a valid replacement or another account's or device's slot.

The frontend discovers state under a fresh app-lock scope. An explicit action
selects or retains destination metadata before code entry and resume, because
the OS picker can rotate that scope. A fresh unlocked action can claim retained
destination metadata without reopening the picker. Cancelled selection or scope
loss clears local code and wire without calling resume. Resume never calls create.
Implicit disposal keeps the encrypted draft. Destructive discard and invalid-slot
repair require separate explicit actions.

Provider `finish()` must succeed before exact-ID cleanup. Cleanup uses the ID
captured by create or the chosen descriptor, not a later state lookup. It uses
the same still-current owning scope. An old completion cannot acquire a new
scope or delete a successor. After a known successful file publication, failed
cleanup reports `savedPending`: the file is saved and the encrypted draft remains.
That operation cannot publish again. A later explicit visit can resume or discard
the retained draft. Local disposal clears owned code fields and buffers without
claiming prompt erasure of every runtime copy.

Create's successful native reply is version 2 followed by draft ID, vector wire
and vector code. State uses version 1 and tag 0 for empty, 1 for pending or 2 for
repair-required. Empty and repair-required replies are exactly two bytes; pending
is 46 bytes. Resume is version 1 plus vector wire. Discard is exactly 34 bytes,
including the same draft ID and status 1 for removed or 2 for absent. Repair
success is exactly two bytes, version 1 and status 1 for repaired or 2 for empty.
Decoders reject wrong lengths, unknown tags, mismatched IDs and trailing bytes.

`mesh_messenger_backup_pending_repair` has `max_input: 40239` and ABI
`max_output: 32`. The 32-byte boundary also admits the fixed native error strings,
whose UTF-8 lengths reach 29 bytes. The Mesh runtime applies the boundary to
both successful bytes and error strings. Success decoding remains exactly two
bytes. A valid-draft refusal must remain `MESH_LIBRARY_ERR_APPLICATION`, not an
output-too-large error. This changes export metadata and generated bindings,
not the repair success format or runtime rules.

The development contract is backed by separate source, privacy, client, native
and UI receipts. Actual iOS Simulator and Android emulator apps pass
unauthenticated startup and background/foreground checks. Authenticated backup
and provider flows, enabled OS authentication, physical-device and release
qualification remain separate.

## Verification and limits

The ten focused test groups pass at optimization levels 0 and 2, including
independent byte literals, full-width timestamps, malformed framing, duplicates,
exact maximum sizes and one-byte-over-limit refusal. Four unchanged encryption
and recovery-code compatibility groups pass at optimization level 2. An
allocation-budget regression failed before its fix and passes afterwards.

The four source/test files were adopted through
`.morse/d4-backup-p0-adoption-v1/result.json`, backed by
`.morse/witness-proof/d4-backup-p0-v1/manifest.json`.
The guarded core, management and readers are adopted through
`.morse/d4-backup-v2-work-v1/actual-flow-work-v1/joint-backup-qualification-v1/adoption-v1/result.json`.
Authenticated import preview is adopted through
`.morse/d4-backup-v2-work-v1/actual-flow-work-v1/archive-preview-work-v1/adoption-v1/result.json`.
It restores and validates the complete file against current account custody,
then fences the original authority before returning protected payload or overview
data. It does not reserve capacity or inspect the destination archive index.
Import independently revalidates the exact file, recovery code and confirmed ID.
All 36 combined optimization-2 checks and the actual mobile-main host build pass;
the source-matched disclosure report contains 314 modules and 42 reviewed sites.
Separate compiler controls refuse direct public file writes of protected archive
IDs, times, counts, messages and validity-dependent outcomes. Those historical
checks did not cover a native backup ABI or establish a usable app UI.
Wire limits do not bound process RSS: input, parsed values, output and temporary
GC-managed copies can coexist. This evidence does not qualify native memory
usage, prompt plaintext erasure, account recovery or a complete backup feature.

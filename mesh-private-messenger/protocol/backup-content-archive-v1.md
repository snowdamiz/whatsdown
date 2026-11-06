# Portable attachment-content archive v1

The MCA1 successor includes attachment bytes in an encrypted, read-only backup.
Its codecs, authenticated capture, atomic pending publication, native request
routing and app components are adopted locally, with matching libraries for
iOS device/simulator and Android ARM64/x86_64. The qualified Core has 321
modules, 49 reviewed disclosure sites and the unchanged 175-export ABI. The
adopted app source retains its 626 passing host tests and strict typing checks.
Full app linking, authenticated whole-app provider flows, physical-device and
release qualification remain open.

The source and acceptance records are linked from the
[Witness Network plan](../../WITNESS_NETWORK_PLAN.md). Existing text archives
remain readable under the [text-archive contract](backup-text-archive-v1.md).

## Policies and limits

Creation has two content policies: require every selected attachment, or allow
explicit attachment omissions. The native create request retains tag 1 for
text-only creation and uses tags 2 and 3 for these respective content policies.
They share the existing strict selection framing and 42,004-byte request cap.
Unknown tags, incomplete requests and trailing bytes refuse.

An omission retains its original position within its message. Its reason is
unavailable, expired, unsupported or above the supported profile. Allowing
omissions does not permit authentication failures, source changes, transport
failures or arbitrary HTTP errors to become successful omissions. The network
reader treats only the reviewed 404/410 cases as unavailable; it authenticates
metadata before deciding whether a file may be omitted.

The complete encoded plaintext payload is limited to 16,777,216 bytes, including
all metadata and attachment framing. The encrypted file is limited to
16,796,864 bytes. A single file therefore cannot use the entire plaintext
budget. There are 1–32 scopes, 1–4,096 included records, at most 8,192 candidate
records, at most 4,096 attachment slots and at most 10 slots per record.
Larger-file streaming is outside this profile.

## Canonical payload

Integers are unsigned big-endian. A vector contains a u32 length followed by
that many bytes. The 195-byte header is:

```text
u8 version = 1
3 bytes "MCA"
u8 policy (0 require, 1 allow omissions)
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
u32 attachment_slot_count
u32 included_file_count
u32 unavailable_file_count
u32 expired_file_count
u32 unsupported_file_count
u32 above_profile_file_count
vector scope repeated scope_count times
```

Scopes retain the text archive's kind, ID, peer, UTF-8 name and u16 record count.
Each record is a vector containing its u16 original ordinal, u8 direction,
message-ID vector, 32-byte sender account, 16-byte sender device, u64 timestamp,
text vector, u8 attachment count and that many attachment vectors. Attachment
positions are zero-based and contiguous within the record.

An included attachment vector contains:

```text
u8 position
u8 status = 0
vector UTF-8 filename (0–255 bytes)
vector UTF-8 MIME type (1–127 bytes)
32 bytes SHA-256 of content
vector content (nonempty, within the aggregate payload budget)
```

An omitted attachment vector contains only its u8 position and u8 status:
1 unavailable, 2 expired, 3 unsupported or 4 above profile. Policy 0 forbids
these statuses. All five file counters must match the actual slots and sum to
the declared slot count. Message candidate and omission counters retain the
text archive's consistency rules.

Decoding checks canonical scope/record ordering, exact slot positions, UTF-8,
content digests, remaining record/slot budgets, total encoded size and the end
of every vector. A digest is an integrity check within the encrypted archive;
it does not itself authorize a history record, account or remote object.

## Encryption, capture and publication

New content archives use the typed content creator in `Backups.PortableV2` and
the existing version-2 encrypted envelope. The reader admits exactly the
supported MTA1 or MCA1 payload schema after authenticating the envelope; it
does not try another decoder after a malformed selected schema. Legacy
version-1 and version-2 text reads remain available.

The guarded app operation captures account and history authority, keeps the
original storage key and authenticates attachment manifests with the retained
device keys. Retrieval uses the captured fixed origin and bounded part range.
The sole new disclosure exposes a closed action: refuse, finish, publication
eligible, or fetch an exact 32-byte object ID and 32-byte download capability
at part 1–256. Request count and order are inherent in fetching. Filename,
MIME type, plaintext length, digest, content and expiry remain protected.

The pending writer checks captured source/native/TLS state and the original
pending-row state before inserting either row. It checks freshness, monotonic
time and the earliest included attachment expiry before and after publication
inside the transaction. Failure rolls the pair back. The whole operation
retires captured resources and destroys its original storage key on either
result.

Once publication commits, pending state retains the original draft metadata,
and resume returns the exact committed ciphertext, including after the source
attachment expires. The saved backup has no source-attachment TTL. Interrupted export uses
the existing recovery-code and ciphertext-only pending continuation contract.

## Reading and qualification limits

Imported content stays in a separate archive; it does not restore live
sessions, ratchets, keys or funds. File reads retain record/slot association,
revision-bound tokens, chunk limits and authority checks before releasing a
result. App save operations use the current scoped file provider and retire
stale work when the scope closes.

Generic legacy group history still cannot prove its historical local owner.
Full mobile bridge timing, protected destination output, authenticated backup
and restore flows, physical devices and release qualification remain open.

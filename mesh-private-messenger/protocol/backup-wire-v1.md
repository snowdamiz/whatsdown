# Encrypted Backup Wire v1

Backup v1 is an opt-in client-side format. The service may store the sealed
manifest and chunks, but it never receives the recovery secret, derived key,
plaintext state, or plaintext history.

## Recovery profile

Version 1 has one fixed profile:

| Field | Value |
|---|---:|
| Salt | 16 random bytes |
| KDF | Argon2id v1.3 |
| Memory | 65,536 KiB |
| Iterations | 3 |
| Parallelism | 1 |
| Output | 32 secret bytes |

The Argon2 salt input is the ASCII domain `mesh-msg/v1/backup-key` followed by
the stored random salt. Decoders reject any changed parameter. A future profile
requires a new version; implementations must not silently weaken version 1.

## Sealed manifest

The canonical wrapper is:

```text
u8 version = 1
3 bytes "EBM"
u8 profile_version = 1
16 bytes salt
u32 memory_kib = 65536
u32 iterations = 3
u8 parallelism = 1
32 bytes backup_id
12 bytes random nonce
vector ciphertext (exactly 104 bytes)
```

The encrypted 88-byte manifest contains `BMF`, the backup ID, creation time,
chunk size/count, total plaintext size, and SHA-256 of the complete plaintext
snapshot. Manifest encryption derives a subkey with HKDF-SHA-256 and
`mesh-msg/v1/backup-manifest`; the clear profile and backup ID are authenticated
as associated data. The complete wrapper is exactly 182 bytes.

## Sealed chunks

```text
u8 version = 1
3 bytes "BCH"
32 bytes backup_id
u32 chunk_index
12 bytes random nonce
vector ciphertext
```

Chunks use the `mesh-msg/v1/backup-chunk` HKDF label. Their associated data
binds the canonical manifest hash and chunk index. Chunks are at most 65,536
plaintext bytes; a backup has at most 256 chunks and 16 MiB plaintext. Wrong
keys, changed manifests, reordered chunks, truncation, oversized vectors, and
trailing bytes fail closed.

A maximum plaintext chunk seals to 65,552 ciphertext bytes, and its complete
`BCH` wrapper is therefore at most 65,608 bytes.

The snapshot hash is checked only after every authenticated chunk has been
reassembled. A successful cryptographic restore does not itself recover account
access or authorize a new device; those are separate product operations.

## Version 2: backups in the object store

Builds make version 2 only. The version 1 `EBM`/`BCH` frames above were never
stored anywhere and stay only as a format; version 2 keeps the version 1
recovery profile (Argon2id, 64 MiB, 3 iterations, 1 lane) and replaces the
frames with an [attachment wire version 2](attachment-wire-v1.md#version-2-padded-objects)
object, so the store sees a backup exactly as it sees an attachment of the
same size bucket. Mesh code: `Mobile.Backup`, `Mobile.BackupKeys` and
`Mobile.BackupSnapshot` in `packages/mobile-core`.

### The recovery code

The core makes the code when backups are turned on: 32 bytes from the
operating system's random generator. It returns it once, for the app to show,
and keeps nothing it could show again. The app shows it as 52 Crockford base32
characters (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`, 5 bits each, most significant
first; the last character carries the final 1 bit and four zero bits) in 13
groups of four. Reading it back ignores case, spaces and dashes, reads `O` as
`0` and `I` or `L` as `1`, and refuses any other length, character, or nonzero
final bits. Backups turn on only once the user has typed the code back.

Everything else comes from the code `R`:

```text
L    = SHA-256("mesh-msg/v2/backup-locator" || R)
salt = first 16 bytes of SHA-256("mesh-msg/v2/backup-salt" || R)
K    = Argon2id(R, "mesh-msg/v1/backup-key" || salt, 65,536 KiB, 3, 1) -> 32 bytes

position(d, i)  = u64be(d) || u8(i)
object_id(d, i) = SHA-256("mesh-msg/v2/backup-object"   || L || position(d, i))
upload(d, i)    = SHA-256("mesh-msg/v2/backup-upload"   || L || position(d, i))
download(d, i)  = SHA-256("mesh-msg/v2/backup-download" || L || position(d, i))
```

`d` is the UTC day, `floor(unix_ms / 86,400,000)`, and `i` is 0 through 3:
each day has four slots. The salt comes from the code because the code must
find its backup before anything is downloaded, and a 256-bit code gains
nothing from a random salt. `L` names the objects and their capabilities; only
`K` opens them. The store sees only the object ID and the hashes of the two
capabilities, and cannot link one day's slots to another's without `L`.

While backups are on the device keeps `L` and `K`, never `R`: `K` sealed as a
storage purpose `5` `SecretBytes` whose context has zero account and device IDs
and the label's hash as its object ID ([storage wrapping](storage-wrapping-v1.md)),
labels `backup-key/v1` and, during a restore, `backup-restore-key/v1`. The
record `backup/v1` holds the state (`1` waiting for the typed code, `2` on),
`L`, the sealed key, the time of the last backup, and every slot used in the
past week (`u32 day || u8 index`) so that they can be deleted.

### The object

A backup is the attachment wire version 2 object of its snapshot, sealed with
`K` as the attachment key: an `AMF` version 2 manifest (attachment ID a random
32-byte backup ID, chunk size 65,536, chunk count
`ceil(padded(n) / 65,536)`, plaintext size `n`, expiry, an empty filename,
MIME type `application/vnd.morse.backup`), sealed into a 514-byte `EAM`, then
every chunk of the padded snapshot as `ACH`, padding-only chunks included. Its
grant (`OGR`) names the slot's object ID and capabilities, `c + 1` parts, the
same proof of work as an attachment's, and the same lifetime: six days from
creation (518,400,000 ms). Part sizes, part count, clear headers, lifetime and
total are therefore those of an attachment of the same bucket. `n` is at most
16,777,216 bytes, the largest free bucket; a larger snapshot fails with
`backup_too_large`.

### The snapshot

The plaintext is six vectors (`u32` length, then the bytes):

| Field | Contents |
|---|---|
| header | `u8 1 \|\| "BKS" \|\| account_id[32] \|\| u64 created_at_ms` |
| app record | at most 4 MiB, opaque to the core (below) |
| conversations | a list: vectors one after another to the end of the field |
| groups | a list |
| presentation | a list |
| account | three vectors: the username, the canonical account identity, and the sealed account key (empty from a device without it) |

A conversation is seven vectors: the peer's account ID (32), this device's key
for the conversation (16), the peer's username (1 to 64 bytes of UTF-8), the
safety number (0 or 64), `u8 blocked`, `u32` disappearing-timer seconds, and
its history, a list whose entries are `u8 direction (1 sent, 2 received) ||`
the canonical inner envelope. A group is its ID (32) and its history, a list
of entries of eight vectors: `u8 direction`, `u64 epoch`, sender account (32),
sender device (16), `u64 timestamp`, body, message ID (0 or 32), `u8 kind`
(`0` message, `1` view-once, `2` timer notice). A presentation record is its
key (`user/<hex>`, `nickname/<hex>` or `group/<hex>`, as `presentation_save`
takes it) and the record. The app record is JSON the app writes and reads
back: `{"v":1}` with its read marks, receipt marks, declined community
requests, and its read-receipt, notification-preview and appearance settings.

### The account key

A backup made on the device that holds the account authorization key (the
device that created the account) carries that key, so that the code alone
brings the account back when every device is lost. It is sealed with Mesh's
`StorageKey.from_secret`, never as bytes:

```text
A  = HKDF-SHA-256(K, salt "mesh-msg/v2/backup-account-key",
                  info "account authorization key", 32)
BK = StorageKey.from_secret(A, "morse/backup-account-key/v1")
     = HKDF-SHA-256(A, "mesh/storage-key/derived/v1", "morse/backup-account-key/v1")
blob = SigningPrivateKey.seal_for_storage(account_key, BK, context)
```

The context is the [storage wrapping](storage-wrapping-v1.md) context of the
account (its ID), a zero device and session ID, the object ID
`SHA-256("backup-account-key/v1")`, purpose `6` (account authorization key),
and snapshot version 1. The blob is 99 bytes. Each derivation of `BK` draws its
own random nonce prefix and starting counter, so blobs sealed on different
days never share a nonce. A linked device holds no account key, and its
backups carry an empty field: they restore only onto a device already linked.

**The trade-off.** With the account key in the backup, the recovery code
recovers the account itself: whoever holds the code (and can reach the store
within the six days a backup lives) can add a device to the account, remove
the others, delete the account, and read the backed-up history. The code is
256 random bits, so guessing it is not the risk; where it is kept is. The app
says so when it shows the code and asks the user to keep it like a password.
Every device added this way is an ordinary logged transition in the account's
device set, which the account's other devices see at their next sync.

### What a backup holds, and what it never does

It holds every conversation this device accepted or blocked, with its
history; the history of every group this device is in; the names, photos and
nicknames it shows; the app record; and, from the device that created the
account, the account key (above). A message request never accepted stays
behind.

It never holds:

- **Any private key but the account key**: the device's signing and DH keys,
  signed, one-time, last-resort and ML-KEM prekeys. A restored device makes its
  own; the old device's keys belong to a device that may still exist, and the
  account can remove it.
- **Ratchet sessions.** Restoring one would roll its sending chain back to
  before messages the device sent later, and the restored device would send
  under message keys already used. As in Signal, sessions start again after a
  restore; here the restored device is a new device, so its sessions are new
  anyway.
- **Group state.** An old epoch cannot follow the group's later commits, and
  its sending generations would repeat. The history is restored; membership
  comes back when a member adds the device again.
- **Anything with a disappearing timer.** A backup outlives the message; the
  six days it is kept can be longer than the timer. Direct messages with a
  timer and group messages with an expiry are left out.
- **View-once content.** The entry is kept as a stub with its content removed.
- **Attachments.** A reference's key is wrapped to the device that received
  it and the object is gone within a week; references are dropped and
  attachment-only messages with them.
- The outbox, delivery and receipt state, trust alarms and the transparency
  view (the new device verifies again), verification marks (verification is
  per device, as on any newly linked device), the app-lock setting, credit
  tokens, and the wallet, which has its own recovery phrase.

### Making backups

| Export | Request (after the database path) | Returns |
|---|---|---|
| `mesh_messenger_backup_begin` | nothing | the 32-byte code, this once; state `1` |
| `mesh_messenger_backup_confirm` | the code as typed | nothing; state `2`, or `backup_code_mismatch` |
| `mesh_messenger_backup_status` | nothing | `vector(u8 state: 0 off or waiting, 2 on) vector(u64 last backup ms)` |
| `mesh_messenger_backup_prepare` | app record, `u32` work difficulty | output list: object ID, upload capability, `OGR`, `OCP`, `ODL`, `u32` part count |
| `mesh_messenger_backup_part` | `u32` part index | part 0 the `EAM`, then each `ACH` |
| `mesh_messenger_backup_finish` | `u8 stored` | nothing; `1` records the backup as the last one |
| `mesh_messenger_backup_disable` | nothing | output list of `ODL` for every slot of the past week; the key and state are gone |

Every request is `vector(database path)` followed by that many vectors. The
app backs up once a UTC day while backups are on, when the app runs and then
hourly while it stays open; "Back up now" makes one at once. Prepare takes the
day's next free slot and records it before anything is uploaded, so a failed
attempt never reuses an object ID; a fifth backup in one day fails with
`backup_limit_reached`. The host grants, uploads every part in order with the
upload capability, and completes; on any failure it deletes the object and
calls finish with `0`. The snapshot waits sealed in `backup-outgoing/v1` and
`backup-outgoing/v1/<i>` until finish removes it.

Turning backups off forgets the key at once and hands back a deletion for
every slot used in the past week, which the host sends; any it cannot reach
expire within six days and nothing can open them. Deleting the account does
the same once the directory has accepted the deletion.

### Restoring

In the [multi-device model](multi-device-wire-v1.md) a restored device is
always a new device, with its own keys and device ID; nothing of the old
device is reused, so a device that still exists keeps working and can be
removed. There are two ways in:

- **The account back, on a fresh install** (onboarding's "Restore from a
  backup"). The backup must carry the account key. The device downloads the
  backup, learns the account's username from it
  (`mesh_messenger_backup_restore_identity`), looks the account's device set
  up in the key log as any lookup does (`KTQ` and its evidence, verified
  against the pinned witnesses), and hands the verified set to
  `mesh_messenger_backup_restore_account`. That refuses a set the key log does
  not show (`device_set_transparency_unverified`) or of another account
  (`backup_account_mismatch`), opens the account key, makes a link request for
  this device, authorizes it with the account key at the set's next sequence
  (the same `LNA` another device would give), completes it, and keeps the
  account key sealed under this device's storage key, all in one transaction;
  then it adds the snapshot as below. The host registers the device with the
  directory, which records the new device set like any link. The app then
  offers to remove the devices the user no longer has (Linked devices, an
  ordinary `DVR` revocation signed by the account key it now holds). A device
  that already has an account is refused (`account_already_exists`); a backup
  without the account key is `backup_has_no_account_key`, and the app offers
  linking instead.
- **Onto a linked device** (Settings -> Backups, or onboarding after linking).
  Another device of the account links this one with an ordinary `LNA`, and
  `mesh_messenger_backup_restore_finish` adds the snapshot; it works with any
  backup of the account.

| Export | Request (after the database path) | Returns |
|---|---|---|
| `mesh_messenger_backup_restore_slots` | the code | output list of 32 × `object_id \|\| download capability`: days from tomorrow (a clock ahead) back to six days ago, newest first, each day's slots 3 down to 0 |
| `mesh_messenger_backup_restore_begin` | the code, part 0 | `u32` chunk count |
| `mesh_messenger_backup_restore_chunk` | `u32` chunk index, the part | nothing |
| `mesh_messenger_backup_restore_finish` | nothing | `vector(u32 conversations) vector(u32 groups) vector(u64 created_at) vector(app record) vector(u32 snapshot size)` |
| `mesh_messenger_backup_restore_identity` | nothing | `vector(username) vector(account_id) vector(u8 carries the account key)` |
| `mesh_messenger_backup_restore_account` | the verified device set (`DVS`) | as `restore_finish`; the device now has the account |

The host asks each slot for part 0 with its download capability and takes the
first that answers `200`; `403`, `404`, `409` and `410` mean no backup there.
None: `backup_not_found`. Begin derives `K`, opens the manifest, and refuses a
wrong key (`backup_code_mismatch`), anything but a version 2 manifest with the
backup MIME type (`backup_damaged`), and an expired one (`backup_expired`).
The host then downloads every chunk, padding-only ones too, and hands each
over; a chunk that fails authentication, index, size or padding is
`backup_damaged`, and a part the store answers `410` for is `backup_expired`.
Finish needs every data chunk (`backup_incomplete`), a profile on this device
(`backup_restore_needs_account`) and the same account in the header
(`backup_account_mismatch`). It then:

- files each conversation under the key this device already uses for the
  peer, or, for a peer it does not know, gives it the record a sibling's sync
  would (`ensure_conversation_alias`: no ratchet, so the first message either
  way starts a fresh session with this new device) under the backup's key;
- puts the restored history before what this device already holds, leaving
  out messages it has (same sender and client message ID), newest 256 kept;
- blocks again every peer the backup had blocked, which also gives this device
  a new contact address, as any block does;
- merges each group's history the same way (by message ID) into the group's
  history record, where it shows once the device is in the group again;
- saves presentation records unless this device holds a newer revision.

Restoring the same backup again adds nothing twice. The app then merges its
record (marks this device already has win), applies the settings, and
restarts its notification journal from what the device now holds, so restored
messages are neither announced nor answered with delivery receipts again.

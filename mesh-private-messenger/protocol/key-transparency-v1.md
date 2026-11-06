# Key Transparency v1

Status: implemented development profile. The two witness keys currently share
an operator/account; they do not provide independent trust against that
operator. Internal verification is required for release. Outside review is
additional scrutiny, not an activation prerequisite.

This document specifies the legacy hash profile. The separately versioned
[RFC 6962 log and authenticated transition](key-transparency-v2.md) preserve
these roots and signatures; they do not modify historical v1 checkpoints.

## Commitments

Each canonical account/device-set transition is hashed as:

```text
SHA-256("mesh-msg/v1/transparency-leaf" || canonical transition bytes)
```

The balanced Merkle tree hashes internal nodes with
`mesh-msg/v1/transparency-node`. Checkpoints bind the tree size and root,
monotonic checkpoint sequence, previous signed-checkpoint hash, timestamp, and
the service signing public key under `mesh-key-transparency-v1`.

## Client rules

Clients reject a directory response unless all of these hold:

- the returned device-set commitment has a valid inclusion proof;
- the service checkpoint signature matches the pinned service key;
- the new tree is consistent with the cached checkpoint;
- the configured threshold of distinct, pinned witnesses signed the exact
  checkpoint hash;
- account and device-set sequence rules still pass independently.

Two valid service-signed checkpoints at the same sequence and tree size with
different roots are a publishable conflict. Witness IDs are not authorities by
themselves; each ID is pinned to an expected public key.

## Witness history rules

Before signing, a witness verifies the service signature and requires the
checkpoint timestamp to be within one minute of its clock in either direction.
It rejects sequence or tree-size rollback, changed contents at the same
sequence, and a log-version change without the authenticated migration path.
An advancing sequence must have a strictly later timestamp. Adjacent sequences
must link to the exact hash of the previously signed checkpoint. Across a gap,
the consistency proof must bind the exact old and new sizes, roots and log
version; an adjacent hash-link check alone cannot cover that gap. The accepted
checkpoint is durably persisted before its witness signature is released.

## Proof versions and capacity

Version 2 inclusion and consistency proofs carry compact RFC 6962 audit paths.
The existing Morse hash domains and tree shape remain unchanged: migrating
storage or proof formats changes neither roots nor checkpoint signatures.
Version 1 full-leaf proofs remain accepted for the native-client transition.

Both proof frames use big-endian integers:

- `KTI`: version u8, `KTI`, leaf index u32, tree size u32, node count u16,
  then that many 32-byte hashes.
- `KTC`: version u8, `KTC`, old size u32, new size u32, node count u16,
  then that many 32-byte hashes.

In v1 the hashes are the full leaf list, bounded at 4,096 leaves. In v2 they
are the RFC audit or consistency path in its canonical order. Parsers check
its exact expected length from the dimensions, reject unsupported versions,
and reject trailing or truncated data. Sizes are bounded at 4,294,967,295;
inclusion uses at most 32 hashes and consistency at most 33. Empty and equal
prefixes have empty consistency paths. The `KTK` checkpoint and `KTE`
evidence container retain their existing versions.

`POST /v1/transparency/consistency` accepts the existing 8-byte query
`1 || KTS || old_size:u32` for a proof to the latest tree, or the new 12-byte
query `2 || KTS || old_size:u32 || new_size:u32` for a fixed historical range.
The latter always returns v2 and rejects zero, reversed or uncommitted target
sizes. It never silently substitutes the latest tree. Immutable interior nodes
provide historical proofs even after entry bytes or checkpoints are pruned.

The directory stores dense leaf positions independently of the entry's SQL
sequence, whose gaps can survive rolled-back transactions. An append updates
complete interior nodes in the same transaction; checkpoints and compact proofs
read those nodes in O(log n). Node tile coordinates reserve groups of 256 for
future object-storage publication; tiles are not published yet.

`MORSE_COMPACT_PROOFS=off` is the migration default. While the log fits v1,
new accounts stop at 3,584 entries and all appends at 4,096, reserving 512
transitions for existing accounts. `on` enables compact output and raises those
limits to 4,294,966,783 and 4,294,967,295. Once a committed tree exceeds 4,096,
compact output and the larger limits are mandatory even if the flag is turned
off. This avoids making an existing tree unusable during configuration rollback.
Native clients and witnesses must support v2 before activation; old binaries
cannot read a tree beyond their wire bounds.

For group anchors, a compact consistency proof only covers one size pair.
The native core verifies the anchor's service signature and ordering, fetches
an exact-range proof when the current cached proof does not cover it, and seals
that proof locally. The cache has 256 slots selected by the anchor hash. Every
hit is verified against both checkpoint roots; a collision only causes a new
fetch. Same-size conflicting roots, invalid signatures, future checkpoints and
invalid proofs never authorize a group. Network failure remains a verification
failure. The directory origin arrives through the native request and is stored
atomically with verified evidence.

## Entry storage and retention

Migration 020 adds content-addressed canonical device records and ordered
entry references. Each transition retains its exact DVS header and suffix.
The directory reconstructs the original bytes and checks their stored leaf hash
before serving them. New writes use this representation immediately. The Mesh
backfill checks canonical encoding, reconstruction and leaf hashes before
replacing legacy bytes, in transaction batches of at most 100 entries.

Retention defaults to `off`. `MORSE_TRANSPARENCY_RETENTION=dry-run` reports
bounded candidates without replacing or deleting data; `on` applies pruning
and runs the verified backfill. Scheduled directory work and the local retention
worker use the same Mesh implementation. Each run considers at most 100 entries
and 100 checkpoints. A database ledger enforces a UTC daily limit per category
(default 1,000, configurable from 1 to 100,000); restarts cannot reset it.

Only superseded entry content older than 90 days is pruned. The current entry
for every account, recent content, account commitments, sequence numbers, leaf
positions, hashes and tree nodes remain. Unreferenced device records are removed;
account deletion forgets all its entry content and unshared device records
immediately. Checkpoints older than 35 days are removed with their witness
signatures, except the latest checkpoint and every checkpoint recorded in
`transparency_anchors`. The implemented chain writer records finalized anchor
receipts through the authenticated receipt API. Those database coordinates
protect retention; public readers still authenticate chain state independently.
Production deployment and release activation remain separate gates.

A phone that skips account sequence numbers warns that the account changed while
it was away and opens Linked devices, even when the current device identities
match its old snapshot. This conservative notice also covers intermediate
transitions whose content has been pruned. Ordinary single-step key renewal
continues without a device-change warning.

Witnesses and optional blockchain anchors receive checkpoint commitments only,
never usernames, device records, mailbox capabilities, account identifiers, or
message data.

The client rejects directory evidence more than five minutes old or more than
one minute ahead of its clock. Receipt time does not renew a replayed checkpoint.
The directory refreshes an unchanged tree on demand after four minutes, advancing
the signed checkpoint sequence and retaining the same tree root. New witnesses
must sign that new checkpoint before clients can authorize it. Migration 010
allows several checkpoint sequences for the same tree size. A failed or pending
witness check remains an error; it does not permit unchecked encryption.

Freshness currently applies to evidence ingestion and cached device-set
requirements used by fanout and identity operations. Extending it to every group
send and updating group recipient discovery remain implementation work; these
paragraphs do not claim those paths complete.

# Custom Groups, Version 1 (legacy)

Status: implemented and reachable. Group suite `0x0003` is a custom protocol, with no independent audit claimed. Release candidates require successful internal behavioral verification and applicable platform evidence; outside review is not a prerequisite.

New groups and upgraded epochs use [group schedule version 2](group-schedule-v2.md).
The legacy format below is preserved for queued ciphertext and snapshot reads.

Legacy padded application messages use version `2`; see
[client privacy revision 2](client-privacy-v2.md). That revision supersedes the
message plaintext limit below with 65,342 bytes. Membership-control formats
remain unchanged, and existing version-1 messages remain readable.

This profile applies MLS concepts and the RFC 9420 ciphersuite primitives, but
it is not an RFC 9420 wire-compatible implementation. It uses RFC 9180 base
mode HPKE with X25519, HKDF-SHA256, and ChaCha20-Poly1305; Ed25519 authenticates
commits and group messages. The compiler proof pins HPKE to RFC 9180 Appendix
A.2.1.

## State and transitions

Groups contain at most 64 device leaves in a fixed 127-node left-balanced tree.
Each leaf binds an account ID, device ID, signing key, join-only HPKE
initialization key, ratcheting leaf HPKE key, mailbox capability, transparency
checkpoint, witness count, and sorted extension list. Public parent nodes bind
their HPKE key and sorted unmerged leaves. The cached tree hash commits to both
leaf and parent state.

Every add or remove creates exactly the next epoch and rotates the committer's
leaf key. A fresh path secret is advanced through the six-node direct path with
HKDF-SHA256; each level derives a deterministic X25519 parent key. The commit
contains those public nodes and HPKE-encrypts the matching path secret to the
resolution of each copath node. A newly added leaf is excluded from the commit
ciphertexts, and a removed leaf has no resolution entry.

The Ed25519 signature binds the prior transcript, proposal, resulting tree
root, new leaf key, every public parent node, every unmerged-leaf list, and all
recipient ciphertexts. A receiver opens the first path secret addressed to a
leaf or parent private key it owns, derives the remaining path, verifies every
derived public key, and derives the next epoch secret from the root secret.
Replaced private path material is consumed. Receivers reject stale, skipped,
reordered, altered, wrong-group, or wrongly addressed commits without changing
their state.

Welcomes carry the signed add commit, complete indexed roster and public parent
tree, negotiated extensions, transparency policy, recipient leaf, and one
HPKE-wrapped secret at the recipient's lowest common ancestor with the
committer. The long-lived initialization key is used only for this join. The
recipient proves possession of both its initialization and ratcheting leaf
private keys before deriving and validating its private path. The Welcome HPKE
associated data also binds the negotiated extensions and transparency policy.
Every member must meet the minimum directory sequence, exact checkpoint,
witness threshold, and selected extensions.

The mobile core admits a key package only when the accompanying canonical
`DeviceSet` exactly matches Mesh-verified transparency evidence cached for the
same checkpoint. A self-signed set that merely repeats a public checkpoint
hash is insufficient. Each device keeps at most one pending join package; a
repeat request returns the identical signed package, and accepting its Welcome
atomically consumes the package and both private join keys.

Messages derive a per-sender, per-generation AEAD key from the epoch secret.
The signature and AEAD associated data bind the group ID, epoch, tree root,
sender leaf, generation, nonce, and caller data. Per-sender generations prevent
replay. Delivery fanout returns active mailbox capabilities except the local
sender; the delivery service still sees only opaque mailbox tokens and
ciphertext.

Add, remove, and local encryption failures return the unchanged live group
state, so validation or cryptographic errors cannot consume the caller's only
copy. State advances only after a complete transition succeeds.

## Canonical encodings and limits

All integers are unsigned big-endian. Decoders require complete input and
reject trailing bytes before cryptographic work.

| Value | Magic | Maximum encoded bytes |
|---|---|---:|
| Commit | `GCM` | 8,200 |
| Welcome | `GWL` | 65,527 |
| Group message | `GMS` | 65,527 |
| Group snapshot | `GST` | 65,535 |

Variable bytes use a `u32` length. Rosters, recipient sets, and unmerged-leaf
lists are capped at 64; update paths contain exactly six ordered parent nodes;
extension lists are capped at 16 and strictly increasing; group-message
ciphertext is capped at 65,362 bytes, leaving an exact plaintext maximum of
65,346 bytes after AEAD and canonical framing. Each TreeKEM HPKE ciphertext is
exactly 80 bytes. Commit and message signatures are exactly 64 bytes. Decoders
reject non-canonical counts, out-of-range nodes, duplicate or unsorted public
lists, and trailing data.

Mobile delivery wraps one canonical group value in `version || "GRP" || kind ||
u32 length || value`, a nine-byte overhead. Thus every encoder-valid `GMS` and
`GWL` fits the 65,536-byte `OuterEnvelope.ciphertext` limit exactly. The outer
suite is `0x0003`; add/remove commits, welcomes, and messages use the same
encrypted persistent outbox as direct messages.

The Mesh mobile API owns the group records exposed to the thin app bridge.
`group_list` returns at most 128 summaries; `group_inspect` returns the current
epoch and at most 64 member summaries; `group_history` returns at most 256
message records and at most 65,536 encoded bytes, dropping the oldest records
first to satisfy both bounds. Public records use the existing canonical
`output_list` framing (a vector-wrapped `u32` count followed by vector-wrapped
items). History records bind direction, epoch, sender account and device,
local receipt/send time, and plaintext body.

## Persistence

Snapshots encode the complete public tree, transcript, counters, transparency
policy, extensions, available private-path levels, and monotonic snapshot
version. The epoch secret remains a `SecretBytes` resource sealed under storage
purpose `16`. The leaf private key and six fixed private-path slots remain
`X25519PrivateKey` resources sealed under purpose `17`; unavailable slots hold
independent dummy keys and are ignored.

Each 123-byte storage context binds the local account, device, group ID, hash
of the complete public snapshot header, purpose, key slot, and version. Restore
authenticates all eight sealed resources and verifies the leaf and every
available parent private key against the public tree before returning state.
It rejects rollback, wrong-device use, altered public state, trailing data, or
failed authentication.

The encrypted group-state blob and bounded group index are committed together
on create or join. Sending commits the next group state, plaintext history, and
all encrypted outbox entries in one SQLite transaction. Receiving a message
commits the replay counter, plaintext history, and group state in one
transaction, so a crash cannot acknowledge a delivery whose plaintext was
discarded.

Mailbox processing classifies suite-3 results before producing an ACK. Applied
deliveries and permanently malformed/authentication-rejected poison entries
are acknowledged. A future epoch, missing earlier group state, or local durable
storage failure is omitted so it can be retried; a batch containing only such
entries returns empty bytes and the app must not submit an ACK. Mixed batches
acknowledge only the safe envelope IDs.

## Release verification

The M15 proof covers the RFC 9180 HPKE vector and the
[MLSWG `treekem.json`](https://github.com/mlswg/mls-implementations/blob/main/test-vectors/treekem.json)
cipher-suite-1 leaf private/public X25519 vector, plus this profile's complete
path derivation, hostile wire inputs, add/remove, multi-device membership,
epoch ordering, removal exclusion, private-path recovery, fanout, extension
negotiation, transparency-bound joins, bounded pending packages, persisted
mobile-core create/add/remove/send/receive fanout, group list/inspection and
plaintext history, future-epoch retry/ACK behavior, the exact maximum delivery
boundary, and mobile-target compilation. This custom profile is not expected
to consume RFC 9420 wire vectors directly. Release readiness depends on the
internal verification and platform evidence [SECURITY.md](../../SECURITY.md)
requires, at the candidate revision.
Internal tests do not constitute an independent audit.

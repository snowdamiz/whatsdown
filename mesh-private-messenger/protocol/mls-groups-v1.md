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
commits and group messages. Group messages of version 6 are signed with a
per-epoch key each sender announces over its pairwise sessions instead of its
long-term device key (see "Deniable sender authentication"). The compiler
proof pins HPKE to RFC 9180 Appendix A.2.1.

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
witness count (see "Witness sets"), and selected extensions.

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

## Witness sets

The transparency policy names the pinned witness set it was made under:
`u64 minimum_directory_sequence || checkpoint_hash32 || u8 k || set_id32`, where
`set_id` identifies the security config's witness set and `k` is its strict
majority ([witness-network-v1.md](witness-network-v1.md), "Security config
v2"). A version 1 policy has no `set_id` (`u64 || hash32 || u8`) and means 2 of
2 under the set version 1 configs pin, witness-a and witness-b. Its bytes, and
every transcript and HPKE context built from them, are unchanged.

- A welcome is `GWL` version 1 when its policy is version 1 and version 2 when
  it names a set; the encoder picks the version from the policy, and the
  decoder reads both.
- A commit moves the group to the committer's set by carrying `set_id32 || u8 k`
  right after its proposal, in commit frame `GCM` version 2 (version 1 frames
  carry nothing). Those bytes are part of the signed commit context, so the move
  is authenticated and bound into the next epoch, and every member applies the
  same policy. A welcome made by a moving commit must carry the moved policy.
- A snapshot is `GST` version 2 when its policy names a set.
- A leaf's witness count is the `k` its build pinned when it joined. Under a
  version 1 policy it must still reach the policy's `k`; under a set it must be
  at least 1, so members already in a group stay valid as it moves between sets.

What phones do (`Mobile.GroupSets` in mobile-core):

- New groups take the config's set. A build that pins exactly the version 1 set
  keeps version 1 policies, so the builds before sets can still join its groups.
- Every commit a device makes (add, remove, or the update before a send) moves a
  group that is not on its set to it, and a send in such a group makes that
  update first. Groups created under an older set keep verifying under it until
  then.
- A welcome's set, and the set a commit moves to, must be one the device knows:
  its own, the version 1 set, the group's current set, or one it verified under
  before an update. Otherwise the envelope waits in the mailbox with
  `group_witness_set_unknown` and the network status tells the app that a
  newer build is needed ("update Morse"). A device installed fresh on a newer
  set never ran the older ones, so a member still on an older build must update
  before it can welcome such a device.

## Disappearing and view-once messages

A group message of version `5` is version `4` (no inner padding, recipient
transport) whose plaintext is a `GOP` frame. The version is part of the signed
message context, so a version 5 message cannot be passed off as version 4, and
a build that predates it rejects it at decoding (`invalid_group_message`, a
permanent rejection, acknowledged unread).

```text
u8 version = 1 || "GOP" || u8 flags || u32 timer_seconds || u64 timer_stamp ||
u64 sent_at || vector32(content)
```

- `flags`: `1` view-once, `2` a change of the group's timer, whose content is
  empty; no other value. A timer change never has content.
- `timer_seconds` (0 to 2,592,000; the app offers 60, 3,600 and 86,400) and
  `timer_stamp` (u64 milliseconds): the sender's view of the group's timer.
- `sent_at`: the sender's clock, in milliseconds.
- `content`: what version 4 would carry, the presented message with its
  presentation records and attachment envelope. At most 65,261 bytes, so the
  whole plaintext stays within version 4's 65,290.

Mobile-core (`Mobile.GroupTimer`) keeps the timer in `group-timer/v1/<group>`
as `u32 seconds || u64 stamp`, and forgets it with the group.

- **Changing it.** `mesh_messenger_group_timer` (path, group ID, u32 seconds)
  sends a timer change with the stamp `max(now, previous stamp + 1)`, applies
  it in the same transaction, and adds a notice to history. Setting the timer
  the group already has sends it again under its own stamp, which changes
  nothing for anyone who has it and teaches it to anyone who doesn't. Any
  member of a plain group may change it; in a community only its owner and
  admins may (`group_timer_not_allowed`).
- **Applying it.** A receiver takes the timer from any version 5 message whose
  authenticated sender may set it (for a community, by the roles in the group
  record) when it is newer: a later stamp, or the same stamp and more seconds.
  So every member settles on the same timer whatever order messages arrive in.
  A timer change that changed something leaves a notice (history kind 2, body
  the seconds in decimal); one that changed nothing leaves none.
- **Sending under it.** A message goes out as version 5 when it is view-once
  or the group's timer is on, carrying the timer; otherwise as version 4, which
  older builds read. A device added later therefore learns the timer from the
  first timed message it receives; the app sends an empty presentation message
  after each membership change, which carries it.
- **Expiry.** A message expires `timer_seconds` after `sent_at`, or after its
  arrival if the sender's clock is ahead, and the sender's copy that long after
  it was sent. `Mobile.Expiry` deletes it from the sealed history at every
  sync, on the app's timer, and when the history loads.
- **View-once.** The sender's device keeps a stub without content (history kind
  1, empty body and attachment); so does every device of the sender's account
  that receives it. Other members keep the content and list it as unopened
  until `mesh_messenger_group_open_view_once` (path, group ID, message ID) hands
  it over once and deletes it in the same transaction.

Group history records gain two fields after the message ID: `u64 expires_at`
(0: it stays) and `u8 kind` (0 message, 1 view-once, 2 timer notice), eleven in
all; records of seven, eight and nine fields still read. The exported summary
adds the same expiry and an exported kind: 0 message, 1 view-once unopened
(body and attachment empty), 2 view-once opened or sent, 3 timer notice.

## Deniable sender authentication

Messages of versions 1 to 5 are signed with the sender leaf's long-term Ed25519
device signing key, the key its device credential and the key-transparency log
publish. A member who keeps such a message can prove to anyone that the device
wrote it (§22.3 C5 of the witness network plan). A group message of version
`6` is version 5 (no inner padding, recipient transport, a `GOP` plaintext,
flags `0` for an ordinary message) whose signature is made with a key the
sending device made for that epoch and told each other member device over
their pairwise session. Its version is in the signed context, so it cannot be
passed off as any other version, and a build that predates it rejects it at
decoding. The code is `Groups.GroupMessages`
(`encrypt_group_message_deniable`, `decrypt_deniable_group_message`),
`Groups.SenderAnnouncement` and, in mobile-core, `Mobile.GroupSigning`.

### Keys: one per sender and epoch

A device makes a fresh Ed25519 key pair for a group epoch at its first message
in that epoch, and uses it for every message it sends in the epoch. The epoch
is the rotation interval because it is already the unit of the group's key
schedule and membership:

- every add, remove and update commit starts a new epoch, so a device that
  joins gets fresh keys from everyone who sends after it joined, and a removed
  device is not a leaf of any epoch a key is looked up for, with no rule of
  their own;
- an announcement names its epoch, so it cannot be replayed into another one;
- receivers only open messages of their current epoch, so they keep keys for
  that epoch and ones they have not reached yet, nothing older;
- messages under one key are linkable to one (unnamed) signer only within an
  epoch, and a stolen key signs for one epoch at most.

The cost is one pairwise message per other member device at a device's first
message of each epoch it sends in. Epochs change at membership changes and
after 256 messages from one sender (`group-schedule-v2.md`), so this is well
below one announcement per message.

The private key is sealed in the device's record `group-signing/v1/<group>`
(`u8 1 || u64 epoch || u8 mode || vector(public_key) || vector(sealed_key)`,
itself sealed as local data) under storage purpose `7` with the object label
`group-signing/v1/<group>/<epoch>`. The next epoch's record overwrites it, and
forgetting the group deletes it.

### The announcement

Inner message type `9` ([canonical-codecs-v1.md](canonical-codecs-v1.md)),
sent over the existing pairwise session with each other member device, carries
one `GSA` frame of 76 bytes:

```text
u8 version = 1 || "GSA" || group_id32 || u64 epoch || signing_public_key32
```

It has no signature and names no sender: the sender is the session's peer,
which the ratchet authenticates. The announcements go into the send's outbox
transaction after the update commit, if there is one, and before the message's
own envelopes, and a device never lets one of its envelopes overtake another
for the same mailbox, so each normally arrives before the message it is for.
Announcements are control messages: never shown and never in history, and
taken from a blocked contact too, whose group messages still arrive.

A receiver:

- ignores a malformed frame, an epoch older than its own, and an announcement
  for its current epoch from a device that is not a member of it;
- retries (`group_signer_pending`: the envelope waits in the mailbox, like one
  it cannot open yet) an announcement for a group it has not joined yet, or
  from a device that is not a member yet of a later epoch; the welcome or
  commit is on its way;
- otherwise files the key under the group, the epoch and the peer's account and
  device in `group-signers/v1/<group>` (`u8 1` then entries of
  `u64 epoch || account32 || device16 || key32`, sealed as local data). A new
  announcement for the same epoch and device replaces the old one; each write
  drops the keys of epochs the device has left; a device holds at most four
  epochs at once, and more are ignored.

### When a device signs deniably

Inner-envelope extension `3` (session features) gains bit `8`: this build reads
inner message type 9 and group message 6. Receivers record features only from
authenticated messages and never forget them
([ratchet-message-v2.md](ratchet-message-v2.md)). At its first message in an
epoch, a device signs deniably when, for every other member device, it has a
session that:

- a send uses as it is, without a new handshake: the mailbox, safety number and
  suite of the verified device set, not replaced by a session reset; and
- whose peer advertised bit 8.

Otherwise the epoch is signed with the long-term key (version 4, or 5 for a
timed, view-once or timer message), which every build reads. That fallback
keeps every group working, and it is not silent: the group's inspection
(`group_inspect`) gains an eighth field, one byte, for how this device signs in
the current epoch (0 nothing sent yet, 1 long-term, 2 deniable), which the app
shows in the group's details with what it takes to become deniable.

The first message fixes the mode for the rest of the epoch. When a device's
epoch is long-term and every other member device has since become able to read
version 6, its next send starts a new epoch with an update commit, as after 256
messages, and signs deniably from its first message there. So a receiver may
read "I hold this device's key for this epoch" as "every message of this device
in this epoch is version 6".

### Receiving version 6

The receiver takes the sender leaf's account and device from the tree of the
message's epoch and looks up the key that device announced for that epoch.

| Case | Result |
|---|---|
| Version 6 and no key yet | `group_sender_key_pending`: retried, so the message waits for its announcement; the inbox's attempt limit applies as to any envelope it cannot open yet |
| Version 6 that does not verify under the key | `group_message_rejected`, permanent |
| Version 1 to 5 from a device that announced a key for the message's epoch | `group_downgrade_rejected`, permanent |
| Version 1 to 5 with no key for the epoch | Verified under the leaf's long-term key, as before |

A version 6 message never verifies under a long-term key, and a key announced
by one device never signs for another: the lookup is by the sender leaf.

### What stays signed with the long-term key

Commits (add, remove, update) and welcomes, which carry the add commit, stay
signed with the committer's long-term device key. They decide who can read the
group from the next epoch on, so every member must be able to check them with
nothing but the tree: a device that joins verifies its welcome before it has a
session with the committer, members apply commits in whatever order their
mailboxes hand them over, and communities check them against the owner's and
admins' roles. They carry no message content; what they prove is that a device
changed the group's membership or keys at an epoch. Group key packages and
invitations are unchanged: invitations and acceptances already travel over the
pairwise sessions (inner types 3 and 4).

### Linked devices, communities, joins and removals

- **Linked devices.** Each device is its own leaf with its own key per epoch,
  and announces to its own account's other devices over their sessions as to
  anyone else's. A device whose sibling has never sent it anything signs
  long-term until it has.
- **Communities.** The sender stays authenticated to every member, only not to
  anyone else, so the owner's and admins' roles are checked against the sender
  leaf exactly as for version 4 and 5: posts in the announcement thread, timer
  changes and record changes. An owner's or admin's posts in a part are
  deniable once its device has a session, with the feature, with every device
  in that part.
- **New members.** A join is a new epoch, so the next message of each sender
  decides again, now including the new device. A sender with no session with
  the new device, or none that has heard from it, signs long-term there until
  they have exchanged direct messages; its next send after that starts a new
  epoch and signs deniably.
- **Removal.** A removal is a new epoch. The removed device is no leaf of it,
  so none of its keys is looked up again, its messages from its last epoch are
  stale (`group_stale_epoch`), and receivers drop its keys at their next write.

### What this gives, and what it does not

It gives offline deniability of authorship against a third party:

- A transcript of a version 6 message and its announcement holds no signature
  by any long-term key. The only thing tying the key to the sender's identity
  is the announcement, authenticated by the pairwise ratchet's symmetric keys,
  which the receiver holds too. The receiver, or anyone holding its device
  state, could have made the key, the announcement and the message itself: it
  also holds the epoch's sender chains, so it can produce the encryption of a
  message from any leaf. A member therefore cannot prove with a signature who
  wrote a message.
- Inside the group, sender authentication is unchanged: a member cannot sign
  under a key someone else announced, so it cannot pass off a message as
  another member's.
- The pairwise session that carries the announcement is deniable in the same
  sense: its handshake follows X3DH, where the only signatures are the
  credential and signed prekey, made ahead of time and public
  ([classical-handshake-v1.md](classical-handshake-v1.md)).

It does not give:

- **Secrecy from members.** A member can still show the plaintext, a screenshot
  or its device, and say who sent it. What is gone is the cryptographic proof.
- **Protection against corroboration.** Two members who received the same key
  from a device independently can vouch for each other; either could have
  invented a key, but not the same one without colluding.
- **Metadata protection.** Nothing changes for delivery: it still sees
  mailboxes, size buckets and times, as described in
  [privacy-contract.md](privacy-contract.md).
- **Deniable membership changes.** Commits and welcomes stay provable (above).
- **Deniability in a long-term epoch.** Messages a device sent while it signed
  long-term remain provable. The group's details say which mode it is in.
- **Protection after a compromise.** Someone who takes a device during an epoch
  can sign as it with that epoch's key until the next epoch.
- **Unlinkability within an epoch.** One sender's messages in an epoch share a
  key, so they can be shown to have one (unnamed) signer.

Ceilings: each send in a long-term epoch checks the members' sessions again
until the first device without the feature. An announcement lost with a broken
pairwise session is not sent again in that epoch: that sender's messages there
wait for the inbox's attempt limit and are then acknowledged unopened, like any
group message whose commit never arrives, and the next epoch announces again.

`messenger-protocol/tests/group_deniable.test.mpl` covers the round trip, the
announcement codec, verification only under the announced key, a message
re-signed under another member's key, the transcript property (no long-term
key verifies it), version binding and removal. `mobile-core/tests/deniable_groups.test.mpl`
covers the fallback before any session, the upgrade into a new epoch once both
sides have heard each other, a message waiting for its announcement, an
announcement that shows nothing, downgrade refusal, both directions, a new
member without a session, rotation with an old epoch's key refused, a linked
device's key refused for another leaf, and removal.

## Canonical encodings and limits

All integers are unsigned big-endian. Decoders require complete input and
reject trailing bytes before cryptographic work.

| Value | Magic | Maximum encoded bytes |
|---|---|---:|
| Commit | `GCM` | 8,200 |
| Welcome | `GWL` | 65,527 |
| Group message | `GMS` | 65,527 |
| Group snapshot | `GST` | 65,535 |
| Sender key announcement (inner type 9) | `GSA` | 76 (exactly) |

Variable bytes use a `u32` length. Rosters, recipient sets, and unmerged-leaf
lists are capped at 64; update paths contain exactly six ordered parent nodes;
extension lists are capped at 16 and strictly increasing; group-message
ciphertext is capped at 65,362 bytes, leaving an exact plaintext maximum of
65,346 bytes after AEAD and canonical framing. Each TreeKEM HPKE ciphertext is
exactly 80 bytes. Commit and message signatures are exactly 64 bytes. Decoders
reject non-canonical counts, out-of-range nodes, duplicate or unsorted public
lists, and trailing data.

Mobile delivery wraps one canonical group value in `version || "GRP" || kind ||
u32 length || value`, a nine-byte overhead. Kinds: 1 welcome, 2 commit, 3
message, 4 a member's contact address (`GCH`, sent by a device with a price on
its inbox; [credits-v1.md](credits-v1.md#what-credits-pay-for)), which builds
before it refuse and drop. Thus every encoder-valid `GMS` and
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

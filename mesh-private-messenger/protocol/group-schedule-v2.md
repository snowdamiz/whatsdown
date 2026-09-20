# Custom group schedule, version 2

This is a custom protocol, not RFC 9420 interoperability. Commits and state
use version 2, recipient-wrapped application messages use version 4, and the suite remains 3. Version 3 retains its original padded application format.
All versions are authenticated. Legacy snapshots and messages retain their
original decoders; a legacy group cannot send new application messages until
an authenticated version-2 epoch transition succeeds. A version-2 state
rejects version-1 commits and version-1/2 messages. Old messages gain no
retroactive forward secrecy.

## Derivation and deletion

The existing TreeKEM path derivation produces `path_epoch`. For each transition:

```text
salt = SHA256(canonical update-path context)
prior = HKDF(previous_init, salt, "mesh-mls/v2/epoch-mix", 32)
epoch = HKDF(prior || path_epoch, salt, "mesh-mls/v2/epoch", 32)
next_init = HKDF(epoch, group_id, "mesh-mls/v2/next-init", 32)
chain[leaf] = HKDF(epoch, group_id, "mesh-mls/v2/sender-chain" || u16(leaf), 32)
```

The epoch seed, prior init, path secrets and replaced sender chains are
destroyed. Only the independent next init and evolving sender chains remain.
Retaining a receiving leaf or parent key may let an attacker reopen an old
commit, but the erased previous init is also required to recover its epoch.

For sender `leaf` and generation `g`, both outputs use the current chain:

```text
message = HKDF(chain, group_id, "mesh-mls/v2/message-key" || u16(leaf) || u32(g), 32)
next = HKDF(chain, group_id, "mesh-mls/v2/chain-next" || u16(leaf) || u32(g), 32)
```

Messages retain the signed header, random 96-bit nonce, padding and AEAD
context of the earlier format. Version 4 moves padding to the recipient transport; version 3 retains inner padding. State
advances only after signature and AEAD verification. Speculative maps are
independent resources; errors discard them. There are 64 sender slots and at
most 64 skipped keys across the group. A sender may jump over at most 32
messages. Skipped keys expire outside that sender's 32-generation window or
on epoch change. Capacity errors preserve committed state. Skipped keys are
deliberately retained secrets and are excluded from the erased-key claim.

## Authenticated epoch and welcome

A version-2 commit appends a 16-byte confirmation before its Ed25519 signature.
The confirmation is ChaCha20-Poly1305 over empty plaintext, using nonce zero,
the canonical path context as AAD, and a dedicated key derived with the same
salt and label `mesh-mls/v2/confirmation`. Receivers authenticate it with AEAD
open; they do not reseal it. It is never an application encryption key.

A version-2 welcome appends an 80-byte HPKE encryption of the epoch seed to
the recipient's one-use initialization key, with info
`mesh-mls/v2/welcome-epoch` and the signed commit as AAD. The recipient checks
the confirmation before using the seed. The join initialization private key
must be destroyed after successful durable admission; the mobile core consumes
its pending key record atomically. An old stolen welcome key or old snapshot
can still reveal the corresponding historical epoch.

Proposal kind 3, followed by a zero u16, updates keys without changing the
roster. Each sender must refresh after 256 messages in an epoch. The mobile
core prepares the update and message together and stores both sets of outbox
ciphertexts with the new snapshot and history in one transaction. Retries use
those stored ciphertexts. Legacy groups use this path to upgrade on send.

Temporary compromise recovery requires a fresh update by every member whose
live leaf/path keys were compromised, after attacker access ends. Another
member's update alone does not heal a still-known receiving key. Permanent
signing-key compromise requires identity replacement and renewed verification.
Removal excludes the removed leaf from the new path. Delivered plaintext,
local history, old backups and continuing endpoint control are not erased.

## Snapshots and evidence

Version-2 `GST` appends two vector-wrapped, authenticated secret maps for sender
chains and skipped keys, using storage purpose 12 with distinct slots 8 and 9.
Their contexts bind the account, device, group, complete public header and
monotonic snapshot version. Purpose 16 now holds only next-init material;
purpose 17 still holds the live TreeKEM private keys. Legacy version-1 snapshots
retain their epoch-root semantics. The total snapshot ceiling remains 65,535
bytes. Delivery ciphertext is at most 65,536 bytes. Recipient-wrapped application plaintext is at most 65,290 bytes, including encrypted presentation fields.

`groups.test.mpl` reproduces the old retained-root attack and exercises current
state plus captured TreeKEM traffic, two senders, reordering, replay, removal
and update-only epochs. `group_snapshot.test.mpl` exercises durable restoration
and tampering. `scripts/group-oracle.test.mjs` compares epoch derivation and
confirmation with Node/OpenSSL and rejects a deliberately altered oracle.
`group-schedule-model.py` is a bounded symbolic knowledge model with explicit
negative controls, not a proof of the application or a replacement for an
independent protocol audit.

Remaining migration/availability work: delayed application packets from an
earlier epoch still follow the existing stale-epoch behavior. They require a
separate bounded old-epoch receive-state policy before claiming arbitrary
cross-epoch reordering. The full crash/restore and compromise campaign in the
security plan remains the release acceptance contract.

## Recipient transport

New mobile group deliveries wrap the complete signed `GRP` control/application
packet in `SGP` version 1: a four-byte header, HPKE encapsulation and authenticated
ciphertext. HPKE uses the existing direct-initial primitive with the distinct info
`mesh-msg/v1/recipient-group` and recipient DH public key as AAD. Every recipient
gets its own wrapper, using its freshly authorized device credential. This permits
offline welcomes without creating a direct conversation. Group signatures,
transcripts, and account membership checks remain inside the wrapper.

The 52-byte transport overhead and four-byte encrypted length leave at most
65,480 bytes for the inner group packet. Power-of-two buckets run from 256 to
65,536 bytes. Application version 4 omits redundant inner padding: its group and
packet framing consume another 190 bytes, leaving 65,290 bytes. Legacy unwrapped
`GRP` packets remain decodable for queued deliveries; their exposed metadata is
not retroactively hidden. Versions 1–3 retain their existing decoding semantics.

This transport hides group IDs, rosters, and names from delivery. It does not hide
destination mailboxes, timing, or size buckets. Later compromise of a recipient's
long-lived device DH key can expose captured wrapper metadata; the inner group
message schedule still governs content forward secrecy. The wrapper alone does
not provide forward secrecy for group metadata.

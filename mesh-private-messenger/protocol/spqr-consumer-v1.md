# Inactive sparse post-quantum key consumer

`Session.Spqr` implements the volatile key consumer for Morse's development
Braid profile. It is not enabled in conversations and does not define Signal
wire interoperability. Its tests exercise actual bilateral Braid epoch outputs.
Typed persistence, authenticated epoch-zero bootstrap and an inactive
first-output journal now exist as separate modules. Continuation, subsequent
epoch coordination and live message encryption integration remain open.

The consuming coordinator must call the Braid kernel against the captured
authenticated session and consume its output in the same atomic state change.
`BraidEpochOutput` carries an epoch and an opaque key, not a session identifier;
this module cannot establish the output's source scope. Parsing or reconstructing
a CBF1 fragment also does not establish that scope.

## Key derivation

All integers below are unsigned big-endian. Configuration and session identifiers
are each exactly 32 bytes. The coordinator must use the canonical authenticated
handshake transcript hash as the session identifier. Direction is fixed by the
initial handshake: 0 is initiator to responder and 1 is the reverse. It does not
flip when the Braid roles alternate.

Let `D = UTF8("mesh-msg/spqr/v1") || 0x00 || configuration || session`.
`HKDF(IKM, salt, info, length)` means HKDF-SHA256. `Z` is 32 zero bytes.

| Operation | Derivation | Output split |
|---|---|---|
| Initialize | `HKDF(seed, Z, D || 0x00 || "Chain Start", 96)` | Root, direction-0 chain, direction-1 chain; 32 bytes each |
| Add epoch E | `HKDF(BraidOutput, oldRoot, D || 0x00 || "Chain Add Epoch" || E:u64, 96)` | New root and two new chains; 32 bytes each |
| Message n | `HKDF(chain, Z, D || 0x00 || "Message Key" || E:u64 || direction:u8 || n:u64, 64)` | Next chain and message key; 32 bytes each |

The old root is a secret salt in the add operation. Roots, chains and message
keys remain opaque `SecretBytes` or `SecretMap` values. Epoch zero is the
initialized chain pair; incorporated Braid epochs start at one. Message numbers
start at one. Overflow refuses the operation instead of wrapping.

## Retained state and progress

`L` is the latest incorporated epoch and `K` is the latest epoch used for
sending or receiving. The state requires `K <= L <= K + 1` and retains the
contiguous epoch range `max(0, K - 1)` through `L`: at most three slots.

Each slot has send/receive counters and chain-presence flags. Receive chains
exist for every retained slot. Future slots above `K` have zero counters. At
most one retained send chain has a positive counter. A send chain can be absent
only below `K`, with its counter zeroed.

Adding an epoch requires `L == K` and the exact successor `L + 1`. Sending can
use `K` or advance to `L`; it cannot return to an older epoch. Sending at a newer
epoch deletes older send chains. Receiving can still use the retained `K - 1`
chain. Advancing `K` prunes older slots and their skipped keys.

The chain map has capacity seven: a root and two chains per retained epoch.
The skipped-key map has capacity 64 across all retained epochs. Its public
index contains sorted, unique 16-byte `(epoch, messageNumber)` records. A cached
key is usable only when both the index and map contain it; use removes it from
both. Its number must be strictly below that slot's receive counter.

A forward receive can derive at most 64 missing keys plus the requested key.
The aggregate skipped-key capacity is checked before derivation. A replay,
retired epoch, missing cached key or capacity overflow refuses the operation.

## Ownership and persistence boundary

The inactive [bootstrap coordinator](../packages/mobile-core/mobile/braid_spqr_bootstrap.mpl)
derives distinct HE and SPQR roots from the actual authenticated hybrid handshake
and its configuration-bound transcript. The responder authenticates the entire
initial body before returning owners; the empty control body is discarded.
Current prekey custody, account generation, native policy and captured record
values guard one atomic commit of the initial owners, pending envelope and
outbox. Recovery returns the exact persisted envelope without rekeying.

This initializes `L = K = 0`; it does not consume a Braid epoch output or advance
the message chains. Scoped host checks passed at optimization levels 0 and 2,
with separate race, abort, lost-reply, independent derivation and compatibility
checks. These establish logical record rollback and fresh-actor recovery, not
physical database equality or an OS crash guarantee. Live conversations do not
call this coordinator.

The state is affine. Successful operations return its successor; refusals return
the original state. Work happens on forked secret maps so a failed operation
does not partially advance the original. Incorporating an epoch consumes the
Braid output on both success and refusal. The output is never serialized here.

This module's ownership guarantee is in memory. A caller must atomically commit
the successor Braid state, SPQR state and any resulting message/outbox changes
before publishing effects. It must handle restart, competing writers and lost
replies without replaying an output.

The inactive [first-output journal](../packages/mobile-core/mobile/braid_spqr_journal.mpl)
implements that transaction for its bounded initial exchange. It authenticates
and collects header fragments, consumes the actual first Braid epoch output, and
commits the successor owners with the encrypted control response and outbox
records. Recovery returns the original pending response. This is not a complete
coordinator for subsequent epochs or ordinary messages, and live conversations
do not call it.

The map API cannot enumerate arbitrary foreign contents. The volatile consumer
validates required names and the public skipped index. The separate
[typed storage module](../packages/messenger-protocol/session/spqr_store.mpl)
seals and restores both maps with their SPQR storage roles, which validate exact
name sets and 32-byte value lengths. Its contexts bind scope, direction, revision,
transition, descriptor and retained-state metadata. A failed second restore
does not publish the first candidate. The volatile consumer alone remains
unsuitable as a generic deserializer or proof that restored maps are canonical.

Scoped host checks pass at optimization levels 0 and 2. They include independent
KDF tags, two actual Braid epochs with reversed roles, message-key agreement,
three-slot retention, skipped-key boundaries, duplicate/gapped epoch refusals,
counter overflow and malformed state. Ownership misuse is rejected at compile
time. These checks do not establish native or release qualification.

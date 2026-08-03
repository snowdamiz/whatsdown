# MLS-Based Groups, Version 1

Status: implemented for development testing. Group suite `0x0003` must not be enabled in a production release until an independent protocol review of the final revision is recorded.

This profile applies MLS concepts and the RFC 9420 ciphersuite primitives, but
it is not an RFC 9420 wire-compatible implementation. It uses RFC 9180 base
mode HPKE with X25519, HKDF-SHA256, and ChaCha20-Poly1305; Ed25519 authenticates
commits and group messages. The compiler proof pins HPKE to RFC 9180 Appendix
A.2.1.

## State and transitions

Groups contain at most 64 device leaves. Each leaf binds an account ID, device
ID, signing key, HPKE initialization key, ratcheting leaf HPKE key, mailbox capability, transparency
checkpoint, witness count, and sorted extension list. A cached immutable
Merkle tree makes the root and member count constant-time while add/remove
path updates remain bounded.

Every add or remove creates exactly the next epoch, signs the prior transcript,
proposal, resulting tree root, and one HPKE-wrapped 32-byte epoch secret for
every active device. Wrapped-secret entries must be sorted, unique, exactly 80
bytes, and match the resulting leaf set one-for-one. A removed device receives
no next-epoch secret. Receivers reject stale, skipped, reordered, altered, or
wrong-group commits without changing their state.

Version 1 wraps each epoch secret to long-lived device initialization keys. It
does not provide MLS TreeKEM forward secrecy or post-compromise security:
compromise of an initialization key can expose recorded epoch commits for that
device. Production activation requires replacing this distribution mechanism
with independently reviewed TreeKEM update paths.

Welcomes carry the signed add commit, complete indexed roster, negotiated
extensions, transparency policy, and recipient leaf. The recipient proves
possession of the leaf initialization key before opening its epoch secret.
Every member must meet the minimum directory sequence, exact checkpoint,
witness threshold, and selected extensions.

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
| Welcome | `GWL` | 26,052 |
| Group message | `GMS` | 65,750 |
| Group snapshot | `GST` | 26,151 |

Variable bytes use a `u32` length. Member and epoch-secret lists are capped at
64; extension lists are capped at 16 and strictly increasing; ciphertext is
capped at 65,536 bytes. Commit signatures and message signatures are exactly
64 bytes.

## Persistence

Snapshots encode the public tree, transcript, counters, transparency policy,
extensions, and monotonic snapshot version. The epoch secret remains a
`SecretBytes` resource and is sealed under storage purpose `16`; it never
becomes ordinary `Bytes`. Its 123-byte storage context binds the local account,
device, group ID, the hash of the complete public snapshot header, purpose,
and version. Restore rejects rollback, wrong-device use, altered public state,
trailing data, or failed authentication before returning a group state.

## Release gate

The M15 proof covers the official HPKE vector, hostile wire inputs, add/remove,
multi-device membership, epoch ordering, removal exclusion, persistence,
fanout, extension negotiation, and mobile-target compilation. Production
activation still requires a recorded independent review of the protocol and
its final wire revision; this repository does not treat its internal proof as
that review.

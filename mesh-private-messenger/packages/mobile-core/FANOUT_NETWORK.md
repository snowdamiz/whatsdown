# Profile-bound native fanout

`Mobile.FanoutNetwork.native_fanout_send` owns witnessed peer and own-device
resolution, local device-set admission, prekey claims and final fanout commit.
JavaScript submits an intent and displays a five-byte result. It does not select
an origin, supply DeviceSets, mint work, inspect prekey responses or receive
outgoing envelopes.

The request is seven ordinary u32BE length vectors, with no count prefix:

| Field | Bound |
| --- | --- |
| Database path | 1..4096 UTF-8 bytes, no NUL |
| Expected local public profile | 1..36134 bytes |
| Peer lookup | exact username 1..64 or `@` plus 64 lowercase hex digits |
| Action kind | one byte: 1 message, 2 group invitation, 3 invitation acceptance |
| Body | at most 32000 bytes; exactly 32 bytes for kinds 2/3 |
| Expected peer account | empty or 32 bytes |
| Attachment reference | empty or at most 16384 bytes; empty for kinds 2/3 |

Maximum input is 88740 bytes. Success is `01 46 4e 4f` followed by contact-changed
0/1. An export output allowance must be at least 4096 bytes to preserve native
error strings. Empty message bodies require an attachment. Names use canonical
protocol characters; arbitrary URLs and case-normalized identity substitutions
are refused. Native validation remains authoritative.

The expected profile binds account/device IDs and identity keys. Routine renewal
of the same identity is allowed when starting the action. Every later stage uses
the exact encrypted profile captured at that point. Replacement before or during
HTTP refuses the action. Changed immutable network/security pins also refuse it.
The optional peer account must match the authenticated peer before prekey work.

Resolution uses the existing bounded native directory verifier, including its
version migration and guarded checkpoint/device-set commit. Prekey POSTs use only
native core_origin, zero redirects, an 8-second individual timeout and a 30-second
prekey pass budget, at most 15 claims and at most 19312 response bytes. Requests
carry application/octet-stream and no-store, no account cookies or authorization.
Responses require exact no-store. A generated reservation ID is sealed before
HTTP; an unknown response retains that ID for retry. Valid reservations are
committed only against their initiating profile and session/source snapshot.

Final encryption and publication capture up to 256 relevant source labels in
bounded 64-row read snapshots. All snapshots share captured encrypted custody.
The final SQLite transaction checks those snapshots, the earlier group action
basis when applicable, and the outbox/postage/delivery basis before changing
ratchets, history, invitation state or queued envelopes. A changed source aborts
all writes. A late outbox snapshot cannot authorize old-account crypto against a
replacement account or overwrite a concurrent receive. Group key-package writes
also compare their original profile, package and transparency source rows.
No SQL transaction remains open across cryptography or network I/O.

The UI frames and copies the initiating profile and intent before entering its
per-database serial queue. A native refusal or malformed result never triggers
outbox draining. Explicit subsequent message actions remain distinct messages;
this API does not invent message-level retry deduplication. Existing sealed
outbox entries provide delivery retry. Group invitation state preserves its
existing exact no-op/retry behavior.

Generic host dispatch denies the legacy
prepare_fanout_prekeys, send_fanout, group_invite and group_invitation_accept
entries. Their in-language implementations remain available for internal tests.
The JS fetch bridge and Tauri raw HTTP command have been removed. Account-bound
journal callers also replace the old generic journal_load/journal_save entries.
Owned iOS Simulator and Android emulator proofs exercise successful message and
group invitation/acceptance exchanges through signed Mesh HTTP peers, restart,
exact control retries and refusal after account replacement.

This is local integration qualification. Removing current app transport calls
does not disable arbitrary JavaScript or third-party native networking. Startup
global restrictions, the native capability inventory, complete Plaintext field
integration, outside review and production deployment remain separate gates.

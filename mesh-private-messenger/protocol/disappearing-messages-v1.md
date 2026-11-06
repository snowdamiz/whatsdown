# Disappearing-message storage maintenance

Status: development source and matching native libraries adopted with group
support and header encryption. Host tests cover guarded sync deletion; iOS
Simulator and Android emulator cover group timer transport, actual partial
direct/group-history expiry and complete history-row deletion during sync before
history display. Full Expo UI, physical-device and release qualification remain separate.
The scoped native proofs are recorded in
`.morse/witness-proof/d3-group-native-expiry-v1/manifest.json` and
`.morse/witness-proof/d3-direct-native-expiry-v1/manifest.json`, with complete
deletion in `.morse/witness-proof/d3-complete-native-expiry-v1/manifest.json`.

## Direct messages

The existing authenticated inner envelope carries the sender's timestamp in
milliseconds and `disappearing_seconds`. Zero means no expiry. The existing
conversation policy controls the timer for outgoing messages; changing it does
not rewrite old messages. A message expires inclusively when elapsed time is
at least the requested duration. A timestamp in the future remains visible.
Elapsed-time subtraction avoids overflow when adding a duration to a timestamp
near the maximum unsigned 64-bit value.

The native mailbox sync performs local maintenance before network setup, so
missing configuration or failed transport cannot prevent already-stored expiry.
Delivery-batch processing also maintains history after applying the batch and
before returning its acknowledgement. A message that expired in transit must
therefore advance the receiving protocol and remain acknowledgeable without
remaining in history after that sync. Direct history display uses the same
guarded maintenance path and still filters its returned view.

Maintenance enumerates the sealed session index, including linked-device
conversation aliases, and handles each conversation independently. It leaves
unchanged history ciphertext byte-for-byte intact. Partial expiry replaces the
single authenticated history blob, including its bounded internal chunks; an
entirely expired history removes its row. It does not delete a session, replay
state or delivery acknowledgement merely because its visible history expires.

Before mutation, a transaction checks the exact encrypted account profile,
session index, selected session record and history ciphertext that supplied the
plan. A concurrent change refuses the stale plan with `account_state_changed`.
It cannot overwrite newer history, recreate a removed history row from a stale
plan or apply a previous account's cleanup after custody replacement. A later
sync can retry using current state. Reads and cryptographic work do not hold a
database transaction open.

This is deletion from the application's current logical history. It does not
erase another participant's copies, explicit exports, old database backups,
filesystem snapshots or SQLite WAL/free-page remnants. It does not claim a
background timer runs while the operating system has suspended the app.

## Development evidence

Both owned native platforms exercise real conversation policy, timed sending,
receipt and acknowledgement through the generated ABI. Sender and recipient
agree on the authenticated message ID, timestamp and 60-second timer. After the
deadline, failed mailbox sync changes exactly one encrypted history row on each
peer, preserving the untimed message and every other record. Raw storage is
sampled before history display; the getter then causes no additional writes.
This attribution relies on the pinned production getter synchronously persisting
expiry before returning, rather than merely filtering its output. These are
partial-history checks using the adopted native libraries unchanged.

The complete-history successor passes 68 generated-ABI calls on each platform.
Authenticated invitation controls establish the session without untimed history;
each peer then stores exactly one timed direct message and one timed group
message. After both real 60-second deadlines, failed sync removes exactly two
rows on each peer, with no additions or changes to surviving ciphertext. Both
history getters return empty without writing, and repeated sync/getters leave
storage unchanged. Session and group indices remain intact. As above, logical
row attribution relies on the pinned getters' synchronous persistence, not on
decoding the opaque storage keys. The archive preserves two harness prerequisite/
observer-order failures and their corrections; production code and native
libraries are unchanged. Root verified 327 records and three provenance
references in the complete-deletion archive
(`ea75034af14a1acebfb9a9736983317611b35e737c998ff0c0dd11747f1cd68a`).
Temporary apps were removed and the iOS Simulator returned to Shutdown.

The empty-sync regression reads the sealed row directly without invoking a
history display/export. It failed against the original implementation and
passes against guarded cleanup. Further cases cover preservation of untimed
and unexpired entries, byte-identical no-op repeats, inclusive expiry and U64
overflow boundaries, deletion of fully expired history, cleanup before failed
network setup, and stale history/index/session/account refusal.

The real conversation-policy workload also sends an authenticated message,
waits for its one-second timer to expire in transit, then feeds it through the
production delivery-batch API. It checks the acknowledgement and stored
history before any display call. Exact source/tool/log records are retained
under `.morse/d3-disappearing-work/runs/`; individual run results determine
which checks have completed. This document does not by itself qualify them.

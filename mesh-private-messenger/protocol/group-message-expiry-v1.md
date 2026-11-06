# Disappearing group messages

A timer is a sending preference of this device for one group. It does not change other senders' preferences or revoke completed explicit file exports. Duration zero writes the existing permanent GMS5/GAP1 format. Nonzero durations are 1–2,592,000 seconds.

## Authenticated timed format

GMS6 uses the unchanged group-message framing, signature and AEAD context, with mandatory version 6. Both signed bytes and AEAD associated data include that version; rewriting it to 5 cannot downgrade a timed message. The encrypted plaintext is:

`02 || "GAP" || sender_timestamp_ms:u64be || disappearing_seconds:u32be || GAP1_tail`

`GAP1_tail` is the existing application payload following `01 || "GAP"`. Only application kind 1 is permitted in GAP2. The hint and empty routing fields retain GAP1's canonical checks. The body maximum is 65,225 bytes, twelve fewer than GAP1; with its maximum 40-byte gossip hint the total plaintext remains at most 65,290 bytes. GMS6 does not add padding. The existing group ciphertext/wire and crypto limits are unchanged. Unknown versions, malformed/trailing bytes, invalid durations, and version confusion refuse.

The group construction remains MLS-inspired; this format does not claim full MLS conformance.

## Compatibility and admission

Capability mask 16 means this exact device can read GMS6/GAP2. It is trusted only in a verified, current witnessed account/device set and an account-signed device credential. Before a timed send, every actual device in the current authenticated group roster must match its witnessed signing key and carry bit 16. Failure leaves the ratchet, history and outbox unchanged. The sender never falls back to an untimed message.

New accounts and link requests in the adopted development profile advertise baseline + ACH3 + padded attachments + header encryption + group expiry (31). Existing devices upgrade only through an exact device-signed RNWv2 request, followed by the existing account-signed credential answer and durable prior-request checks. The latest requested mask is `old | 2 | 4 | 8 | 16`; unrelated existing bits are retained. RNWv1 and older signed reader claims preserve their existing masks. Earlier authenticated masks, including D3-only 23 and C4-only 15, retain their exact signed meaning; a linked device does not gain capabilities by inference.

GMS1–5, GAP1 and version-1 stored history remain readable. They carry duration zero and are never retroactively expired by this preference. Existing queued bytes retain their original format and retry semantics.

## Receive and local history

Expiration uses the sender timestamp inside authenticated ciphertext and the shared elapsed-time predicate. At the inclusive deadline `now - timestamp >= seconds * 1000`, an authenticated expired message still advances group replay state and is acknowledged. It retains no user body, attachment reference or presentation update. Required authenticated control and gossip handling remains separate; group control kind 5 is not a GAP2 timed payload. A future sender timestamp remains visible, matching the direct-message clock policy.

Only timed history rows use stored entry version 2: the existing nine fields followed by a four-byte duration (ten total). UI summaries use version 2 with the existing ten fields followed by duration (eleven total). Permanent rows retain their exact old version-1 encoding. Row count (256) and total sealed history budget (64 KiB) are unchanged. Malformed authenticated rows refuse rather than becoming an empty history.

Cleanup guards the exact encrypted profile, group index, group ratchet and history ciphertext or absence before changing history under one transaction. Message receive captures the original sealed profile before decoding it, captures group state/history before opening the ratchet, and adds the authenticated sender's presentation row before preparing writes. Application, expired and kind-5 message writes require the same exact basis at commit; a concurrent cleanup, first history writer, rotation or forget refuses without restoring an older row. Independent authenticated gossip evidence remains outside this write plan and may survive a failed message commit, as before. Outbound preparation captures its basis before reading presentation; capture errors are observed at their original point so presentation validation retains its error priority. It preserves unrelated groups and protocol/outbox/delivery state. Partial cleanup re-seals remaining rows, complete cleanup deletes the row, and unchanged cleanup does not rewrite it. The sync hook is `Mobile.GroupHistoryExpiry.expire_group_history(path, now)`, invoked beside direct cleanup after deliveries and before transport setup.

## Native preference and display

The additive `mesh_messenger_group_policy` export takes vector-framed `[database_path, group_id]` to read or `[database_path, group_id, seconds:u32be]` to update. Inputs are at most 4,144 bytes; group ID is exactly 32 bytes, duration is bounded above. The result is the existing counted output list `[01, group_id, seconds:u32be]` (57 bytes). The sealed `group-disappearing/v1/<grouphex>` record contains `01 || seconds:u32be` and uses the unchanged label-bound storage associated data. Missing state means zero; malformed/authentication failures fail closed. Profile/index/ratchet/preference changes race against an exact guarded update. Forgetting a group deletes its timer.

The app schedules local history reloads at the next deadline for already visible direct/group messages. Those timers initiate no RPC. On removal it aborts that attachment's pending preview/save request, wipes its cached and retained preview bytes, and releases its preview URI. An obsolete completion or save lease cannot populate/unlock/release a newer generation of the same object. A pending native save-picker rechecks the per-object abort signal before creating or writing the file. Separately selected composer files and completed explicit exports remain owned by their existing flows.

This describes adopted development source and matching native libraries. Host tests cover raw sync deletion; iOS Simulator and Android emulator qualify timer transport, membership and actual partial group-history expiry through the generated ABI. Raw storage changes during failed mailbox sync before the history getter runs; a longer-lived message remains, and the getter causes no further storage change. This relies on the pinned getter synchronously persisting expiry before returning history. The scoped proof is `.morse/witness-proof/d3-group-native-expiry-v1/manifest.json`; the separate direct partial-expiry proof also passes on both platforms.

The complete-history successor also passes on both platforms: one timed direct and one timed group message per peer expire after their real 60-second deadlines. Failed sync removes exactly those two logical history rows before either getter, leaving all surviving ciphertext and session/group indices unchanged. Both getters return empty without writes; repeated sync/getters make no changes. Attribution uses the same pinned synchronous-persistence semantics. Root verified all 327 records and three provenance references in `.morse/witness-proof/d3-complete-native-expiry-v1/manifest.json` (`ea75034af14a1acebfb9a9736983317611b35e737c998ff0c0dd11747f1cd68a`), including both earlier harness failures and their narrow corrections. Full Expo UI, physical-device and release qualification remain separate; logical deletion is not forensic erasure of SQLite WAL or backups.

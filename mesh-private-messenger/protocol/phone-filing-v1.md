# Phone fork filing v1

Status: local implementation and host/native tests. No public relay, funded
deployment, physical-device background guarantee or bounty-wallet release is
claimed. The finder setting and fresh wallet addresses remain Phase 4 work.

## Native authority and transport

`mesh_messenger_fork_filing` accepts only the app database path. It reads retained,
encrypted `FRK` evidence and native security config v5. Neither JavaScript callers,
the directory nor relay responses may supply relay origins, RPC providers, the
judge program, log identity or receipt mint. Earlier configurations leave filing
disabled. Invalid evidence remains retained and exportable.

Mesh verifies the proof before work starts. A durable compare-and-swap reserves
the next retry before any network access. The export then starts a Mesh actor and
returns local state; network I/O never occupies the serialized host call. The
actor uses the shared finalized receipt reader, authenticating agreement from two
providers over the receipt, Log and Economics accounts. Owner, derived addresses,
service key, log version, mint and proof hash must match the native pins. Receipt
checkpoint hashes must match the locally retained proof. Unavailable, malformed,
stale or disagreeing reads cannot confirm payment.

Unless settlement is already confirmed, the actor posts the exact retained `FRK`
bytes to every pinned relay concurrently, including its unchanged finder bytes.
Requests contain no account credential or cookie, do not follow redirects, allow
30 seconds each and cap responses at 4,096 bytes. Only schema 1, matching proof
hash, HTTP 202/`queued` or HTTP 200/`settled` responses count as acknowledgments.
Even a relay's `settled` acknowledgment cannot confirm payment.

## Recovery and scheduling

The encrypted `fork-filing/v1` record is at most 192 plaintext bytes. Its scope
binds the judge, log, service key, mint, log version and exact evidence, including
the local finder. Target changes do not reset retry or finalized-context history.
Backoff is 1 minute, 5 minutes, 15 minutes, 1 hour, then 6 hours. A restart or
interrupted request consumes the already reserved attempt. Concurrent wakes share
the same CAS; stale workers cannot complete another reservation. The native
configuration is checked before work, before posting and before completion.

The last completed acknowledgment count survives a new reservation for the same
targets; different targets clear that count. The accepted count describes the
latest completed attempt, not cumulative delivery to named operators. Successful
receipt observations persist the actual finder, exact u64 payout and finalized
context. Once settled, endpoint rotation or repeated wakes perform no network work.

The app checks on foreground entry with retained evidence, then every minute.
It polls local state every two seconds for at most 45 seconds per new reservation.
That bound prevents a crashed actor's persisted reservation from causing endless
fast polling. Existing headless notification wakes also start filing after mailbox
work, including failed synchronization, and await it for up to 24 seconds. OS wake
delivery and execution time are not guaranteed; suspension is recovered on a
later wake or foreground entry. Messaging and local navigation do not await filing.

## Native view and Details

The output is the existing length-prefixed byte-list format with twelve UTF-8 fields:

| Index | Value |
| --- | --- |
| 0 | `none`, `disabled`, `invalid_evidence`, `pending`, `accepted`, `rpc_unavailable`, `rpc_disagree`, `settled`, or `paid_elsewhere` |
| 1 | Lowercase proof hash hex |
| 2 | Finder named in retained evidence, base58; the zero address means none |
| 3 | Actual paid finder, base58; empty until independently confirmed |
| 4 | Exact payout in token base units, canonical u64 decimal |
| 5 | Pinned mint, base58 |
| 6–7 | Latest acknowledgment count and configured relay count, each 0–8 |
| 8–9 | Last completed attempt's start time and next permitted attempt time, u64 milliseconds |
| 10 | Non-regressing finalized context slot, canonical u64 decimal |
| 11 | `1` while a reservation remains incomplete, otherwise `0`; this is not a process-liveness assertion |

The three inactive statuses carry empty identity/address fields and numeric zeroes.
The UI rejects malformed or contradictory views. Payment amounts never pass through
a floating-point number. Display uses base units and mint identity rather than
assuming an asset or decimal scale. A nonzero expected finder differing from the
receipt yields `paid_elsewhere`; Details explains that another phone or monitor
could honestly have submitted the same fork first. A zero finder uses the judge's
submitter fallback and is not labeled as substitution.

The fork warning continues to block new chats and key changes regardless of filing
or payment status. Details can copy the original hex or save `morse-fork.frk`
through the platform's file picker for `morse-relay submit`. It never exports a
relay response as evidence.

## Verification

Mobile-core tests cover encrypted restart/rate history, competing wakes, completion
fences, errors, receipt attribution and actual concurrent HTTP requests with a
three-server acknowledgment barrier. The optimized native fixture in
`tests/phone-filing-native` runs the real actor and finalized reader through the
C byte ABI against loopback transports and SBF-generated account records for all
three fork kinds, both signed and native/C2SP anchored. It holds
receipt I/O while another native call reads the retained evidence, then checks
payment, different/zero finder, owner/mint/hash rejection, provider disagreement,
context regression and no-work repeated wakes. Its fixture-only origins and clock
are not available from the production export.

`scripts/test-filing-status.mjs` exercises the exported React app with native IPC
fixtures, including pending requests, outages, payout attribution, disabled config,
local errors and byte-exact file export. These UI fixtures do not prove a live chain
or physical mobile background execution. CI also runs the native proof with the
judge job's authenticated artifact inputs.

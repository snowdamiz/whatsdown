# Local versioned collateral/rewards operator proof

This package is isolated from the native app and production issuer. It prepares
instructions and tests policy; it does not activate a crank or move live funds.
`Transparency.TokenCustody`, `Transparency.TokenRewards` and
`Transparency.TokenWrite` are additive public protocol codecs/builders. Native
exports and production operator configuration remain separate.

`RewardRead` requests exactly26 canonical roles in one finalized
`getMultipleAccounts` call, slices at8416 bytes, caps the body at512KiB and each
request at5 seconds. It authenticates owners, full account spaces, loader-v3
executable/ProgramData links, release slots, both mints, the Log/service/ring,
attendance clock/week, binding/profile, separate liabilities, reserve allocation
and permanent reserve receipt. Direct vault donations are surplus. A stale
MORSE TWAP is `None`, not a zero-valued live feed. Finalized earned claims remain
valid after later unbonding, grace changes or source rotation. Staged records
expose revision mismatch and their fixed one-hour deadline for cancellation.

Two of three distinct configured URLs must agree on the complete account
snapshot digest. URL uniqueness does not prove organizational independence.
Tests exercise actual frozen-SBF account bytes through loopback fake RPC servers;
they do not establish production RPC finality or provider independence. The
Pyth publication prestate is injected and does not qualify a live MORSE feed.

`RewardIdentities` fetches only the next one to three mandatory attendance
identities. It checks owner/schema/log and derives the canonical Witness PDA
from each immutable ID/public-key preimage. Its later account read is not claimed
to be the same bank as the26-role snapshot and does not make eligibility
judgments. The onchain append rechecks Witness/Bond/Pending/Member and the pinned
eligibility/source revisions. Every attendance row, including unadmitted and
Registered zero-weight rows, is required before financial settlement.

`RewardKeeper.plan_token_reward_step` prepares at most one next instruction:
open, attendance open/seal, begin, ordered append, cancel or finalize. It pauses
on unqualified code/source pins, a previous epoch, cosign window or unavailable
floor funding. It computes the cap/shortfall with integer policy before proposing
finalize, using the immutable staged TWAP rather than a later market observation.
Claims prepare canonical ATA creation plus the fixed-payout USDC or MORSE claim;
earned entitlements are independent of current eligibility and price availability.

This is an instruction planner. Durable signing, uncertain-packet reconciliation,
continuous permissionless grace assessment, scheduling and CLI/service integration
remain required before calling it an operational keeper. These functions do not
authenticate structs invented by a caller; the intended input is the strict
finalized reader, followed by an onchain revalidation at execution.

Run `scripts/prove-token.sh` for the required local gate. It rebuilds all three
SBF programs, checks legacy compatibility, generates actual SBF snapshots,
compiles Mesh instruction/policy/reader tests, replays the emitted writer objects
through SBF and runs both loopback RPC/restart harnesses. Its report keeps the
remaining Phase5/live acceptance gates explicit.


The burn-carry extension is separately versioned in
`protocol/token-burn-carry-v2.md`. `BurnCarryRead` uses a12-role custody-only bank
read and prepares a permissionless close only after week end; unavailable price
or market programs cannot trap accounted unspent input. It authenticates the
terminal receipt and keeps transferred carry separate from spent/burned input
and donation surplus. The pure raw codecs/builders and sealed journal live in
`ops/token`, while this package owns finalized custody reads, close planning and
actual-SBF/loopback transport tests. Journal retries retain the exact packet and
expired funding is reconciliation-only. No autonomous crank or live submission
is enabled.

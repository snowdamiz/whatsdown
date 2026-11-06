# Phase5 token custody and execution design

This is a local implementation design for §6.12, approved in this task. It does
not authorize a live mint, deployment, treasury submission or claimed Phase5 exit.
The existing issuer and its pre-token accounting remain frozen until a separately
coordinated post-token split integration.

## Fixed supply and custody

A separate Pinocchio `morse-token` program will initialize one classic SPL mint:
6 decimals, exactly1,000,000,000 tokens (1,000,000,000,000,000 integer units), no
freeze authority. One atomic initialization mints the entire allocation and
revokes mint authority. Bootstrap authenticates the executable's loader-v3
upgrade authority, as the existing rewards program does; an arbitrary first
caller cannot choose governance, beneficiaries, mint or vaults. Program addresses
and launch accounts in local tests are disposable fixture identities.

| Allocation | Integer units | Custody/release |
|---|---:|---|
| Treasury25% | 250000000000000 | Program vesting vault; pinned multisig beneficiary;48 months |
| Ecosystem20% | 200000000000000 | Fixed pinned grants multisig allocation |
| Team18% | 180000000000000 | Program vesting vault;48 months including12-month cliff |
| Backers15% | 150000000000000 | Program vesting vault;36 months including12-month cliff |
| Witness reserve15% | 150000000000000 | Program reserve vault; qualified floor shortfalls only |
| Liquidity5% | 50000000000000 | Fixed pinned liquidity multisig allocation |
| Advisors2% | 20000000000000 | Program vesting vault;24 months including12-month cliff |

The cliff is included in the total term. At the team cliff,25% has accrued.
Cumulative vesting advances through the original UTC monthly anniversaries;
short-month clamping never moves later anniversaries. Claims pay only cumulative
entitlement minus prior claims to the fixed beneficiary's canonical ATA. There
is no discretionary withdrawal from vesting, reserve or buy/burn custody. The
restricted reserve cap is0.05% of original supply per epoch:500,000 tokens, or
500,000,000,000 units. Multisig composition and real-world operator independence
remain outside qualification; bytes cannot prove those facts.

SPL permanently revokes an authority when it is set toNone. `BurnChecked`
reduces both the source balance and mint supply while checking decimals. These
are the actual Token Program operations, rather than transfers to a purported
"dead" address. [Solana authority docs](https://solana.com/docs/tokens/basics/set-authority),
[Solana burn docs](https://solana.com/docs/tokens/basics/burn-tokens).

## Oracle and token-bond boundary

The current judge accepts one pinned USDC mint; token support requires a
versioned custody extension with unchanged legacy USDC behavior. Token admission
must cover the full USD target with rounding up. A strictly-below80% valuation
starts one seven-day grace period. A partial topup does not restart it. Recovery
to the full target clears the period; expiry removes eligibility without a
price-triggered slash. Existing USDC custody, pending deposits, exits and
USDC-funded reward entitlements do not depend on an available MORSE price.
New or reactivated capacity admission still requires fresh complete TWAP when
any MORSE collateral participates in aggregate directory coverage: an unavailable
price cannot prove the USD value of that exposure. This fails closed rather than
treating the unpriced principal as zero required coverage.

Pyth's EMA is approximately one hour and is not the specified seven-day window.
It must not be renamed or treated as7d coverage. [Pyth averaging explanation](https://www.pyth.network/blog/whats-in-a-name),
[Pyth freshness/confidence guidance](https://docs.pyth.network/price-feeds/core/best-practices).

The proposed onchain accumulator authenticates a release-pinned source program,
account/feed identity, full verification status, positive normalized price,
bounded confidence and monotonically increasing oracle publication time. It
integrates the piecewise-constant sequence of accepted observations, with at
most60 seconds between accepted publications and no future/stale observations.
Hourly time-weighted buckets retain the latest168 fully completed UTC hours
(604800 seconds), plus the current partial hour. The valuation window ends at
the latest completed hour, at most3600 seconds behind chain time; the separate
latest observation must still be fresh within60 seconds. No partial-hour
aggregate is prorated as though prices were constant inside it.
It is a TWAP of this bounded sampled oracle series, not a claim to know every
trade between observations. Missing coverage invalidates the window; it cannot
be filled by extrapolation or a keeper-supplied average. Source changes reset
coverage. Stale/missing feeds disable token eligibility and leave USDC fallback.
No MORSE feed or market is assumed to exist; production activation needs actual
release pins and independently qualified source availability.

Every oracle/account change relevant to staged reward eligibility must preserve
the existing coherent snapshot/revision guard. Price observations that do not
change eligibility must not introduce the cheap invalidation attack previously
removed from unchanged bond topups.

The rewards program currently requires a fully funded USDC floor atomically.
Token reserve support therefore needs a versioned settlement result that records
USDC paid and token shortfall separately, binds the same complete eligible
attendance snapshot, and never represents token units as USDC funding. Reserve
claims use immutable entitlements and the per-epoch cap; they cannot consume a
second epoch's budget or leave an unbacked USDC claim marked funded.

## Shared bounded swaps and weekly burns

The generic Mesh validator/journal will accept only a bounded ExactIn router
shape. Jupiter's current V2 `/build` endpoint returns raw instructions for CPI
and custom composition; V1 Metis is no longer maintained. The implementation
will pin a concrete supported router instruction ABI and approved DEX program
set, rather than accepting an arbitrary returned transaction. [Jupiter current
API paths](https://developers.jup.ag/docs/swap).

Each chunk gets its own PDA authority and exact funded input escrow. The swap
CPI cannot receive authority for vesting, reserve, other chunks or the main
revenue vault. Validate every account and signer role; reject unapproved programs,
additional fees/tips, arbitrary writable custody accounts, delegates and close
authorities. Enforce exact maximum input and an independent conservative fresh
oracle minimum output, with slippage at most100 basis points. A caller cannot
make an arbitrarily bad quote safe by lowering its own quoted minimum. Validate
post-CPI balances and burn the actual fixed-mint output atomically. A failed
postcondition rolls back the whole swap and burn.

Weekly orders bind a fixed30% budget and at least24 positive chunks. Random
execution offsets fall inside distinct windows spread over the week; funded
amounts and membership are committed before execution. Tiny budgets that cannot
fund24 positive or viable chunks remain explicitly pending. Every chunk has a
permanent completion record. Its signed packet/signature are durable before any
broadcast, and an unknown outcome can only recover that same packet. No caller
or governance can substitute a new destination or withdraw the input budget.

The same bounded swap journal may later convert SOL revenue to USDC. Its
original-asset liability remains SOL until authenticated finalized execution
shows actual USDC received in the pinned custody account. Conversion is not a
quote-price multiplication and does not mint accounted USDC.

## Revenue rounding and compatibility work

Independent20% and30% fractional carries can jointly allocate two units from a
one-unit week. Post-token splitting needs one conservation rule with backed dust,
not a negative operations balance or an unfunded burn marked complete. The first
isolated model will reserve actual0..9 cash units and distribute complete10-unit
lots as2/3/5. Migration of the existing pre-token witness fractional carry is a
separate explicit transaction/policy, never an implicit rewrite of closed weeks.
This must be settled before changing the frozen issuer.

New Mesh policy/codec/builders and local Pinocchio/SBF tests precede any judge or
rewards wire change. Legacy instruction/account vectors remain mandatory.
Program-owned token vaults mean SPL Token owns the account while the Morse PDA
is its token authority; no service seed controls those vaults. Local proof data
must distinguish injected authenticated-account fixtures from actual upstream
oracle verification, real DEX execution, and live acceptance. No review or
production-readiness claim follows merely from local tests.

## Approved versioned judge/rewards integration contract

The following integration contract was reviewed and approved in this task after
the isolated local mint/oracle foundation passed. Its versioned custody, mixed
proof, rewards and reserve handlers now execute in local SBF. The immutable
`token-rewards-v2-checkpoint` preserves the24-check source/artifact snapshot;
it does not qualify live source availability, governance or a production exit.

Legacy `MEC1`/`MBD1` remain interpreted exactly as before. They never reinterpret
raw USDC principal as MORSE. A separate governance-authenticated14-day binding
pins the token executable, Config, fixed mint, Oracle, rewards executable and
canonical pool/log. Activating it moves Economics to an explicit `MEC2` boundary;
legacy custody/proof handlers must refuse it. Existing claims and permanent
funding receipts retain their old interpretation. All closed v1 epochs and any
collecting settlement must be drained before activation; earlier finalized
unclaimed allocations stay payable. The fixed USDC mint stays pinned.

`MEC2` keeps the192-byte frame and original USDC mint, minimums, USDC principal
counters and eligibility revision at168..176. New aggregate MORSE witness and
directory principal occupy176..192; an explicit directory asset identifies its
unit. `MBD2` keeps the canonical subject PDA and208-byte frame, with an explicit
asset discriminator and underwater-since timestamp. A full migration must validate
all reachable status/version/asset combinations and counters; zero padding is
never a disguised default asset. USDC fallback remains a supported actual bond
asset. New mixed-asset proof settlement must include every authenticated target,
transfer each asset to its corresponding canonical finder/locked ATA, decrement
only the matching asset counters, and atomically persist one permanent proof.
No v1 proof may partially slash a mixed-asset verdict.

Directory coverage is compared in one USD unit using the same authenticated
TWAP and both aggregate witness principal counters; token units are not added to
USDC units. Bond eligibility uses the configured USD target, with exact rational
80% comparisons and full-target recovery. Price changes alone never slash custody.
A permissionless assessment starts a single grace clock below80%, preserves it
through partial recovery, and clears it only at100%. A below-threshold bond with
no recorded assessment must be assessed before a rewards stage can treat it as
eligible; repeated unrecorded virtual grace periods are forbidden.

Continuous price observations must not invalidate collecting rewards stages.
Versioned begin pins an authentic fresh complete TWAP, source revision, chain
time and judge eligibility revision. Every row uses those same immutable inputs;
append/finalize require unchanged source/eligibility revisions. Existing ordered
complete attendance, deadline, cancellation and immutable payout rules remain.
A source rotation invalidates the stage and discards oracle coverage as designed.

One-unit active topups must not recreate global revision denial of service.
Financial deposits can accumulate as separately accounted pending collateral,
which is not an eligibility input. Activating that pending collateral is allowed
only outside an authenticated collecting rewards stage, then updates principal,
grace state and the judge revision coherently. Direct token donations do not
silently become accounted pending collateral. New/rebonded full-target admissions,
unbonding and actual slashes remain real eligibility changes. A stage deadline
bounds how long a legitimate collateral activation can wait.

Reserve topups require a versioned finalized settlement with separate USDC and
MORSE immutable liabilities. USDC is reserved first; only its actual floor
shortfall can request MORSE at the pinned TWAP. The reserve allocation authority
retains control of its own vault and checks a permanent per-epoch receipt and the
original-supply500000-token cap before CPI funding. No token amount is recorded
as accounted USDC. A capped/underfunded reserve cannot create an unbacked floor
claim: settlement fails atomically for genuine topup/retry. No eligible cohort
consumes reserve or subsidy. Claim replay cannot spend a second epoch's cap.

Local migration, maximum mixed-asset proof vectors, collector-boundary topup
tests and reserve entitlement/cap tests pass at that checkpoint. The exact issuer
20/30/50 transition remains a separately coordinated integration. Permissionless
continuous grace assessment is also an operational requirement: its stored clock
records the first authenticated assessment, not a proven historical first price
crossing.

## Current local keeper/read checkpoint

The prepared burn builders, strict19-account finalized reader and two-of-three
provider agreement are implemented in the isolated `ops/token` package. Actual
Jupiter/Raydium/SPL execution produced four local weeks of96 immutable burn
receipts; Mesh replays those exact states and instruction vectors. The bounded
loopback RPC proof covers wrong response IDs, RPC failures, stale contexts, wrong
owners, reordered/missing accounts, malformed numeric types, redirects, oversized
responses, code upgrades, retry and disagreement. A donated canonical Week ATA
cannot create an accounted budget or block an otherwise unfunded week.

The sealed signed-packet journal reserves canonical immutable intent and persists
exact authenticated packets before send. Unknown results and process restarts
recover the same packet. The separate bounded burn worker now schedules already
funded rows, authenticates a common31-account finalized bank with two-provider
agreement, and confirms prior receipts even after their execution window.

Explicit replacement additionally requires finalized height beyond the stored
lifetime and two same-bank observations that the actual signed blockhash is no
longer valid. The original row must remain unexecuted inside its immutable window;
code, route, price floor and canonical intent remain pinned. SQLite atomically
archives the entire retired packet and replaces the current ciphertext. Four
competing local workers produce one replacement; a fresh process authenticates
that archive. An understated imported lifetime cannot authorize replacement while
the old hash remains valid.

Missed rows receive durable markers without releasing funds. At the original
week boundary the worker uses the existing canonical close-to-carry path. Fresh
owned RPC/restart/race tests and actual SBF replacement/close execution are in the
separate burn-worker checkpoint; controlled LiteSVM height/time do not prove real
ledger finality or independent production providers. See `BURN_WORKER.md` for the
explicit CLI, limits and reproduction driver. No service is installed or started
automatically.

See separate burn-worker and public-chain checkpoints; the original umbrella
does not qualify scheduling, recovery or public rendering. This is not a Phase5
exit. The immutable swap profile still pauses on qualified code or factory
changes; it has no implicit refresh or discretionary escape transfer.

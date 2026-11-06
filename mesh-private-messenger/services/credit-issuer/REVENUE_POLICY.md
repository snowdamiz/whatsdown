# Versioned credit revenue allocation

This local implementation does not activate token economics or move live funds.
`MESSENGER_CREDIT_REVENUE_POLICY` defaults to `1`. Version `2` is an explicit
operator selection for newly created quotes. The persisted version and SHA256
policy definition belong to the quote, not to the eventual issuance time or
worker configuration. Lost-response retries retain the original quote policy.
CQT224, signed quote authentication and blind issuance wire formats are unchanged.

Version 1 preserves historical accounting exactly: the witness share is
`floor((gross + witness_remainder) / 5)`, operations receives the rest, and the
next remainder is modulo 5. It has no burn allocation or reserved cash dust.
Existing quotes, revenue, weekly batches and permanent rewards funding receipts
remain version 1 after migration.

Version 2 assigns the original-asset gross amount with numerators 2, 3 and 5 over
10 to witnesses, burn and operations. Each numerator has its own remainder.
For each share, `allocation = floor((gross * numerator + old_remainder) / 10)`.
The next remainder is modulo 10. The sum of the three remainders is 0, 10 or 20;
its quotient by 10 is an actual reserve of zero, one or two base units. Thus
`witness + burn + operations + reserve_after = gross + reserve_before`.
The reserve never belongs to operations. An allocation may spend prior reserved
dust, so a batch's allocations can exceed its newly received revenue by at most
two units. This exact per-share carry is associative across chunking. In
particular, gross 3 allocates witness 0, burn 0, operations 1 and reserves 2;
applying 3/8 to a rounded remainder would incorrectly allocate burn 1.

Weekly membership is immutable, ordered and committed with the version, policy
hash, asset, mint, treasury configuration and week. Every event is allocated once.
Version 1 and version 2 occupy separate carry lanes. A configuration or mint
change fails closed; it cannot silently inherit another custody lane's reserve.
Only actual issued revenue whose exact sweep has finalized successfully enters a
Solana weekly batch. Late sweeps enter a later batch. Direct vault donations are
not revenue. Actual overpayments accepted within the quote limit are revenue.

USDC uses its original six-decimal units. SOL remains lamports and Lightning
remains millisatoshis. Neither is recorded as USDC before a separately verified
conversion and custody journal. Burn liabilities are distinct from the witness
funding handoff and operations allocation. An off burn operator retains the
liability; it cannot route that money to operations. Existing rewards funding
continues to use permanent, idempotent tag-12 receipts for the exact witness
allocation. No treasury-owner secret is imported into the issuer.

Qualification includes independent integer reference vectors through U64::MAX,
N=1..20, adversarial legal carries and chunk associativity; PostgreSQL tests cover
quote-time pinning, version changes, immutable historical allocation, concurrent
freezing, exact dust conservation and original-asset accounting. The local token
burn program's source, oracle, DEX, schedule, permanent closed-week carry and
actual CPI proofs remain separately scoped; no live feed or funded operation is
claimed by this accounting policy.


## Witness funding identities

Legacy version-1 IDs remain exactly
`SHA256("morse-credit-week-funding-v1" || config_hash || batch_id_le64 || epoch_le64)`.
Version-2 IDs use domain `morse-credit-week-funding-v2`, the same three fields,
then `policy_hash || membership_hash || witness_amount_le64`. All integers use
eight-byte unsigned little-endian encoding. Direct reload and reconciliation
validate version-2 metadata against the immutable weekly commitment. Existing
version-1 records and their permanent receipts retain their original bytes.
Only idempotent rewards tag 12 is emitted; a send acknowledgment is not funding.

## External burn handoff

`MORSE_BURN_MODE` defaults to `off`. Explicit `test` or `live` configuration must
match the issuer purpose and the pinned treasury providers, genesis, treasury
owner, USDC mint and token-program release. Additional pins are
`MESSENGER_TREASURY_BURN_PROGRAM`, `_GOVERNANCE`, `_PROGRAM_SLOT` and `_FACTORY`.
The program's own immutable profile authenticates the oracle and DEX accounts.
There is no fabricated live MORSE feed, production signing or automatic burn
activation in this implementation.

`treasury burn-request <epoch> <carry>` reads a complete bounded finalized bank
from both pinned providers and reserves at most 64 ordered USDC burn liabilities.
The exact cash amount, separately accounted onchain carry, 24 cryptographically
random schedule weights/entropy values, profile, membership and full tag-14
instruction are persisted before returning an external-owner request. Concurrent
and restarted requests return the same immutable intent. Treasury cash donations
and carry-vault surplus never enlarge the accounted carry allocation. The issuer
does not hold the treasury owner's secret, sign this request or broadcast it.

`treasury burn-reconcile <intent-id-hex>` requires both pinned finalized views to
prove the exact permanent funded identity. It accepts an active funded week or
its later immutable closed receipt; current partial execution does not change
the original cash/carry allocation. The update of every member liability and the
intent is atomic. A funding proof discharges the offchain funding liability;
actual execution and burning remain independently observable through the token
week's CPI-verified rows and closed receipt. A receipt from another policy,
configuration, owner, mint, schedule or membership cannot discharge this intent.
Provider disagreement, missing data or ambiguous outcomes leave it reserved.

An unfunded intent remains reserved after its funding deadline. The additive
[`MBX1/MBU1 expiry boundary`](../../protocol/token-burn-expiry-v1.md) supplies
permanent evidence that the old epoch can never accept funding. Run
`treasury burn-expire-request <epoch>` to prepare the exact rent-only tag15
instruction for the separately held owner. It requires both pinned finalized
banks to prove canonical absence after the deadline; preparation does not
release members, sign, or broadcast. Execute it externally, then run
`treasury burn-reconcile <intent-id-hex>` to require the exact permanent pair
from both providers before atomically recording terminal `expired_unfunded`.
A terminal response contains the original attempted allocation as history and
has no funding instruction; it does not represent spent cash or burnt tokens.

Migration012 retains every old member row with a one-way release marker. Only
that intent's reservations are released; the underlying liabilities remain
pending for a new future epoch with a new immutable randomized schedule. An
old expiry retry cannot release a later reservation or discharge a funded
liability. Canonical absence alone, elapsed time, provider disagreement, missing
data and ambiguous outcomes never authorize release. Both original funding
tags reject the permanent tombstone even after a clock rollback. Existing
funded or closed epochs cannot be expired, and existing funded records retain
their previous bytes and semantics.

## Required local evidence

Run `scripts/prove-credit-revenue.sh` with the selected compiler, host archives,
qualified token/judge/rewards ELF fixtures and DEX fixtures. It freezes source
bodies and artifact hashes before execution and rejects any change during the
gate. The proof includes all isolated issuer PostgreSQL tests; pre-migration
legacy receipt preservation through migrations 010/011; integer reference and
funding-ID regressions; pinned-RPC rejection cases; both policy versions funding
actual rewards SBF exactly once; and the actual issuer CLI's immutable request
executed by the external test owner through all 24 local Jupiter/Raydium/SPL
burn chunks. Loopback RPC views mirror one disposable bank; they do not establish
independent production operators, live finality, liquidity or a live price feed.
SOL/BTC conversion, continuous keeper operation and the live four-week Phase5
exit remain separate gates.

Run `scripts/prove-token-expiry.sh` for the separately frozen expiry gate. It
rebuilds the token SBF program, runs its complete compatibility suite, replays
Mesh writer objects through actual SBF, exercises strict finalized RPC rejection
cases, checks legacy receipts through migration012 and all isolated issuer
PostgreSQL tests, and drives the actual CLI through absence, ambiguous reads,
external local expiry, restart, concurrent release/reallocation and a later
120,000,000-base-unit USDC funding with24 actual router/DEX/SPL burn chunks.
The prior42-check revenue checkpoint remains a separate immutable record.

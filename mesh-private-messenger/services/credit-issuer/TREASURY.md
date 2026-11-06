# Issuer treasury boundary

Treasury policy and persistence live in Mesh. Service treasury defaults disabled;
explicit privileged configuration supplies provider pins and sealed operational
signers before the service worker starts. See
[`OPERATIONS.md`](../../ops/credit-treasury/OPERATIONS.md) for that integration.
Never send a seed, arbitrary message, payment Boolean or refund recipient through
the buyer API.

Apply all issuer migrations in order, including003 and004. New issuance commits a
single original-asset revenue event atomically with its blind signatures; failure
to write that event rolls the entire issuance back. Historical issued rows can be
backfilled only through `record_issued_credit_revenue`, which reads their stored
quote/payment. Rejected underpayments are separate observations and never sales.

`Runtime.Treasury.TreasuryWorkerConfig` contains two distinct pinned providers,
`test_mode`, and `Payment.Treasury.TreasuryChainConfig`. The latter pins the
cluster genesis hash, ordered provider-set hash, mint, treasury owner, fee payer,
nonce authority/account and rewards program/pool. Providers require HTTPS;
explicit test mode additionally permits loopback HTTP. Requests reject redirects,
bind RPC IDs, limit bodies/time and verify the cluster. Provider quorum is a
trust boundary, not a light client or proof of operator independence.

`observe_treasury_deposit(pool, config, quote_id, signature, kind, now)` fetches
both finalized signed payment proofs itself. `kind:0` reserves an issued sale for
sweeping, while `kind:1` reserves a positive underpayment for refund. The latter
derives SOL payer or canonical payer USDC ATA from the original verified payment.
Every signature reserves exactly its observed amount once; balances, rent and
unsolicited donations never enlarge it. A sweep's 300–3600-second random delay is
persisted once. Quotes and payment allocations are locked before movements.

`run_treasury_movement(pool, config, id, borrow wrapping, service_key,
borrow fee_payer, borrow nonce_authority, now)` uses opaque privileged keys and
unseals only the selected quote's deposit key. It reconstructs the canonical
nonce-first SOL or USDC transfer, including idempotent ATA creation, reserves the
message, then commits the authenticated signed packet before network submission.
No database guard is held across RPC. Each invocation submits at most one packet
with bounded 3-second RPC calls and reconciles first. The separate batch API
combines up to four movements within the complete 1,232-byte signed packet bound.

Movement states are 0 reserved, 1 signed-unknown, 2 finalized-success,
3 finalized-failure and 4 blocked-history. A lost acknowledgment never clears the
packet or allocation. Missing history with a changed nonce enters 4, preserving
custody. A nonce change alone is not success: failed execution can consume it and
charge fees. Only an authenticated finalized failure permits explicit
`retry_failed_treasury_movement`; old packets/fees remain in the attempts table.
Stale outcomes cannot resolve a newer attempt. Customer amounts are never reduced
for fees or ATA rent, which are paid by the separate fee payer.

`freeze_treasury_week(conn, week, asset, mint, config_hash, now)` freezes a closed
UTC week from issued events whose exact sweeps finalized successfully. One
PostgreSQL statement snapshots all members, totals and their domain-separated
SHA256 commitment, then inserts membership. Concurrent retries return the same
batch. Only sweeps with its exact config hash are eligible; config/mint changes
cannot inherit fractional carry without an explicit accounting migration. Later
finalized sweeps are adjustments in a later batch. Exact numeric
20/80 allocation carries fractional fifths independently per asset. SOL witness
units remain conversion-pending; they are never reported as USDC funding.

`Runtime.TreasuryFunding.prepare_weekly_treasury_funding(pool, config, batch_id)`
returns a stable pending/funded intent for USDC. Pass a pending intent with the
pinned `RewardWriteContext` and fee payer to
`Storage.TreasuryFunding.treasury_funding_request` to obtain the existing
`ops/rewards` fund request. It always uses idempotent tag 12, revenue kind 0, the
fixed witness amount and operation ID. `reconcile_weekly_treasury_funding`
authenticates the permanent receipt and Clock together from each finalized
provider before discharging the liability. Signature acknowledgment is not
funding. Wrong owner, pool, mint, funder, source, epoch, operation or amount fails.

An old pending intent can expire only when both providers show its permanent
receipt absent alongside a later chain epoch. The program cannot then create an
old-epoch receipt. A linked new-epoch child retains exactly the same weekly
liability; a funded intent always replays unchanged after rollover. Floor subsidy
kind 1 and SOL conversion are excluded. Provider history uncertainty remains
fail-closed.

Run `scripts/prove-credit-treasury.sh` with the built public compiler and fresh
judge/rewards SBF artifacts. It uses owned temporary PostgreSQL, actual local
Agave System execution, actual SPL/ATA and rewards SBF, public compiled Mesh,
independent OpenSSL/SDK signatures and process restarts. It moves no live funds.
The separate Agave oracle dependency audit has documented legacy advisories;
it is isolated test tooling and does not enter issuer or public runtime builds.
See `tools/solana-nonce-proof/README.md` for that boundary and
`ops/credit-treasury/DESIGN.md` for the accounting/custody design.

## Immutable payment batches

`Runtime.TreasuryBatch.prepare_treasury_batch(pool, config, movement_ids, now)`
canonically sorts one to four unique movement IDs, locks them in that order, and
reserves the complete membership commitment and nonce-first message atomically.
Members must share config, asset, mint and sweep/refund kind. No source may alias
another destination. Duplicate destinations share one idempotent ATA instruction.
A packet that exceeds1,232 bytes fails before assigning any members. Select a
smaller group explicitly; never remove a member from an existing batch.

`run_treasury_batch(pool, config, batch_id, borrow wrapping, service_key,
borrow fee_payer, borrow nonce_authority, now)` unseals each deposit key outside
DB transactions, signs exactly the reserved message, commits one authenticated
packet/signature for every member, reconciles first and submits at most once per
invocation. Single-movement APIs reject assigned members. Single payments and
batches share a durable nonce fence, including blocked-history state.

`reconcile_treasury_batch(pool, config, batch_id)` only reads finalized history.
All members receive the same finalized success or failure. Aggregate lamport and
SPL deltas, exact ATA CPI groups, owner/mint/program metadata and the complete
committed packet are checked. Successful members retain their full payment
amount; the separate payer covers fees and ATA rent. Fee allocation is equal by
canonical member order, with each remainder base unit assigned to the first
members. Rent belongs once to the first member using the created ATA. Per-attempt
cost rows conserve both totals and survive retries.

Only explicit `retry_treasury_batch(pool, config, batch_id)` after finalized
failure reserves a new authenticated nonce/message. Membership stays unchanged,
old signed packets and costs stay permanent, and a previously attempted nonce
cannot be reused. Missing history never authorizes this reset.


Versioned post-token accounting and external burn handoffs are described in
[REVENUE_POLICY.md](REVENUE_POLICY.md). Policy 1 remains the default and preserves
historical 20/80 receipts. Explicit policy 2 accounts for exact 20/30/50 shares
and a bounded dust reserve in each original asset; USDC burn requests remain
external-owner instructions with authenticated finalized reconciliation.

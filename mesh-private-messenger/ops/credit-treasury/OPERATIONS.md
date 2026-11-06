# Treasury service operations

The production issuer contains the Mesh treasury worker and operator commands.
`MORSE_TREASURY_MODE=off` is the default. Enabling settlement does not enable new
credit purchases: `MORSE_CREDITS_MODE` remains independent. No command below has
been run against live funds as part of local qualification.

Apply issuer migrations in lexical order through `006_treasury_queue.sql` to
the issuer's separate PostgreSQL database. Preserve the existing protected
`MESSENGER_CREDIT_STORAGE_DIR` across upgrades and database restores. It wraps
issuer, quote-deposit and operational signing keys. Do not copy an older storage
key/counter over that directory or export private seeds.

The issuer executable accepts these commands with its normal protected service
environment. Commands do not start the HTTP service or its background workers:

```sh
credit-issuer treasury provision
credit-issuer treasury status
credit-issuer treasury run-once
credit-issuer treasury refund QUOTE_ID_HEX PAYMENT_SIGNATURE_BASE58
credit-issuer treasury weekly CLOSED_UNIX_WEEK usdc
credit-issuer treasury weekly CLOSED_UNIX_WEEK sol
credit-issuer treasury funding-request WEEKLY_BATCH_ID
credit-issuer treasury funding-reconcile INTENT_ID_HEX
credit-issuer treasury retry-batch BATCH_ID_HEX
credit-issuer treasury retry-movement LEGACY_MOVEMENT_ID_HEX
```

Run `provision` while treasury mode is off. It generates a fee payer and a
separate nonce authority inside the opaque Mesh signing runtime. Both wrapped
keys commit in one database transaction. Concurrent or repeated commands return
the same two public addresses. Damaged, missing-half or substituted records
fail; this command never rotates an existing identity. Public addresses are the
only output. Restrict command and database access to treasury operators.

Configure these public pins before enabling the worker:

| Environment variable | Meaning |
|---|---|
| `MORSE_TREASURY_MODE` | `off`, `test` or `live`; active mode must match `MESSENGER_CREDITS_PURPOSE` |
| `MESSENGER_TREASURY_GENESIS` | Base58 Solana cluster genesis hash |
| `MESSENGER_TREASURY_RPC_A`, `MESSENGER_TREASURY_RPC_B` | Two distinct HTTPS origins; test mode alone permits loopback HTTP |
| `MESSENGER_TREASURY_OWNER` | Separately held treasury owner that receives sweeps and authorizes rewards funding |
| `MESSENGER_TREASURY_FEE_PAYER` | Fee-payer public address returned by `provision` |
| `MESSENGER_TREASURY_NONCE_AUTHORITY` | Nonce-authority public address returned by `provision` |
| `MESSENGER_TREASURY_NONCE_ACCOUNT` | Initialized durable nonce account assigned to that authority |
| `MESSENGER_TREASURY_REWARDS_PROGRAM`, `MESSENGER_TREASURY_REWARDS_POOL` | Rewards program and its derived `pool` account |

The mint is the existing `MESSENGER_CREDIT_USDC_MINT`; there is no second mutable
mint setting. Fund the separate fee payer with SOL and provision the nonce
account through the chain operator's reviewed account-creation procedure before
enabling settlement. The worker never creates a replacement nonce or discovers
providers from an HTTP response. Startup checks both opaque signing keys against
the configured public pins before serving HTTP. Chain reads additionally check
the genesis hash, nonce owner/authority and provider agreement. Different origins
are a configuration check; operators still have to establish provider independence.

Without command arguments, the service runs a bounded cycle every 30 seconds.
It recovers signed batches and legacy singles, claims at most eight new issued
deposits, and prepares one ready group of at most four compatible payments. An
unavailable observation is deferred for 60 seconds so later deposits can proceed.
Initial sweeps retain their durable random delay of 300–3600 seconds. A group
that exceeds Solana's packet limit is reduced only before reservation. After
reservation its members and signed packet are immutable. Multiple service
processes share the same database membership and nonce fences.

`refund` takes only an existing quote ID and its payment signature. Two pinned
providers must authenticate a positive underpayment. The worker derives the
original payer and canonical destination itself; operators cannot supply a new
recipient or amount. Fees and token-account rent are paid separately. A request
reserves the refund; the next worker cycle performs it. A receipt or status
displayed as pending is not evidence of payment.

Movement states are `0` reserved, `1` signed with outcome unknown, `2` finalized
success, `3` finalized failure, and `4` missing history after nonce change.
`status` reports exact counts as strings. Only state 3 permits an explicit retry
command, which reads a fresh agreed nonce and retains the previous attempt and
costs. State 4 requires recovery of authoritative transaction history; the nonce
changing or an RPC returning null never authorizes a new payment.

The worker freezes the previous closed Unix week independently for USDC and SOL
and reconciles up to eight pending USDC funding liabilities. A Unix week here
is `floor(unix_seconds / 604800)`. Closed snapshots include only finalized
successful sweeps; later sweeps enter a subsequent week. The exact pre-token
split is 20% witness pool and 80% operations, carrying fractional fifths.
Config changes cannot silently move a previous treasury's revenue or remainder.
SOL liabilities remain in SOL until the separately reviewed conversion workflow
is implemented; this service does not describe them as funded USDC.

`funding-request` returns the existing rewards operator's idempotent revenue
request, with its permanent operation ID and exact amount. It requires the
issuer's release-pinned judge/log configuration. The separately held treasury
owner is both payer and funder for this request; the issuer never exports its
fee or nonce key. Execute that request through the reviewed
[`ops/rewards` workflow](../rewards/README.md), then use `funding-reconcile` or
the background cycle to authenticate the permanent on-chain receipt. An RPC
acknowledgment alone does not discharge the liability. An expired unexecuted
funding epoch is replaced only after both providers prove the permanent receipt
absent together with a later chain epoch. Actual funding remains pending until
the treasury owner executes the request.

Run `scripts/prove-credit-treasury.sh` for the local ledger, actual Solana/SPL/SBF
and recovery proofs. The production service/process proof is selected with
`TREASURY_PROOF_CASE=service python3 scripts/prove-credit-treasury.py`; it owns
temporary PostgreSQL, a disposable key directory and loopback HTTP endpoints.
These local checks do not constitute deployment, external review or live
purchase/treasury acceptance.

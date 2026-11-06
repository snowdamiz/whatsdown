# Rewards operator

This page describes v1. The [explicit v2 settlement and claim path](README-v2.md)
uses a versioned Mesh executable with the same durable journal and writer.

The local Mesh planner authenticates finalized rewards, attendance and funding
receipt accounts with two matching independent providers. It prepares one
operation at a time. The Node boundary signs with `@solana/kit`, persists the
exact packet in SQLite before sending, and reconciles finality or an expiry
barrier before preparing another packet. The request never grants phone trust.

Implemented requests are `fund`, `settle` and `claim`. Settlement opens missing
ledgers, opens and seals empty attendance weeks, begins a draft, appends at most
four canonical witness rows per packet, finalizes, and cancels stale or expired
drafts. It waits for closed weeks, cosign windows, prior epochs, Economics and
floor funding. A claim uses its finalized payout row and creates that owner's
canonical token account if necessary. All economic selection stays in Mesh.

Funding requires a stable, nonzero random 32-byte operation ID. The program
stores a permanent receipt binding the funder, source ATA, pool, mint, epoch,
kind and exact amount. Retrying that same intent cannot transfer twice, even
after the week has ended. Reuse the request and journal after an interruption;
creating a different operation ID authorizes another deposit. Legacy tag 2
funding is never emitted by this operator.

Build and qualify locally:

```sh
bash scripts/prove-rewards.sh
bash scripts/prove-rewards-operator.sh
```

Set `MESHC` and `CARGO_BUILD_SBF` to the intended public Mesh compiler and pinned
SBF builder when they are outside PATH. The proof builds the production planner
and a separate test-only loopback fixture, then executes actual programs and
token transfers in LiteSVM. Both binaries are placed in `.morse/witness-proof`
at the repository root. The test binary must never be installed as the operator.

An operator configuration uses absolute local paths:

```json
{
  "binary": "/opt/morse/rewards-operator",
  "securityConfigPath": "/etc/morse/client.security",
  "logVersion": 2,
  "requestPath": "/etc/morse/rewards-request.json",
  "walletPaths": ["/run/secrets/payer.json", "/run/secrets/funder.json"],
  "journalPath": "/var/lib/morse/rewards/intent.sqlite",
  "pins": {"program":"REWARDS_PROGRAM","judge":"JUDGE_PROGRAM","log":"LOG_PDA","mint":"MINT","payer":"FEE_PAYER"},
  "rpc": {"urls":["https://provider-one.example","https://provider-two.example","https://provider-three.example"],"genesisHash":"CLUSTER_GENESIS_HASH"},
  "policy": {"maxLamports":"100000000","maxTransactions":128}
}
```

Addresses and URLs above are placeholders, not deployment recommendations.
The native security frame pins the service, judge, log and reader providers;
the operator additionally pins the rewards program, mint, payer and cluster.
Wallet files use Solana's 64-byte JSON key format and must have mode 0600.
The funder may equal the payer; each required signer is supplied only once.
Recovery of an already signed packet needs no wallet files. The planner process
never receives wallet keys or inherited credential environment variables.

Example request shapes (amounts and epochs are canonical decimal strings):

```json
{"action":"fund","program":"REWARDS_PROGRAM","mint":"MINT","log":"morse-main","payer":"FEE_PAYER","epoch":"2813","funder":"FUNDER","kind":1,"amount":"300000000","operation_id":"NONZERO_64_LOWERCASE_HEX_CHARACTERS"}
```

`kind: 0` funds this week's revenue; `kind: 1` funds the separately accounted
floor reserve. To settle, use the common fields and `action: "settle"`. To claim,
use `action: "claim"` and a zero-based integer `row` in 0–63. These requests do
not initialize the pool, admit members or change governance.

```sh
npm ci --prefix ops/rewards --ignore-scripts
node ops/rewards/cli.mjs --config /etc/morse/rewards-operator.json --watch
```

Without `--watch`, one cycle runs and exits. With it, the operator checks every
five seconds until this explicit intent completes. It does not silently advance
to another epoch or deposit. A concurrent process is fenced by a renewable
30-second lease. One journal is bound permanently to one request, pin set and
spending cap. Preserve its SQLite database, WAL and SHM together. Unknown costs
after pruned transaction history consume the full reservation; an absent
effect is not proof of zero fees: even after expiry with history available,
missing finalized debit metadata consumes the full reservation. Unresolved
packets retain their exact bytes. Unexpected overspending halts the journal.

This is local qualification. Independent operators, actual mint/program
deployment, reviewed upgrade/multisig custody, publishing the exact Mesh build,
live funding and production canary gates remain separate work.

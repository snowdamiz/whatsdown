# Explicit BTC witness-output funding handoff

This command prepares or reconciles one finalized bucket-0 BTC conversion output
for the existing rewards `fund_once` instruction. It writes accounting state and
prints a bounded `TreasuryFundingIntent`; it never signs or submits a transaction.
There is no timer, scheduler, settlement, member claim, or unattended operation.

Build this package with the reviewed Mesh compiler. The command reuses the issuer's
existing server, BTC conversion and treasury configuration. BTC conversion and
ordinary treasury pins must be enabled and consistent; no addresses are supplied
on the command line. `prepare` takes the conversion ID; `status` and `reconcile`
take the returned funding ID, all canonical lowercase 32-byte hex.

```
meshc build ops/btc-witness-funding -o /private/review/btc-witness-funding
/private/review/btc-witness-funding prepare CONVERSION_ID
/private/review/btc-witness-funding status FUNDING_ID
/private/review/btc-witness-funding reconcile FUNDING_ID
```

The JSON `state` is 0 pending, 1 funded, or 2 expired. A pending intent is an
accounting handoff, not evidence of an onchain effect. The existing BTC conversion
status remains unchanged; the bridge intent and permanent receipt are a separate
explicit reporting surface. A separate explicitly
invoked transaction path may use `Storage.BtcConversionFunding.btc_witness_funding_instruction`
with an authenticated `RewardWriteContext`; the typed builder reuses
`treasury_funding_instruction`. The fee payer remains distinct from the treasury
owner. The owner must authorize the eventual token transfer. This package
includes no signer, wallet import, RPC submission, or transaction retry worker.

## Binding and recovery

Migration 015 follows the already-qualified migration 014. Only a stored arrived
bucket-0 output is eligible. Every read checks its immutable 340-byte MCB2 receipt,
conversion/profile/order identity, exact positive output amount, treasury config
hash, classic mint, owner and canonical owner ATA. The configured rewards pool
must be the canonical pool PDA for the pinned rewards program. The original
Lightning msat allocation and BTC/provider/subunit residual accounting are
unchanged; source msat are never treated as USDC units.

The permanent output-use reservation is
`SHA256("morse-btc-witness-output-use-v1" || conversion_id || SHA256(MCB2) || treasury_config_hash)`.
Its migration-014 bucket is 0, and it can never be released or reassigned.
Each funding attempt is separately
`SHA256("morse-btc-witness-funding-v1" || conversion_id || reservation_id || SHA256(MCB2) || epoch_u64_LE || program || pool)`.
A partial unique index permits one pending/funded attempt per conversion; a
transaction advisory lock serializes preparation and reconciliation across
processes. Exact retries return the existing attempt. Original attempt identity,
expired attempts and funded permanent receipts are immutable.

`Runtime.BtcConversionFunding` obtains `TreasuryFundingProof` from the existing
`read_treasury_funding` implementation: the configured cluster, program-derived
receipt address, owner/layout, same-bank Clock slot, receipt time, and exact receipt
bytes must agree across the two pinned sources. This is the existing
**program-identity/two-source trust surface**. It does **not** authenticate the
current Pool configuration or executable release, establish provider independence,
or add a new release policy. Its controlled local proof is not evidence of public
RPC finality, a live exchange account, real USDC or mainnet liquidity.

Only authenticated permanent-receipt absence together with an advanced chain
epoch expires an unfunded attempt. The onchain program then refuses that old
absent-receipt packet. A new attempt uses the advanced epoch and the **same**
permanent output reservation. HTTP acknowledgments, arbitrary timeouts, nonce
changes and caller-provided epoch numbers cannot expire runtime attempts. A
funded attempt cannot expire, reopen, or create another attempt; exact permanent
receipt replay remains valid after epoch rollover. The borrowed-PgConn storage
functions require their caller's `Repo.transaction`; production runtime and CLI
always provide it. Raw `TreasuryFundingProof` structs are an internal verified
reader boundary, not a public HTTP admission API.

## Owned regression qualification

`tests/qualify.py` creates a new isolated work directory and PostgreSQL cluster,
verifies the exact compiler/runtime/ELF pins, freezes copied source bodies, and
tears down only its owned services. It never opens PostgreSQL 55438 or the BTC
adapter's historical 61546. It does not reset a pre-existing database.

```
PATH=/opt/homebrew/opt/rustup/bin:$PATH python3 ops/btc-witness-funding/tests/qualify.py \
  --work /private/review/new-btc-witness-proof \
  --product /absolute/path/mesh-private-messenger \
  --mesh-lang /absolute/path/mesh-lang \
  --toolchain-profile http10-fixed \
  --toolchain /absolute/path/http10-response-persistence-host-scoped/toolchain \
  --rewards-elf /absolute/path/rewards_elf \
  --rewards-sha d4521ada26a87b5fdf7cbdda94cc39897c12a21381bbd98c4746ee7cca1c8714 \
  --token-elf /absolute/path/spl_token-3.5.0.so \
  --lightning-tools /absolute/path/lightning-tools
```

Current qualification explicitly selects `http10-fixed`. The default
`legacy-hmac` profile remains available for historical reproduction only. Both
profiles require their exact compiler/runtime triple; mixed or unknown bundles
are rejected before the work directory or owned services are created. Cargo
builds use one job and the new work directory's `sbf/target`, regardless of an
inherited `CARGO_TARGET_DIR`.

The local environment/profile regression starts no services:

```
BTC_TEST_LEGACY_TOOLCHAIN=/absolute/path/hmac-sha512-tag-host/toolchain \
BTC_TEST_HTTP10_TOOLCHAIN=/absolute/path/http10-response-persistence-host-scoped/toolchain \
python3 ops/btc-witness-funding/tests/test_fixture_environment.py
```

Requirements: PostgreSQL 17, Rust, pinned LiteSVM dependency lock, and the owned
Bitcoin31.1/LND0.21.4-beta regtest tools already used by the BTC conversion proof.
Run `python3 tests/test_handoff.py` for the deterministic atomic command-file
regression without any service. No external provider credentials are accepted by the harness. The Kraken
fixture checks authenticated request bytes against its own test key; LND uses
owned regtest nodes. The fresh Rust bank retains private test keys, exports its
complete treasury identity before conversion reservation, and executes a genuine
classic SPL transfer before Mesh admits its **new** MCB2 receipt. The historical
arrived checkpoint is used only for storage/rollback/race/restart tests because
its treasury owner key is unavailable. Account bytes and historical signatures
are never relabeled or spliced into the fresh bank.

The proof checks missing-migration transaction rollback, concurrent process
reservation, immutable original accounting, forbidden output release, stale
attempt expiry, and pending/funded restart recovery. Each exact Mesh instruction
is compared against independently constructed SDK metas/data, signed only by
Rust-owned test keys, and executed by the pinned existing SBF rewards program:
old absent-receipt epoch refusal, one exact transfer, duplicate no-op and
post-rollover permanent-receipt no-op. Fourteen malformed, mismatched or
disagreed RPC/receipt mutations must refuse without marking the attempt funded.
Repeated qualification runs are replays of the same scenario, not additional
independent financial evidence.

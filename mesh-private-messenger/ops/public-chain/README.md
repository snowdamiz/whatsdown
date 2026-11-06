# Public chain reporting

This directory implements read-only reports for explicitly selected burn weeks,
v2 collateral witnesses and v2 slash proof identifiers.
`main.mpl` calls the existing `TokenBurnCarryRead` finalized reader for each of
three configured origins. Mesh validates all12 expected account roles, PDA
addresses, owners, lengths, code slot, mint, vault custody, principal liabilities
and close-receipt/frame linkage. Mesh compares validated digests and computes
the report’s exact decimal-string units and chunk states. There is no signer,
transaction builder, funding, submission, scheduler or deployment path here.

`export.mjs` is a host shell. It validates configuration size and three distinct
origins, supplies the wall-clock retrieval time, invokes the compiled Mesh
binary, and writes a new JSON or JavaScript artifact. Output paths must not
already exist. Endpoint URLs and credentials are never included in the report.
Both the native reader and snapshot producer require distinct canonical origins;
this does not establish independent providers.
At most16 explicit epochs and three5-second requests per epoch are accepted.
Optional collateral adds two independent three-request sections. Each request
is bounded to100 accounts, an8,416-byte slice per account and a512KiB response.
The maximum bond selection is98 accounts; the receipt selection is30 accounts.
No account discovery, complete weekly index, or common bank across epochs is
implied. A report’s maximum age is an explicit operator input, capped at24hours.

## Local qualification

From the product directory, with a locally available Mesh compiler:

```sh
node --test ops/public-chain/export.test.mjs ops/public-chain/collateral.test.mjs
MORSE_PUBLIC_COLLATERAL_FIXTURES_PATH="$PWD/ops/public-chain/fixtures/token-custody-snapshots.json" "$MESHC" test ops/public-chain/tests/collateral_receipt.test.mpl
"$MESHC" fmt --check ops/public-chain
"$MESHC" lint ops/public-chain
node --test apps/landing/network-report.test.mjs apps/landing/network-report.browser.test.mjs
```

Set `PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH` when using an installed Chrome binary
instead of Playwright’s downloaded browser.

The integration test builds Mesh and serves the committed local SBF account
snapshots in `fixtures/token-carry-snapshots.json` through three owned loopback
HTTP servers. The three snapshots are exact subsets of the original SBF output;
their provenance and source digest are included. Every
request must be a bounded finalized `getMultipleAccounts`; any write method
fails the test. It exercises receipt-backed closure, scheduled/delayed/missed
chunks, donation surplus, two-source agreement, bad-receipt exclusion, valid
snapshot disagreement, outage and code-pin drift. Loopback origins prove the
agreement contract, not independent operators. `MESHC`, `MESH_RT_LIB_PATH` and
`MESH_TEST_RT_LIB_PATH` can select a previously qualified compiler/runtime;
`MORSE_TOKEN_CARRY_FIXTURES_PATH` can select another frozen SBF input. The default
test has no dependency on untracked workspace evidence. Replaying account
snapshots tests the reader; it does not rerun the on-chain program.

`fixtures/legacy-closed-report.json` is an actual output of that compiled read
path, retained for browser regression and clearly labeled `local-fixture`.
Its historical source clock and fixed test retrieval time are not current chain
observations. The browser test renders it at390px and1440px and verifies exact
units, fixture labeling, stale data, disagreement, unavailable data and invalid
payload handling. It never edits the landing page’s bootstrap asset.

## Explicit configured reads

Build a local binary, then use the wrapper:

```sh
"$MESHC" build ops/public-chain --output /tmp/morse-public-report
node ops/public-chain/export.mjs --input /absolute/read-config.json --binary /tmp/morse-public-report --output /absolute/new-report.json
```

The input shape is:

```json
{
  "schema_version": 1,
  "scope": "configured-rpc",
  "pins": {
    "program": "EXPLICIT_RELEASE_PROGRAM_KEY",
    "governance": "EXPLICIT_GOVERNANCE_KEY",
    "program_slot": "EXPLICIT_RELEASE_SLOT",
    "usdc": "EXPLICIT_USDC_MINT_KEY",
    "treasury": "EXPLICIT_TREASURY_KEY",
    "factory": "EXPLICIT_FACTORY_KEY"
  },
  "endpoints": ["https://FIRST_CONFIGURED_ORIGIN", "https://SECOND_CONFIGURED_ORIGIN", "https://THIRD_CONFIGURED_ORIGIN"],
  "epochs": ["EXPLICIT_EPOCH"],
  "minimum_context_slot": "EXPLICIT_FINALIZED_FLOOR",
  "max_age_seconds": "EXPLICIT_AGE_POLICY"
}
```

The placeholders deliberately fail validation. No release pins, service URLs,
freshness policy or independence qualification is inferred. All integer inputs
are canonical decimal strings. Configured mode requires HTTPS and three distinct
origins; `local-fixture` permits only owned `http://127.0.0.1:PORT` endpoints.
The program uses existing finalized account requests; it does not fetch or
trust a supplied JSON balance. Two matching valid digests expose a snapshot.
Two or more valid but unmatched digests yield `disagreed`; fewer than two valid
digests yield `unavailable`. Neither error produces zero balances. Code-slot
drift remains an explicit flag on decoded account values. The renderer raises a
page-level warning; this does not qualify the changed code or its behavior.

For a local page preview, write a new report with a`.js` output extension and
place it as `network-data.js` in a disposable copy of `apps/landing`. The browser
checks the retrieval time and each chain source time against the configured age
limit. Historical fixture scope always remains prominent. The renderer does no
monetary arithmetic and makes no third-party requests. Quotes and their source
time remain explicitly unavailable because this custody reader does not read an
authenticated oracle source. A close receipt is required for `closed` status.

## Still required for public operation

The checked-in public page defaults to `bootstrap`, with no live amounts.
Publishing is a separate operation. A reviewed public release-pin/source policy,
actual provider independence, a complete weekly discovery/index policy and the
chosen freshness policy are not supplied by this implementation.

The selected-record adapters do not provide global discovery or an exhaustive
slash history. The existing `AnchorCustody` and `SlashReceiptRead` legacy v1
paths are not used to reinterpret v2 records. A legacy MBD1 bond is unavailable
to this adapter. Empty selections mean no identifiers were selected, not that
no other bonds or slashes exist.

`phase5_complete` remains false. Local SBF executions and a report renderer do
not satisfy the plan’s first four actual executed and published weekly burns.

## Optional v2 collateral configuration

Keep the outer input and burn report schema at version1. Add this complete
`collateral` object to opt into the v2 adapters; omitting it preserves the
original burn-only behavior and unavailable collateral sections:

```json
{
  "schema_version": 2,
  "judge": "EXPLICIT_JUDGE_PROGRAM",
  "judge_slot": "EXPLICIT_JUDGE_RELEASE_SLOT",
  "rewards": "EXPLICIT_REWARDS_PROGRAM",
  "rewards_slot": "EXPLICIT_REWARDS_RELEASE_SLOT",
  "rewards_governance": "EXPLICIT_REWARDS_GOVERNANCE",
  "log_name": "explicit-log-name",
  "log_version": 1,
  "service_public_key": "EXPLICIT_64_LOWERCASE_HEX_SERVICE_KEY",
  "morse_mint": "EXPLICIT_CANONICAL_TOKEN_MINT",
  "network_started": "EXPLICIT_NETWORK_START_SECONDS",
  "witnesses": [{ "witness_id": "explicit-witness", "public_key": "EXPLICIT_64_LOWERCASE_HEX_KEY" }],
  "proofs": ["EXPLICIT_64_LOWERCASE_HEX_PROOF_HASH"]
}
```

These placeholders intentionally fail validation. Token program/governance/code
slot and USDC mint remain pinned by the outer `pins`. Judge, token and rewards
must be distinct; the MORSE mint must be the canonical token-program mint.
At most16 distinct witness-ID/key pairs and16 distinct proof hashes are
accepted. There is no endpoint, mint, identity, witness or proof discovery.
Three distinct origins still do not prove independent operators.

Each section obtains a separate finalized `getMultipleAccounts` batch. The
bond batch includes the canonical log, economics, token binding/config, both
mints, rewards pool identity, actual Clock, three executable/ProgramData pairs,
directory bond/pending/both ATAs, and witness record/bond/pending/both ATAs for
every selected witness. The proof batch has the same context roles plus the
selected canonical proof PDAs. Owners, full sizes, version/magic/padding,
canonical addresses, mint/owner/vault bindings, timestamp bounds, SPL token
state and available balance versus tracked liabilities are checked in Mesh.
Two origins must match the whole section digest, including its context slot,
ordered account keys, actual absence markers and account metadata/data. A
partial or malformed section exposes no amounts. Separate sections and burn
epochs need not share a bank; there is deliberately no combined total.

Output collateral sections use `schema_version:2`,
`selection_scope:"explicit-indexed-records-only"` and
`bank_scope:"this-section-only"`. Bonds expose selected-asset principal,
recorded pending amount, effective pending liability, vault balance and donation
surplus as separate exact U64 strings. A slash leaves a historical pending
record whose effective liability is zero. An absent opposite-asset ATA has a
null balance, while an observed empty ATA has a zero string. Opposite-asset funds
are never added to the bond balance. Selected principal cannot exceed the
corresponding onchain economics counter; this does not authenticate unselected
vaults or create a global custody total.

The report publishes recorded active/unbonding/slashed/withdrawn status and the
recorded underwater timestamp. It does not infer current USD collateral value,
oracle authenticity, grace eligibility or a deadline-based slash decision.
`pending_target_usd_micros` is a recorded accounting target, not a market quote.
Code-slot mismatches, including token/rewards binding slot drift, produce
`code_current:false`; ownership/PDA validation still applies, and the changed
code is not qualified by displaying its decoded state.

MPR2 receipt decoding mirrors the program's400-byte header and up to16
144-byte rows, including exact per-asset totals, per-subject floor10% finder
amounts, checked overflow and prepared/settled invariants. Prepared monetary
fields render null rather than a false zero loss. Settled slashes may include
pending funds and donations: `slashed - principal` is not labeled pending.
Historical receipts are not compared to today's bond amounts. The reader
checks canonical receipt and recorded witness addresses, but does not obtain
or independently reverify the underlying full fork proof or derive the stage
from the receipt hash. `proof_scope` makes this limit explicit.

`fixtures/token-custody-snapshots.json` preserves eight complete selected
snapshots from a fresh local SBF fixture-export test using previously pinned
SBF binaries, with actual same-bank Clock and both ATA observations (including
actual absences). Its source/manifest digests are in `provenance`. No accepted
account is fabricated or spliced between banks. `collateral.test.mjs` replays
these records through three owned HTTP origins, mutates only rejected inputs,
and verifies quorum, mixed assets, pending/grace/withdrawn/slashed state,
prepared receipts, malformed/partial accounts, code warnings and genuine
between-bank disagreement. `MORSE_PUBLIC_CHAIN_BIN` can select an already built
qualified reader. This is a reader replay, not a fresh execution of the token
program. `fixtures/mixed-collateral-report.json` is actual Mesh output for the
renderer tests; it is never installed as the page's bootstrap data.

The browser is a snapshot renderer, not monetary or chain authority. It formats
validated decimal strings without summing assets, clears every amount on an
invalid report, and keeps stale/code-change/fixture warnings. The checked-in
page continues to publish only unavailable bootstrap data. No public provider,
fund, deployment, complete-history or Phase5 completion claim is made.

## Bounded minute publication

The same reader now supports an internal authenticated `--serve` transport for
a default-off minute producer. It retains atomic last-good bytes, fresh failure
status and bounded settled observations without adding signing authority.
See [SNAPSHOT.md](SNAPSHOT.md) for exact build/policy associations, bounds,
crash recovery, source-clock checks, page wiring and owned local qualification.

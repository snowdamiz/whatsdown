# Explicit v2 rewards execution

`tools/rewards-v2-operator` is the native Mesh planner used by the existing
`ops/rewards/cli.mjs`, SQLite journal, Kit signer and finalized quorum writer.
Each journal owns **one explicit epoch settlement or one fixed earned claim**.
It does not choose epochs, schedule several epochs, assess grace or fund pools.
Eligibility, stage cancellation, floor/reserve policy and payout selection stay
in Mesh and the on-chain programs.

Build with the app-compatible compiler and its runtime:

```sh
MESH_RT_LIB_PATH=/absolute/libmesh_rt.a /absolute/meshc build \
  mesh-private-messenger/tools/rewards-v2-operator --opt-level 2 \
  --output /absolute/rewards-v2-operator
```

Use the existing CLI config documented in `README.md`. Set `binary` to this
executable and `securityConfigPath` to a local v2 JSON configuration. Its fields
are `schema_version: 2`, `program`, `judge`, `token`, `log_name`, `usdc_mint`,
`governance`, `token_governance`, `service_key` (32 lowercase hex bytes),
`log_version`, `network_started`, `token_slot`, `judge_slot`, `rewards_slot`,
`source_program`, `source`, `feed` (32 lowercase hex bytes), `source_revision`
and exactly three `endpoints`. U64 fields are canonical decimal strings.
`allow_loopback` defaults to false; true permits disposable loopback RPC banks.
Production reader endpoints must have distinct hostnames; different ports or
paths on one host cannot form a quorum. Distinct loopback ports are allowed
only for the explicit local bank mode.
Program slots, governance, source and service identities are operator pins,
not values learned from an unauthenticated response.

The CLI `pins` include the existing `program`, `judge`, `log` (derived account
address), `mint` (USDC), and `payer`, plus `version: 2`, `token` (program),
`morse` (mint), and `configuration_hash`. The hash is lowercase SHA-256 of the
UTF-8 security configuration after the CLI's `.trim()`. Changes to this
configuration require a new journal; they cannot silently reuse signed work.
The read endpoints should match the independently pinned writer `rpc.urls`.
The writer also authenticates the configured `rpc.genesisHash`.

A settle request has this shape (replace addresses and log name):

```json
{"schema_version":2,"action":"settle","program":"REWARDS_PROGRAM","mint":"USDC_MINT","log":"LOG_NAME","payer":"FEE_PAYER","epoch":"2828"}
```

A claim adds `"action":"claim","row":17,"asset":0` (USDC) or `asset:1`
(MORSE). Mesh selects the payout account from the immutable finalized row.
An already claimed or zero entitlement is complete without another packet.
There is no caller-supplied payout, instruction report or economic decision.

Run one cycle with `node cli.mjs --config /absolute/operator.json`; optional
`--watch` repeats this same explicit intent until complete or a failure/budget
boundary; a waiting result is rechecked on the next cycle. A cycle reconciles the existing packet before asking
Mesh for new work. Signed bytes are stored before broadcast and remain exact
across a restart or lost acknowledgment. After finalized expiry, Mesh rereads
authenticated effects. Absent effects with pruned transaction history retain
the packet and its reserved budget. When the transport permits replacement
after expiry, v2 still charges the full reserved maximum, including for an
absent effect. The oldest available block does not establish continuous history
or zero fees: a landed append can disappear after stage cancellation. Budget
charges are consequently conservative upper bounds until actual finalized
transaction metadata supplies the debit. Stage append evidence is bound to its snapshot,
revisions and witness identities; a different stage is not append evidence.

The v1 schema and instruction limits remain separate and unchanged. V2 admits
at most three attendance rows (31 account roles), one operation, optional
compute budget/ATA setup, a maximum 1232-byte packet and only the fee payer.
Settlement requires an activated, funded pool; this path does not activate,
configure or fund anything on the operator's behalf.

Run `scripts/prove-rewards-v2.sh` with `MESHC`, `MESH_RT_LIB_PATH`, an explicit
`MORSE_TOKEN_CUSTODY_FIXTURES_PATH`, and `CARGO_BUILD_SBF` pointing to the SBF
builder. Cargo and rustc must be on PATH. If using direct toolchain binaries
without rustup shims, also set `SBF_RUSTC` to platform-tools v1.57's rustc.
The script rebuilds all three SBF programs and runs the Rust, Kit, native Mesh,
CLI/journal and v1 compatibility checks.

Local qualification is described by that script and the
retained proof receipt. Loopback endpoints over one disposable bank exercise
real transport and signing; they do not prove provider independence, hosted
finality, deployment, live funding or continuous operation.

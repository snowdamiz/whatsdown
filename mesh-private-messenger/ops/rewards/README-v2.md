# V2 rewards execution and bounded settlement scheduling

`tools/rewards-v2-operator` is the native Mesh planner used by the existing
`ops/rewards/cli.mjs`, SQLite journal, Kit signer and finalized quorum writer.
Each journal owns **one explicit epoch settlement, one fixed earned claim, or
one bounded settlement range**. Mesh authenticates eligibility and completion
for each scheduled epoch. The keeper continuously checks grace before and
during collection. Pool funding remains explicit.
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
paths on one host cannot form a quorum. ASCII case and one trailing dot are
the same hostname. The writer uses that rule for `rpc.urls`. Distinct loopback
ports are allowed only for the explicit local bank mode.
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

A bounded schedule adds `"epoch_count":"2"` to a settle request. Its
`"epoch":"2828"` remains the first epoch. Count must be a
canonical decimal string from 1 through 256. The inclusive range must leave
room for the on-chain pool's `next_epoch`. Claims retain their explicit shape.
Schedules add no payout selection. Do not include a `cursor` in the configured
request: it is internal journal state.

A distinct journal scope binds the immutable range, configuration and budget.
Older journals cannot reinterpret a previously ignored count as a schedule. It
retains its finalized context floor, attempts, spent lamports, and one active
reservation across every epoch and restart. A completion report from the
pinned Mesh executable atomically records that epoch's report and advances
one epoch, or marks the bounded range complete. An epoch completed by another
keeper advances without a redundant transaction. Unknown outcomes always
reconcile against the original pending epoch before any new plan or cursor
transition. Do not use a separate journal per epoch to run a bounded schedule.

`advanced` means a completion report and the next cursor are durable, without
signing next-epoch work in that cycle. `waiting` retains that cursor and budget
for the next poll, including waits for week end, code pins, source pins, or
reserve policy. Expired or invalidated stages use the existing cancellation
and replanning path. Empty and all-excluded
epochs still finalize on chain and carry unallocated revenue forward. No
binding activation, deposit funding or governance operation is synthesized.
`epoch` and `scheduleComplete` in the CLI progress identify durable scheduling
state. Existing explicit journal scopes reopen without a scope or budget reset.
Changing an explicit request into a range requires a new scope.

Run one cycle with `node cli.mjs --config /absolute/operator.json`. Add
`--watch` to repeat the explicit intent or bounded schedule until completion,
failure, or budget exhaustion. The next cycle rechecks a waiting result.
Each cycle reconciles the existing packet before asking Mesh for new work. Signed bytes are stored before broadcast and remain exact
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

Before each settlement step, Mesh checks the directory and every witness in
that epoch's attendance set, including rows already appended. One identity read
and at most five groups of fourteen subjects cover the bounded set. Each group
contains at most 100 canonical account keys and requires two matching finalized
snapshots. A third provider is read only on disagreement. Each group retains the prior
group's finalized context floor. The shared collateral
decoder verifies ownership, exact roles, custody liabilities, executable slots,
source pins and the recorded lifetime target. Judge and token governance pins
are independent. Groups must agree with the settlement's economics revision and
pool cursor. A changed snapshot refuses that cycle and is read again next time.
The resulting context floor includes every group read, even when no packet is needed.

The journal stores a Mesh-selected assessment cursor and advances it only after
the current signed packet is terminal. The next scan starts after that subject
and wraps through the whole bounded set. An earlier subject that changes again
cannot repeatedly hide later subjects. The cursor is internal journal state,
separate from the epoch cursor and immutable request hash.

Mesh proposes Judge tag45 only when active MORSE principal first falls strictly
below 80% of its recorded target or recovers to at least 100%. Partial recovery
retains the original grace start. Without a usable authenticated TWAP, Mesh
prepares no grace mutation and the existing USDC settlement policy still applies.
Pending topups and donated balances do not
increase the assessed principal. A real transition updates the eligibility
revision. The next authenticated plan cancels the old collection and begins a
new snapshot. Repeated no-op checks fall through to settlement, and actual
no-op tag45 execution preserves the revision. Grace expiry uses the stage's
saved timestamp and price; crossing the deadline does not rewrite an existing
snapshot. Tag36 pending activation is never synthesized by this operator.

Assessment packets use the same journal, reservation, transaction count,
lamport cap, signer and restart path as settlement. The journal reconciles an
old assessment before any cancellation, replan or epoch advancement. After
expiry, effect evidence must match the selected subject's bond lifetime,
principal, mint, owner, recorded target and canonical instruction. An unrelated
revision increase cannot prove that assessment. Missing evidence with pruned
history retains the original packet; permitted expiry replacement charges its
full reserved maximum. Code or source drift pauses effect-based reconciliation.
Finalized transaction metadata can still reconcile the exact original packet.

`--watch` repeats these checks throughout the explicit intent or bounded range,
including waits for week end, cosign completion and reserve funding. Completion still stops the finite request.
Claims use immutable entitlements and do not depend on a maintenance scan.
This path monitors the current epoch's attendance set and directory, not every
registered witness in the network. It does not activate governance bindings,
apply pending collateral, fund pools or change payouts.

Local qualification is described by that script and the
retained proof receipt. Loopback endpoints over one disposable bank exercise
real transport and signing; they do not prove provider independence, hosted
finality, deployment, live funding or continuous operation.

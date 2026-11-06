# Mixed-asset relay reference

The schema 2 adapter uses `ops/collateral-v2/proof_read.mpl` and `proof_plan.mpl`
for authenticated account selection and the next operation. Node assembles the
Mesh instructions with Kit and persists each signed packet in `RelayJournal`
before broadcast. It does not verify forks or calculate token payouts.

## Operator configuration

The relay configuration keeps the schema 1 fields and adds:

- `schema_version: 2`.
- `plannerConfigPath`: an absolute path to the operator-owned Mesh planner JSON.
- `pins.usdcMint` and `pins.morseMint`: distinct pinned token mints.

`pins.mint` remains the legacy USDC mint and must equal `pins.usdcMint`.
The planner JSON extends the collateral operator configuration with `submitter`,
`fee_payer`, `morse_mint`, and `witnesses`. Both payer fields must equal
`pins.submitter`. `judge`, `usdc_mint`, and `morse_mint` must match the relay pins.
The planner's three `endpoints` must match the writer RPC URLs.

The collateral configuration pins the judge, token and rewards programs, their
release slots, governance, log name, service key, network start, and oracle source
identity and revision. Mesh authenticates those pins against finalized accounts.
`witnesses` contains at most 16 pinned `{witness_id, public_key}` records, including
historical keys needed by the evidence. Relay responses never supply new pins.

`verifierBinary` points to the compiled `ops/relay-mpr2` executable. The wrapper
creates private, bounded files and runs:

```sh
relay-mpr2 --pins operator.json --input evidence.frk --request request.json
```

Requests select `admit`, `receipt`, `stage`, `effect`, `lookup`, or `lookup-close`
and carry a canonical decimal `min_context_slot`. The wrapper passes the Mesh
operation's opaque effect token unchanged when reconciling an older packet.

## Journal upgrade and execution

Stop the legacy worker before reopening its database with the mixed-asset pins.
Keep the security frame, cluster, provider set, wallet, policy, and journal path.
The upgrade adds the asset pins to the existing scope. An active legacy lease
refuses the upgrade. It retains old jobs, charges, signed bytes, and the single
global pending packet fence.

The scheduler reconciles that packet before adopting a replacement plan. Missing
acknowledgments retain the packet. Pruned history requires the finalized expiry
barrier and a Mesh-authenticated effect, with the reservation charged
conservatively. A prepared receipt does not authorize cleanup or suppress the
settlement packet.

The Mesh planner stages the evidence, verifies its signatures, prepares the
permanent receipt with tags 41 through 43, creates payout accounts for both
assets, and settles with tag 44. Packet admission checks the tag 44 account shape:
13 fixed accounts and three accounts per witness. Wide packets use the stable
Mesh-selected lookup table and wait for authenticated activation. Old tables
must retire before an incompatible replacement can claim their resources.

## Authenticated receipt contract

`ops/relay-mpr2/receipt.mpl` exposes `read_receipt`, `receipt_keys`,
`decode_receipt_snapshot`, and `receipt_report`. `RelayReceiptState.status` is
`missing`, `prepared`, or `settled`. Authentication binds the pinned judge's
program data, immutable log identity, proof PDA, allocation, owner, receipt bytes,
and agreed finalized context. It does not depend on a current bond, registry
entry, oracle source, or collectible lifetime.

MPR2 receipt reports have `schema_version: 2`, `format: "MPR2"`, the authenticated
finder, both mints, checkpoint and stage identities, preparation and settlement
times, and separate slashed and finder amounts for USDC and MORSE. Amounts and
chain coordinates are decimal strings. `prepared` amounts are not payments.
MPR1 receipts retain the existing schema 1 report and settled meaning.

A settled admission envelope keeps `receipt` as the PDA address and places the
immutable payout report in `settled_receipt`. The receipt read method instead
returns `{status, address, proof_hash, context_slot, receipt}`. Another finder's
authenticated receipt wins without replacing the originally requested finder.
HTTP admission status is not payment evidence. Phone callers must read the
pinned chain receipt and compare the actual finder.

Only an authenticated settled receipt permits stage closure. The journal keeps
cleanup obligations until stage and any lookup table are closed. Permanent paid
receipts remain readable after later unbonding and source rotation.

## Local proof and remaining gates

Run `bash mesh-private-messenger/scripts/prove-mpr2-relay.sh` from the repository
root. The script records compiler, runtime, retained deployed-program source,
fixture, fresh packet, receipt, and balance evidence under
`.morse/mpr2-relay-proof`. `MORSE_MPR2_RUN_BASELINE=1` also reruns the old-reader
failure. Initialized collateral fixtures and retained SBF programs are reused;
relay packets are freshly signed and executed.

The three local origins share one disposable bank. This proof does not establish
independent provider agreement, validator finality, native phone adoption,
published Mesh or witness artifacts, funded deployment, governance activation,
or the four published weekly burns required by the Phase 5 exit.

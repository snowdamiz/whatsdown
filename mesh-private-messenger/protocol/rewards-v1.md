# Rewards v1: separate local Solana program

`morse-rewards` is an independently deployed Pinocchio program. Its only token
signer is its own `pool` PDA. It cannot sign for judge Bond PDAs and no rewards
instruction accepts a bond vault as a transfer source. All verification here is
local; no live program, mint, Squads deployment, or funded reward pool is claimed.

The pool pins one classic six-decimal SPL mint, the judge executable, exact Log
account/log ID, the AttendanceClock activation timestamp as network start, and
Morse's permanent witness record. There are no setters for these fields. A mint
having six decimals does not establish that it is USDC: deployment tooling and
users must separately pin the intended USDC mint.

Initialization authenticates the rewards program's canonical loader-v3
ProgramData, executable linkage, and actual upgrade-authority signature. A first
caller cannot take over the pool. Pre-funding a PDA with lamports cannot squat it.
The signer chooses the governance address, rather than an arbitrary subsequent
caller. Deployment must put the upgrade authority behind the reviewed timelock;
internal policy alone does not restrict the loader's upgrade instruction.

## Admission and entitlement

Every witness is excluded unless its canonical rewards Member record admits it.
Admission requires governance, a full fourteen-day delay, then permissionless
execution. Its execution timestamp must be at or before the rewarded epoch's
start. Status 2 is permanent exclusion and cannot later become admitted. The
immutable Morse witness pinned by initialization can never be admitted, including
through governance rotation. Other Morse-owned registrations must remain
excluded or be permanently excluded before outside recruitment.

These records enforce an explicit admission decision, not real-world identity.
Operator independence and the 3-of-5 Squads composition with at least two outside
Morse remain external qualifications. The program cannot prove those facts.
Governance may rotate its signer after fourteen days. It has no arbitrary token
withdrawal, recipient override, treasury drain, or bond authority instruction.

Rewards use complete sealed judge AttendanceEpochs starting at first_full_epoch.
The program checks canonical owners, all PDAs, Log hash/context, immutable mint,
clock activation, sorted row identities, Witness/Bond relationships and vault ATA
address. Every attendance row must be consumed in order, including excluded,
inactive, or Registered/unbonded witnesses. An absent Bond is accepted only at its
canonical PDA as an empty nonexecutable System account for a Registered witness
whose vault and unbond fields are zero. It earns zero. A payable witness must be
Active in both judge records, with nonzero principal, no unbond/slash timestamp,
no judge exclusion flag, admitted for the full week, and bonded at or before the
week's start.

For `n` posts and `s` signatures, the exact weight is
`clamp(20*s - 16*n, 0, 3*n)`. The factor is weight divided by `3*n`: zero through
80%, full from 95%. Zero-post weeks have no rows and no floor. The first twelve
original UTC monthly anniversaries each earn 300,000,000 units; short-month days
are clamped from the original start date. Weekly amounts are differences of the
cumulative entitlement, then factor-scaled, so they telescope without day drift.
First reserve all factor-scaled floors from that week's revenue plus prior carry.
Use the dedicated subsidy reserve only for a floor shortfall. Distribute remaining
revenue in exact proportion to weights, round each allocation down, and carry the
dust. Subsidy never becomes extra proportional revenue. If there is no eligible
weight, all revenue carries and no subsidy is consumed. An underfunded floor
fails atomically; explicit subsidy funding permits retry.
Unused subsidy stays in its reserve after the first-year floor expires. This
version has no subsidy withdrawal or conversion into revenue instruction.

## Funding, staging and claims

Funding is an actual SPL `TransferChecked` CPI. Every revenue deposit is assigned
to an open ledger for the chain's **current** seven-day Unix epoch. A keeper cannot
backdate revenue to an old settlement. Subsidy funding is separately classified
and never assigned as that ledger's revenue. Direct token donations increase the
actual balance but never the accounted amount, revenue, carry, subsidy, or claims.

Settlement proceeds sequentially. `begin` authenticates the sealed week and
Economics revision, pins the whole attendance-account SHA-256, and starts a fixed
one-hour stage deadline. `append` consumes one or more exact next rows. It stores
only canonical witness/payout/bond identities, factor and floor in account data.
Every append and finalize checks the same immutable attendance hash and custody
revision. Member/governance execution is frozen while a stage is active.

The judge increments Economics' eligibility revision on initial/rebond deposits,
first unbond transitions, withdrawal and witness slash. An Active top-up does not
change eligibility and does not increment it. If a relevant state transition
happens between stages, append/finalize fail and anyone can cancel the stage.
Anyone can also cancel after its fixed deadline; late append/finalize fail.
Cancellation preserves the deposited revenue, next epoch, reserve, carry, total
accounting and existing liabilities. It clears only unfinished staging state.
A new begin then reads the coherent current revision. The timeout prevents an
abandoned/underfunded stage from indefinitely freezing governance execution.

Finalize requires every row, fixes all amounts and payout wallets, reserves the
sum as outstanding liabilities, advances exactly one epoch, and releases staging.
Unclaimed liabilities are never available to later settlements. A claim pays only
the snapshot payout wallet's ATA for the immutable mint, using the pool PDA as
signer. Each row has one claim bit; replay is rejected with no second transfer.
Later unbond, slash, exclusion, or governance changes do not revoke an already
finalized earned allocation. There is no administrative claim redirection.

## Instruction wire contract

Integers are little-endian. Payload widths below exclude the instruction tag.
`S` is signer, `W` writable; other accounts are read-only. Judge accounts are
always read-only in rewards instructions. Classic Token and ATA IDs are exact.

| Tag | Payload | Accounts in order |
|---|---|---|
| 0 initialize | governance 32 bytes, network start i64, Morse witness 32 bytes | upgrade authority S, payer SW, Pool W, pool vault W, rewards executable, ProgramData, judge executable, Log, AttendanceClock, mint, Token, ATA, System |
| 1 open ledger | epoch u64 | payer SW, Pool, Epoch W, System |
| 2 legacy fund (unsafe to blindly retry) | kind u8 (0 revenue/1 subsidy), positive amount u64 | funder S, Pool W, current Epoch W, pool vault W, source W, mint, Token |
| 3 propose member | status u8 (0 excluded/1 admitted/2 permanent exclusion) | governance S, payer SW, Pool, Witness, Member W, System |
| 4 apply member | empty | Pool, Member W |
| 5 begin | empty | Pool W, Epoch W, Log, AttendanceClock, AttendanceEpoch, Economics |
| 6 append | empty | same six accounts as begin, then one or more ordered triples: Witness, Bond, Member |
| 7 finalize | empty | same six accounts as begin |
| 8 claim | row index u8 | Pool W, Epoch W, pool vault W, destination ATA W, mint, Token |
| 9 propose governance | next governance 32 bytes | current governance S, Pool W |
| 10 apply governance | empty | Pool W |
| 11 cancel stale/expired stage | empty | Pool W, Epoch W, Economics |
| 12 fund exactly once | kind u8 (0 revenue/1 subsidy), positive amount u64, nonzero operation ID 32 bytes | funder S, payer SW, Pool W, Epoch W, pool vault W, source W, mint, Token, FundingReceipt W, System |

Open ledgers can be created from next_epoch through the current chain epoch.
Opening an existing canonical ledger preserves its contents. Historical unfunded
weeks therefore still have a permissionless zero-revenue ledger for settlement.
Never skip an attendance row or a full epoch. One-row append transactions support
all 64 judge rows within the 1,232-byte packet limit; larger batches depend on
packet size. Two passes over account bytes avoid large arrays on the SBF stack.

## Account formats

All reserved bytes are zero. Amounts are u64 base units; weights are u128.

Pool: PDA `["pool"]`, 304 bytes.

| Offset | Field |
|---|---|
| 0 | `MRP\x01` |
| 4, 36, 68, 100, 132 | governance, judge program, Log address, log ID, mint (32 bytes each) |
| 164 | immutable network start, i64 |
| 172, 180 | first full epoch, next sequential epoch, u64 each |
| 188, 196, 204, 212 | subsidy reserve, revenue carry, outstanding liabilities, total accounted tokens, u64 each |
| 220 | active staged epoch plus one, or zero |
| 228, 260 | pending governance (32 bytes), ready-at i64 |
| 268 | permanently excluded Morse witness, 32 bytes |
| 300 | four reserved bytes |

Its vault is the ATA of this PDA and mint. Pool accounted tokens include all open
revenue ledgers, reserve, carry and outstanding claims; actual tokens must cover
that amount before any outgoing claim. Token donations are harmless surplus.

Member: PDA `["member", witness_address]`, 64 bytes.

| Offset | Field |
|---|---|
| 0 | `MRM\x01` |
| 4 | Witness address, 32 bytes |
| 36, 37 | current and pending status, u8 each |
| 38 | two reserved bytes |
| 40, 48 | pending ready-at, current effective-at, i64 each |
| 56 | eight reserved bytes |

Epoch: PDA `["epoch", epoch_u64_le]`, 8,416 bytes: 224-byte header followed by 64
rows of 128 bytes. Rent is paid by the permissionless creator; no close/refund
instruction is implemented because claims may remain outstanding.

| Header offset | Field |
|---|---|
| 0 | `MRE\x01` |
| 4 | Pool address, 32 bytes |
| 36, 44 | epoch number, explicitly funded revenue, u64 each |
| 52, 53, 54 | status (0 open/1 collecting/2 finalized), appended rows, expected rows, u8 each |
| 55 | one reserved byte |
| 56 | sealed AttendanceEpoch SHA-256, 32 bytes |
| 88 | post denominator, u64 |
| 96 | total eligible weight, u128 |
| 112, 120, 128 | required scaled floors, base floor, frozen revenue+carry, u64 each |
| 136, 144, 152 | subsidy consumed, allocated liabilities, resulting carry, u64 each |
| 160 | claimed-row bitmap, u64 |
| 168 | fixed stage start, i64 |
| 176 | judge eligibility revision, u64 |
| 184 | forty reserved bytes |

Each row stores Witness address at 0, immutable registered payout wallet at 32,
canonical Bond address at 64, weight u128 at 96, scaled floor u64 at 112 and final
amount u64 at 120. Unused rows and unfinished amounts remain zero.

`Transparency.RewardsChain` derives these PDAs and decodes Pool, Member and Epoch
records in Mesh. It preserves full unsigned amounts/weights and checks padding,
stage state, ordered rows, claim bits and conservation. These are raw codecs:
callers still authenticate owners, the pinned program/mint/log, requested account
addresses, finalized context and provider agreement. No production rewards RPC
reader or keeper is implied by successfully decoding bytes.

## Local proof

Run `scripts/prove-rewards.sh` with `CARGO_BUILD_SBF` pointing to cargo-build-sbf
4.4.0 and host Cargo on PATH. It performs format/clippy checks, a fresh v0 SBF
build with stack diagnostics treated as errors, arithmetic tests, and real LiteSVM
SBF/SPL tests. Evidence is written under `.morse/witness-proof` in the repository
root by default: `rewards-program.log` and `rewards-program-fixtures.json`.
`MORSE_REWARDS_PROOF_DIR` or `MORSE_REWARDS_FIXTURES_PATH` override destinations.
The fixtures include finalized/unclaimed and claimed canonical account snapshots
for independent Mesh codec replay. Run the judge proof as well after changes to
its eligibility revision. External review, real mint selection, upgrade/timelock
custody, and live economic funding remain deployment gates.

The independent replay requires the generated fixture; it never skips for a
missing environment variable:

```sh
MORSE_REWARDS_FIXTURES_PATH=../.morse/witness-proof/rewards-program-fixtures.json \
  ../mesh-lang/target/debug/meshc test packages/messenger-protocol/security/rewards-chain.test.mpl
```

## Durable funding intent and retries

New operator workflows use tag 12. Tag 2 remains byte-compatible for existing
callers; blindly re-signing its expired transaction can make a second transfer.
Before preparing tag 12, persist a unique nonzero 32-byte operation ID with the
intended epoch, kind, amount, source, mint and funder. Reuse exactly that identity
after a crash, lost response, transaction expiry, or process restart.

FundingReceipt is a permanent 192-byte program-owned account at
`["funding", funder_pubkey, operation_id]`. The first successful invocation
atomically creates it and performs the actual SPL token transfer. A canonical
pre-funded empty System account cannot squat this PDA. Failed creation, balance
check or token CPI leaves the receipt and all accounting uncommitted. Fresh
funding still requires the chain's current open epoch.

A matching existing receipt is an authoritative no-op, even after epoch rollover
or settlement. The same funder must sign, and all intent fields must match.
Changing epoch, amount, kind, source, mint, or operation ID cannot reuse a receipt
to authorize another transfer. The rent payer may differ on a retry. There is no
receipt close instruction and no lease expiry that makes an old operation new.
A later source-account closure does not invalidate the already committed intent.

| Receipt offset | Field |
|---|---|
| 0 | `MRF\x01` |
| 4, 36, 68 | Pool address, funder address, operation ID (32 bytes each) |
| 100 | funded chain epoch, u64 |
| 108 | funding kind, u8 |
| 109 | three reserved zero bytes |
| 112 | funded amount, positive u64 |
| 120, 152 | source token account, immutable mint (32 bytes each) |
| 184 | positive on-chain funding timestamp, i64 |

## Local writer transaction bridge

Build `cargo build --manifest-path programs/Cargo.toml -p morse-rewards
--features svm --example rewards_writer_bridge`. The binary reads one JSON line
per request and emits one JSON response per line. It loads real rewards and judge
SBF plus LiteSVM's actual SPL Token/ATA programs. It uses disposable fixture
accounts, supplied public keys, and externally signed transactions; it reads no
wallet secret and connects to no remote chain.

The first request is `{method:"initialize", payer:PUBLIC_KEY}` with optional
`funder`, `governance`, and three `payouts` addresses. The response contains the
fixed program/judge/mint, all canonical account addresses, epoch, timestamps and
witness IDs/signing keys/row indices. Prior empty epochs and timelocked admission
are fixture setup; the exercised open/fund/begin/append/finalize/claim/cancel
instructions execute through the actual SBF entrypoint. These fixtures do not
prove deployment bootstrap or human operator qualification.

`context` returns the current blockhash, local block height, last valid height,
slot and Unix time. `account` takes `address`, optional `offset` and `length`;
`accounts` takes `addresses` with the same optional slice. Both use RPC-shaped
owner/executable/lamports/space/base64 data responses. `send` accepts a base64
serialized fully signed legacy/v0 transaction and returns actual SBF/SPL results
and pool accounting. A bad signature fails in the VM.

`warp` takes `unix_timestamp` and optional `slot`, advances the fixture clock,
expires its old blockhash, seals past fixture attendance weeks and prepares the
current week. `revision` changes the disposable judge eligibility revision to
exercise stale-stage cancellation. `state` reports balances and accounting.
These controls are local test APIs and are not production operator instructions.

For transaction-level integration tests, `expire_blockhash` refreshes only the
local transaction lifetime. `missing_payout` takes a sorted attendance `row` and
removes its disposable payout ATA so the real ATA-create-plus-claim path is
exercised. `missing_week` takes an `epoch` and removes its fixture attendance
account so the actual judge open/seal instructions must create the empty week.
These operations are exposed only by the local bridge, never by either program.

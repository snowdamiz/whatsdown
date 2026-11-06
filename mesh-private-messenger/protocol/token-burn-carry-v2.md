# Local burn carry wire v2

The prior 30-check operator checkpoint is preserved separately. This extension
is implemented locally and undergoing the combined required gate; it does not
authorize live activation.

## Account versions

- MTW1 remains the existing active 2176-byte frame: header256 +24 rows80.
- MTW2 is active2240 bytes: header320 +24 rows80. Original header fields/units,
  including funded_at56 and funding hash192, stay at their original offsets.
  New cash_budget256:u64, carry_budget264:u64, carry authority272..304, zero304..320.
  Total budget44 = cash_budget + carry_budget, checked u64. Rows keep existing
  semantics, but their start is320. No existing active MTW1 is reinterpreted.
- Closing changes only magic/status to MTC1/MTC2 and status byte52=2, retaining
  the corresponding original length, financial fields and rows. All active fund/
  execute parsers reject closed magic. This is a deliberate explicit terminal
  version, preventing delayed execution even if clock time later decreases or
  the old vault receives new donations.
- MCY1 carry metadata ['burn-carry'],192 bytes: profile4..36, USDC mint36..68,
  canonical carry vault68..100, accounted100:u64, cumulative closed108:u128,
  cumulative reserved124:u128, close_count140:u64, funding_count148:u64,
  zero156..192. Accounted = cumulative closed - reserved, exactly representable
  as u64. Its canonical classic SPL ATA has this PDA authority, no delegate,
  native reserve or close authority. Direct donations are surplus.
- MBC1 close receipt ['burn-carry-epoch',epochLE],256 bytes: profile4, Week36,
  source vault68 (32-byte addresses), epoch100:u64, budget108:u64, spent116:u64,
  burned124:u64, carried132:u64, closed_at140:i64, carry authority148..180,
  original funding hash180..212, original active frame SHA256212..244,
  original version244:u8 (1/2), zero245..256. Receipt is permanent.

## Token13 close epoch:u64LE

Ordered accounts: payer SW, Config, MORSE mint, swap profile, Week W, Week USDC
ATA W, carry metadata W, carry USDC ATA W, receipt W, USDC mint, SPL Token, ATA,
System. Exact canonical addresses, owners, schemas and profile/mint context are
required. Existing source/DEX code availability and TWAP are not required.

Clock now >= (epoch+1)*604800. Parse the complete active week and all24 rows,
including exact budget/spent/burned/mask conservation. Transfer only budget-spent,
leaving source donations untouched. Create/prefund-safe initialize carry/ATA and
receipt; close magic/status, transfer, counters and receipt commit atomically.
A zero remaining week still gets a permanent zero receipt. A duplicate validates
closed frame plus exact receipt and returns without a transfer or rent change.
No reservation/staging phase can block another caller. No receipt-close or
administrator withdrawal exists. Overflow or token CPI failure rolls everything
back. Closed state is not reported as additional burned input.

## Token14 fund v2

Payload epoch:u64LE,cash:u64LE,carry_take:u64LE,24*(weight:u32LE,entropy:u64LE).
Ordered roles use the existing17 funding roles plus carry metadata W and carry
ATA W. The profile's fixed treasury must sign even when cash=0; payer also signs.
This prevents an arbitrary first caller from choosing the week's schedule.

The same current/next-week and first-window funding bounds, qualified DEX/source
pins, fresh spot quote guard, positive24 rows and max1% bounded execution apply.
Create only the canonical absent Week; existing MTW1 or closed versions reject.
An existing MTW2 with the exact v2 funding hash is an idempotent retry, never a
second transfer. Hash binds profile and the complete cash/carry/schedule payload.

Carry_take <= carry.accounted. Transfer cash from the fixed treasury USDC ATA
and carry_take from the program's carry ATA into the Week ATA, validating exact
balance deltas. For cash=0 the canonical treasury source may be empty System
prestate; there is no source transfer or implicit source ATA rent allocation.
New total budget is exactly cash+carry_take; carry accounting decrements exactly
carry_take. Both CPIs, new Week and carry counters are one atomic transaction.
A prefunded Week or donated destination ATA must not seize the first call or
inflate its budget. Carry never becomes new credit revenue/operations funding.

## Required local qualification

Legacy MTW1 execution/funding and all original96 real DEX chunks remain green.
Add actual SBF close/fund replay, legacy/v2 terminal frames, partial/all-missed/
zero-remaining close, exact custody/donation conservation, two old closes and
one new fund interleavings, carry-only and mixed-cash funding, wrong owners/
PDAs/mints/authorities/profile, early closure/funding, permanent replay receipts,
first-caller/pre-funded accounts, terminal rejection after clock rollback/new
old-vault donations, and late SPL-CPI rollback including rent/prefunded receipt.
New actual DEX execution must burn an MTW2-funded chunk and preserve its immutable
cash/carry classification. Extend Mesh codecs/finalized reader and keeper journal
without treating a closed Week's transferred carry as burned or missing funds.
No live deployment, market liquidity, source qualification, independent governance
or four published live weekly burns follows from this local proof.

## Operator and recovery boundary

`ops/token/BurnCarry` decodes explicit active/closed v1/v2 frames, the MCY1 ledger
and permanent MBC1 receipt. It retains the original version/status instead of
passing a closed or v2 account to the legacy MTW1 decoder. A normalized active
frame hash preserves the original version and every row. Closed custody has zero
remaining executable budget; its transferred amount remains `carried`, never
`spent` or `burned`.

`ops/token/BurnCarryWrite` derives all close and funding roles. The close builder
has13 roles and no oracle or DEX accounts. The v2 fund builder preserves the
existing17 canonical funding roles, appends carry metadata/vault and requires
the fixed treasury signer even for a carry-only schedule. Preparation is not a
chain proof and does not sign or submit anything.

`ops/token-v2/BurnCarryRead` authenticates12 canonical roles in one finalized
`getMultipleAccounts` call: Config, MORSE mint, swap profile, USDC mint, Clock,
Week, Week ATA, carry metadata, carry ATA, close receipt, own executable and own
ProgramData. Slices are2240 bytes, full spaces/owners/lamports are checked, the
body is capped at128KiB and each call at5 seconds. The reader verifies all frame,
receipt and liability bindings and reports donations separately. It checks its
own pinned release slot; it intentionally does not require market availability
for custody recovery. Its close planner returns `waiting:week`, `paused:code`,
`close` or `complete`, and prepares at most one close instruction.

Two of three distinct configured URLs must agree on the authenticated bank
digest. Different URL strings do not establish organizational independence.
The shared source validator also covers rewards identity reads; duplicate URLs
and non-HTTPS production sources are rejected before an RPC request.

The existing sealed burn journal supports kinds13/14 with separate immutable
operation identities. Funding keeps the first-window deadline and two signer
roles; permissionless closure starts at week end with one rent-payer signer.
The exact authenticated packet/signature is committed before a network call.
Conflicting amounts/schedules reject, retries retain the committed packet,
and ambiguous send responses or mismatched returned signatures never replace it.
Expired signed funding packets become reconciliation-only. Permanent close
receipts can reconcile matching historical v1 funding and v2 chunk executions
after closure without broadcasting again. A missed, unexecuted expired chunk
is not falsely confirmed as a burn; explicit unresolved-packet disposition and
rescheduling remain separate operator work.

## Accounting and qualification

For carry custody, cumulative closed minus cumulative reserved equals current
accounted USDC exactly. Cumulative amounts are u128 and all transfer amounts are
u64. Direct token donations never enter these counters. A later week's total
budget includes its reserved carry, so summing weekly budgets would count the
same money again. Across the isolated test's active/closed weeks, original cash
funding equals executed USDC input plus currently accounted carry plus unspent
active budgets; donations are an independent surplus. MORSE burned is measured
by actual mint-supply reduction and never increased by closing or carrying USDC.

Schedule weights and entropy are immutable signer-supplied intent, checked for
24 positive rows and bounded execution windows. The onchain program does not
prove that an external signer chose entropy impartially. It enforces the fixed
signer, canonical custody, current/next-week creation rules and the existing
bounded swap output policy.

The local tests use the pinned LiteSVM dependency's classic SPL3.5.0 ELF for the
carry adversarial cases, in addition to the existing bank token implementation
used by the original burns. They reach recipient overflow failures inside SPL,
including the second transfer after a successful cash transfer, and assert
restoration of all financial accounts and prefunded receipt/metadata rent.
Oracle publications remain injected authenticated-format fixtures. Market
programs execute as pinned local SBF images; no production route, live feed,
provider independence or four published live weekly burns follows from this
qualification. The required script captures exact source, compiler, runtime,
SBF and fixture hashes rather than treating this document as release approval.

# Token boundary v1 — local qualification

This documents the local `morse-token` Pinocchio boundary and Mesh operators in
`ops/token`. It is not a live program identity, audit, deployment instruction or
Phase5 acceptance. Program addresses in proofs are disposable. No live MORSE
oracle feed or market is assumed. The complete custody design, remaining work
and external dependencies are in [DESIGN.md](../ops/token/DESIGN.md).

All integers are little endian. Addresses are32 raw bytes. Only classic SPL Token
is supported; mint accounts are82 bytes and token accounts165 bytes. Program
accounts must have exact lengths, expected owners, non-executable state and
canonical PDAs. Every transfer checks exact source/destination balance deltas.
Token vaults are SPL-owned accounts with Morse PDAs as their token authorities.

## Addresses and initialization

The canonical PDAs under the token program are `['token']`, `['mint']`,
`['allocation',kind:u8]` for kinds0..6 and `['oracle']`. Every vault and payout is
the canonical classic ATA for its authority and the fixed MORSE mint.

| Tag | Payload | Ordered accounts |
|---|---|---|
|0 initialize | governance32 + seven beneficiary32 | bootstrap signer, payer signer writable, Config writable, Mint writable, executable program, loader ProgramData, Token, ATA, System, seven pairs of Allocation writable + Vault writable |
|1 claim | kind:u8 (reserve kind4 forbidden) | payer signer writable, Config, Allocation writable, Vault writable, fixed payout ATA writable, fixed beneficiary, Mint, Token, ATA, System |
|2 prepare | empty | payer signer writable, Config writable, System, seven Allocation writable |

Bootstrap requires the actual loader-v3 ProgramData PDA and its current upgrade
public key as signer. Payloads cannot choose a past vesting start: initialization
uses the chain clock. Every beneficiary is nonzero and distinct from the mint,
Config and all allocation authorities. Identical initialized tag0 retries are
idempotent and cannot mint a second supply; changed intent is rejected.

Tag2 permissionlessly creates only zeroed program-owned metadata. It chooses no
beneficiaries and creates no SPL mint. Anyone can pay its rent without gaining
control. This bounds the instruction trace when future PDAs/ATAs have been
prefunded. Operators prepare first, then initialize. The latter still atomically
initializes the mint, creates seven canonical ATAs, mints every exact allocation,
checks the full supply, and revokes mint authority. Freeze authority is never set.
The local initializer uses a bounded400,000-unit compute budget; seven prefunded
metadata accounts, the mint and all seven ATAs are covered by the SBF proof.

| Kind | Name | Units | Vesting |
|---|---|---:|---|
|0 | Treasury |250000000000000 |48 months |
|1 | Ecosystem |200000000000000 | immediate to fixed beneficiary |
|2 | Team |180000000000000 |48 months including12-month cliff |
|3 | Backers |150000000000000 |36 months including12-month cliff |
|4 | Witness reserve |150000000000000 | no generic claim |
|5 | Liquidity |50000000000000 | immediate to fixed beneficiary |
|6 | Advisors |20000000000000 |24 months including12-month cliff |

Total supply is1000000000000000 units:1B tokens with6 decimals. Cliffs are included
in the total term. Each cumulative claim uses the original UTC month anniversary,
with short-month clamping computed afresh from the original date. Inside month
`i`, progress is `(i * duration + elapsed) / (months * duration)`, rounded down
once after multiplication by the allocation. Before the cliff, entitlement is
zero; at total term, the full allocation is vested. Claims subtract prior claimed
entitlement and can only pay the immutable beneficiary ATA. Permissionless callers
can pay rent/fees but cannot redirect a claim. Later token burns may reduce supply;
they cannot restore mint/freeze authority.

Config is320 bytes: magic `MTK1` (byte3 is binary1), governance4..36,
mint36..68, start68..76, zero76..80, beneficiaries80..304, zero304..320.
Allocation is128 bytes: magic `MTA1`, kind4, zero5..8, Config8..40,
beneficiary40..72, start72..80, allocation total80..88, claimed88..96,
mint96..128. The supply/allocation constants and all account bindings are checked.

## Authenticated sampled seven-day TWAP

The supported source codec is Pyth Receiver `PriceUpdateV2`, pinned to the source
commit/hash in [oracle-source.json](../ops/token/oracle-source.json). Recognized
receiver identities are the default `rec5...` and Pro-compatible `rec2...` IDs from
that SDK; a chosen oracle binds one exact executable receiver, account and feed.
The codec requires the Anchor discriminator, exact134-byte account allocation,
Full verification, exact feed, positive price, confidence at most1%, supported
exponent-12..0, publication no older than60 seconds and not in the future, previous
publication not later than current, and posted slot not later than chain slot.
The full variant serializes133 bytes inside a134-byte allocation, so the final
allocation byte is intentionally not treated as a meaningful Borsh field.

Price is normalized to six USD decimals from `price - confidence`, rounded down.
This is conservative collateral valuation. Normalization to zero or beyondu64 is
rejected. The approximately one-hour Pyth EMA is never used as a seven-day TWAP.

| Tag | Payload | Ordered accounts |
|---|---|---|
|3 initialize oracle | source account32 + feed32 | governance signer, payer signer writable, Config, Mint, Oracle writable, receiver executable, source, System |
|4 observe | empty | Config, Mint, Oracle writable, receiver executable, source |
|5 validate full TWAP | empty | Config, Mint, Oracle |
|6 propose source | new source32 + new feed32 | governance signer, Config, Mint, Oracle writable, new receiver executable, new source |
|7 execute source | empty | Config, Mint, Oracle writable, pending receiver executable, pending source |

Tag3 checks the fixed Config governance. Identical initialized pins replay safely.
A new source proposal requires a currently authentic fresh source. It waits exactly
14 days. Repeating the same pending proposal preserves its original deadline;
changing it restarts the delay. Permissionless execution requires fresh pending
source evidence, increments a checked source revision, discards all old coverage
and seeds a new observation. No source rotation can carry old price history into
a different feed. The revision is intended for coherent staged consumer snapshots.

Oracle is5728 bytes:320-byte header plus169 hourly32-byte ring entries. Header:
magic `MTO1`, Config4..36, mint36..68, receiver68..100, source100..132,
feed132..164, last publication164..172, last conservative price172..180,
last posted slot180..188, pending receiver188..220, pending source220..252,
pending feed252..284, ready time284..292, source revision292..300, zero300..320.
No pending proposal means the pending fields and ready time are all zero.
Each bucket is absolute UTC hour:i64, time integral:u128 and covered seconds:u64.
Its index is `hour mod169`. All169 entries remain in account data; no large SBF
stack array is used.

Accepted publications integrate the previous conservative price over the elapsed
seconds. A time step may be at most60 seconds and cannot move backwards. Crossing
an hour splits the integral exactly at that boundary. A larger gap discards all
coverage and seeds a new series; it is never extrapolated. Exact duplicate
publication/price/slot is idempotent; conflicting or older evidence is rejected.

Valuation requires168 complete, individually matched hours with exactly3600
covered seconds each. Their sum is divided by604800 once, rounding down. The
current partial hour is never prorated. The latest publication must be fresh and
in the current UTC hour, so the covered endpoint is the latest completed hour.
Missing/partial/stale history is unavailable and must leave USDC fallback.
The TWAP describes this bounded sampled series, not every trade between samples.

## Supported swap instruction policy

The current pure validator supports exactly one Jupiter `route_v2` ExactIn hop:
RaydiumCP enum46,10000bps, input index0, output index1. It rejects trailing data,
other route variants/hops/DEXes, platform fees, positive-slippage fees and slippage
above100bps. The amount must match the independently reserved input exactly.
Its quoted minimum must also satisfy an independent conservative oracle bound:
`ceil(inputUSDC * 1000000 * 9900 / (MORSE_USD_price * 10000))`. A bad router quote
cannot lower this bound. The finalized read-only Anchor IDL observation and hashes
are in [jupiter-source.json](../ops/token/jupiter-source.json).

The executor below uses this validator with the fresh authenticated conservative
spot publication, not a seven-day average execution price. Bonds/reserve still
require the complete seven-day TWAP. A fresh spot after a coverage gap does not
fabricate bond coverage. Raw API instructions confer no authority.

## Delayed swap profile and exact weekly custody

The initial profile pins one classic six-decimal USDC mint, external treasury
owner, canonical RaydiumCP pool/config/vaults/observation, and the canonical
Jupiter/Raydium executable and loader-v3 ProgramData accounts. It checks the
supported pool account schema, both mint/program roles, vault token authorities,
canonical Raydium PDAs and bounded factory fees. The complete factory config is
hashed. A14-day initial qualification delay applies before funding or execution.
Identical profile initialization preserves the deadline; altered pins are rejected.

The profile captures both loader upgrade slots and checks them again before any
new funding or swap. A router/DEX upgrade or changed factory config cannot silently
change the qualified execution path. The v1 profile is immutable. Supporting a
changed external release requires an explicitly qualified versioned migration;
there is no automatic pin refresh or administrator withdrawal.

| Tag | Payload | Ordered accounts |
|---|---|---|
|8 initialize swap profile | empty | governance signer, payer signer writable, Token Config, MORSE mint, Swap Config writable, USDC mint, treasury owner, Raydium pool, factory config, token0 vault, token1 vault, observation, Jupiter executable, Jupiter ProgramData, Raydium executable, Raydium ProgramData, System |
|9 fund immutable week | epoch:u64 + total budget:u64 +24 pairs(weight:u32, entropy:u64) | treasury signer, payer signer writable, Token Config, MORSE mint, Swap Config, USDC mint, Week writable, Week USDC ATA writable, treasury USDC ATA writable, Token, ATA, System, Jupiter executable, Jupiter ProgramData, Raydium executable, Raydium ProgramData, Oracle |
|10 execute chunk | index:u8 +39-byte supported route | payer signer writable, Token Config, MORSE mint writable, Swap Config, USDC mint, Week writable, Week USDC ATA writable, chunk authority, chunk USDC ATA writable, chunk MORSE ATA writable, Oracle, Token, ATA, System, Jupiter executable, Jupiter ProgramData, Raydium executable, Raydium ProgramData, Raydium pool writable, factory config, input pool vault writable, output pool vault writable, observation writable, Raydium authority, Jupiter event authority |

Swap Config PDA is `['swap']`. Its320-byte frame is magic `MTS1`, Token Config4..36,
USDC mint36..68, treasury owner68..100, Raydium pool100..132, factory config132..164,
token0 vault164..196, token1 vault196..228, observation228..260, Jupiter upgrade
slot260..268, Raydium upgrade slot268..276, ready time276..284, factory hash284..316,
zero316..320. Both executables have fixed program IDs; program identities cannot
be selected through route bytes.

Week PDA is `['burn-week',epoch:u64]`; chunk authority is
`['burn-chunk',Week,index:u8]`. Only the pinned external treasury owner can fund a
new week from its canonical USDC ATA. A week can be the current or next chain
week; funding after the first window has ended is rejected. Exactly24 positive
chunks divide the entire budget. One unit per chunk is reserved first, remaining
units are proportional to positive weights, and rounding dust goes to the first
canonical indices. Each entropy picks an offset in a distinct25200-second window.
The offchain Mesh keeper must draw these inputs using its public cryptographic
randomness API. Onchain enforcement proves immutable commitment and spread over
the week; it is not an unbiasable public randomness beacon.

Weekly funding is atomic and intent-bound. Its permanent Week record hashes the
entire immutable funding/schedule payload and profile address. Identical retries
return without a second transfer even after rollover; changed intent is rejected.
Direct donations are not added to budget or spend totals. The accounting source
of the specified30% revenue share belongs to the separate issuer migration; a
funder's token balance alone is not proof of revenue.

Week is2176 bytes:256-byte header plus24 rows of80 bytes. Header is magic `MTW1`,
Swap Config4..36, epoch36..44, budget44..52, funded status1 at52, zero53..56,
funded time56..64, USDC mint64..96, treasury owner96..128, Week vault128..160,
source160..192, funding intent hash192..224, completion bitmap224..232,
spent USDC232..240, burned MORSE240..248, zero248..256. Each row is amount0..8,
window start8..16, window end16..24, due time24..32, burned output32..40,
execution intent hash40..72, zero72..80. Row amounts sum to budget; completed rows
sum exactly to the header spend/burn counters. Uncompleted rows have no output or
execution hash. Reserved bitmap bits are zero.

A new execution is permitted only at/after its due time and strictly before its
window ends. It creates canonical per-chunk ATAs and transfers exactly that row's
reserved input from the Week vault. Only the chunk PDA is a router signer; the
Week authority/vault, reserve, vesting and other chunks are absent from the CPI.
Every router account role is constructed by the Morse program from authenticated
pins; callers cannot forward arbitrary remaining accounts. Only the one approved
RaydiumCP hop executes. Actual input/output balances and unchanged pre-burn supply
are checked, then the actual new MORSE output is burned using `BurnChecked` in the
same instruction. All balance/supply/counter postconditions are atomic.

Pre-existing donations in a chunk's ATAs are preserved and excluded from funded
input and recorded output. A failed real router/DEX operation rolls back Week
funding to the chunk, ATA creation, balances and receipt mutations. A successful
chunk writes one permanent amount/hash and emits `MORSE_BURN_V1`; only finalized
successful transactions and authenticated receipt accounts may count toward the
public burn view. Identical completed executions replay without any further CPI,
including after expiry; a different execution intent cannot reuse that row.
An expired unexecuted row remains an explicit unspent USDC liability in its Week
vault. It is never counted as a completed burn or treated as newly earned revenue.
The durable offchain packet journal/public reader and safe future carry migration
remain separate required work.

## Evidence and boundaries

Run `scripts/prove-token.sh` with an existing public Mesh compiler and
`cargo-build-sbf4.4.0`/tools1.57. The script creates fresh SBF output, runs actual
LiteSVM/SPL/ATA instructions, all10,080 seven-day observations, actual pinned Jupiter/Raydium SBF execution for four simulated weeks and adversarial rollback/upgrade/donation/window cases, pure adversarial
codec/arithmetic tests, and compiled Mesh replay of actual SBF states and Rust
instruction vectors. It records source/compiler/artifact hashes in
`token-local.json`, whose `phase5_complete` remainsfalse until the listed remaining
boundaries are implemented and qualified.

Pyth-owned account bytes in local tests are explicitly injected fixtures. These
prove the consumer codec, ownership/pin checks and accumulator, not Wormhole guardian
verification or live MORSE feed availability. The chain IDL observation submitted
no transaction. Program upgrade immutability, deployment configuration, DEX/source
availability, audits and human multisig independence remain separate release gates.

## Mesh prepared instructions and authenticated burn observations

`ops/token/BurnWrite` derives the complete ordered tag8/9/10 account list from
fixed program IDs, pinned profile roles and canonical PDAs/ATAs. It rejects a
profile whose pool, vault or observation addresses do not match those derivations,
invalid chunk indices, noncanonical funding weights and malformed routes. All96
executed local chunk instructions are independently compared against the Mesh
builders, including signer/writable roles and every payload byte. These helpers
prepare instructions; they do not authorize a live transaction.

`BurnRead.token_burn_read_keys` derives a19-account ordered batch containing
Config, both mints, Swap Config, Oracle, Clock, both external executables and
ProgramData records, Raydium pool/config/vaults/observation, the requested Week and
its vault, and the Morse executable/ProgramData. The external read pins also bind
governance, USDC, treasury, factory and the qualified Morse deployment slot.
`read_token_burn_from` requests this batch at finalized commitment with a minimum
context slot, a5728-byte slice cap, a5-second timeout, a262144-byte response cap
and redirects disabled. RPC IDs, numeric types, full allocation sizes and exact
slice lengths are checked. Clock must match the returned bank context. Every
account is bound to its expected owner/schema and canonical role; mints/vaults
receive their additional token authority and balance checks.

The reader keeps unspent committed budget separate from donations, including a
canonical ATA created or donated to before a Week exists. Missing/stale seven-day
coverage is reported separately from a fresh spot observation. A changed external
upgrade slot, factory hash or disabled pool pauses execution eligibility without
rewriting or invalidating authenticated historical burn receipts. A changed Morse
deployment slot also pauses against the operator's qualified release pin.

`read_token_burn_quorum` permits three configured distinct endpoints and requires
two identical authenticated account snapshots. At most three bounded requests are
made; provider failure or disagreement fails closed. Production sources require
HTTPS. Plain loopback HTTP is accepted only under explicit local test mode.
Different URL strings do not prove different operator ownership: release source
selection must establish that independence externally. The proof uses three
loopback paths over one isolated bank and therefore proves the agreement contract,
not real-world provider independence or live finality.

## Durable keeper packet boundary

`BurnJournal` uses one sealed SQLite row per `(program,tag,epoch,index)` operation.
Fund has index0; execute has an index0..23. The operation identifier is the SHA256
of a versioned domain and those exact binary fields. `reserve_token_burn_fund`
and `reserve_token_burn_chunk` construct their instruction through the canonical
builders before inserting anything. Repeating the same intent returns its current
state; changing the payer, route, schedule or other account/data intent conflicts.

The journal uses the public `StorageKey.file` and `StorageKey.seal_bytes` APIs,
with standard123-byte purpose14 contexts bound to program and operation ID. It
introduces no private crypto format or plaintext signer export. SQLite uses full
synchronous commits and bounded busy waits. A ciphertext compare-and-swap makes
competing intent/packet writers fail or recover the already durable winner.
Operators must keep the file-backed wrapping key and database in their private
persistent directory. Manual backup/rollback of local state is outside this
process-crash proof; permanent onchain funding/chunk receipts still prevent a
second principal transfer or burn for an identical intent.

States are0 reserved intent,1 committed signed packet,2 RPC acknowledged and
3 finalized permanent program receipt. Acknowledgment is not finality. Packet
commit validates every Ed25519 signature on the complete public signed wire,
requires a legacy message with exactly the fixed1000000-unit budget instruction
and reserved Morse instruction, and binds all account identities/global roles.
SDK key ordering inside a privilege class may differ; no extra account, privilege,
instruction, fee or substituted data is permitted. An unrelated but valid SDK
signature does not authorize another chunk.

`sign_and_commit_token_burn_entry` borrows opaque payer and treasury signing
resources, reconstructs the reserved message, and commits the signed packet
before returning. It signs only the declared roles. If a packet already exists,
it returns that exact packet even when offered a newer blockhash. There is no
implicit fresh signing after a timeout or restart. `submit_token_burn_entry`
loads the committed packet, bounds one RPC attempt, checks the returned signature,
and preserves state on ambiguous errors. It refuses sends before the committed
execution time, at/after the window deadline, or after the recorded blockhash
height. Such entries become reconciliation-only; automatic packet replacement is
not implemented. Finalization checks the authenticated Week/row's exact immutable
intent hash and finalized context, including when external code has since paused.

The local proof imports actual SDK packets executed by the SBF test, forces an
ambiguous HTTP result, retries exactly the same bytes/signature, restarts twice,
and finalizes through the authenticated reader. Two additional Mesh processes
race the same immutable reservation/packet. The HTTP fixture receives public
packets only; it does not submit to a live chain. The separate SBF proof executes
real pinned router/DEX/SPL code in an isolated bank.

## Explicit judge collateral v2

The local judge extension preserves every legacy USDC unit and finalized rewards
claim. It adds a separate `['token-binding',log_id]` MJB2 account (320 bytes).
Governance proposes the exact token program/Config/mint/Oracle and rewards
program/pool, including both loader-v3 upgrade slots and the oracle source
revision. Fourteen days, fresh complete seven-day coverage, unchanged qualified
code/source, no collecting rewards epoch and all closed legacy epochs settled
are required before permissionless activation. Activation changes MEC1 to MEC2;
it moves no token balance. Existing funding receipts and finalized USD claims
keep their original semantics. Active bindings cannot be silently refreshed.

MJB2 fields are Log4..36, log ID36..68, token program68..100,
Token Config100..132, MORSE mint132..164, Oracle164..196,
rewards program196..228, Pool228..260, ready time260..268,
activation time268..276, activation epoch276..284, token upgrade slot284..292,
rewards upgrade slot292..300, source revision300..308, zero308..320.
Magic byte3 is binary2. All addresses are canonical and nonzero.

MEC2 retains192 bytes and the immutable USDC mint, original USD counters and
eligibility revision. Directory asset is byte165 (0 USDC,1 MORSE), bytes166..168
are zero, MORSE witness/directory principals occupy176..184/184..192. MBD2 retains
the canonical subject PDA and208 bytes: asset6, zero7 and underwater time200..208;
the original principal and timestamp fields keep their offsets. A permissionless
USDC migration changes only the explicit version byte after authenticating its
exact witness/directory, owner, mint, canonical vault and aggregate context.
No v1 handler accepts MEC2 or treats MORSE units as USDC.

The companion `['bond-pending',Bond]` is96 bytes, magic MBP2, Bond4..36,
mint36..68, tracked pending amount68..76, first pending time76..84,
immutable MORSE USD target84..92, zero92..96. USDC target is zero. A new/rebonded
MORSE lifetime snapshots its entry target; later timelocked minimum changes only
affect new/rebonded bonds. A migrated USDC bond can lack this companion until its
first v2 topup. Only a canonical empty System-owned account is accepted for that
case. Existing MORSE bonds always require their authenticated target companion.

Active topups transfer into the canonical bond vault but change only the tracked
pending account. They never change principal, bonded time, grace or eligibility
revision during collection. Direct vault donations are neither principal nor
pending collateral. Outside collection, permissionless activation applies all
tracked pending units together, checks mixed collateral coverage in one USD
unit and advances the eligibility revision once. Price observations alone do not
change that revision. The same entry target governs all assessments: strictly
below80% starts one seven-day clock; partial recovery preserves it; only full100%
clears it. At the exact grace deadline the still-underwater bond is ineligible,
without a slash or token transfer.

Owner-only unbond requests start the original thirty-day delay. Matured exits
need neither fresh oracle coverage nor an available external router. They pay
only the immutable owner's canonical ATA, return the entire remaining vault
balance (including pending units/donations), clear only the matching principal
counter and cannot pay again on replay. Directory collateral cannot leave while
any USDC or MORSE witness principal remains. USDC witness eligibility retains the
legacy full-week Active semantics; an unrelated directory price/status change
cannot retroactively remove an earned USD entitlement.

The scoped actual SBF evidence is recorded in `token-bond-*-{red,green}.log`.
These handlers are local integration work. The mixed-asset settlement and
versioned rewards contracts below are separate qualified boundaries; public v2
operator/read integration and the live exit gates remain necessary before
production activation or Phase5 acceptance.

### Judge v2 instruction wire

`M` below denotes the fixed MORSE mint; `Token program/metadata/Config/Oracle`
are the immutable binding roles. Mutable accounts carry `W`; signers carry `S`.
The legacy request tags remain unchanged and do not accept v2 collateral.

| Tag | Payload | Ordered roles |
|---|---|---|
|31 propose binding | empty | governance S, payer SW, Judge Config, Log, Economics W, Binding W, token executable, token ProgramData, Token Config, M, Oracle, rewards executable, rewards ProgramData, Pool, System |
|32 activate binding | empty | same15 addresses; permissionless, no token transfer |
|33 migrate USDC bond | witness:u8 | Log, Economics W, Binding, Bond W, optional Witness |
|34 witness deposit | asset:u8 + amount:u64 | operator SW, Log, Economics W, Binding, Witness W, Bond W, Pending W, vault W, source W, selected mint, token executable, token ProgramData, Token Config, M, Oracle, rewards executable, rewards ProgramData, Pool, Token, ATA, System |
|35 directory deposit | asset:u8 + amount:u64 | governance S, Judge Config, operator SW, Log W, Economics W, Binding, Bond W, Pending W, vault W, source W, selected mint, token executable, token ProgramData, Token Config, M, Oracle, rewards executable, rewards ProgramData, Pool, Token, ATA, System |
|36 apply pending/assess | witness:u8 | Log, Economics W, Binding, Bond W, Pending W, vault W, token executable, token ProgramData, Token Config, M, Oracle, rewards executable, rewards ProgramData, Pool, optional Witness |
|37 request unbond | witness:u8 | operator S, Log, Economics W, Binding, Bond W, Pending, optional Witness W |
|38 matured withdrawal | witness:u8 | operator S, Log, Economics W, Binding, Bond W, Pending W, vault W, fixed owner ATA W, selected mint, Token, optional Witness W |
|39 propose minimums | witness USD target:u64 + directory USD target:u64 | governance S, Judge Config, Log, Economics W, Binding |
|40 apply minimums | empty | Log, Economics W, Binding |

Witness flags are exactly0 directory or1 witness; asset flags are exactly0 USDC
or1 MORSE. Amounts are positive. An active bond cannot change asset. A withdrawn,
empty lifetime can choose a new asset and snapshots the then-current entry target.
All pending/record/bond/vault identities are checked before principal accounting.
Existing USDC topups do not require available token price coverage. Admission or
activation that needs to value nonzero MORSE aggregate exposure fails closed on
missing complete TWAP. Mixed aggregate coverage uses exact rational USD units,
without adding token units directly or rounding an underfunded entry upward.

### Prepared mixed-asset verdicts

A permissionless preparation authenticates the complete staged fork, historical
ring/generation when anchored, every canonical witness/bond identity, fixed
finder, asset and bond lifetime. It creates the permanent `['proof',log_id,hash]`
receipt and moves no tokens. Exact preparation replays are idempotent; a different
payer cannot change the finder or source stage. Prefunded empty System-owned PDAs
are safe. The preparation has no fee-payer lock or cooperation requirement.
Its deadline is the original earliest evidence timestamp plus28 days; preparation
never extends that window.

The separate financial instruction revalidates all current status, owner, mint,
canonical vault, principal counters, frozen subject keys/assets/bonded time and
recipients, then transfers every target atomically. An exact legacy USDC schema
migration between preparation and settlement is allowed because it preserves the
frozen lifetime. Later principal/pending topups are included in the actual vault
balance. A completed owner withdrawal or a replacement bond lifetime cannot be
substituted. Previously slashed sources contribute zero and cannot pay again.
The ten-percent bounty is rounded down independently for each source; its
remaining balance goes only to that asset's canonical locked ATA.

| Tag | Payload | Ordered roles |
|---|---|---|
|41/42/43 prepare | expected second checkpoint hash32 | payer SW, Log, Stage, Economics, Binding, Receipt W, System, directory Bond; for anchored evidence: historical Ring + Set; then every ordered Witness + Bond pair |
|44 settle | empty | Log W, Economics W, Binding, Receipt W, directory Bond W, directory vault W, USDC mint, USDC finder ATA W, USDC locked ATA W, M, MORSE finder ATA W, MORSE locked ATA W, Token; then every ordered Witness W + Bond W + vault W triple |

Tags41/42/43 are the existing fork kinds1/2/3. Only MBD2 can financially settle;
preparation can recognize an authenticated legacy USDC MBD1 awaiting tag33.
The transfer pass uses account data directly. Sixteen mixed-asset subjects compile
to64 total runtime account locks including fee payer, judge and budget program.
The local actual-ALT vector is368 bytes and consumes605141 compute units. These
are observed fixture bounds, not a live fee/latency claim.

Slashing drains actual principal, pending units and direct donations from each
currently held source. The Bond becomes permanently Slashed and its principal
counter is cleared. Pending companion bytes remain historical, voided by that
permanent status; every pending activation, deposit and withdrawal path rejects
that status. They cannot create a second claim against another vault.

The proof receipt is400 + count*144 bytes, magic MPR2 (distinct from rewards
Pool MRP). Header: kind4, anchored5, count6, status7 (0 prepared/1 settled),
log ID8..40, proof hash40..72, finder72..104, submitter104..136,
USDC mint136..168, MORSE mint168..200, first/second hashes200..232/232..264,
prepared time264..272, USDC total/bounty/directory balance272..296,
MORSE total/bounty/directory balance296..320, verified bits320..328,
Stage328..360, deadline milliseconds360..368, directory bonded time368..376,
directory asset376, zero377..384, settled time384..392, zero392..400.
Each144-byte row is subject identity0..32, Witness32..64, signing key64..96,
asset96, zero97..104, bonded time104..112, settled principal112..120,
settled balance120..128, bounty128..136, zero136..144. Prepared financial fields
are zero. Settled row sums must equal their asset header totals. Neither status
permits arbitrary destinations or administrator withdrawals.

### Grace assessment during collection

Judge tag45 has the tag36 roles and witness flag, but Pending may be read-only.
Its vault is still writable because the shared strict custody validator requires
that flag. It never applies pending units or moves tokens. Only an actual grace
start/clear changes the eligibility revision; exact repeats and one-unit pending
topups cannot manufacture a collection reset. This permissionless assessment can
run during collection so an unrecorded below80% transition cannot deadlock a
staged epoch. Tag36 still rejects pending activation during collection.

## Versioned rewards and floor-only reserve

`MRP2` keeps the304-byte Pool and every USDC field at its original offset and in
its original units. Existing finalized MRE1 claims and permanent MRF1 funding
receipts remain usable; no migration claims a second entitlement. Legacy begin,
append, finalize and cancel refuse v2. A newly opened v2 main ledger is `MRE2`,
still8416 bytes with the same USDC header/rows. An unsettled MRE1 ledger can change
version only while open, preserving its USDC revenue. A finalized MRE1 is never
rewritten. Funding is still assigned to the current chain epoch, not to an old
settlement being collected. Direct donations remain outside accounted funding.

The immutable token reserve profile is `['reserve-config']`,320 bytes, `MRS2`.
Fields are Config4, MORSE mint36, USDC mint68, judge100, Log132, Binding164,
rewards196, Pool228, token Pool260 (each address32 bytes), ready292:i64,
rewards upgrade slot300:u64, judge upgrade slot308:u64, zero316..320. Token tag11
requires the token Config governance, the active judge binding, genuine
loader-v3 code metadata, canonical Pool/Log/Economics and fresh complete TWAP.
It waits14 days. Identical replay preserves the original deadline even if price
coverage later expires. Altered pins cannot replace it. Only one global profile
exists, so creating multiple reward pools cannot multiply the reserve cap.

Rewards tag13 requires current Pool governance and the mature profile. It creates
`['token-pool']` and the Pool's canonical MORSE ATA, then changes only the Pool's
version byte. No price is required to preserve USDC service. The token Pool is
`MRT2`,320 bytes: Pool4, Binding36, token program68, Config100, MORSE mint132,
Oracle164, profile196, MORSE vault228, MORSE accounted260:u64,
MORSE liabilities268:u64, binding activation epoch276:u64, zero284..320.
The two MORSE amounts are equal: no unallocated reserve or MORSE revenue is
silently treated as free reward funding. A pre-existing ATA donation is surplus,
not an allocation. Governance has no arbitrary withdrawal instruction.

Each v2 epoch also uses `['token-epoch',epoch:u64LE]`, `MTE2`,1280 bytes.
Header256: token Pool4..36, main ledger36..68, epoch68:u64, pinned TWAP76:u64,
source revision84:u64, snapshot time92:i64, actual USD floor gap100:u64,
MORSE allocation108:u64, MORSE claimed bitmap116:u64, MORSE claimed total124:u64,
USD committed132:u64, USD floors140:u64, status148:u8 (0 open/1 collecting/2 final),
zero149..152, reserve receipt152..184 (zero when no MORSE), zero184..256.
There are64 fixed16-byte rows: USD gap:u64 then MORSE allocation:u64. The payout
identity is the immutable corresponding main-ledger snapshot row. USD and MORSE
claims have independent bitmaps and cannot consume each other's liabilities.

Staging pins the judge revision, oracle source revision, TWAP and time. Ordinary
price observations do not invalidate a coherent stage. An unavailable/stale
TWAP is represented by price0 after authenticating the Oracle owner, canonical
PDA, configuration and source revision. MORSE bonds then have zero weight and a
MORSE floor shortfall cannot settle; fully funded USDC earnings remain live.
Every sealed attendance row must be supplied in canonical order, including
Registered witnesses with canonical absent Bond/Pending accounts and default
excluded/unadmitted witnesses. A MORSE row authenticates its exact entry target
and recorded grace. Currently Active full-week USDC eligibility keeps its legacy
meaning. No mechanism proves human identity or real-world operator independence.

A genuine eligibility/source revision change invalidates every remaining append
and finalization. Permissionless cancel then resets only staged data. Unchanged
stages cannot be cheaply cancelled early. They have a fixed one-hour deadline;
append/finalize fail at that deadline and permissionless cancel becomes possible.
Cancellation never consumes revenue, subsidy, reserve or prior liabilities.

Settlement first reserves actual epoch revenue/carry and only the required
available USDC subsidy. If USD floors are still underfunded, canonical cumulative
quotient differences allocate **every** available USD unit before MORSE is
requested. Each remaining row gap is converted with `ceil(gap*1e6/pinned_TWAP)`.
Each row's rounding is included in the cap. The cap is exactly500,000 tokens
(500,000,000,000 raw units),0.05% of the immutable original supply, per epoch;
burns and donations cannot increase it. Reserve shortage or a cap violation
fails the entire settlement atomically for a later USDC topup/retry. No eligible
row carries the USD revenue and consumes neither kind of subsidy. Remaining USD
revenue above floors is allocated by exact attendance weights; dust carries.
No fake USDC amount is booked for a MORSE payout.

Token tag12 is available only through the pinned rewards Pool PDA signature.
It reauthenticates the mature global profile, all code slots and binding roles,
current eligibility/source revisions, main-ledger stage/TTL, all completed rows,
USD quotient allocations, row gaps and MORSE rounding/cap. It transfers only the
computed shortfall from the program-owned allocation4 reserve ATA into the
canonical Pool MORSE ATA. Original reserve claimed accounting limits all-time
funding to the original15% allocation even if the vault receives donations. A
permanent `['reserve-epoch',epoch:u64LE]` receipt prevents repeated epoch funding.
The transfer, receipt, USDC accounting and both finalized allocation snapshots
commit in one transaction; staging itself moves no financial balance.

The reserve receipt is `MRR2`,256 bytes: profile4, Pool36, token epoch68 (addresses),
epoch100:u64, USD gap108:u64, TWAP116:u64, MORSE amount124:u64,
source revision132:u64, funded time140:i64, mint148..180, destination180..212,
SHA256 of ordered main rows and token rows212..244, zero244..256. It has no close,
refund or administrator rewrite path. Claiming a finalized row pays only that
row's registered payout ATA, even if its bond is later unbonded or slashed.

### Rewards v2 instruction wire

The19-role `C` prefix is: Pool W, token Pool (W on finalize), main Epoch W,
token Epoch W, Log, AttendanceClock, AttendanceEpoch, Economics, Binding,
token executable, token ProgramData, Token Config, MORSE mint, Oracle,
rewards executable, rewards ProgramData, judge executable, judge ProgramData,
reserve profile. All addresses/owners/context are checked; it is not a caller
assertion that a price or witness is authentic.

| Rewards tag | Payload | Ordered roles |
|---|---|---|
|13 activate | empty | governance S, payer SW, Pool W, token Pool W, Pool MORSE ATA W, judge executable, judge ProgramData, Log, Economics, Binding, token executable, token ProgramData, Token Config, MORSE mint, Oracle, reserve profile, rewards executable, rewards ProgramData, SPL Token, ATA, System |
|14 open | epoch:u64 | payer SW, Pool, token Pool, main Epoch W, token Epoch W, System |
|15 begin | empty | C |
|16 append | empty | C; then each ordered Witness, Bond, Pending, Member quartet, in bounded batches |
|17 finalize | empty | C; reserve Allocation W, reserve ATA W, Pool MORSE ATA W, reserve receipt W, payer SW, SPL Token, System |
|18 MORSE claim | row:u8 | Pool, token Pool W, main Epoch, token Epoch W, Pool MORSE ATA W, registered payout MORSE ATA W, MORSE mint, SPL Token |
|19 cancel | empty | C |

The token tag12 CPI roles are: Pool signer, token Pool, main Epoch, token Epoch,
profile, Config, MORSE mint, Oracle, reserve Allocation W, reserve ATA W,
Pool MORSE ATA W, receipt W, payer SW, rewards executable, rewards ProgramData,
judge executable, judge ProgramData, Economics, Binding, token executable,
token ProgramData, SPL Token, System. A direct caller cannot sign the Pool PDA.
These contracts are local implementation; see the exact scoped proof checkpoint
for passed cases and unresolved integration/live gates.

### Prepared Mesh rewards v2 instructions

`Transparency.TokenWrite` constructs token tag11 and rewards tags13 through19
from pinned context, canonical PDAs and exact per-role signer/writable flags.
Append accepts one to three strictly ordered authenticated witness identities;
it does not drop Registered, excluded or zero-weight attendance rows. The program
still requires every row in the sealed epoch before finalization. The builder
does not authenticate caller-supplied account structs or assert chain finality.

MORSE tag18 and the compatible USDC tag8 claim builders use the immutable decoded
finalized row's registered payout. Each has a separate canonical idempotent ATA
setup builder, so an absent payout ATA does not require a substitute recipient.
An arbitrary payer may pay that account's rent without becoming its owner.
The local proof compares34 Mesh-generated instructions against independent
Solana SDK vectors, then signs and executes those exact instruction bytes and
role flags through real SBF and SPL/ATA programs. It includes all64 attendance
rows, both claim bitmaps, missing payout ATAs and replay rejection. A forced late
reserve SPL transfer failure rolls back both allocation snapshots, all accounting
and a pre-existing System-owned receipt's rent/data; retry succeeds after funding.

The v2 raw codecs and prepared instructions are additive. A full-context finalized
v2 reader and keeper policy are separate requirements; preparing bytes does not
authorize signing or broadcasting them. Existing USDC earnings and claims remain
independent of MORSE price availability. New or reactivated capacity admission
must authenticate fresh complete TWAP whenever MORSE principal participates in
directory coverage, even when the new deposit itself is USDC.

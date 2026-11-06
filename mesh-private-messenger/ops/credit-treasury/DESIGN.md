# Credit treasury: proposed local implementation boundary

This is the implementation boundary and local qualification plan. No issuer
route, worker, production custody setting or live chain submission is enabled
by this directory.

The existing issuer already seals an independent Ed25519 deposit key for each
immutable quote. Its quote row records payment metadata only in the same commit
as blind issuance. Consequently, rejected underpayments have no durable payment
record yet. No existing worker sweeps, refunds or allocates weekly revenue.

## Custody and supported operations

Keep observation, allocation and transaction policy in Mesh. A separate privileged
Mesh worker unseals only the keys selected by an immutable movement intent, using
`StorageKey.file`; it never accepts a raw signing request from the purchase HTTP
service. The native customer wallet SDK remains separate. Pin cluster, providers,
USDC mint, treasury owner/ATA, fee payer, nonce accounts/authority and rewards
program/pool in operator configuration. Persist their hash with each intent.

Initially support the same finalized legacy SOL/System and USDC/TransferChecked
purchase shapes as `Payment.Verify`. A refund request contains only quote ID and
payment signature. Derive its destination from the verified original sole payer:
the payer itself for SOL or that payer's canonical pinned-mint ATA for USDC.
The requester cannot choose a recipient. Return the entire underpayment; pay chain
fees from a separate treasury fee payer. Do not classify fees or ATA rent as sales.
Do not close deposit ATAs in this slice or sweep arbitrary account balances.

A sweep reserves only an issued payment's verified amount, including the accepted
at-most-1% overpayment. An underpayment is reserved for its refund. Unobserved
transfers, unsolicited donations and other account balances confer no revenue or
spending authority. Persist a random bounded sweep delay once; a restart must not
resample it. Bound a batch to four movements and the serialized packet limit.

## Durable rows and lock ordering

Migration003 adds issuer-only tables, without core/user/nullifier linkage:

| Record | Immutable content and role |
| --- | --- |
| Payment observation | Unique chain signature, quote, finalized slot/time, payer, asset/mint, verified amount, exact signed-wire hash; disposition accepted/underpaid/unsupported |
| Movement and allocations | Stable ID, sweep/refund kind, fixed source/destination, amount, observed payment allocations, policy/config hash, ready time and nonce-account reservation |
| Movement attempt | Exact message, complete signed packet/signature, nonce value, fee reservation and finalized execution evidence; committed before network submission |
| Revenue event | One per issued payment; original asset units and payment time, with durable recognition cursor; never synthesized from treasury balance |
| Weekly batch | Frozen event cutoff/membership hash, 20/80 split and per-asset fifths carry; immutable reward-funding child intents and final receipt evidence |

Use one documented order: quote/payment ownership lock, then payment allocations,
then movement/nonce reservation. No RPC or key prompt under PostgreSQL locks.
Unique payment allocation constraints and revision fencing prevent a sweep and a
refund from spending the same units. The current issuance transaction must add
its revenue event atomically with the response before any signature is returned.
Refund observation/classification is distinct from payment acceptance; relaxing
underpayment observation must never relax issuance eligibility.

## Submission and recovery

Movement states are reserved, signed-unknown, finalized-success,
finalized-failure and blocked-history. Persist packet and signature before any
broadcast. A timeout cannot release its allocation or authorize another payment.
Authenticate finalized transaction signatures, full message and exact transfers
before finalization; RPC acknowledgment alone is not a successful movement.

Use a separately reserved durable nonce account for each in-flight lane. The
transaction's first instruction advances it, followed by bounded transfer
instructions. Reuse the exact packet after interruption. A changed nonce alone
is not success: execution can fail after nonce advancement while fees still
commit. A missing/pruned history result remains blocked; never blindly rebuild
with a new nonce or recent blockhash. Current public Mesh has no Solana nonce
primitives in its previous API. The new public `Solana.Nonce`,
`Solana.TransactionWrite` and finalized-outcome APIs are qualified against
independent SDK vectors and actual local Agave System Program execution, including
nonce advancement after failed transfer. No runtime or app-only Rust signing
implementation is needed.

The official [nonce contract](https://solana.com/docs/core/transactions/durable-nonces)
warns that durable nonces may be deprecated in a future release. This qualification
supports the current nonce format and must not imply future deployment support.
[Submission acknowledgment](https://solana.com/docs/rpc/http/sendtransaction)
is distinct from finality. Status recovery must request
[transaction history](https://solana.com/docs/rpc/http/getsignaturestatuses).

## Weekly accounting and rewards handoff

Use the plan's pre-token 20% witness / 80% operations allocation. Keep independent
asset ledgers: split integer USDC base units and SOL lamports with a 0..4 fifths
carry so fragmentation cannot lose the witness's fraction. Recognition begins
only on issuance commit; accepted overpayment is included. A late recognition
appears as an explicit next-batch adjustment, never a rewrite of a closed batch.
A source payment week and accounting batch are retained separately.
Immutable multi-payment packet batches contain up to four canonically ordered
movements, bounded by the complete1,232-byte signed packet. Batch membership,
message, packet, signature and per-attempt fee/rent allocation are durable before
broadcast. All members share one atomic finalized outcome; failed or uncertain
packets cannot partially release reservations. Shared destination ATA creation
is deduplicated, and its rent is allocated once. The separate payer covers costs
without reducing customer transfer amounts.

SOL's witness allocation remains explicitly conversion-pending. It is not USDC
rewards funding. A later separately reviewed pinned swap adapter must account for
actual finalized USDC output and conservation before it can discharge that SOL
liability. No implicit quote-price conversion or unaudited aggregator call.

For settled USDC, create a stable rewards `kind:0` funding intent and operation ID
inside the weekly-batch transaction. The existing rewards operator signs and
journals its packet, while the program's permanent receipt proves the exact
amount/pool/funder/source/mint/epoch intent once. Fund only the chain's current
rewards epoch; retain the originating accounting week separately. If an unfunded
intent misses that epoch, first reconcile its canonical receipt, prove the old
intent can no longer create a receipt, then create one linked current-epoch child
for the still-reserved liability. Never reuse a funding ID with changed epoch.
Floor subsidy (`kind:1`) is distinct and must not absorb credit revenue.

No quote IDs, buyer wallets or per-purchase rows need publication with aggregate
weekly totals. Those remain confined to the issuer database and the already
public chain, never copied into the redemption core.

## Required proof before activation

- Actual SDK-signed finalized SOL/USDC observations, underpayment and wrong-payer,
  quote, mint, reference, token program and >2^53 amounts.
- Owned PostgreSQL concurrent issuance/refund/sweep allocation races and rollback.
- Actual local nonce creation/advancement, exact replay rejection, execution-failure
  nonce advancement, malformed owner/version/length and unauthorized prefix.
- Forced interruption before/after packet commit and after successful transfer but
  before response; restart retains exactly one movement and its signed bytes.
- Missing/pruned history and nonce changes never invent success or authorize a
  second transfer. Fees are separately reserved even for failed transactions.
- Weekly split dust conservation, late recognition, no donation attribution, no
  subsidy conflation, and exact permanent rewards receipt reconciliation.
- SOL conversion-pending liabilities cannot become USDC-funded status.

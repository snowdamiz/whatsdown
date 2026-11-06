# Credit payment verification

`Payment.Verify.verify_credit_payment` fetches the transaction itself from the
issuer-configured Solana RPC. It accepts no caller-provided payment Boolean,
parsed instruction, balance or execution status. Unknown transactions return
`None`; malformed, failed or mismatched proofs return an error. Issuer routes
must use this fetch boundary. `verify_payment_response` is an offline replay
helper for trusted captured RPC responses, not an HTTP approval endpoint.

Launch supports a single signed payer and one top-level payment, preceded by
zero, one or two compute-budget limit/price instructions and, for USDC, one
optional canonical ATA CreateIdempotent. Duplicate compute settings, extra
programs/transfers, memo instructions, arbitrary setup, multisig/delegated
spending, token-2022, inner-only transfers, unrecorded inner execution, and ALT
messages are rejected. The reference is exactly the quote ID, appended to the
transfer as a read-only nonsigner, following the Solana Pay reference convention.
Every account address and role comes from the authenticated signed message.

Asset 0 is six-decimal legacy SPL USDC. Mint comes from trusted issuer
configuration, and must match the quote and `TransferChecked` instruction.
Source is the payer's canonical ATA and destination is the fresh deposit
owner's canonical ATA. Both recorded token owners/programs/mints/decimals and
exact source/destination token balance changes must match. ATA setup must use
the canonical ATA program, six exact accounts and data byte1. Existing ATAs
produce no CPIs; new ATAs permit only the matching recorded setup group: token
GetAccountDataSize, System CreateAccount (or the prefunded ATA transfer/allocate/
assign path), token InitializeImmutableOwner, and InitializeAccount3 for the
quoted deposit owner. Exact data, account addresses, order and rent changes are
checked; all other inner groups/operations fail. A prefunded ATA cannot bypass
recipient checks or redirect funding. Asset 1 is native
SOL: exact System `Transfer`, quoted destination equal to deposit owner,
recipient increase equal to the encoded lamports, and payer decrease equal to
payment plus the recorded fee. For USDC the payer decrease also includes only
the verified destination ATA rent increase. Other lamport balances remain
unchanged. Unused extra accounts are rejected.

Received amount must be at least the quote and at most floor(quote * 101/100),
using u128 intermediate arithmetic. No floating point or JavaScript Number is
used for chain amounts. Quote duration is exactly 900 seconds; block time must
be in `[issued_at, expires_at)` and no later than verifier time. For SOL the
issuer-owned oracle observation must be at most 60 seconds before quote
issuance and never in its future. A fixed quote does not reprice while waiting
for finality. Historical re-verification after expiry is allowed when the
transaction's block time was inside the original window.

The receipt contains the exact transaction signature, sole signed payer, slot,
block time and received amount. Fresh/unique quote IDs and deposit owners,
prepayment blind-batch commitment, global transaction-signature uniqueness,
idempotent issuance and durable receipt claiming belong to the issuer ledger.
A public onchain reference cannot authenticate an HTTP claimant; the quote
must already bind its blind batch before payment becomes public. Payer records
remain in the issuer database, away from redemption services.

RPC finality/status/balance/time remain assertions by the configured RPC;
message signatures are verified independently. Local loopback tests use real
SDK/OpenSSL-signed wire fixtures and synthetic finalized RPC metadata. Three
additional fixtures execute real bundled SPL/ATA SBF in LiteSVM, creating an
absent ATA and exercising both low-dust and fully prefunded System accounts.
Their recorded CPIs, actual balances and fees pass the same compiled RPC
policy. Local VM blockhash checking is disabled for the fixed signed fixture;
signature and program execution checks remain active. Tests do not claim
mainnet execution or a light-client inclusion proof. Tests execute the
actual compiled Mesh fetch and policy, including signed wrong payments,
precision above 2^53, pending/retry, historical replay, crossquote references,
wrong RPC IDs, execution failure, malformed versions/indices and oracle expiry.

References: [Solana Pay](https://docs.solanapay.com/spec),
[Circle USDC addresses](https://developers.circle.com/stablecoins/usdc-contract-addresses),
[Solana RPC getTransaction](https://solana.com/docs/rpc/http/gettransaction).

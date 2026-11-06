# Custom wallet custody boundary

This is the custom Morse wallet-core crate approved for seed custody and Solana
signing. It is not Trust Wallet or a general wallet SDK. Blind RSA, credits
pricing, issuer decisions, receipt policy, network transport and token storage
remain in public Mesh/runtime or Mesh application modules. The Rust crate has
no network API and never receives a payment-success Boolean.

## Privileged interface

The C ABI is specified in `include/morse_wallet_core.h`. Only trusted native
host code calls it. It offers creation, the local payment public key, a reserved
bounty public key, a constrained quote-payment packet, and a constrained
two-signer transfer from a reserved bounty key. There is no seed
import/export/reset, arbitrary derivation path, generic message signing or
secret-to-Mesh/JavaScript operation. Public addresses and signed packets are the
only outputs. Native host code must keep the payer address off core/edge
requests; finalized payment verification happens at the issuer.

Callbacks are borrowed for one synchronous invocation and never retained.
They must not throw across C. Native acquire/release serialize every process
sharing a wallet. Load copies a sealed-at-rest record directly into a
Rust-owned zeroizing buffer. Replace must atomically commit an authenticated,
sealed replacement and acknowledge only after durable persistence. A process
mutex or generic keychain get/put without this transaction contract is
insufficient. Apple/Android/desktop storage adapters are separate native host
components; their platform tests are additional gates.

Creation, payment and bounty movement require a foreground native confirmation. The callback
must cancel when dismissed or backgrounded. It must never accept an approval
Boolean from JavaScript. The SDK releases storage locks before prompting and
rereads the seed afterward. The quote expiry is checked both before and after
the prompt. The pure `morse_wallet_authorization_text` helper emits bounded
UTF-8 with exact integer decimal amounts, purpose, credits, payer, destination,
deposit owner, reference, issuer key, batch commitment and expiry. It discloses
public payment visibility and additional fees/rent. It neither authorizes nor
signs. Test/live describes credit purpose, not the Solana cluster or whether
money has value.

## Derivation and persistence

A CSPRNG creates a 32-byte seed. Hardened Ed25519 derivation follows
[SLIP0010](https://github.com/satoshilabs/slips/blob/master/slip-0010.md):

- payment: `m/44'/501'/0'/0'`;
- bounty: `m/44'/501'/2147483647'/index'`, with `0 <= index < 2^31`.

The fixed internal record is `MWL1 || seed[32] || next_index:u64LE`, 44 bytes.
It is not a public serialization/export format. Malformed, truncated, oversized
or exhausted records fail closed and are never regenerated automatically.
Reserve increments and durably replaces the record before deriving or returning
the corresponding public address. An interrupted or unknown outcome can burn
an index. It must never return an address before the reservation commits.

Local wallet loss, locked OS credentials or loss of the sealed record can make
funds inaccessible. This initial interface has no seed recovery/export path.
Do not restore an older seed/counter backup: rollback can repeat bounty indices.
Native storage must refuse unsafe or partially committed state; this crate
cannot detect a privileged rollback of all trusted host storage. Rooted hosts,
process memory compromise and malicious native callbacks are outside this
custody boundary. Zeroizing buffers reduce retained copies; they are not a
claim that every compiler register, stack slot or platform callback is erased.

## Exact payment shape

The trusted Mesh journal verifies issuer authorization before native export of
a raw CQT224. The SDK checks the complete canonical quote: magic/size, purpose,
credit pack, nonzero pins and references, exact 900-second window and USDC
amount equal to `credits * 50_000`. The native configuration supplies the fixed
nonzero USDC mint even when signing SOL. SOL has zero mint and destination equal
to the one-time deposit owner. All account roles are distinct.

Rust reconstructs a legacy message from the quote, local payer and supplied
recent blockhash. SOL contains exactly one System transfer with the readonly
quote reference. USDC contains canonical Associated Token Account
CreateIdempotent followed by SPL TransferChecked (six decimals), with both ATAs
derived from owner/token-program/mint and the readonly reference. There are no
ALT lookups, compute-budget additions, arbitrary instructions or arbitrary
private messages. A transaction is at most 1232 bytes. Ed25519 signing is
followed by strict public verification before output.

The official [Solana transaction format](https://solana.com/docs/core/transactions)
and [associated-token-account derivation](https://www.solana-program.com/docs/associated-token-account)
are the external format references. The separate Mesh payment verifier checks
finalized execution, balances, mint, destination, reference and quote time.

## Exact bounty transfer shape

SDK operation 5 accepts the fixed BWT166 intent documented in the C header.
It derives only an index already reserved by this wallet and verifies its
public key against the intent. It constructs exactly ATA CreateIdempotent and
SPL TransferChecked from that finder's ATA to the destination owner's ATA.
The separate payment key pays fees; both keys sign the same legacy message.
The destination may be this wallet's payment address. Self-transfers, role
aliasing, zero values, unknown indices and malformed bounds are rejected.

The intent includes an exact amount, mint, decimals (0 through 18), purpose,
blockhash and a five-minute confirmation window. A native USDC mint requires
six decimals. Other legacy SPL mints are explicitly identified by address;
the pure confirmation formatter does not invent a token symbol. It explains
that movement links the one-time address to the destination and fee-paying
wallet publicly, and shows additional fee/rent responsibility. Expiry and
wallet continuity are checked again after confirmation. No fee payer or
finder secret leaves Rust. There is no Token-2022 or arbitrary instruction API.

The SDK only signs. Mesh must authenticate the bounty receipt and release pins,
reserve an immutable intent, verify the exact signed packet and persist it
before submission. Host submission/recovery and the withdrawal UI remain
separate gates; a passing signer proof is not a usable withdrawal flow.

## Pinned implementation dependencies

Direct versions are exact and the independent Cargo.lock is committed with the
crate: ed25519-dalek 2.1.1; getrandom 0.3.4; hmac 0.13.0; sha2 0.11.1;
zeroize 1.8.2; subtle 2.6.1; solana-address 2.9.0; solana-hash 4.6.0;
solana-instruction 3.5.1; solana-message 4.6.0. The instruction crate currently
reexports its compatible 4.0 implementation. Message serialization uses its
wincode feature, with wincode 0.6.3 locked transitively, and no bincode dependency.
Dalek also uses its own sha2 0.10.9 provider. HMAC/SHA2/Zeroize/getrandom are
MIT OR Apache-2.0, Dalek/subtle are BSD-3-Clause, and these Solana SDK crates
are Apache-2.0. Check registry metadata and advisory results when updating.

HMAC-SHA512 and hardened child derivation use private zeroizing buffers.
The enabled RustCrypto zeroize features clear provider state on drop, and
Dalek's zeroize feature clears its signing key. No custom big-integer or RSA
implementation is added. A local cargo-audit run against this lockfile found
zero vulnerabilities and zero warnings; this is a point-in-time advisory
check, not an external security audit or release approval.

## Local proof

`scripts/prove-wallet-core.sh` runs focused Rust tests, an independent Node
HMAC/Ed25519 derivation oracle, official @solana/kit message encoding and real
LiteSVM System/SPL/ATA execution. Kit and Rust SDKs choose different legal
account orders; the proof reindexes Kit's compiled message into the Rust SDK's
raw-address order before comparing the complete message and OpenSSL signature.
It verifies 256 bounty addresses and submits all resulting payment fixtures
through the actual compiled Mesh finalized-transaction parser over loopback
HTTP, including a SOL amount above 2^53 and absent, prefunded and existing ATAs.
All seeds, signatures and balances used by these fixture tools are public test
data. No proof moves live funds or queries a live RPC.

The bounty-transfer proof independently constructs four complete Kit messages
and eight Node/OpenSSL signatures, then executes those packets against the real
SPL/ATA programs. It covers fresh, prefunded and existing destinations, a
distinct fee payer, amounts above 2^53 through u64::MAX minus one, decimals
0/6/18 and eight same-bank duplicate rejections.

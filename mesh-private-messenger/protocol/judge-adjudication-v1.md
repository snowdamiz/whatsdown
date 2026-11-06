# Judge fork adjudication and receipts v1

This is the local ABI for atomic USDC fork settlement, implemented in the
Pinocchio judge. The program still needs rewards, later token support,
production governance verification and external review before an immutable
deployment. These tests use disposable wallets, a local six-decimal mint and
LiteSVM; they do not establish a funded deployment or live finality.

## Admission

Tags 22, 23 and 24 adjudicate FRK kinds 1 (same-size equivocation), 2
(contradictory inclusion) and 3 (rollback). Each uses a sealed Stage and its
verified signature bits, described in `judge-stage-v1.md`. Both legacy and
RFC 6962 log profiles retain their own Merkle hashing rules. The instruction
payload after the tag is exactly the expected second checkpoint hash (32 bytes).
For an anchor target, this also prevents a ring overwrite between preparation
and execution from silently changing the checkpoint being adjudicated.

The first checkpoint must have a verified service signature. A fully supplied
second checkpoint needs its own verified service signature. A ring reference
instead authenticates the registered ring, occupied index, checkpoint version,
posting slot, expected checkpoint hash and exact historical witness generation.
The current generation cannot reinterpret an old bitmap. Generation zero uses
the Log account as the explicit empty-set sentinel. The program checks the
fork relation independently of signatures; signed honest growth is not a fork.

Neither checkpoint may be in the future relative to the chain Clock. The older
checkpoint's service-signed millisecond timestamp must be at most 28 days old,
inclusive. The window is a compiled constant, not governance policy. Uploading,
verifying or replaying a Stage does not refresh timestamps.

Only verified optional attestations can accuse a witness. For two supplied
checkpoints the exact ID and immutable signing key must sign both hashes. For
a ring target the same key must also be in its historical bitmap. Kind 3 uses
only native signatures and the ring's native bitmap: C2SP does not attest
Morse's sequence metadata. Duplicate annotations do not duplicate a slash; a
bad optional signature cannot suppress a valid duplicate. Service-only evidence
can slash the directory. Invalid or unverified annotations do not accuse keys.

The uploader authorizes optional witness verification writes. Service
verification and final settlement remain permissionless. This prevents a third
party from forcing an optional unfunded identity into an existing Stage's
required settlement accounts. The uploader must select collectible evidence
before authorizing those bits. Once verified, an implicated identity cannot be
omitted from that Stage's settlement; an incompatible account list is refused.

## Accounts

`S` means signer and `W` writable. All other accounts are read-only. The first
12 accounts are fixed:

| Index | Account |
|---:|---|
| 0 | Transaction/rent payer S/W |
| 1 | Registered Log W |
| 2 | Sealed Stage |
| 3 | Per-log Economics W |
| 4 | Proof receipt W: `["proof", log_id, FRK_hash]` |
| 5 | Directory Bond W |
| 6 | Directory Bond's associated token vault W |
| 7 | Finder's associated token account W |
| 8 | Locked authority's associated token account W |
| 9 | Configured mint |
| 10 | Classic SPL Token program |
| 11 | System program |

An anchor target adds the Ring and historical WitnessSet immediately after
these accounts. Each unique implicated witness then adds its immutable Witness
record W, Bond W and associated token vault W. Order is first appearance among
verified first-checkpoint attestations. Counts are exact: no omitted victim or
extra account is accepted. Up to sixteen witness triples fit in a v0 transaction
using an address lookup table. The largest anchored settlement uses 64 runtime
account keys including the judge and compute-budget programs. Lookup tables
must already be created, extended and active.

The submitter creates destination ATAs idempotently before settlement. The
finder owner is the FRK's nonzero address, otherwise the original Stage
uploader. A different final transaction payer cannot redirect that fallback.
The locked owner is the PDA `["locked", log_id]`; its ATA is derived with the
configured mint. Neither destination can alias any source vault or each other.
Missing or substituted ATAs are refused. Settlement itself needs no ATA-program
CPI or additional destination owner accounts.

The finder field is not signed by checkpoint signers. Stage binding protects
an existing upload; it does not establish exclusive ownership of discovering a
fork. Another party with the evidence can construct a competing upload with a
different finder. The first successful settlement wins the shared receipt PDA.
No claim of public-mempool front-running protection is made by this ABI.

## Atomic settlement

Every source is authenticated against the immutable log, configured mint,
registration identity, owner, PDA and canonical token vault. Witness lifecycle
mirrors and aggregate principal must agree. Active and Unbonding bonds are
collectible. Withdrawn, unregistered or absent bonds are refused. Already
Slashed identities may participate with zero principal and zero new payout;
their later vault donations cannot earn another finder payment.

Settlement transfers the entire actual balance of each collectible vault,
including donations. For each vault separately, the finder receives
`floor(balance / 10)` and the locked ATA receives the remainder. Token transfers
use the authenticated Bond PDA signer and the configured six-decimal mint.
Only implicated principal is subtracted from the witness aggregate. All
implicated collectible witnesses and the directory become Slashed; principal
is zeroed and the Log's service-slashed flag is set. Unimplicated witnesses
retain their bonds and ordinary owner withdrawal rights.

The receipt is rent-funded with prefunding-safe PDA initialization in the same
transaction. Allocation, all token transfers, lifecycle writes, counters and
receipt creation either commit together or roll back together. A transaction
with no newly collectible assets fails. There is no locked-vault withdrawal,
receipt reset or receipt-close instruction.

The FRK hash excludes the finder, so changing that address cannot pay the same
proof again. Reordering or adding annotations changes the hash but cannot
recover an already-slashed bond. A later proof may identify an additional
double-signer and collect that still-active bond after the directory was
already slashed. Its receipt records zero for previously settled identities.

## Receipt layout

The judge-owned receipt is `288 + 96 × witness_count` bytes. Integers are
little-endian. Reserved bytes are zero.

| Offset | Bytes | Field |
|---:|---:|---|
| 0 | 4 | `MPR` followed by byte `1` |
| 4, 5, 6, 7 | 1 each | kind, anchored flag, witness count 0–16, reserved |
| 8 | 32 | Log ID |
| 40 | 32 | Finder-independent FRK hash |
| 72 | 32 | Resolved finder wallet |
| 104 | 32 | Original Stage uploader |
| 136 | 32 | Mint |
| 168, 200 | 32 each | First and second checkpoint hashes |
| 232 | 8 | Chain Clock slash time, nonnegative signed seconds |
| 240 | 8 | Total amount newly slashed |
| 248 | 8 | Total finder payment, sum of per-vault floors |
| 256 | 8 | Directory amount newly slashed |
| 264 | 8 | Stage verified-signature bitmap used for this verdict |
| 272 | 16 | Reserved |
| 288 onward | 96 each | Witness rows |

Each row contains the Witness PDA (32), immutable signing key (32), removed
principal (8), newly slashed vault amount (8), finder payment (8) and eight
reserved zero bytes. This records the historical payment; the finder's present
wallet balance may differ after they spend or transfer it.

Mesh's `Transparency.SlashReceipt` codec rejects truncated/noncanonical layouts,
impossible signature flags, repeated identity rows and inconsistent payout sums
without narrowing u64 money values. `Transparency.SlashReceiptRead` derives the
receipt PDA and authenticates Log, Economics and receipt together using two
distinct finalized RPC origins. It checks the release-pinned service, profile,
program, log and mint before publishing decimal-string amounts.

## Dogfood and verification

`morse receipt --log LOG_NAME --proof LOWERCASE_SHA256_HEX` reads an authenticated
receipt using the same `MESSENGER_SECURITY_CONFIG`, `MORSE_BOND_MINT`, optional
`MORSE_BOND_LOG_VERSION` and `MORSE_BOND_MIN_CONTEXT_SLOT` pins as `morse bonds`.
Missing, stale, conflicting or wrongly owned accounts produce an error and no
payout report. A relay's claim that a transaction succeeded is insufficient.

Run `bash scripts/prove-adjudication.sh` from `mesh-private-messenger`, with
`MESHC` and `CARGO_BUILD_SBF` set when using local toolchains. It builds fresh SBF
objects, rejects compiler stack diagnostics even when the compiler exits zero,
runs all judge tests, exports actual receipt accounts, and replays them in Mesh.
CI transfers the SBF and both custody/receipt fixtures with SHA-256 checksums.

The SBF tests cover all three kinds and both log profiles; age boundaries;
unbonding and withdrawal; key rotation and historical attribution; native/C2SP
distinctions; finder substitution and fallback; donations and rounding; failed
transactions after successful token CPIs; replay across finder/annotation
changes; and later additional double-signers. Shared OpenSSL/Mesh signed-proof
vectors run through actual staging and token settlement. Maximum native and
C2SP contradictions include 32 attestations, sixteen 64-byte IDs, maximum u32
tree sizes and two 32-level paths. Both supplied-checkpoint and anchored forms
execute atomic sixteen-witness payouts using real lookup-table and token
programs, within the transaction packet, account and compute limits.

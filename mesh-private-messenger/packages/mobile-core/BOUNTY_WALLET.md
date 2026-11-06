# Native finder selection

The collection preference is off by default and sealed in `fork-bounty/v1`.
The trusted native wallet host checks that SDK operation 2 can open the wallet
before enabling it. Disabling collection does not require wallet access.

After verifying a fork, Mesh atomically retains the first proof and captures
that preference with a single SQLite compare-and-swap transaction. Incoming
finder bytes are stripped. Raw zero-finder evidence independently maintains
the security pause. Later valid proofs cannot evict it. Preference changes
affect future detections and cannot change the finder of retained evidence.

If collection was enabled, both evidence export and automatic filing refuse
to disclose the proof until native wallet orchestration resolves the choice.
The host reads `bounty_status`, privately calls SDK operation 4, then commits
its exact 40-byte index/address response against the retained proof's SHA-256.
This identity hashes the complete raw zero-finder FRK, and is distinct from
the judge's fork hash. The SDK durably increments its derivation counter before
returning an address. A racing reservation may burn an unused index; it cannot
overwrite the winner. Selected addresses and indices stay in sealed storage.

A failed SDK reservation selects a durable, visibly unavailable zero finder,
so wallet failure does not suppress evidence. It cannot be changed after
disclosure. Evidence from older builds preserves its original finder exactly,
because it may already have been exported or filed. Filing workers check both
native configuration and the exact frozen evidence before network activity;
erased or replaced evidence invalidates a queued worker.

## Byte boundary

`bounty_status` takes the raw UTF-8 database path. Its counted-vector response
has six fields: `01 42 46 50` (`BFP`), enabled byte, status byte, raw proof
SHA-256, finder address, and derivation index as unsigned 64-bit big endian.
The hash and finder are empty when no proof exists; a pending finder is empty.
The index is zero except when an SDK address has been selected.

| Status | Meaning |
| --- | --- |
| 0 | No retained proof |
| 1 | Awaiting native wallet selection |
| 2 | Collection was off at detection; zero finder |
| 3 | Selected SDK address |
| 4 | Wallet unavailable; zero finder |
| 5 | Frozen evidence from an older build |

Three exports use counted inputs and return the same view:

| Export | Input |
| --- | --- |
| `bounty_set_enabled` | database, one enabled byte |
| `bounty_commit` | database, raw proof hash32, SDK reservation40 |
| `bounty_unavailable` | database, raw proof hash32 |

Those three exports are host-private. Desktop must deny them at its public
invoke dispatch; Swift and Kotlin must omit them from generic invoke switches.
Generated bindings alone do not grant invocation authority. Public wallet host
operation 7 takes only the enabled byte and supplies its own database path.
The generic JavaScript bridge must not expose raw SDK operation 4.

Preflight both `transparency_fork` and `fork_filing`: read the status, resolve
status 1 through SDK reservation/commit, then invoke the original export.
On a compare-and-swap or frozen-selection race, reread the status and continue
only when terminal; retry boundedly while still pending. A commit/storage
failure is not an SDK failure and must not silently replace a reserved address
with zero.

The domain, native byte boundary and eight-writer race proofs are in
`tests/bounty*.test.mpl`. Native host/UI integration and fresh platform artifacts
are separate gates. No local proof claims a live finder payment.

## Moving a paid bounty

The native host operation8 accepts a destination owner and obtains the payer
from SDK operation2. Mesh derives the selected finder/index from sealed local
custody and independently reads the finalized slash receipt, mint and source
token account through a two-of-three pinned RPC quorum. It transfers exactly
the receipt's bounty amount; unrelated deposits never enlarge it. This works
with the optional credit issuer disabled. Source authority, mint initialization,
token decimals and sufficient units are checked before a signing prompt.

Private `bounty_transfer_prepare` accepts counted `[database,destination32,payer32]`
and returns six fields: `01BMP`, filing identity32, needs-signature byte, SDK
`BWT` intent166, signature0/64, status byte. The host passes that intent directly
to SDK operation5. Its native prompt shows the exact quantity/mint, destination,
finder and fee-paying wallet, including that the public move links these
addresses and incurs separate fees/rent. Generic JS cannot invoke SDK5 or the
three private Mesh prepare/commit/submit exports.

Private commit takes `[database,identity32,packet]`. Mesh verifies both signatures
and the complete canonical ATA-create plus SPL TransferChecked instructions,
account-role union, payer, mint, amount and blockhash. The signed packet is sealed
in `bounty-transfer/v1` before any broadcast. The SQLite CAS simultaneously checks
the selected-bounty record, so an operation racing account erasure cannot
recreate its journal. Private submit takes `[database,identity32]` and sends only
the stored bytes, with bounded requests, fixed RPC IDs and no redirects.

Public `bounty_transfer_status` takes the raw database path; `recover` and `cancel`
take counted `[database,identity32]`. All return twelve counted fields: `01BMW`,
identity, status, signature, finder, destination owner, mint, amountu64BE,
decimals byte, fee-lamportsu64BE, finalized-slotu64BE, execution-error UTF8.
An empty journal has an empty identity/address/signature and zero quantities.
Status0 means absent/cancelled unsigned, 1 awaiting approval, 2 signed-unknown,
3 RPC-acknowledged, 4 finalized-success, and 5 finalized-failure. Cancel can only
abandon an unsigned intent. A cancelled or expired unsigned plan can be prepared
again; a stale prompt cannot commit after its blockhash/time window changes.

Recovery requires two providers to authenticate the exact transaction and agree
on finalized slot, fee and outcome. Successful execution also requires exact
source/destination token deltas with the expected owners, program and decimals.
Only a proved failure permits another signed attempt; the old packet/fees are
archived atomically with the new plan. Success is permanent for this proof.
Missing transaction history stays unknown even after expiry: an RPC `null`
does not prove nonexecution, and the app never signs a second payment on that
basis. This conservative case needs restored provider history before automatic
resolution. See the [Solana transaction lookup contract](https://solana.com/docs/rpc/http/gettransaction).

`packages/wallet-core/tests/bounty-network.test.mjs` builds the real Mesh driver,
uses the actual SDK, executes real SPL/ATA programs and destroys the first
acknowledgment. Fresh processes prove the packet existed before sending and
recover the same signature; the proof covers provider disagreement, altered
token deltas, expiry, stale prompts, concurrent commits and account erasure.
Its generated fixtures replace transport endpoints with owned loopback servers;
release HTTPS validation remains unchanged. These proofs and the independent
SDK wire oracle are mandatory in `scripts/prove-wallet-core.sh`.

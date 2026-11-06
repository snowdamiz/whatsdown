# Relay admission and settlement preparation v1

Status: local implementation. This boundary prepares unsigned instructions in
Mesh. JavaScript signing, the spending journal and RPC adapter consume this boundary;
funded qualification and phone autofiling remain
unfinished. The on-chain contract is [judge-adjudication-v1.md](judge-adjudication-v1.md).

`Transparency.RelayAdmission.admit_relay_fork` accepts operator-pinned program,
log, service key, log version, mint, independent RPC endpoints and submitter,
plus the original bounded FRK. HTTP clients do not supply an account list or
transaction. The native `tools/fork-verifier` command exposes preparation as:

```sh
morse-fork-verifier --input evidence.frk --submitter PUBKEY --mint MINT
```

`MESSENGER_SECURITY_CONFIG` supplies the existing native anchor pins;
`MORSE_RELAY_LOG_VERSION` selects 1 or 2 and
`MORSE_RELAY_MIN_CONTEXT_SLOT` supplies a canonical unsigned slot floor.
The command's original `--input` mode remains cryptographic preflight only.
Neither mode holds a signing key or submits a transaction.

## Admission order

1. Canonical framing, log/version binding, service signatures and signed fork
   relations are checked before network I/O. Invalid optional witness signatures
   do not invalidate directory evidence.
2. The derived proof receipt, Log and Economics are read as one finalized
   batch. Two independent providers must agree. A valid existing receipt returns
   `AlreadySettled` before ring, age or custody work. Missing and system-owned
   empty prefunded receipt accounts mean no settlement; malformed or foreign
   accounts remain errors.
3. Signed targets authenticate the Log and discover collectible historical
   witness identities without requiring an initialized ring. Anchor targets
   authenticate the exact ring entry and its immutable witness generation.
   Current membership cannot reinterpret a historical cosign bitmap. C2SP
   signatures cannot accuse a witness of rollback metadata equivocation.
4. The custody quorum binds mint, principals, actual vault balances and account
   identities. Active and Unbonding witnesses can be selected; withdrawn or
   previously slashed witnesses remain in the FRK but are omitted from Stage
   verification bits. A previously slashed directory contributes zero. There
   must be some collectible balance unless a receipt has appeared meanwhile.
5. The public Mesh `Solana.Read.clock_sysvar` decoder authenticates the sysvar
   owner and exact layout. Each finalized Clock must have an embedded slot equal
   to its RPC context. Two providers must independently accept both checkpoint
   times as nonfuture and the older time as no more than 28 days old, inclusive;
   selected bonds must not claim a future deposit time. Clock bytes need not
   match across different finalized banks. The judge checks its current Clock
   again during execution; admission is not a promise that a deadline will hold.
6. The exact finder and locked ATAs are derived locally and checked by another
   whole-batch quorum. Destinations must be distinct from each other and all
   source vaults. Existing destinations must be initialized classic token
   accounts for the expected mint/owner with no native reserve. Locked custody
   additionally forbids a delegate or close authority. Checked additions reject
   destination balance overflow. Missing or empty prefunded ATAs can be created
   by the prepared idempotent instructions. A final receipt check detects a
   concurrent winner before returning a plan.

The existing RPC trust assumption is at most one dishonest selected provider.
Errors never become an empty registry, zero balance, missing receipt or a
successful payout. Estimates include donations to collectible vaults and round
the ten-percent finder share down **per vault**, matching the judge.

## Prepared result

`relay_admission_report` emits schema version 1. A ready result contains the
unaltered proof, finder-independent proof hash, submitter, mint, receipt PDA,
Stage upload and signature-verification plan, two idempotent ATA setup
instructions, the ordered settlement instruction, observed Clock bounds and
context slot. Public `Solana.Tx.instruction_report_json` supplies ordered account
keys, signer/writable sets and instruction bytes. Token amounts and unsigned
slots are decimal strings to preserve full precision.

Ready reports also contain a compute-budget instruction and a lookup-table plan
from public `Solana.LookupTable` APIs. The table uses the submitter as authority
and refund recipient and the observed Clock context as creation slot. Addresses
retain settlement order, omit signers and duplicates, and extend in batches of
at most twenty. Preparation allocates nothing; a transaction assembler can skip
the table when the uncompressed settlement fits. Jobs using the same wallet and
creation slot derive the same table. The durable writer must serialize ownership
of that resource and use a new authenticated slot on a conflicting allocation.

A nonzero finder is preserved; zero resolves to the original Stage uploader.
The settlement includes the pinned second checkpoint hash. Optional witness
triples follow the first verified first-side occurrence in the FRK, independent
of RPC ordering. The Stage plan retains precompile index zero; the transaction
assembler must patch it to the actual earlier Ed25519 instruction position.

A settled result contains the independently authenticated on-chain receipt,
including its actual finder and submitter. That finder can differ from the
submitted proof if another reporter proved the same fork first. A relay HTTP
response or transaction signature alone is not proof of payment.

## Local proof

`scripts/prove-relay-admission.sh` exports fresh funded judge snapshots,
prepares plans through real Mesh RPC readers, executes their bytes in the
compiled SBF program with real Ed25519 and SPL Token CPIs, and authenticates the
resulting receipts in Mesh. It uses local test identities and no live funds.
The proof executable can be transferred with the tested SBF artifact to a Mesh
CI job; the script also supports building it locally with Cargo.

The nineteen settlement cases cover all fork kinds under both log versions,
historical native/C2SP cosigns after rotation to another key under the same ID,
and sixteen-witness signed/anchored contradictions under both profiles. The
maximum RFC signed proof is 8,009 bytes. Maximum settlements create and extend
a real lookup table, use a versioned transaction within 1,232 bytes and 64
account locks, and stay within 1.4 million compute units. Replays reuse the
table and cannot pay again. Mesh subsequently reads the actual SBF receipts.
These admission checks exercise unsigned Mesh preparation and SDK execution.
The JavaScript signing component has the additional proof described below.

`ops/relay/transactions.mjs` now assembles and signs these reports with pinned
Kit 8.4.0. It binds operator pins and original proof bytes, checks upload order
and the full hash, batches at most four verification pairs according to actual
packet size, and patches each judge instruction to its earlier Ed25519 position.
Only opaque steps produced by the local preparation boundary can be signed.
Maximum settlements use a validated lookup-table view and the Mesh compute
budget; all packets remain within 1,232 bytes.

`ops/relay/journal.mjs` adds SQLite durability, fenced worker leases, exact
message/signature authentication, per-job and rolling spending caps, and retry
backoff recorded before broadcast. Duplicate admission cannot replace the first
finder. A competing receipt preserves the original finder separately from the
actual winner and requires cleanup before completion. Finality/expiry and account
observations remain trusted local adapter inputs: the RPC recovery loop and
HTTP/manual entry points now use the serialized admission service. See the relay
README and runbook for that contract.

The native command exposes finalized lookup recovery as:

```sh
morse-fork-verifier --lookup-state --submitter PUBKEY --slot SLOT --addresses KEY,KEY,...
```

It derives the table locally and requires whole-account agreement from two
independent configured providers. Responses distinguish missing/prefunded,
partially extended, same-slot warm, ready and cooling tables. Wrong authority,
frozen accounts, changed address order or suffixes, future metadata and quorum
disagreement fail. A prefix allows the writer to resume at the next extension;
it never authorizes replaying an uncertain extension with a new signature.
Only a ready result authorizes signing a compressed settlement. Cooling does
not by itself authorize closure: SlotHashes must establish the end of cooldown.

The native command now exposes that prerequisite as `--lookup-close-state` with
the same submitter/slot/address arguments. Each provider supplies table, Clock
and SlotHashes in a single finalized account batch. Public Mesh decoders enforce
account ownership, layout, ordered history and the official cooldown rule. The
Clock's slot must equal the RPC context, and no history entry may be in its
future. Two independent providers must agree on the status and exact table
bytes; their changing sysvar bytes need not match. The returned context is the
lower accepted context and `remainingBlocks` is the larger accepted count.

`closable` requires a past deactivation slot absent from both accepted histories.
The deactivation slot itself remains `cooling` with 513 remaining blocks even
before it appears in history. A retained older slot has `512 - position`
remaining blocks. These are SDK status counts, not time estimates or proof of a
successful refund. Missing, mutable active, warming, partially extended and
cooling tables remain distinct, and changed/frozen authority or inconsistent
views cannot authorize closure. The writer must still journal submission and
authenticate finality after obtaining this prerequisite.

The signer now requires this locally authenticated `closable` view before
hashing/reserving/signing a closure. It binds the table, authority, creation slot,
expected address prefix, past deactivation and zero remaining blocks. Prefixes
include an empty or partially extended table. The durable packet preserves the
accepted context floor for both table activation and closure; an older bank
cannot be used for broadcast preflight.

Mesh ready reports include `rent_allocations` with the step, account address and
full allocation size. Sizes cover the Stage header plus original proof, each
classic token destination, the selected receipt entries, and cumulative lookup
extensions. These are conservative bounds: the writer never deducts existing
account funding or expected refunds while quoting. A locally generated plan
without allocation data is refused by the quote and reconciliation APIs.

The JavaScript RPC adapter binds three separately configured provider hosts to
the cluster genesis hash. Two providers must agree on the finalized blockhash
and lifetime, then on exact-message fees and allocation rent. It uses Kit's
public JSON-RPC interface and bigint codec, preserving full unsigned values.
The journal binds the quote's message hash and context before signing. Broadcast
uses only its persisted wire with RPC retries disabled.

Finalized reconciliation compares exact signed bytes and loaded address order
against the opaque local recipe. Balance arrays must match those account keys
and conserve the reported fee. Only rent destinations may gain lamports, and
only the designated cleanup account may refund them. Gross spending is fee plus
rent funding; payer refunds cannot create budget credit. A failed transaction
must leave all other balances unchanged. Two providers must report the same
slot, outcome and gross debit before the journal records finality.

Expiry first establishes a finalized height beyond the stored lifetime, then a
slot barrier, then searches history again and requests the transaction. An
isolated missing response, failure or stale context cannot release a reservation.
The resulting barrier also requires a fresh Mesh effect read. An authenticated
effect consumes the full reservation when its exact cost is unavailable. An
absent effect only permits expiry if two providers retain the relevant history;
operators must pin providers with complete indexed history in their available
range. Pruned or unavailable history with no effect leaves the packet unresolved.
These checks assume at most one dishonest selected provider; they do not prove
chain consensus cryptographically.

The bounded native wrapper supplies fixed arguments and public release
configuration to Mesh. It owns private temporary evidence files, strips inherited
credentials, limits process concurrency/output/runtime and rejects unsuccessful
or substituted reports. The durable scheduler must still connect these primitives
to authenticated phase recovery, resource ownership and receipt completion.

The writer execution functions now fence quotes and signatures, reserve before
signing, persist before broadcast and reconcile signed packets without a wallet
after restart. Unacknowledged submissions retain exact bytes and spending
reservations. Unsigned crash reservations may be abandoned; signed packets need
the RPC finality or expiry/effect boundary. Step scheduling, plan revisions and
ownership across jobs remain separate unfinished work.

Stage recovery is exposed as:

```sh
morse-fork-verifier --stage-state --input evidence.frk --submitter PUBKEY
```

Mesh validates the bounded evidence and operator pins before network access,
derives the Stage from the submitter and full proof hash, and reads Stage and Log
as one finalized quorum batch. The Log binds program, service key, log ID,
version and ring. Missing or empty system-owned prefunded accounts are distinct
from malformed, foreign or unfunded judge accounts. Stage headers bind the full
digest, uploader and log; the received prefix must exactly match the evidence,
the unused suffix must be zero, and sealing requires a complete upload.

The report distinguishes `missing`, `uploading`, `uploaded` and `sealed`, with
exact byte counts, context slot and earned signature ordinals/public keys.
Unknown bits, bits before sealing, the second service bit on anchored evidence,
nonzero unused key slots and invalid witness signatures are refused. Historical
witness keys are returned without consulting current membership or custody.
They describe the upload; they do not authorize a new settlement after custody
changes. The writer must reconcile these observations with its journal before
retrying, and must retain unresolved signed packets until finality or expiry.
The account reader permits at most 9,161 bytes for this boundary; existing
custody readers retain their 4 KiB default.

`scripts/prove-relay-writer.sh` additionally signs and executes all nineteen
fresh plans through the journal, Kit and SBF, covering 88 verification batches
and four full lookup lifecycles. Restarts preserve signed packets before
broadcast and after execution. It proves same-slot refusal, actual token payments, pay-once
rejection, Stage refunds, early-close refusal and eventual lookup rent recovery.
It operates on local fixture banks with public test identities and no live
network or funds.

The writer proof also exports 190 Stage snapshots from those actual executions
and authenticates them through the Mesh reader's independent-provider boundary.
This covers every upload chunk, seal and verification batch, as well as closure,
for both log profiles, all fork kinds, native/C2SP attestations and the maximum
proofs. Negative quorum cases cover foreign/substituted accounts, stale slots,
oversized data, invalid Log ownership, provider outages and disagreement.

An additional 42 actual lookup/Clock/SlotHashes snapshots cover four complete
table lifecycles, including SBF refusal before history expiry and the eventual
rent refund. They are read through the same Mesh cooldown boundary. The public
package's optimized SDK comparison separately covers compact/padded histories,
skipped slots, empty/full histories and unsigned coordinate limits.

The focused admission fixtures exercise whole-vault donations and rounding,
withdrawn witness selection, zero-finder fallback, missing/prefunded/paid
receipts, expired evidence, underfunded or frozen sources, frozen/wrong-mint/
overflowing destinations, locked delegates and source/destination aliasing.
Already-paid evidence does not require a Clock read. These are local checks,
not evidence of remote CI, live finality, funded operation or deployment.

Phase recovery also exposes `--receipt-state` and `--destinations-state`, each
with `--input`, `--submitter` and `--mint`. Receipt absence now retains its agreed
context and derived address instead of becoming an unqualified null result.
Destination recovery uses the same validator as admission, with zero incoming
units, and authenticates Log/Economics/mint alongside both token accounts. It
permits an existing finder delegate but refuses locked delegates or close
authorities, wrong token ownership/mint, frozen/native accounts and malformed
layouts. Prefunded empty system accounts still require setup.

The writer's effect selector consumes these Mesh reports, Stage state and lookup
lifecycle reports. It binds the exact opaque step, proof and original prepared
signature batches, and requires the expiry context floor. An earned signature
with a different public key is an error. A competing receipt satisfies settlement
while preserving the actual winner. Only the RPC finality/expiry boundary may
release or conservatively charge a pending transaction; an effect read alone
cannot discard it.

The portable proof exports another 76 actual SBF snapshots around destination
setup and payout. Mesh authenticates them, and the JavaScript selector evaluates
460 effects across these and the existing Stage/lookup reports. Fixture matching
includes the pinned log because proof bytes and proof hashes alone do not
identify a log. Durable progress stores observations and a monotonic context
floor; account ownership prevents jobs sharing a table PDA from spending or
cleaning it concurrently. The durable scheduler now reobserves each phase,
refreshes custody through Mesh admission, retains only identical step intent,
and retires incompatible lookup tables before replacement. Its original proof
and finder, resource ownership and all spending survive plan revisions.

The optimized native scheduler proof executes all nineteen cases in SBF with
38 restarts and complete resource cleanup. This positive native path also
dogfoods the public Mesh mixed-sum GC alignment fix. Funded/live qualification remains pending.

The public HTTP boundary accepts only bounded raw FRK evidence. A queued response
follows Mesh admission and SQLite commit; it is not a finality claim. The manual
command uses the same verifier, scheduler, journal and pinned signer. Both retain
the original finder and report a competing receipt's actual winner. Their local
proof covers all nineteen HTTP-to-native-to-SBF payouts; production TLS and
provider independence are not established by the loopback oracle.


Relay journal schema 2 preserves gross per-job charges and authenticated context
when compacting old terminal packets. Pending packets are never pruned. A paid,
fully cleaned job may leave the local store after seven days, because the judge
has a permanent proof receipt and Mesh reads it before doing age/custody work.
The retained global context floor applies to all later admissions, and the RPC
writer must quote a blockhash with a lifetime strictly above the compacted
history. These floors prevent stale snapshots/quotes from reintroducing work;
they do not replace the finalized quorum and immutable-program assumptions.
The nineteen native SBF cases include restart and no-spend resubmission after
local pruning. No receipt deletion or reset is added to the judge.

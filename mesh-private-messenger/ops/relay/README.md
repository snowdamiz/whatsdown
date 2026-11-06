# Morse relay

Transaction signing, the SQLite spending journal, a bounded native verifier
wrapper, finalized RPC adapter, durable scheduler, bounded HTTP endpoint and
manual wallet command and bounded retention are implemented locally. Funded
deployment and operator release qualification remain pending. See [the runbook](RUNBOOK.md).

Protocol verification, custody/age admission, account selection, lookup-table
recovery and unsigned instruction preparation live in Mesh. This package uses
pinned `@solana/kit` 8.4.0 to assemble and sign those instructions. It accepts
locally generated Mesh reports and operator pins; public clients must only
submit bounded raw FRK evidence.

`prepareRelayTransactions` binds the proof and configured program/log/mint/payer,
checks staging bytes and account reports, batches Ed25519 verification pairs to
the packet limit and exposes opaque transaction steps. `signRelayStep` signs a
known step with its designated payer and a supplied blockhash lifetime. Signed
bytes and their signature must be durably recorded before broadcast; ambiguous
submission must resend those exact bytes. The signer does not send transactions.

`RelayJournal` uses Node's built-in SQLite with WAL, full synchronous commits and
immediate write transactions. Keep its database in an operator-owned private
directory. The database is created with mode 0600 and stores public evidence and
signed packets, never private keys. Its immutable identity must bind the cluster
and verifier configuration; program, log, mint, payer and spending policy are
also checked on every reopen. Changing a wallet or policy cannot silently reset
the existing ledger.

The writer must claim a 30-second fenced lease, reserve a conservative maximum
lamport debit, sign the exact prepared step, call `recordSigned`, and only send
the packet returned by `authorizeBroadcast`. That method commits retry backoff
before returning the packet. The journal authenticates the reserved message and
the payer's Ed25519 signature, preserves exact bytes and full unsigned coordinate
precision across restart, and permits only one unresolved transaction globally.
An old worker cannot record a late signature after another worker takes over.
An unsigned reservation can be abandoned; a signed one cannot.

`submitRelayStep` connects quoting, reservation, wallet signing, authenticated
packet persistence and broadcast in that order. It rechecks the worker lease
after asynchronous operations. `recoverRelayPending` needs no wallet: it abandons
an unsigned crash reservation, reconciles signed packets through the RPC adapter,
records finalized charges or authenticated expiry/effects, and resends only the
journal's unchanged packet. Missing acknowledgments retain the reservation;
receipt suppression and retry backoff still apply. An expiry barrier is never
rebroadcast. Supplying the native `verifier` connects its authenticated effect
reader automatically; a trusted explicit `readEffect` remains available for
testing. `createRelayScheduler` now selects and reconciles the next step. The
daemon serializes admission with these scheduler ticks.

Per-job gross spending is cumulative. The rolling 24-hour cap includes recent
charges plus every unresolved reservation, regardless of its age. Rent refunds
do not increase either budget. Finalized failures still consume their actual
fees. A quote overrun is recorded durably and halts new reservations. All costs
are canonical unsigned decimal strings and use exact integer arithmetic.

Finality, expiry, receipt and cleanup observations are trusted local adapter
inputs, not HTTP request fields. `connectRelayRpc` binds three distinct pinned
provider hosts to one genesis hash and requires two matching observations.
The operator must choose independently operated providers with complete indexed
transaction history in their advertised available range. Expiry requires a finalized block height beyond the
packet's lifetime followed by history and account-state checks; an RPC timeout
or one missing response cannot release a reservation. If history is unavailable
but the effect is authenticated, `observeEffect` waits for expiry and charges
the whole reservation. Waiting prevents a late packet from acting on an account
recreated after cleanup. Observations of finalized transactions must include
gross debit, including fees even when the payer received a rent refund.

The first accepted finder and plan are immutable. A competing authenticated
receipt records the actual winner separately, suppresses preparation broadcasts,
and allows cleanup after pending transactions are resolved. A job completes only
after a receipt and all required cleanup steps. The journal currently retains
all unresolved jobs and recent completed history, bounded by `maxJobs`. The
scheduler revises the current plan while preserving the accepted
proof, finder, Stage and original plan.

`progress` exposes durable completed steps and the greatest authenticated context
from the plan, receipts and transaction/effect observations. `observeStep` can
record an already present effect without a charge only when no transaction is
pending, using a context at or above that floor. An unresolved packet must go
through finality or expiry accounting first. `claimResources` atomically binds
the Stage and, when needed, lookup table to one job. Every reservation also
enforces ownership. Ownership survives restarts and is released only after
receipt-backed completion and all cleanup; a waiting job still needs a fresh
plan before trying to create an expired table address.

The native `--stage-state --input evidence.frk --submitter PUBKEY` command now
provides Stage recovery in Mesh. It validates the original evidence before RPC,
derives the Stage locally, and reads it with the pinned Log in one finalized
quorum batch. Missing/prefunded, uploading, uploaded and sealed states are
distinct. Recovery binds the full proof digest, uploader and log, checks the
exact uploaded prefix and zero unused suffix, and authenticates earned signature
ordinals and witness keys. It reports historical earned bits even after custody
changes; fresh admission still decides whether those identities remain
collectible. A state read alone cannot release an unexpired packet reservation.

Lookup tables are prepared in Mesh. Compressed settlements require a ready
result from the native `--lookup-state` command, including exact authority,
addresses and a context after the last extension slot. Table creation/extension
and cleanup are separate steps. The caller must serialize jobs that derive the
same table, authenticate partial uploads after restarts, and retain cleanup work
until deactivation has aged out of SlotHashes. A local wall-clock delay is not
sufficient proof that rent can be reclaimed.

`--lookup-close-state --submitter PUBKEY --slot SLOT --addresses KEY,KEY,...`
now authenticates the closure prerequisite. Mesh reads the table, Clock and
SlotHashes together from each provider, validates the same table identity and
requires two matching decisions. Providers may have different finalized sysvar
bytes; the Clock must match each response's context, and history cannot be from
the future. `closable` means the deactivation slot is past and absent from both
accepted histories. `cooling` includes conservative `remainingBlocks`, including
513 in the deactivation slot. These counts are not wall-clock delays. A closed
table returns `missing`; other lifecycle states remain distinct. The signer
consumes this prerequisite before closure; the RPC adapter authenticates its
transaction result and gross fee/refund accounting afterward.

`signRelayStep` and journal reservation now enforce the `closable` prerequisite:
zero remaining blocks, exact table/authority/creation identity, a valid expected
address prefix, and past deactivation. Empty and partially extended tables can
be reclaimed. Both settlement activation and closure preserve their authenticated
context floor in the durable packet. Negative SBF closure probes deliberately
build raw test instructions outside this signer, retaining the chain's own
cooldown checks.

`createRelayVerifier` invokes an operator-specified native Mesh executable with
fixed arguments and a minimal environment containing public pinned configuration.
Evidence is copied into a private temporary directory and removed after the
process closes, including cancellation and failure. One process may run at a
time; evidence, stdout, stderr and execution time are bounded. Unsuccessful,
malformed, substituted or stale reports cannot enter the writer. Wrapper tests
use fixture executables; the optimized native test also checks cheap rejection
and unavailable RPC through this wrapper. Successful native TLS admission still
needs an integration environment; Mesh quorum tests use local fixture servers.

Mesh admission reports now include `rent_allocations` for each spending step.
The adapter quotes the exact serialized message and full allocation rent,
requiring two providers to agree on the blockhash/lifetime and fee/rent tuple.
Using full rent is conservative for prefunded accounts, repeated ATA setup and
lookup extensions. Quotes bind their message hash and context in the journal.
The adapter does not produce a new quote from an older plan without allocation
metadata. Differing finalized blockhashes can temporarily prevent a quote; the
scheduler must retry without signing or reserving money.

Reconciliation authenticates the exact signed wire, loaded addresses, finalized
slot, balances and fees. Only the prepared rent destinations may gain lamports;
only the designated cleanup account may refund them. Gross debit counts fees
plus rent funding, even when cleanup increases the payer's balance. Failed
transactions must leave every nonpayer balance unchanged. Two matching results
are required. The local SBF proof supplies actual SDK rent and before/after
balances for all nineteen cases; it does not establish live provider finality.

An expiry check reads finalized height, then slot, then searches historical
signature status again and fetches the transaction. It also checks history's
retention floor. A missing result yields an `expiry-barrier`, never automatic
permission to discard a packet. The scheduler must supply a fresh Mesh effect
check at that floor. An authenticated effect after expiry consumes the full
reservation when actual cost is unavailable. An absent effect can authorize
expiry only with two providers covering the packet's history; otherwise the
reservation remains pending. Read timeouts and conflicting observations retain
the reservation. Broadcast uses the journal's exact bytes and slot floor with
RPC retries disabled; acknowledgment alone never means finality.

The wire contracts follow Solana's [fee query](https://solana.com/docs/rpc/http/getfeeformessage),
[rent query](https://solana.com/docs/rpc/http/getminimumbalanceforrentexemption),
and [finalized transaction metadata](https://solana.com/docs/rpc/http/gettransaction).

Install locked dependencies with `npm ci --ignore-scripts`. From the repository
root, after building the judge SBF with the pinned toolchain, run:

```sh
MESHC="$PWD/mesh-lang/target/debug/meshc" bash mesh-private-messenger/scripts/prove-relay-writer.sh
```

The script generates fresh Mesh plans and real funded fixture accounts, runs
the admission proof, then executes journaled Kit-signed transactions in LiteSVM,
including restarts before broadcast and between execution and recording the
result. Separate journal tests cover fencing, rolling budgets, failed fees,
quote overruns, changed packets and competing receipts. The local bank supplies
execution observations; this does not test live RPC finality. Tests
require those generated fixture paths; they do not silently skip missing SBF
evidence. The script exports 190 actual Stage snapshots across all nineteen
cases and reads them back through the Mesh quorum boundary, including maximum
9,161-byte accounts. CI transfers the tested SBF and compiled proof/bridge executables into
the Mesh job. Local verification does not establish remote CI, a published Mesh
release, live finality or deployment.

The proof also exports 42 lookup lifecycle snapshots with actual 20,488-byte
SlotHashes accounts. Mesh reads them back through the cooldown quorum. Real SBF
closure is refused both in the deactivation slot and in a later bank retaining
that slot, then succeeds after history retirement and refunds the table rent.

`--receipt-state` retains the authenticated context even when the receipt is
missing or only prefunded. `--destinations-state` reads the pinned Log, Economics,
mint and both token destinations in one quorum batch. It distinguishes missing
or prefunded accounts from initialized classic token accounts and rejects wrong
ownership/mint, frozen or native accounts, unsafe locked custody and conflicting
or stale views. Admission shares this destination validator and also checks
payout overflow.

`createRelayEffectReader` selects the effect of an opaque prepared step from
these native reports, Stage state or lookup lifecycle state. Verification steps
bind the exact earned ordinals and public keys after transaction batch splitting.
Append/extension steps require their complete expected prefix, and settlement
accepts an authenticated competing receipt. Missing, malformed or conflicting
reads never become successful effects. The result must satisfy the caller's
expiry barrier; it does not itself release a reservation.

The portable proof now also reads 76 actual SBF snapshots before and after token
setup and settlement through Mesh, then feeds all 308 exported reports into the
JavaScript effect adapter for 460 decisions. Reports are matched by log and proof:
identical evidence bytes can legitimately appear under different pinned logs.


`createRelayScheduler().tick()` takes or renews the durable fenced lease and
advances at most one new transaction. It recovers an unresolved packet before
selecting another job, reads the receipt before preparation, and fairly schedules
jobs using persisted attempt times. It reobserves effects even for completed
steps: an externally closed finder token account must be recreated without
resetting its prior spending. Concurrent ticks return busy; a second process
cannot spend through another worker's lease.

Fresh Mesh admission may change collectible custody and instruction batches.
`revisePlan` preserves completed steps only when their exact instruction intent
is unchanged. An active owned table can be reused only for the same addresses;
an incompatible or deactivating table must finish chain-authenticated cleanup
before replacement. A missing table permits fresh preparation. Original evidence,
finder identity and cumulative charges never change. Globally unique signed
transaction signatures prevent a failed packet being charged twice under a new
reservation.

The portable proof now also drives the production scheduler with an optimized
native Mesh executable, three loopback RPC views of actual SBF accounts and
actual Kit packets. All nineteen cases settle, restart twice and reclaim their
Stage/table accounts: 38 restarts, 8 activation/cooldown waits, 1,325 native reads
and 273 transactions. The test harness takes trusted fixture configuration;
this does not establish production TLS, provider independence or deployment.

That optimized proof exposed a generic Mesh GC defect: mixed sum payloads were
byte-aligned, allowing live pointers to be missed by conservative scanning.
Mesh now uses aligned, initialized machine-word payloads, with debug and optimized
allocation-pressure regressions. Rebuild all Mesh artifacts with the fixed
compiler; old mobile libraries and a published release are not qualified by this
host proof. See Mesh's `docs/gc-value-layout.md`.


`createRelayService` accepts copied raw evidence in a bounded queue, runs native
admission between scheduler cycles, and acknowledges only after journal commit.
`createRelayHttpServer` provides the public 8 KiB endpoint, per-socket-IP limits,
bounded connections/concurrency and upload/admission deadlines. Disconnects cancel
queued work; lost acknowledgments do not remove a committed job. Public errors
exclude native/provider diagnostics. No forwarded header selects a wallet, plan,
provider, program or rate-limit identity.

`cli.mjs serve` connects the operator configuration, owner-private wallet, native
verifier, finalized RPC adapter and durable journal. `submit evidence.frk --wallet`
uses that same loop and preserves the finder through completion. The package
exposes `morse-relay`; both commands require an operator configuration, supplied
by `--config` or `MORSE_RELAY_CONFIG`. Neither command was run with a funded live
wallet during local qualification. The SBF proof now sends every initial proof
through the actual HTTP handler and native Mesh admission before journaled work.


Schema 2 compacts terminal signed history after seven days into lifetime charge,
context and signed-history aggregates. The rolling-day budget keeps recent
charges and every unresolved reservation. A seven-day-old completed job can be
removed only after a contextual receipt and full cleanup, with no owned resources
or signed packet rows left. Global admission/context and transaction-lifetime
floors survive deletion. Mesh reads the permanent proof receipt before new
admission, so a resubmitted paid proof does not create another spending job.

Maintenance runs under the worker lease, at most once per minute with no pending
packet, and is atomic: malformed history rolls back the entire pass. Each pass
compacts at most 256 rows and prunes at most eight jobs. Only 32 recent abandoned
unsigned records are retained; a 32,768-row hard limit refuses new reservations
when compaction cannot free space. Per-job totals, spending halts and the fact
that a job signed a packet cannot disappear with its transaction details.

The native SBF proof now prunes all nineteen completed jobs, reopens their
journals and submits the same evidence over HTTP again. The authenticated chain
receipt returns the winner with no new job, signature or spend: 57 total restarts
and nineteen post-retention submissions. Stop all older processes before the
schema-1 migration; the runbook describes the upgrade and its assumptions.


The witness packager also exports `relay.tar` from its digest-pinned, revision-
checked service image. The service image contains an allowlisted relay source
payload beside its native verifier. Packaging does not run either signer or copy
from the operator's local checkout. The Docker proof exercises the production
source stage, normalized archive and unpacked CLI using a fixture native binary;
release-image/native qualification is still required.

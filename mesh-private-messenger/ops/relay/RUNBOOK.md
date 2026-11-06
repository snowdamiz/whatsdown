# Running the relay locally

This implements the daemon and manual writer. Local tests use funded SBF fixture
banks; no live funded deployment, production TLS admission, independent provider
qualification or published Mesh release has been established. Container/witness
distribution tooling now includes this relay in the witness bundle; a verified
release image and published bundle remain unqualified. The journal retains recent
history and every unresolved job, and refuses new work at its capacity limits; it must not be
deleted to regain capacity or reset spending limits.

Use Node 24 in CI (the local proof also uses Node 22.23.3). Install the locked
writer dependencies with `npm ci --ignore-scripts` in this directory. Build
`tools/fork-verifier` with the qualified Mesh compiler for the machine where it
will run. Record that compiler identity with the binary. The optimized relay
proof requires the mixed-sum GC fix described in Mesh's `docs/gc-value-layout.md`;
old compiled Mesh libraries need rebuilding.

Copy `relay.example.json` outside the checkout and replace every placeholder.
All paths in it are absolute. `securityConfigPath` points to the operator's
release security frame, including the judge, log and independent HTTPS RPC pins.
The writer's `rpc` providers must refer to that same cluster and its exact genesis
hash. Select three independently operated providers with complete transaction
history in their advertised range. `pins.log` is the judge's derived Log account,
not the anchor ring. Mesh checks the configured program/log against every ready
plan; the writer verifies its cluster before quoting or broadcasting.

The example spending limits are operational inputs, not fee estimates. Select
per-job and rolling-day limits for the funded wallet. They count gross fees and
rent, including failed transactions; refunds do not replenish them. The immutable
journal scope binds the public security frame, log version, provider set, genesis,
program/log/mint/payer and policy. Changing these cannot silently reopen the old
ledger. Reordering the same RPC URLs does not change its identity.

Supply an existing Solana JSON keypair file (64 byte values) owned by the relay
user with mode 0600. Its public key must equal `pins.submitter`. The wallet is
imported into a non-extractable Kit signer; temporary byte arrays are cleared.
Neither SQLite nor the native verifier receives the key. Keep the wallet,
journal directory and temporary verifier directory owned by the service user.

From this directory:

```sh
node cli.mjs serve --config /etc/morse/relay.json --wallet /etc/morse/relay-wallet.json
node cli.mjs submit /path/to/evidence.frk --wallet /etc/morse/relay-wallet.json --config /etc/morse/relay.json
```

The package also declares the `morse-relay` executable for a local installation.
`MORSE_RELAY_CONFIG` can supply the config path for either command. A manual
submission prints its durable admission result, then keeps processing until its
receipt and cleanup complete. If a receipt already exists, it reports the actual
finder and continues any existing local cleanup job. It does not replace a
nonzero finder address. The same journal and worker lease govern both commands;
a second process waits for the active owner's lease rather than spending beside
it. Other accepted jobs continue to receive fair scheduling.

Serve behind an operator-managed HTTPS edge. The default listener is loopback;
binding all interfaces is an explicit configuration choice. The edge must enforce
per-client IP limits using its authenticated connection address. The relay uses
only its own socket address and ignores all forwarding headers, so proxied
requests also share an aggregate limit for the proxy address. This prevents
client-supplied forwarding headers from bypassing limits.

## Public endpoint

`POST /v1/fork-evidence` accepts only `application/octet-stream`, without
compression, and at most 8,192 bytes. It accepts raw FRK bytes; clients cannot
supply plans, instructions, account lists, executable paths, RPC endpoints or
wallets. Mesh verifies the evidence before admitting a spending job.

- `202`: `schema_version`, `status: "queued"`, `proof_hash`, `finder`, `duplicate`.
  SQLite has committed the job. This does not mean that a payout is finalized.
- `200`: `status: "settled"`, `proof_hash`, and the actual receipt's `finder`.
- `400`, `413`, `415`: empty/invalid body, excessive size or unsupported encoding.
- `408`: body upload timed out. `429`: per-IP limit, with `Retry-After: 60`.
- `503`: busy or admission unavailable. Native rejection and provider failures
  share this response; it does not attest that a proof is invalid or paid.

The default bucket allows six requests per minute per socket IP with a burst of
six; at most 4,096 active buckets are kept. New identities are refused while that
bound is occupied. The server caps connections at 64 and in-flight admissions at
16, with a five-second body deadline and a sixty-second admission deadline.
Disconnected/timed-out requests cancel queued verification. A committed job
survives a lost response; retrying preserves the original finder and plan.
There is no request, evidence, wallet or IP access log in this tool.

## Recovery

On SIGINT/SIGTERM, new work stops and admissions cancel. An already running
scheduler cycle may finish one durable transaction; shutdown waits for it before
closing SQLite. Forced termination is recovered from the journal at the next
start. Keep its database, WAL and SHM together when handling a live store; stop
the writer before making a plain filesystem backup.

An acknowledgment loss resends the exact signed bytes. A pending transaction
always precedes new work and retains its budget until finalized/expired with
sufficient evidence. Missing history, unavailable RPC, a cooling lookup table
or a competing receipt never authorizes discarding that reservation. A worker
restart may wait up to the old 30-second lease expiry. Lookup cooldown follows
chain history, not a wall-clock timer.

The daemon reports generic worker-unavailable/lease-busy transitions without
provider URLs or wallet data. Inspect local configuration and the durable journal
when intervention is needed; do not replace it with an empty file. An over-budget
finalized debit halts new reservations durably. Capacity exhaustion, stale or
conflicting observations and changed configuration fail closed.

Before shipping an operator release, qualify and publish the distribution artifacts,
exact Mesh release pinning, native rebuilds, live TLS/provider qualification and
the plan's funded staging/canary gates. Phone autofiling and receipt monitoring
are separate unfinished work.


## Retention and upgrades

Journal schema 2 runs maintenance at most once per minute, before selecting new
work and only when no transaction is pending. Each pass compacts at most 256
transaction rows and removes at most eight completed jobs. Terminal signed
packets are retained for seven days after accounting. Only the newest 32
abandoned unsigned attempts are retained; these were never broadcast and carry
no charge. The hard transaction-row limit is 32,768. Hitting it refuses a new
reservation until safe maintenance frees space. `maxJobs` bounds both working
jobs and completed jobs still in their retention window.

Old charges move into a per-job lifetime total. Context floors, whether a job
ever signed anything, and the durable spending halt survive compaction. No refund
or pruning resets those values. Seven-day-old charges are already outside the
24-hour rolling window. Pending reservations never age out, regardless of their
wall-clock age. SQLite reuses freed pages; maintenance does not rewrite the
entire database or promise an immediate reduction in its file size.

A completed job is removed only after its completion retention window, an
authenticated receipt context, released account ownership and removal of its
signed transaction history. The reviewed judge has no receipt-reset or
receipt-close instruction. Its permanent proof PDA becomes the duplicate
submission authority after local deletion. This relies on the plan's immutable
judge deployment and finalized quorum assumptions. Admission then uses a durable
global minimum context slot, and new RPC quotes must have a strictly later
last-valid block height than every compacted signed packet. The trusted RPC
adapter binds that lifetime to its finalized blockhash. Stale plans and quotes
fail before reservation; unavailable chain history never permits replay.

Before upgrading a schema-1 installation, stop **all** older relay/manual
processes, allow their 30-second lease to expire, and back up the stopped journal.
The new executable migrates atomically without changing pins, spending policy,
charges or exact pending packets. It refuses migration while a legacy lease is
active. Do not run mixed executable versions or roll back to a schema-1 binary;
older binaries cannot account for compacted totals. Unknown schema versions
fail closed. Legacy completed rows start their retention window at their first
maintenance pass; receipts missing an authenticated context are retained until
a fresh observation supplies it.


## Operator bundle

The witness package now includes `relay.tar`. It contains this source, locked
npm dependencies manifest, configuration/runbook and the native verifier from
the same pinned service image. Verify the bundle checksums before extraction;
run `npm ci --ignore-scripts` inside the extracted `morse-relay` directory and
point `verifierBinary` at the adjacent `morse-fork-verifier`. It targets the
service image's Linux x86-64 environment. The local archive proof validates file
selection, reproducibility and loading the unpacked CLI with a fixture native
binary; an actual reviewed release image and Linux verifier remain release gates.

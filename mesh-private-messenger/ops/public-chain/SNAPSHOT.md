# Minute public snapshot producer

The default-off producer connects the existing canonical Mesh reader to a
separate read-only SQLite Durable Object. It adds no transaction authority.
No deployed source policy, provider independence, live amounts, public Mesh
release or weekly-burn completion is established by the local qualification.
The checked-in landing `network-data.js` remains bootstrap data.

## Trust and activation inputs

The Worker requires all of these explicit deployment inputs:

- `MORSE_PUBLIC_REPORT_MODE=on` (absent or any other value stays disabled).
- `MORSE_PUBLIC_REPORT_CONFIG`: exact JSON configuration accepted by the existing
  reader, with `scope: configured-rpc`, three distinct canonical HTTPS origins,
  explicit release/account pins, bounded epochs/history, minimum finalized slot
  and a maximum age. Omit `generated_at_unix`; the native server owns this clock.
- `MORSE_PUBLIC_REPORT_POLICY_SHA256`: SHA-256 of those exact UTF-8 JSON bytes.
- `MORSE_PUBLIC_REPORT_GENERATOR_SHA256`: SHA-256 of the exact built reader.
- `MORSE_PUBLIC_REPORT_INTERNAL_TOKEN`: a separate 32–256 character bearer token.
  Keep this and the complete RPC policy in trusted configuration, not public
  assets. Never reuse signing seeds or financial-service tokens here.

The Docker recipe builds `/app/public-chain-report` at explicit optimization2
and emits its fixed `/app/public-chain-report.sha256` companion from those bytes.
The native endpoint checks the exact canonical digest, its expected configured
pin and the fixed companion filename before serving. The owned harness rehashes
both. This is a build association, **not runtime attestation**. The existing
Docker compiler revision policy is unchanged: the new language/runtime work
still needs its public release and exact approved dependency before deployment.
The local qualified compiler/runtime pins do not silently become release pins.

`POST /internal/v1/public-report` is internal only, bearer authenticated, and
accepts exactly one lowercase 64-hex nonce as its entire body. Requests cannot
supply accounts, policy pins, origins, timestamps or a generator identity.
The server calls `read_public_report`; all account decoding, financial math,
PDA/owner/layout/code/custody/receipt validation and digest quorum remain Mesh.
The reply associates that nonce, the exact policy/build, server retrieval times
and canonical report. The Worker checks this association, completeness, public
pin labels, nonfuture source times and freshness before publication. It does
not parse Solana accounts or compute monetary values. Three origins establish
only distinct origins; `provider_independence` remains `not-established`.

## Scheduling, failure and history

The existing minute cron schedules `PUBLIC_SNAPSHOTS.getByName('primary')` only
in explicit `on` mode. This separate DO owns a minute alarm, so witness,
directory and anchor work cannot serialize it. Public GETs never start reads.

Each attempt first commits a monotonic generation and random nonce, marks
current data unavailable and installs a recovery alarm before network I/O.
Transport is bounded to120seconds and8MiB; reservations expire after600seconds.
The final synchronous SQLite transaction checks the same generation/nonce,
then atomically writes report chunks, retained receipts and publication state.
A late overlapping result cannot replace a newer generation. Crashes after
reservation or after I/O preserve the last-good bytes and recover via lease
expiry. Source/retrieval clocks beyond the configured age, future clocks,
clock rollback, disagreement, code drift, incomplete pages, mismatched pins or
builds, transport errors and stored-byte corruption cannot yield healthy old
current data. A local host clock rollback preserves its previous clock fence.

The public envelope has `current: null` on failure and keeps `last_good`
explicitly historical. It retains the last32 attempt observations and up to128
unique settled onchain receipts (each at most32KiB), across repeated reads,
restarts and bounded index changes. Only wholly accepted reports add settled
observations. Receipt conflicts or capacity refusal are sticky: no receipt is
evicted, last-good bytes remain, and current data stays unavailable. Repair or
policy/build rotation requires a separately reviewed state/archive migration;
there is deliberately no public reset or POST configuration route. A changed
policy/build cannot silently reinterpret an old database.

One accepted report is at most8MiB, split into60,000-byte SQLite blobs. The
ledger is not an exhaustive slash index or independent fork verification.
Unsupported records and absent selections never mean zero or “never slashed.”
No USD value, oracle quote or provider independence is inferred.

## Read-only publication and page wiring

With the producer explicitly configured, Worker `GET /public/network-data.json`
and `GET /public/network-data.js` return the envelope with `no-store`. Other
methods and query strings are refused. The JavaScript form assigns only
`globalThis.MORSE_NETWORK_REPORT`; script-sensitive characters are escaped.
The page accepts this envelope, labels last-good amounts historical during an
outage and always shows retained settled receipt identities. Original exact
receipt contents remain in the downloadable source data, with no browser sums.

Actual same-origin routing of the landing page's `network-data.js` to these
bytes is an external rollout operation. No route, deployment, live policy,
independent provider qualification or bootstrap replacement was activated.
A reverse proxy/static host must preserve same-origin routing and `no-store`;
serving a cached old script indefinitely would conceal fresh failure status.

## Local replay

Use an explicitly qualified compiler/runtime and an owned output directory:

```sh
MESH_RT_LIB_PATH=/absolute/qualified/libmesh_rt.a "$MESHC" build ops/public-chain --opt-level 2 --output /absolute/owned/public-chain-report
shasum -a 256 /absolute/owned/public-chain-report | cut -d ' ' -f1 > /absolute/owned/public-chain-report.sha256
MORSE_PUBLIC_CHAIN_BIN=/absolute/owned/public-chain-report MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY=/absolute/owned node --test ops/public-chain/snapshot-http.test.mjs
MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY=/absolute/owned node --test ops/cloudflare/public-snapshot.test.mjs
node --test ops/cloudflare/public-snapshot-worker.test.mjs
MORSE_PUBLIC_SNAPSHOT_PROOF_DIRECTORY=/absolute/owned PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/absolute/Chrome node --test apps/landing/network-publication.browser.test.mjs
```

The native harness serves committed exact SBF account snapshots through three
owned loopback peers, validates bearer/nonce/config/build refusals and exact
receipt fields, then confirms that their historical clocks produce a stale
publication at today's real clock. Only the owned native harness permits
`local-fixture` with `MORSE_PUBLIC_REPORT_ALLOW_FIXTURE=owned-local-only`;
the deployed Container does not pass that escape, and Worker policy refuses it.
Publication-state and workerd transport tests separately use synthetic retrieval
metadata around canonical fixture values; these are not live account reads or
independent-provider tests. Browser fixtures remain visibly local bank data.

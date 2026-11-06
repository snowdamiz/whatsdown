# Cloudflare backend

Cloudflare runs the four Mesh HTTP services and two transparency witnesses in
Containers. A Worker exposes the public HTTP/WebSocket routes and keeps delivery,
push dispatch, R2 access, and witness checkpoint writes private. Encrypted parts
live in R2; witness checkpoints use Durable Objects with compare-and-swap writes.
Neon PostgreSQL holds directory state, the sealed push queue, and object metadata.
Container disks hold no durable application state.

Background work is event-driven. Before committing a transaction that creates
delivery work, a checkpoint, an object expiry, or a push job, the Mesh service
registers that transaction ID with a Durable Object scheduler. If registration
fails, the transaction rolls back. The scheduler waits until PostgreSQL reports
the transaction finished, processes durable work, and sets an alarm for the next
retry, receipt check, or expiry. An aborted transaction causes a harmless check.
No message bodies, mailbox identifiers, or provider tokens enter the scheduler.

There is no periodic keep-warm cron. Idle schedulers have no alarm and make no
database queries. The ordinary local runner retains its polling behavior;
Cloudflare sets `MESSENGER_JOBS_URL` to enable external scheduling instead.

## Provisioned resources

| Resource | Name |
| --- | --- |
| Cloudflare Worker | `morse-backend` |
| Public origin | `https://morse-backend.snowdamiz.workers.dev` |
| R2 bucket | `morse-encrypted-objects` |
| Neon project | `morse-backend` (`falling-river-26057651`, AWS US East 1) |
| PostgreSQL database | `messenger` |
| Database roles / schemas | `morse_delivery` / `delivery`, `morse_objects` / `object_store`, `morse_push` / `push_broker` |

Each database role owns only its service schema. Remote connections verify TLS.
The R2 lifecycle rule deletes `opaque/` objects after eight days, beyond the
protocol's maximum seven-day object lifetime. This also cleans up parts left by
interrupted uploads.

This deployment starts fresh. Previous local SQLite queues, metadata, and files
are neither imported nor deleted. Move any required existing data before directing
those clients at this deployment.

## Deploy from a workstation

From this directory, with Docker running:

```sh
npm ci
npx wrangler login
npx wrangler whoami
node migrate.mjs
npm run deploy -- --containers-rollout=immediate
```

Set `MESSENGER_DATABASE_URL` to the delivery role's connection URL before running
migrations. `psql` must be installed. The runner applies numbered SQL migrations
transactionally and checks their recorded checksums; applied files must not change.
Object and push schemas initialize idempotently when their services start.

Builds use the latest published Mesh release. A release deploys the exact commit
its verification used, passed as `MESH_LANG_REVISION`; any other build resolves the
latest release with `../../scripts/mesh-release.mjs`. `prepare-build.mjs` writes an
ignored `wrangler.build.json`; Docker caches each compiler commit for later builds.

Publication also requires the successful verification result for the exact Morse
and Mesh commits (`VERIFICATION_RESULT`, `GITHUB_SHA`, `VERIFIED_MORSE_REVISION`,
`MESH_LANG_REVISION`, `VERIFIED_MESH_REVISION`). These are supplied by the release
workflow. For workstation publication, use the successful candidate's evidence;
setting these variables without running its checks does not establish readiness.

### Separate privacy-edge deployment

Sealed delivery hides which mailbox a source connection is sending to only if
the component that sees the connection cannot unseal, and the component that
unseals never sees the connection. `npm run deploy` therefore builds a backend
with **no** privacy edge: it answers `404` on `POST /v1/envelopes/batch` and
instead exposes `POST /v1/ingress/sealed`, which maps to the delivery core's
bearer-authenticated internal route. Deploy the edge on its own:

M2 remains open end to end: the opt-in backend certificate guard and its exact
operator prerequisites are documented in [INGRESS_MTLS.md](INGRESS_MTLS.md).
Cloudflare currently does not support its outbound mTLS binding against a
Cloudflare-proxied backend Worker. The build/runtime preflight rejects that
configuration; the existing development topology must not be called mTLS or a
qualified production cutover.

```sh
# Run with the edge's own deployment credentials.
# MORSE_DELIVERY_URL is the backend's public HTTPS origin.
npm run deploy:edge
```

The edge Worker (`morse-privacy-edge`) needs
`MESSENGER_DELIVERY_INTERNAL_TOKEN`. Credit purchases additionally require
`MORSE_CREDIT_ISSUER_URL` (the separately hosted issuer's HTTPS origin) and
`MESSENGER_CREDIT_PURCHASE_INTERNAL_TOKEN`. It must never be given
`MESSENGER_DELIVERY_SEALING_SEED_HEX`, a database URL, or any signing seed; its
container environment is built from an allowlist so that an over-provisioned
deployment still passes none of them through. It forwards only the sealed body
and that bearer credential, refuses redirects, and exposes anonymous credit
discovery/quote/issue routes. Purchase requests discard client authorization as
well as tracking headers. The internal purchase token never grants issuer-key
publication: `MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN` belongs only to the issuer
and core and is excluded from the edge environment allowlist.
Clients send through it by setting `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL` to
the edge origin. The native security configuration's credit issuer origin must
also name this privacy edge; purchase payloads then reach the issuer through
the edge's restricted outbound route.

Both Workers strip every inbound header except `Content-Type`,
`Authorization`, and WebSocket upgrade headers before a request reaches a
container, so no Mesh service or container log receives a client address,
location, user agent, or cookie.

What this does and does not provide: a bug, log, or compromise confined to one
deployment can no longer join a source address to a mailbox. Run both under one
Cloudflare account and one operator, and that operator (and Cloudflare, which
terminates TLS for both) can still correlate them by timing. Separate accounts
with separately held credentials reduce the impact of an account-wide
compromise; only a genuinely independent edge operator removes the collusion
assumption. Message submission and anonymous credit purchases use the edge; lookups, prekey claims,
mailbox reads, object transfers, and push registration reach the backend
directly and reveal the requester's address to it. Live permission-denial and
account-isolation checks have **not run**, and no live cutover has been
performed. `npm run dev` retains the combined local development topology.

The default-off [OHTTP route](OHTTP.md) adds isolated edge/core forwarding for
configured prekey, directory and proof operations. It has host integration
coverage; matching native artifacts, ingress enforcement and rollout remain
open. The combined development Worker does not expose that route.

The image includes `/app/credit-issuer`, but it is deliberately not bound to an
ephemeral Cloudflare container. Its `StorageKey.file` directory must live on a
durable local filesystem outside database rollback, with separate issuer
PostgreSQL state. Configure a persistent issuer host before enabling purchases.
Core administration can use private HTTPS directly, or the opt-in
`MORSE_CREDIT_ISSUER_INGRESS=on` backend Worker routes
`/v1/ingress/credits/issuers/{announce,evidence,admit,cursor}`. The issuer then sets
`MESSENGER_CREDIT_ADMIN_TRANSPORT=ingress` and the backend HTTPS origin as
`MESSENGER_DELIVERY_INTERNAL_URL`. Only `cursor` uses GET; the other three use
POST. Bodies are bounded, redirects are disabled, and the core authenticates
its separate issuer-administration bearer before decoding or database access.
These routes are absent from the edge and disabled by default; they do not
expose pruning or other administration. Set the backend secret
`MESSENGER_CREDIT_ISSUER_INTERNAL_TOKEN` to match the issuer, never the edge.
Paid retention routes through the edge to the core with the owner-signed CAP
body; its core switch `MORSE_PAID_RETENTION` remains `off` by default.
See
[`services/credit-issuer/README.md`](../../services/credit-issuer/README.md).

### Separate push-broker deployment

The isolated backend requires `MORSE_PUSH_BROKER_URL` and has no broker
container/binding, unsealing seed, queue DB or Expo credential. The broker uses
its own Worker, push-only durable scheduler and database role; it is not deployed
with backend credentials. See [PUSH_BROKER.md](PUSH_BROKER.md) for the exact
credential split, `npm run deploy:push-broker`, bounded ingress and existing-queue
cutover requirements. `npm run dev` retains the combined local topology. No live
separation, queue migration or cutover has been performed by this change.

### Separate witness deployments

`npm run deploy` prepares three service containers and removes the witness and
privacy-edge bindings from delivery. Set `WITNESS_A_URL` and `WITNESS_B_URL` to distinct HTTPS origins.
Each witness uses its own Worker, signing key, and private checkpoint store:

```sh
# Run each command with that witness's deployment credentials.
# MORSE_DIRECTORY_URL is the backend's public HTTPS origin.
npm run deploy:witness-a
npm run deploy:witness-b
```

Provision each witness with `MESSENGER_WITNESS_SIGNING_SEED_HEX`, its matching
`MESSENGER_WITNESS_PUBLIC_KEY_HEX`, `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX`, and a
unique random 32-byte hex `WITNESS_INVOKE_TOKEN`. Delivery holds only the public
witness keys and `WITNESS_A_INVOKE_TOKEN` / `WITNESS_B_INVOKE_TOKEN`. The tokens
request a check of the configured directory; callers cannot supply data to sign
or access checkpoint storage. Failed attestations remain visible and retryable.

Separate Cloudflare accounts are optional. In one account, scope each deployment
identity to its Worker and required container/store resources, and verify that
it cannot change the other deployments. Separate accounts with separately held
credentials additionally reduce the impact of an account-wide administrator
compromise. Neither arrangement provides independent-operator protection when
one operator controls every credential. See
[Cloudflare resource permissions](https://developers.cloudflare.com/workers/authorization/).
Live permission-denial and account-isolation checks have **not run**.

For an existing deployment, preserve each witness's last trusted signed
checkpoint during migration. Do not initialize an empty store for a reused
witness key: that loses its continuity history. The generated delivery config
preserves old Durable Object migrations and does not delete those stores.
Set `WITNESS_INITIAL_CHECKPOINT_HEX` on each witness to its previous 188-byte
signed checkpoint encoded as lowercase hex. The worker imports it only when its
private store is empty, using a conditional write; the native witness verifies
the transferred checkpoint signature before signing. Only for an entirely new
witness identity, set this value to `new-identity`. Remove the bootstrap value
after the first durable checkpoint, so an unexpectedly empty store fails closed.
Verify continuity before switching URLs, then remove both old witness signing secrets from the delivery Worker and restrict
its deployment identity. This configuration has not performed that live cutover.
`npm run dev` retains the combined local development topology.

Worker secrets were generated locally and uploaded with `wrangler secret bulk`.
The ignored `.morse/cloudflare/` directory at the repository root contains the
local recovery copies with restricted filesystem permissions. Back up those keys
securely; replacing identity keys requires a coordinated client configuration
change. Never commit that directory or paste its contents into a ticket.

Required isolated backend Worker secrets:

- `MESSENGER_DATABASE_URL`, `OBJECT_DATABASE_URL`
- `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX`
- `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`, `WITNESS_A_INVOKE_TOKEN`
- `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`, `WITNESS_B_INVOKE_TOKEN`
- `MESSENGER_DELIVERY_SEALING_SEED_HEX`, `MESSENGER_DELIVERY_PUBLIC_KEY_HEX`
- `MESSENGER_DELIVERY_INTERNAL_TOKEN`, `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`
- `MESSENGER_OBJECT_INTERNAL_TOKEN`

Only the separate broker Worker holds `MESSENGER_PUSH_BROKER_SEED_HEX`,
`PUSH_DATABASE_URL`, and optional `MESSENGER_EXPO_ACCESS_TOKEN`; it shares only
`MESSENGER_PUSH_BROKER_INTERNAL_TOKEN` with the backend. Remove historical
combined broker secrets from the backend as part of the explicit cutover. The
broker public key and matching Expo project configuration belong in the clients'
native public configuration. The backend build additionally requires the public
`MORSE_PUSH_BROKER_URL` origin. See the scoped inventories above rather than
reusing one combined secret file for both Workers.

The local `.morse/cloudflare/client.env` contains only the deployed URLs and public
keys. Source it before building the native client. Its transparency, witness, and
delivery keys must be baked into the native security configuration; an OTA update
alone cannot change them. The privacy edge uses proof-of-work difficulty `16`.

Generate that public file from the provisioned environment with
`node mesh-private-messenger/ops/cloudflare/client-config.mjs` from the repository
root (an optional argument chooses another output path). The generator validates
the native configuration and TLS service URLs before writing, uses an explicit
public-field allowlist, and quotes values for safely sourcing the file. It also
exports the canonical `MESSENGER_SECURITY_CONFIG` frame used by the Mesh CLI.
An explicitly set but malformed frame fails closed; the CLI only uses legacy
A/B environment pins when the frame is absent.

Native config v2 is selected by `MESSENGER_WITNESS_SET_JSON`, an array of
`{"id":"witness-a","publicKey":"<64 lowercase hex>","operator":"Morse"}`
records, and `MESSENGER_WITNESS_THRESHOLD`, the strict majority of that array.
The writer sorts IDs; duplicates, duplicate keys and non-majority thresholds
are errors. Optional `MESSENGER_ANCHOR_RING_ADDRESS`,
`MESSENGER_ANCHOR_RPC_URLS` (a JSON array of 3–8 distinct HTTPS URLs), and
`MESSENGER_CREDIT_ISSUER_ORIGIN` pin the later chain/credit integrations; `-`
disables the address/origin and an empty RPC array is allowed with no anchor.
The ring alone does not activate a chain reader. Omitting all v2 fields
preserves the canonical six-line v1 native frame. Credits remain unimplemented.

An RFC migration release supplies `MESSENGER_TRANSPARENCY_LOG_VERSION=2`,
`MESSENGER_LEGACY_WITNESS_THRESHOLD`, and `MESSENGER_LEGACY_WITNESS_SET_JSON`
to select config v3. Add `MESSENGER_ANCHOR_PROGRAM_ADDRESS` and
`MESSENGER_ANCHOR_LOG_NAME` to select v4 and activate the scheduled public-account
reader. Production writers require log name `morse-main`; explicit development
builds may use the canary. Mesh derives the ring PDA and rejects mismatched pins.
To disable v4 anchors, set ring, program and log name to `-`. RPC URLs must have
distinct origins, not just distinct paths.

`MESSENGER_RELAY_URLS` (0–8 distinct canonical HTTPS origins) and
`MESSENGER_SLASH_MINT_ADDRESS` select config v5, preserving the v4 identity and
both witness policies. A nonempty relay list requires enabled anchors and the
judge's nonzero custody mint. Relay origins have no path, query or trailing
slash; the phone uses `/v1/fork-evidence`. These public pins survive `client.env`
export. This configuration support does not yet implement phone autofiling.

An explicit `MESSENGER_MINIMUM_SESSION_SUITE=1` or `2` wraps the canonical
security frame in config v6, preserving its feature profile and trust pins.
Omitting the setting preserves existing bytes and minimum 1; other spellings
are rejected. The envelope is bounded to 8,192 bytes and the public exporter
preserves the setting. Guarded mobile admission and both CLI roles now enforce
the configured minimum for new sessions and pass scoped host checks. Matching
native artifacts and release qualification are still pending. Do not activate
minimum 2 before the plan's renewal-release and 90-day adoption condition.

The shared writer feeds Android resources, iOS resources and desktop
`config.json`. The Mesh parser independently enforces the same canonical frame
and versioned ceiling (4,096 bytes for v1/v2; 8,192 for v3/v4/v5). A native set change invalidates the phone's cached
transparency view without discarding the last checkpoint used against rollback.

## GitHub Actions

Pushes to `release` run `.github/workflows/backend-release.yml`: build the verified Mesh
release, run protocol/storage/event-driven integration tests, deploy both witness
Workers and the privacy-edge Worker, apply migrations, deploy the backend's service
containers and delivery Worker, then verify live health, the edge's routes, and WebSocket
authorization. The separate Workers keep the secrets provisioned on them; CI only
ships their code. A parallel job runs `apps/landing/check.mjs` and publishes the
landing page as the static `morse-landing` Worker
(`https://morse-landing.snowdamiz.workers.dev`). Each of the two jobs runs only when its
inputs changed since the workflow's last successful push run (`scripts/release-changes.mjs`),
so a failed deploy retries on the next push; running the workflow by hand deploys both.
Pushes to `main` run the ordinary CI tests without deploying.
Deployments serialize in the `cloudflare-production` concurrency group and use
the `production` environment, restricted to the `release` branch.

To promote changes, merge them into `release` and push that branch. The backend
release workflow and its dependencies are committed on `release`; the app checkout
can remain on `main`. Do not force-push `main` over `release`.

Repeat the read-only live checks with
`MORSE_BACKEND_URL=https://morse-backend.snowdamiz.workers.dev MORSE_EDGE_URL=https://morse-privacy-edge.snowdamiz.workers.dev node smoke.mjs`.

Repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `MESSENGER_DATABASE_URL` (delivery role only)

Repository variables:

- `CLOUDFLARE_ACCOUNT_ID`
- `MORSE_BACKEND_URL` (the deployed HTTPS origin, without a trailing slash)
- `MORSE_EDGE_URL` (the privacy-edge Worker's HTTPS origin)
- `WITNESS_A_URL`, `WITNESS_B_URL` (the isolated witness HTTPS origins)

The API token is restricted to this Cloudflare account, with Account permissions
`Workers Scripts: Edit`, `Containers: Edit`, `Workers R2 Storage: Edit`, and
`Account Settings: Read`. Leave client IP filtering unset for hosted GitHub runners.
Save a replacement token through the hidden prompt:

```sh
gh secret set CLOUDFLARE_API_TOKEN --repo snowdamiz/whatsdown
```

Runtime secrets stay in Cloudflare and are retained by deployments. CI does not
need the signing seeds, object database credential, or push database credential.
Configure environment approvals in GitHub if deployments should require review.

## Verification and operating limits

`GET /health` checks all four services, runs both witness checks, and reports
whether a scheduler has a failed attempt awaiting recovery. A witness accepts an empty log only before its
first checkpoint; a previously witnessed checkpoint disappearing is a failure.
Health probes read cached scheduler state without waking services. Containers
sleep after five minutes without activity; open
WebSockets can keep the directory service active. Real traffic and due jobs wake
the required services automatically.
Workers Paid and R2 billing must be enabled. Runtime request logging is disabled
to avoid collecting protocol payloads and identifiers.

Neon was provisioned on Free with a 0.25-CU compute. Its 100 CU-hour monthly
allowance covers approximately 400 active hours. With polling disabled, the
database can scale to zero after five idle minutes. Usage depends on traffic and
scheduled work; sustained activity may require a paid plan. Cloudflare charges
are separate. See [Neon's current plans](https://neon.com/docs/introduction/plans).

Each service has exactly one container. Mailbox WebSocket delivery currently uses
process-local rooms, and the push queue has no multi-consumer leasing. Scale those
implementations before increasing replicas. Object operations use a global
PostgreSQL advisory lock; replace it with per-object locking if throughput demands
it. Each service scheduler serializes bounded batches and allows up to 4,096
pending transaction registrations; reaching that limit rejects new transactions
instead of accepting work without a durable wakeup. Failed attempts retain their
work and retry with backoff. The currently provisioned witnesses share an operator/account. Separate deployment
configuration is available, but live credential isolation has not been verified
and independent-operator protection is not claimed.

Run storage tests against an isolated PostgreSQL database whose name ends `_test`:

```sh
export MESSENGER_STORAGE_TEST_DATABASE_URL='postgres://localhost/morse_storage_test?sslmode=disable'
MESHC=/absolute/path/to/meshc npm test
```

These check R2 conditional writes and native Mesh HTTP I/O, checkpoint persistence
and stale-write rejection, the public route allowlist, repeatable migrations,
transaction rollback on registration failure, durable scheduler recovery, and
encrypted delivery with polling disabled. The live integration creates and drops
only its own randomly named test database.
The main CI job also runs native object and broker behavior tests. Never point
fixture tests at the production database.

Public `/health` reports cached scheduler failures. It does not start containers,
run maintenance, or ask witnesses to sign. A green response is Worker/scheduler
health, not a fresh end-to-end attestation; use scheduled job results and an
explicit deployment acceptance flow for that evidence.


## Compact transparency and retention rollout

The source now supports compact Merkle proofs and bounded storage maintenance.
Neither flag is enabled by default. This is a migration procedure, not a claim
that it has run on the live deployment.

1. Ship and verify native mobile/desktop clients and witnesses that accept proof
   v2. The group verifier needs the directory origin in its native request so it
   can fetch exact-range proofs for old anchors.
2. Drain directory writes and replace all directory instances together when
   applying migrations 019 and 020. Migration 019 backfills dense leaf positions
   and interior nodes. Migration 020 prepares shared device records. The old
   binary cannot write the new required leaf position or read normalized entries;
   a mixed old/new directory rollout is unsupported. Check backups before this
   coordinated migration, and resume writes only after the new instance passes
   the storage proof and lookup checks.
3. Set `MORSE_COMPACT_PROOFS=on` after all supported native builds understand v2.
   Roots and signatures stay unchanged. Once the tree exceeds 4,096 leaves,
   resetting this flag cannot restore legacy output; the new binary keeps the
   tree usable with compact proofs. Binary rollback then requires a compatible
   build, never truncating the log.
4. Set `MORSE_TRANSPARENCY_RETENTION=dry-run` and inspect scheduled job results.
   Then set `on` to prune superseded content older than 90 days and unanchored
   checkpoints older than 35 days. The latest checkpoint is always kept.
   `MORSE_TRANSPARENCY_PRUNE_DAILY_CAP` bounds each category per UTC day (default
   1,000); each invocation handles at most 100 of each and backfills at most 100
   entries. Setting retention to `off` stops further maintenance. Already pruned
   content is not recoverable from hashes.

Startup registers durable directory work when retention is enabled. Idle hosted
instances wake at least hourly; active directory jobs also process bounded
batches. The local service uses its existing retention worker. A failed hash
check aborts the backfill transaction and surfaces a maintenance failure;
operators must investigate the source data rather than bypass verification.
The ledger, reference rows, hashes and reconstructed content are exercised by
`transparency_retention.test.mpl`; `prove-m9.sh` includes this test and the
million-leaf compact capacity proof.


## Witness registry migration

Migration 017 replaces request-time A/B key selection with the database's
active witness registry. Apply it before deploying the directory. Empty-registry
startup seeds the existing A/B keys once; existing rows are never overwritten.
The public registry exposes only public operator metadata. Registered shadow
keys can attest, retired keys cannot, and returned evidence is capped at 16
signatures with pinned keys first.

The witness job reads `/internal/v1/transparency/push-witnesses` and then
`/internal/v1/transparency/witness-health`, both authenticated by the existing
internal token. Additional Morse-run push IDs use the secret
`MESSENGER_WITNESS_PUSH_TOKENS` JSON mapping. Legacy A/B invocation-secret names
remain accepted. Pull witnesses have a null push URL. A failed minority leaves
the job healthy only when the current registered pinned set meets its strict
majority. `/health` now returns JSON with cached threshold, signature ages and
anchor lag; missing or stale observations are not healthy. Probes do not invoke
signers or start containers.

The [pull-witness runbook](../witness/README.md) describes bootstrap, local
atomic state, evidence capture, image packaging and the B1 rollout gates.
The new Mesh APIs and native pins must ship before production activation.

## Anchor receipt storage

The directory now accepts bounded receipts from an authenticated chain writer
at `POST /internal/v1/transparency/anchors`. Its 128-byte `KTA` contract is in
[anchor-ring-v1.md](../../protocol/anchor-ring-v1.md#directory-transaction-receipts).
Migration 020 supplies the legacy retention table and migration 024 supplies
the separate RFC table. Both must be present before using this route.

The writer must first confirm finality and read the exact ring entry. Replaying
the same coordinates is safe after a lost response; the first receipt is kept.
A 409 requires investigation, and a 503 is retryable. The public gateway permits
only canonical `GET /v1|v2/transparency/anchor/{sequence}` discovery. Metadata is
not chain authentication. The scheduled poster and cosign crank now use these
routes; funded chain deployment remains pending.

Mesh also supplies bearer-authenticated `anchor-candidate/{version}` and
`anchor-cosigns` preparation routes under `/internal/v1/transparency/`.
`anchor-transactions.mjs` signs their verified instruction bytes with pinned
`@solana/kit` 8.4.0 and packs up to four cosigns within the v0 packet limit.
See the [preparation contract](../../protocol/anchor-ring-v1.md#writer-instruction-preparation).
Run `npm ci` here, then `scripts/prove-anchor-writer.sh` from the product with
the same `MESHC` and `CARGO_BUILD_SBF` settings as the judge proof. It uses
ephemeral local accounts, including actual SBF and precompile execution.
`anchor-outbox.mjs` adds a bounded SQLite journal for exact-wire retries and
durable finalized receipt recovery. `anchor-rpc.mjs` checks the expected cluster,
preserves bigint coordinates, bounds network requests and reconciles finality
and expiry; its readback callback must authenticate the actual judge accounts.
The proof command also runs Durable Object restart and RPC failure tests.
`anchor-accounts.mjs` supplies that readback: it derives and authenticates the
configured Log/ring and historical witness accounts, rejects a moving ring
snapshot, and checks exact entry coordinates and cosign bits. The SBF proof
uses it against actual program output and compares the directory receipt with
Mesh codec bytes. `anchor-job.mjs` connects those exact production adapters to
`anchor-cycle.mjs`; its proof runs the whole job against SBF accounts for both
log versions. A separate bundled Worker test signs with the same non-extractable
wallet resources in Miniflare.

The scheduled writer uses the following variables. It is off by default;
enabling it with valid keys and a registered, funded log permits signing and
broadcasting transactions.

| Variable | Contract |
| --- | --- |
| `MORSE_ANCHOR_MODE` | `off` (default), `devnet` or `mainnet`; each enabled mode pins its actual cluster genesis |
| `MORSE_COSIGN_CRANK` | `off` (default) or `on` |
| `MORSE_ANCHOR_CONFIG` | Public JSON with `program`, `logName`, `version` (1 or 2), `serviceKey` (64 lowercase hex digits), `origin` and `rpcUrl` (HTTPS) |
| `MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX` | Secret: canonical 64-byte Solana keypair as 128 lowercase hex digits |
| `MORSE_ANCHOR_AUTHORITY_KEYPAIR_HEX` | Separate secret in the same format; its public key must match the registered Log |
| `MORSE_ANCHOR_ALERT_URL` | Operator-configured HTTPS alert receiver; no userinfo, fragment or redirects |
| `MORSE_ANCHOR_ALERT_TOKEN` | Optional secret bearer token for that receiver |

Legacy version 1 has an empty origin. Version 2 requires the exact registered
C2SP origin. Both wallets must differ from the service signing key and from
each other; Kit checks keypair correspondence and imports non-extractable
signing resources. Keep these secrets in Worker secret bindings. The directory
container is never given either wallet secret. Replacing a wallet or changing
the program/log/cluster changes the durable scope and refuses reuse of the old
journal; changing only the RPC endpoint preserves recovery state.


The backend's minute cron registers `JOBS.getByName('anchor')`, which owns an
independent fifteen-second alarm and SQLite journal. Enabling a quiet log does
not depend on directory traffic, and slow witness jobs cannot hold this alarm.
The cron does nothing in `off` mode. The next existing alarm also stops when
disabled, retaining signed recovery state. `MORSE_COSIGN_CRANK=off` prevents new
cosign preparation and rebroadcast but still reconciles prior finalized work.

A post requires a changed root/size or a 59-minute heartbeat deadline, a new
checkpoint hash and increasing sequence. Both local durable time and finalized
chain time enforce the one-minute ceiling. The directory's existing witness
polling supplies fresh signed checkpoints for quiet logs. If that checkpoint
stops changing, the writer reports `heartbeat_checkpoint_unavailable` instead
of treating an idempotent repost as a heartbeat. Each crank turn selects one
incomplete checkpoint using its immutable historical generation, rotates a
persisted cursor, and admits only entries within the inclusive 1,500-slot
window. Two outbox passes of at most five transactions provide capacity for a
post and sixteen single-pair C2SP transactions per minute under responsive RPC
and finality; this is capacity, not a live latency guarantee.

Keep operator funding at or below 1 SOL. Budget attendance activation and weekly
account rent separately:
the first post each epoch creates the 2,640-byte judge account atomically. Its
rent is additional to transaction fees; the fee-only spending threshold below
does not guarantee enough funds for this creation. See
[`attendance-v1.md`](../../protocol/attendance-v1.md) for governed setup and the
one-way activation procedure. Deploy the judge's compact C2SP tag 30 support
before the updated directory/writer, then update all readers before activation.

The writer warns at 0.2 SOL and marks
0.05 SOL critical. It refuses new spending below the 25,000-lamport single-packet
reserve, while slashed or timelocked logs and a local clock behind chain time
also stop new spending. An excess deposit raises `fee_payer_overfunded` without
stopping work: anyone can send SOL to the public wallet. Alert events contain
public identity, integer balance and bounded health codes, never wallet secrets
or RPC URLs. Route `critical` events to the operator pager and `warning` events
to the warning channel; `recovered` resolves an earlier delivered alert. The
receiver should deduplicate `eventId`. Its exact JSON body is persisted before
sending and retried after 30 seconds; only HTTP 2xx acknowledges delivery.
An absent or unavailable receiver retains pending alert state without blocking
anchors. No alert receiver or pager has been configured by the local proof.

`/health` now includes the cached `anchor` report: pending transaction count,
fee band, balance, alert delivery state and last recorded post. An enabled
writer with missing/older-than-two-minute status, a fee warning or a job issue
makes health degraded. Probes never read chain RPC, sign or start a container.
Local tests do not satisfy deployment review or the seven-/thirty-day live gates.


The runtime image also carries `/app/morse-relay` (allowlisted writer sources,
lockfile, example and runbook) beside `/app/morse-fork-verifier`. The witness
packager extracts both into its standalone `relay.tar`; this does not start a
relay inside the backend or witness container. The `relay-sources` build target
can be exported independently for the operator archive proof without rebuilding
Mesh. No wallet, journal, local environment file, test source or node_modules is
copied into that payload.

## Read-only public snapshot producer

The minute cron can also schedule a separate, default-off public report DO.
Its internal authenticated Mesh reader accepts only trusted configured policy;
public GETs cannot set pins or initiate reads. Publication is atomic, failures
make current data unavailable, and retained settled observations remain visible.
See [the exact policy, bounds, failure and local replay contract](../public-chain/SNAPSHOT.md).
No producer mode, live policy, public route or deployment is enabled by this change.

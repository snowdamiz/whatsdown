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

All builds use the exact commit in `../../mesh-revision`. A different
`MESH_LANG_REVISION` is rejected. Language changes must be pushed before updating
that pin. `prepare-build.mjs` writes an ignored `wrangler.build.json`; Docker
caches the pinned compiler for subsequent builds.

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

```sh
# Run with the edge's own deployment credentials.
# MORSE_DELIVERY_URL is the backend's public HTTPS origin.
npm run deploy:edge
```

The edge Worker (`morse-privacy-edge`) needs exactly one secret,
`MESSENGER_DELIVERY_INTERNAL_TOKEN`. It must never be given
`MESSENGER_DELIVERY_SEALING_SEED_HEX`, a database URL, or any signing seed; its
container environment is built from an allowlist so that an over-provisioned
deployment still passes none of them through. It forwards only the sealed body
and that bearer credential, refuses redirects, and serves no other route.
Clients send through it by setting `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL` to
the edge origin; every other request goes to the backend origin.

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
assumption. Only message submission uses the edge: lookups, prekey claims,
mailbox reads, object transfers, and push registration reach the backend
directly and reveal the requester's address to it. Live permission-denial and
account-isolation checks have **not run**, and no live cutover has been
performed. `npm run dev` retains the combined local development topology.

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

Required Worker secrets:

- `MESSENGER_DATABASE_URL`, `OBJECT_DATABASE_URL`, `PUSH_DATABASE_URL`
- `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX`
- `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`, `WITNESS_A_INVOKE_TOKEN`
- `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`, `WITNESS_B_INVOKE_TOKEN`
- `MESSENGER_DELIVERY_SEALING_SEED_HEX`, `MESSENGER_DELIVERY_PUBLIC_KEY_HEX`
- `MESSENGER_PUSH_BROKER_SEED_HEX`, `MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX`
- `MESSENGER_DELIVERY_INTERNAL_TOKEN`, `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`
- `MESSENGER_OBJECT_INTERNAL_TOKEN`

`MESSENGER_EXPO_ACCESS_TOKEN` is optional, depending on the Expo project's push
security configuration. Clients also need the matching Expo project configuration
for push delivery.

The local `.morse/cloudflare/client.env` contains only the deployed URLs and public
keys. Source it before building the native client. Its transparency, witness, and
delivery keys must be baked into the native security configuration; an OTA update
alone cannot change them. The privacy edge uses proof-of-work difficulty `16`.

## GitHub Actions

Pushes to `release` run `.github/workflows/backend-release.yml`: build the pinned Mesh
compiler, run protocol/storage/event-driven integration tests, deploy both witness
Workers and the privacy-edge Worker, apply migrations, deploy the backend's service
containers and delivery Worker, then verify live health, the edge's routes, and WebSocket
authorization. The separate Workers keep the secrets provisioned on them; CI only
ships their code. A parallel job runs `apps/landing/check.mjs` and publishes the
landing page as the static `morse-landing` Worker
(`https://morse-landing.snowdamiz.workers.dev`). Pushes to `main` run the ordinary CI tests without deploying.
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
Health probes themselves wake services, so frequent external probes would prevent
them from sleeping. Containers sleep after five minutes without activity; open
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

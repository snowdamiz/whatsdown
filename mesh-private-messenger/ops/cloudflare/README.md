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

The image builds a pinned Mesh compiler and all service binaries for Linux amd64.
The first build on an Apple Silicon workstation runs under emulation and is slow;
Docker caches the compiler for subsequent builds. CI uses an amd64 runner.

Worker secrets were generated locally and uploaded with `wrangler secret bulk`.
The ignored `.morse/cloudflare/` directory at the repository root contains the
local recovery copies with restricted filesystem permissions. Back up those keys
securely; replacing identity keys requires a coordinated client configuration
change. Never commit that directory or paste its contents into a ticket.

Required Worker secrets:

- `MESSENGER_DATABASE_URL`, `OBJECT_DATABASE_URL`, `PUSH_DATABASE_URL`
- `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX`
- `MESSENGER_WITNESS_A_SIGNING_SEED_HEX`, `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`
- `MESSENGER_WITNESS_B_SIGNING_SEED_HEX`, `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`
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

Pushes to `release` run `.github/workflows/backend-release.yml`: build the pinned
compiler, run protocol/storage/event-driven integration tests, apply migrations,
deploy all six containers and the Worker, then verify live health and WebSocket
authorization. Pushes to `main` run the ordinary CI tests without deploying.
Deployments serialize in the `cloudflare-production` concurrency group and use
the `production` environment, restricted to the `release` branch.

To promote changes, merge them into `release` and push that branch. The backend
release workflow and its dependencies are committed on `release`; the app checkout
can remain on `main`. Do not force-push `main` over `release`.

Repeat the read-only live checks with
`MORSE_BACKEND_URL=https://morse-backend.snowdamiz.workers.dev node smoke.mjs`.

Repository secrets:

- `CLOUDFLARE_API_TOKEN`
- `MESSENGER_DATABASE_URL` (delivery role only)

Repository variables:

- `CLOUDFLARE_ACCOUNT_ID`
- `MORSE_BACKEND_URL` (the deployed HTTPS origin, without a trailing slash)

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
work and retry with backoff. The two witnesses have distinct keys and durable checkpoints, but share an
operator/account and therefore do not provide independent-operator protection.

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

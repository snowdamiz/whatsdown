# Independent push-broker deployment

The isolated backend build has no PushBroker container or Durable Object
binding. Its only broker-specific authority is a pinned HTTPS origin and the
exact narrow request credential. The separate broker Worker has its own
container, durable push scheduler and queue database. Combined `npm run dev`
retains the original in-process topology explicitly.

This code/configuration has local routing, refusal and scheduler-restart tests.
No broker was deployed, no key was rotated and no stored queue was migrated by
this change. Existing optional Mesh/PostgreSQL/provider/SBF tests are separate.
Cloudflare accounts and colluding operators can still correlate timing; this
does not make a live account-isolation claim or close the separate M2 topology
gate.

## Configuration and authority

| Deployment | Required broker inputs | Must not hold |
|---|---|---|
| Backend | `MORSE_PUSH_BROKER_URL` canonical HTTPS origin; `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN` exact 32–256 character request credential | Broker unsealing seed, broker queue DB credentials, Expo access token, broker container/DO binding |
| Broker | Same origin and request credential; `MESSENGER_PUSH_BROKER_SEED_HEX`; separate `PUSH_DATABASE_URL`; optional `MESSENGER_EXPO_ACCESS_TOKEN` | Directory/mailbox DB access, delivery unsealing/signing keys, issuer/object/witness credentials, backend service bindings |

The shared request credential permits only a bounded opaque wake at the public
broker ingress. It does not expose the broker's private job endpoint or allow
arbitrary provider URLs. Use a distinct random credential, not an account/device
credential or another service's administration token. Only the public broker
encryption key is distributed to clients; never place the seed in backend or
client configuration.

With the broker operator's independently scoped deployment credentials:

```sh
export MORSE_PUSH_BROKER_URL=https://broker.example
# Provision only this Worker's broker seed, queue DB and request credential.
npm run deploy:push-broker
```

Then supply the same origin and narrow credential to the backend operator. Its
existing `npm run deploy` (`--isolated`) now requires the broker origin and removes
the broker class/binding. The release workflow requires the origin before any
deployments or migration. It does **not** deploy the broker using backend
credentials. No hostname or credential is invented by these commands; the
operator must provide the actual configured values and pass the existing release
verification gate.

Build inputs containing broker-only credentials are rejected by the isolated
backend builder. The Directory container startup and outbound hop also refuse
an over-provisioned backend Worker environment. These checks do not delete old
remote Worker secrets: the operator must audit and remove the old backend seed,
queue DB and Expo token before cutover. Scoped accounts/permissions and distinct
database roles must be verified outside this local fixture. Keep any recovery
copies under the broker operator's control; do not bulk-upload a combined secret
file into the backend.

## Request and job paths

The existing Mesh directory produces canonical sealed `PWK` and retains its
existing outbox/retry behavior. In isolated mode its `http://push.internal`
container callback accepts only `POST /internal/v1/push`, bounds the body at
621 bytes, checks the exact request credential and forwards it to the pinned
broker origin's `/v1/ingress/push` over HTTPS. The request has a 5-second timeout
and manual redirect policy. Redirects/unexpected statuses become 502 without
following them; unavailable transport becomes 503. It forwards no client
tracking headers, caller-selected destination or response body. Workerd may add
its own transport headers; the broker strips them before the container.

The broker public Worker accepts only that exact authenticated ingress (plus
cached `/health`). Wrong credentials are refused before body reading or container
access. Empty or oversized bodies are refused with 422. The container still
performs its existing canonical PWK validation, independent bearer check and
durable queue admission before returning 204. No queue/provider logic moved into
JavaScript. Public `/internal/v1/jobs/push`, backend/admin routes, query variants
and alternate verbs are absent even with a valid ingress credential.

The broker alone exposes the private `jobs.internal/push` container callback and
holds its own `PushJobScheduler`. It accepts only bounded transaction IDs and
push jobs; directory/witness/object/anchor registration is refused. The existing
durable scheduler retains unknown work and retries through broker restarts.
An independent minute cron registers the fixed private recovery job `0`, so an
existing quiet queue or a lost alarm can restart without waiting for a new
public wake. It follows existing queue due times; it cannot choose a destination
or force premature provider retries. No public request can invoke that cron.
Backend health labels the remote broker `not-observed`, rather than claiming the
old backend push scheduler proves remote health. Broker health uses only cached
job failure status and does not wake the container or prove provider delivery.

## Existing queue and deployment cutover

Live cutover is **not automatic**. Quiesce the old broker and reconcile/drain or
transfer its existing sealed queue and tombstones into a broker-only database
role, preserving exact wake hashes and the existing key. Do not run two polling
brokers against the queue: existing queue processing does not lease across
replicas. Validate seed/public-key continuity and durable queue/scheduler startup
under the new deployment before enabling backend forwarding. How an existing
database/DO is moved, backups, permissions and provider receipt checks are actual
operator gates; this fixture does not claim to perform them.

On backend cutover, old backend push scheduler alarms stop and new push-job
registrations there refuse. Pending scheduler records remain available for
inspection; no queued wake is silently deleted or replayed through a new public
job proxy. The broker's private recovery cron can process its existing due queue
after that operator-controlled transfer; it does not perform the transfer or
prove that no row was omitted. Keep the combined development configuration for
local use only.

## Local checks

```sh
node --test push-isolation.test.mjs push-release-preflight.test.mjs
node --test --test-concurrency=2 *.test.mjs
```

The fixtures execute both production Worker routing layers with a fixture
container, deny forbidden bindings/paths/credentials, check bounded opaque-byte
preservation and redirect refusal, and exercise the real durable scheduler over
restart and legacy backend alarm retirement. They use local in-memory transport;
they do not prove live cross-account HTTPS, real queue migration or Expo delivery.

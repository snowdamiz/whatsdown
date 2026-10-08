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

There is no keep-warm cron. Idle schedulers have no alarm and make no
database queries. The two crons (every minute, every hour) do the witness
network's chain work (see "Witness network jobs"): they read the chain, and wake
the directory only for the hourly anchor heartbeat and while a cosign window is
open. The ordinary local runner retains its polling behavior;
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
interrupted uploads. Part indices run 0 through 8,192 (512 MiB attachments paid
with credits); the object store deletes a whole object with one
`DELETE /{object id}` carrying `X-Part-Count`, which the storage binding turns
into batched R2 deletes. The object store's only way into the core is
`delivery.internal`, which forwards `POST /internal/v1/credits/redeem` and
nothing else.

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
and that bearer credential, refuses redirects, and serves no other route than
submission, credit purchases, longer storage, and the Oblivious HTTP relay
(`POST /v1/ohttp`, below). It never holds the OHTTP gateway key either.
Clients send through it by setting `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL` to
the edge origin, and builds pin it as their OHTTP relay (`MESSENGER_OHTTP_RELAY`).

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
assumption. Submission and, as Oblivious HTTP, lookups, prekey claims,
transparency proofs and the mailbox fetch and acknowledgement go through the
edge; the mailbox stream, device-signed writes (registration, prekey
publication, revocation, push binding) and object transfers reach the backend
directly and reveal the requester's address to it
([privacy-contract.md](../../protocol/privacy-contract.md#paths-and-correlation)). Live permission-denial and
account-isolation checks have **not run**, and no live cutover has been
performed (runbook: "Cutover to separate accounts"). `npm run dev` retains the
combined local development topology.

### Sealed ingress edge credential (§22 M2)

The backend's `POST /v1/ingress/sealed` is publicly routable. On top of the
edge's bearer credential, the build can require a credential that only the edge
deployment holds, in either or both of two forms. Each is a property of the
build that protects the route only once it is provisioned; without its pin on
the backend the bearer is the only guard, as before.

**Signed requests (works today).** The edge signs every sealed record it
forwards with an Ed25519 key held only as its Worker secret
`MORSE_EDGE_INGRESS_SIGNING_KEY` (64-hex seed; the container never sees it).
The signature covers the method, host, path, a timestamp, a random nonce and
SHA-256 of the exact body
([format](../../protocol/sealed-delivery-v1.md#edge-request-signatures)). Once
the backend is built with `MORSE_EDGE_INGRESS_PUBLIC_KEY` (comma-separated while
rotating), a request without a valid signature from a pinned key, within 60
seconds of the backend's clock and with a nonce not seen before, answers `403`
and never wakes the delivery core; then the bearer is checked (`401`). Accepted
nonces live in the backend's `IngressNonces` Durable Object until they fall out
of the window. A malformed pin or a missing nonce store fails closed (`503`).

1. On the edge holder's machine, into a directory outside the repository:

   ```sh
   node ingress-key.mjs ~/morse-edge-ingress-key
   ```

   It writes `edge-ingress-signing-key.hex` (0600) and prints the public key.
2. With the edge's own credentials, store the key as the edge's secret, then
   delete the file:

   ```sh
   npx wrangler secret put MORSE_EDGE_INGRESS_SIGNING_KEY --name morse-privacy-edge < ~/morse-edge-ingress-key/edge-ingress-signing-key.hex
   ```

   The edge signs from then on; a backend without the pin ignores the headers.
3. Deploy the backend with `MORSE_EDGE_INGRESS_PUBLIC_KEY=<printed key>`
   (`npm run deploy`; in CI, the repository variable of the same name, or the
   next release drops the pin).
4. Verify: `curl -X POST -H 'Authorization: Bearer x' <backend>/v1/ingress/sealed`
   answers `403`; a message sent through the edge arrives;
   `node isolation-check.mjs` passes `M2 ingress pin` (backend) and
   `M2 edge credential` (edge).

Rotation: generate a new key, deploy the backend pinning both public keys,
replace the edge's secret, then deploy the backend with only the new key.
Rollback: deploy the backend without `MORSE_EDGE_INGRESS_PUBLIC_KEY`. The
backend never holds the private key: CI carries only the public key.

**Client certificate (mTLS, opt-in).** Plan §21 D17's first choice:

- The edge presents it through an mTLS certificate binding,
  `DELIVERY_CLIENT_CERT`, added when the edge is built with
  `MORSE_EDGE_CLIENT_CERT_ID`. The certificate and its key are uploaded to the
  edge's account only.
- Once the backend is built with `MORSE_INGRESS_CLIENT_CERT_SHA256`, it answers
  `403` unless `request.cf.tlsClientAuth` shows a certificate that was
  presented, verified by the zone (`certVerified` is `SUCCESS`), not revoked,
  and whose SHA-256 fingerprint is pinned, plus, when
  `MORSE_INGRESS_CLIENT_CERT_ISSUER` is set, whose `certIssuerDNRFC2253` matches.
  It then checks the bearer (`401`). A refused request never wakes the delivery
  core, and a malformed pin fails closed (`503`). The container checks the
  bearer again.
- Without the pin the bearer is the only guard, as before. The certificate is
  a property of the build; it protects the route only after the steps below.

**Platform limitation (checked 2026-09-29).** Cloudflare's
[mTLS binding documentation](https://developers.cloudflare.com/workers/runtime-apis/bindings/mtls/)
says a Worker can't present a client certificate to a hostname proxied by
Cloudflare: the request fails with `520`. Every Worker hostname is proxied, so
an edge running as a Cloudflare Worker can't reach a backend running as a
Cloudflare Worker with its certificate. **Setting the pin while the edge is a
Cloudflare Worker stops every send.** Pin the certificate only when Cloudflare has lifted
that restriction (re-read the note, then prove it with a staging edge and
backend first), or when the edge runs off Cloudflare, for example with an
independent edge operator (D20), presenting the same certificate from its own
TLS client. The backend side works for any client either way. Until then,
signed requests provide M2.

Certificate steps:

1. Pick a dedicated ingress hostname on a zone in the backend's account, such as
   `ingress.<domain>`. Building the backend with `MORSE_INGRESS_HOSTNAME` set
   attaches it to `morse-backend` as a Custom Domain; the backend's deploy
   token then also needs Zone → Workers Routes: Edit on that zone. workers.dev
   can't verify client certificates, so there a pinned route always answers
   `403`.
2. Turn on client certificate verification for that hostname: SSL/TLS → Client
   Certificates → Hosts → add the hostname. The Worker makes the decision, so no
   WAF rule is needed; a custom rule blocking
   `(http.host eq "<hostname>" and not cf.tls_client_auth.cert_verified)` adds
   defense in depth.
3. Make the certificate on a workstation, into a directory outside the
   repository (the script refuses paths inside it and never overwrites a key):

   ```sh
   node dev-mtls-cert.mjs ~/morse-ingress-mtls
   ```

   It writes a CA (`ca.pem`, `ca.key`), the edge's key and CSR (`client.key`,
   `client.csr`), and `client.pem` signed by that CA for client authentication
   only, and prints the pins. Then choose who verifies it:
   - **Cloudflare-managed CA (any plan).** SSL/TLS → Client Certificates →
     Create Certificate → "Use my private key and CSR", paste `client.csr`, and
     save the certificate Cloudflare returns as `client-cloudflare.pem`. Use it
     instead of `client.pem` below, and take the pins from it:
     `openssl x509 -in client-cloudflare.pem -noout -fingerprint -sha256` and
     `openssl x509 -in client-cloudflare.pem -noout -issuer -nameopt RFC2253`.
     `ca.pem` and `ca.key` aren't used; delete them.
   - **Your own CA (Enterprise, "Bring your own CA").** With a backend-account
     token holding SSL and Certificates: Edit, upload `ca.pem`
     (`POST /accounts/{account_id}/mtls_certificates` with
     `{"name":"morse-edge-ingress-ca","certificates":"<ca.pem>","ca":true}`)
     and associate it with the hostname
     (`PUT /zones/{zone_id}/certificate_authorities/hostname_associations` with
     `{"mtls_certificate_id":"<id>","hostnames":["<hostname>"]}`). For
     production, run the script on an offline machine and keep `ca.key` offline.
4. With the edge's own credentials (a token for the edge account with SSL and
   Certificates: Edit), upload the client certificate and key, and note the ID it
   prints (`npx wrangler mtls-certificate list` shows it again):

   ```sh
   npx wrangler mtls-certificate upload --cert client.pem --key client.key --name morse-edge-ingress
   ```

5. Deploy the edge with `MORSE_EDGE_CLIENT_CERT_ID=<id>` and
   `MORSE_DELIVERY_URL=https://<hostname>` (`npm run deploy:edge`).
6. Deploy the backend with `MORSE_INGRESS_HOSTNAME`,
   `MORSE_INGRESS_CLIENT_CERT_SHA256` and, optionally,
   `MORSE_INGRESS_CLIENT_CERT_ISSUER` (`npm run deploy`). The release workflow
   reads repository variables of the same names, so set them there too, or the
   next release drops the pin.
7. Verify: `curl -X POST https://<hostname>/v1/ingress/sealed` answers `403`;
   `curl --cert client.pem --key client.key -X POST https://<hostname>/v1/ingress/sealed`
   answers `401` (certificate accepted, no bearer); the same request to the
   workers.dev origin answers `403`; a message sent through the edge arrives;
   `node isolation-check.mjs` passes `M2 ingress pin` and
   `M2 edge credential`. Then delete the local `client.key`: the edge
   account holds it.

Rotation: make a new certificate, deploy the backend with both fingerprints
comma-separated, upload the new certificate to the edge account and deploy the
edge with its ID, then deploy the backend with only the new fingerprint, delete
the old certificate (`npx wrangler mtls-certificate delete --id <old>`) and, if
Cloudflare issued it, revoke it under Client Certificates. Rollback: deploy the
backend without `MORSE_INGRESS_CLIENT_CERT_SHA256`, which leaves the bearer as
the only guard.

### Oblivious HTTP gateway key (§22 M3)

The directory is the Oblivious HTTP gateway ([ohttp-v1.md](../../protocol/ohttp-v1.md))
for the requests phones send through the edge: lookups, prekey claims,
transparency proofs, the issuer's keys, and the mailbox fetch and
acknowledgement. The edge relays them to `POST /v1/ingress/ohttp`, behind the
same guards as the sealed ingress (bearer, then the edge's signature or client
certificate once pinned), which maps to the core's `POST /internal/v1/ohttp`.
The edge holds no key: it can't read what it relays.

The key is an X25519 key pair with a one-byte id. Generate one into the ignored
key directory, never printing it:

```sh
node -e 'const c = require("crypto"); const k = c.generateKeyPairSync("x25519");
  const raw = (key, type) => key.export({ format: "der", type }).subarray(-32).toString("hex");
  console.log(JSON.stringify({ MESSENGER_OHTTP_GATEWAY_KEY_ID: "1",
    MESSENGER_OHTTP_GATEWAY_SEED_HEX: raw(k.privateKey, "pkcs8"),
    MESSENGER_OHTTP_GATEWAY_PUBLIC_KEY_HEX: raw(k.publicKey, "spki") }))' \
  > .morse/cloudflare/ohttp.json && chmod 600 .morse/cloudflare/ohttp.json
```

Upload `MESSENGER_OHTTP_GATEWAY_KEY_ID` and `MESSENGER_OHTTP_GATEWAY_SEED_HEX`
to the backend Worker (`npx wrangler secret put …`, or with the others through
`wrangler secret bulk`); the Worker passes them to the directory container,
which refuses to start if a configured key doesn't load and answers `503` when
none is configured. Then pin it for builds: `client-env.mjs --keys
.morse/cloudflare/ohttp.json …` writes `MESSENGER_OHTTP_KEY` (`<id>:<public
key>`) and, from `EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL`, `MESSENGER_OHTTP_RELAY`
into `client.env`; set the same two as GitHub and EAS production variables.
Release builds refuse to build without them. After deploying, check that the
backend serves the pinned key and that a query through the edge comes back
open:

```sh
MORSE_BACKEND_URL=https://… MORSE_EDGE_URL=https://… MESSENGER_OHTTP_KEY=<id>:<public key> node smoke.mjs
```

Order: deploy the directory with the key and the edge with the route before
shipping builds that pin the key; builds that pin none keep using the direct
routes, which stay.

Rotation (RFC 9458 §6.4, §6.6): generate a key with a new id; set it as
`MESSENGER_OHTTP_GATEWAY_KEY_ID`/`MESSENGER_OHTTP_GATEWAY_SEED_HEX` and move the
old pair to `MESSENGER_OHTTP_GATEWAY_PREVIOUS_KEY_ID`/`MESSENGER_OHTTP_GATEWAY_PREVIOUS_SEED_HEX`;
deploy; ship builds pinning the new key; once no supported build pins the old
one, delete the previous pair. Deleting a key is what makes the requests sent
under it unreadable afterwards, so don't keep old keys around. A request under
a key the gateway no longer holds gets a bare `422`, which the phone reports as
an outage until it updates.

The gateway's replay register is in the directory container's memory; see
[ohttp-v1.md](../../protocol/ohttp-v1.md#replays) for what a restart means.

### Separate push-broker deployment (§22 M4)

The broker holds the key that opens provider tokens; the backend holds the link
from a mailbox to its push binding. One deployment holding both could join
them, so `npm run deploy` builds a backend without the broker, and the broker
deploys on its own:

```sh
# Run with the broker's own deployment credentials.
npm run deploy:push-broker
```

`morse-push-broker` runs the broker container and its own push scheduler. Its
secrets are `MESSENGER_PUSH_BROKER_SEED_HEX`,
`MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`, `PUSH_DATABASE_URL` (the `morse_push`
role) and, optionally, `MESSENGER_EXPO_ACCESS_TOKEN`; its container environment
is built from that allowlist. `MESSENGER_PUSH_BROKER_PUBLIC_KEY_HEX` goes with
them as the recovery copy clients are built from. The Worker serves
`GET /health` (the push scheduler's cached state) and `POST /internal/v1/push`,
which checks the broker bearer before waking the container. Every other path
answers `404`.

The backend is built with `MORSE_PUSH_BROKER_URL`, the broker's HTTPS origin, and
keeps only `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN` (the same value as the
broker's): the directory's sealed push jobs go to `<broker>/internal/v1/push`
with that bearer, no other header, and redirects refused. The backend's `/health` no longer covers push, and its old
push scheduler drops any leftover wakeups on its next alarm. Queue rows are
sealed to the broker's key and stay in the same database, so nothing migrates:
queued pushes resume on the broker's first wakeup.

Order: set the broker's secrets, deploy the broker, then the backend. Check
`curl https://<broker>/health` answers `200` and a push arrives. Then remove what
the backend no longer needs, with the backend's credentials:

```sh
npx wrangler secret delete MESSENGER_PUSH_BROKER_SEED_HEX --name morse-backend
npx wrangler secret delete PUSH_DATABASE_URL --name morse-backend
npx wrangler secret delete MESSENGER_EXPO_ACCESS_TOKEN --name morse-backend
npx wrangler containers list   # then delete the morse-backend-pushbroker application
```

### Separate credit-issuer deployment (credits, plan Phase 4)

The credit issuer ([services/credit-issuer](../../services/credit-issuer/README.md))
holds the key-wrapping seed that opens its signing keys, the treasury deposit
seed and its own database. It deploys on its own, like the push broker, and
the backend never holds any of it:

```sh
# Run with the issuer's own deployment credentials.
CREDIT_DATABASE_URL=… node migrate.mjs --credit-issuer
npm run deploy:credit-issuer
```

`morse-credit-issuer` runs the issuer container. Its Worker secrets are
`CREDIT_DATABASE_URL` (the `morse_credit` role on its own database, never the
delivery database), `MORSE_CREDIT_KEY_WRAPPING_SEED_HEX`,
`MORSE_CREDIT_DEPOSIT_SEED_HEX`, `MORSE_CREDIT_ISSUER_INTERNAL_TOKEN` (the same
value the backend holds), `MORSE_CREDIT_EDGE_TOKEN` (the same value the edge
holds) and, with Lightning, `MORSE_CREDIT_LND_MACAROON_HEX`. Its vars are
`MORSE_CREDITS_MODE` (`off` unless set), `MORSE_CREDIT_ISSUER_NAME`,
`MORSE_CREDIT_DIRECTORY_URL` (the backend's HTTPS origin) and the optional
settings in the issuer's README (RPC, mint, oracle, LND, treasury, sweep delays,
split, `MORSE_CREDIT_MAX_OPEN_QUOTES`, `MESSENGER_ABUSE_DIFFICULTY`). The
container environment is built from that allowlist. The Worker serves
`GET /health` and, with the edge's bearer, `POST /v1/credits/quote` and
`POST /v1/credits/issue`; every other path answers `404`.

The edge is built with `MORSE_CREDIT_ISSUER_URL` (the issuer's HTTPS origin) and
holds `MORSE_CREDIT_EDGE_TOKEN` as a Worker secret; its container sends to
`issuer.internal`, and the edge Worker adds the bearer. The backend keeps
`MORSE_CREDITS_MODE` (`off` by default; `live` in production once the issuer
is), `MORSE_CREDIT_ISSUER_INTERNAL_TOKEN` and, optionally,
`MORSE_SIGNUP_SURGE_TARGET`. Migration `018` (spent set, holds, issuer keys) and
`022` (mailbox policies, paid storage, spend totals) run with the backend's own
migrations. The edge's credit calls to the core cross deployments as
`POST /v1/ingress/credits/redeem` and `POST /v1/ingress/mailbox/retention`,
guarded exactly like `POST /v1/ingress/sealed`.

Order: create the issuer's database and role, set its secrets, migrate it,
deploy it; provision and announce its keys (issuer README, "Keys"); deploy the
edge with `MORSE_CREDIT_ISSUER_URL`; then the backend with `MORSE_CREDITS_MODE`.
`backend-release.yml` does the migration and deploy on every release once the
repository variable `MORSE_CREDIT_ISSUER_URL` and secret `CREDIT_DATABASE_URL`
are set, and skips the issuer otherwise. Its mode stays whatever its own Worker
says: a release never turns credits on.

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

The Cloudflare witnesses run the witness binary in its default `once` mode (one
round per `/attest`), with the same checks as every Morse witness: a
checkpoint more than 60 s from the container's clock is refused, a directory
showing this witness's signature on a checkpoint newer than its store halts
it, and consistency is proved with `KTC` v2. They set no evidence directory or
relays, so a broken history appears only as a failed attestation in the jobs
Worker's log. Witnesses off Cloudflare run pull mode from
[`ops/witness`](../witness/README.md).

Verify continuity before switching URLs, then remove both old witness signing secrets from the delivery Worker and restrict
its deployment identity. This configuration has not performed that live cutover.
`npm run dev` retains the combined local development topology.

Worker secrets were generated locally and uploaded with `wrangler secret bulk`.
The ignored `.morse/cloudflare/` directory at the repository root contains the
local recovery copies with restricted filesystem permissions. Back up those keys
securely; replacing identity keys requires a coordinated client configuration
change. Never commit that directory or paste its contents into a ticket.

Required backend Worker secrets (the edge's, the push broker's and the
witnesses' are listed in their sections):

- `MESSENGER_DATABASE_URL`, `OBJECT_DATABASE_URL`
- `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX`
- `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX`, `WITNESS_A_INVOKE_TOKEN`
- `MESSENGER_WITNESS_B_PUBLIC_KEY_HEX`, `WITNESS_B_INVOKE_TOKEN`
- `MESSENGER_DELIVERY_SEALING_SEED_HEX`, `MESSENGER_DELIVERY_PUBLIC_KEY_HEX`
- `MESSENGER_DELIVERY_INTERNAL_TOKEN`, `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN`
- `MESSENGER_OBJECT_INTERNAL_TOKEN`
- `MESSENGER_OHTTP_GATEWAY_KEY_ID`, `MESSENGER_OHTTP_GATEWAY_SEED_HEX` (and while
  rotating the `…_PREVIOUS_…` pair; see "Oblivious HTTP gateway key")

The push broker's `MESSENGER_EXPO_ACCESS_TOKEN` is optional, depending on the
Expo project's push security configuration. Clients also need the matching Expo
project configuration for push delivery. `npm run dev` (the combined topology)
still runs the broker in-process and needs its secrets and `PUSH_DATABASE_URL`.

### Witness registry, log storage and their flags

The directory accepts attestations from its witness registry
(`transparency_witness_registry`, migration 017), not from a hard-coded pair. At
startup it upserts the legacy `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX` and
`MESSENGER_WITNESS_B_PUBLIC_KEY_HEX` as `witness-a` and `witness-b` (pinned,
Morse-run, Mesh software), then every entry of the optional
`MESSENGER_WITNESS_REGISTRY` secret, a JSON array:

```json
[{"witness_id": "witness-c", "public_key": "<64 lowercase hex>", "operator": "Morse",
  "status": "shadow", "software": "mesh"},
 {"witness_id": "acme-1", "public_key": "<64 lowercase hex>", "operator": "Acme",
  "status": "shadow", "software": "c2sp", "c2sp_name": "witness.acme.example",
  "push_url": "https://witness.acme.example/add-checkpoint"}]
```

`status` is `shadow` (accepted and served, pinned by no release: a new witness's
shadow week), `pinned` (in the security config phones ship) or `retired` (never
accepted again, and never revived). `morse_run` defaults to `operator` being
`Morse`. A witness keeps its key for good; an entry that contradicts the stored
registry (another key for an ID, a revived ID) stops the directory at startup.
Onboarding an outside witness is a registry entry, then a release that pins it:
no code change. `GET /v1/transparency/registry` publishes the registry, and the
jobs Worker reads the shadow and pinned entries from
`GET /internal/v1/transparency/push-witnesses` (bearer
`MESSENGER_DELIVERY_INTERNAL_TOKEN`); a registry holding only Morse's witnesses,
and an empty list, are normal.

The directory's flags (container environment, passed through by `worker.mjs`
only when set; no release needed to change one):

| Variable | Values | Effect |
|---|---|---|
| `MORSE_REGISTRY_WRITES` | `on` (default), `off` | `off`: the registry is frozen; startup seeds nothing |
| `MESSENGER_WITNESS_REGISTRY` | JSON array (above) | Entries upserted at startup while writes are on |
| `MESSENGER_TRANSPARENCY_LOG_ORIGIN` | C2SP origin, default `morseapp.io/log/main` (canary `morseapp.io/log/canary`) | The origin line and key name of `GET /v1/transparency/checkpoint.note`, and the note C2SP cosignatures must verify against |
| `MESSENGER_TRANSPARENCY_PRUNING` | `on` (default), `dry-run`, `off` | Daily pruning of superseded entry bytes (after 90 days) and of checkpoints (after 35 days, anchored ones kept); `dry-run` only counts, in `transparency_pruning_runs` |
| `MESSENGER_TRANSPARENCY_PRUNING_DAILY_CAP` | 1-1,000,000, default 10,000 | Rows of each kind one run may prune |

Pruning runs from the directory's scheduled job (`kind: directory`), which is
woken at least once a UTC day for it. A pruning run that fails fails the job, so
it shows in the scheduler's failures and in public `/health`. The directory's
own `GET /health` (inside the container, and public as `GET /v1/transparency/health`) reports `threshold_met` for the latest
checkpoint against the pinned registry entries, each witness's
`last_signature_age_seconds`, `anchor_lag_seconds` and `last_pruning_day`; see
[key-transparency-v1.md](../../protocol/key-transparency-v1.md), "Directory API".
Migrations 017, 019 and 020 must run before the new directory starts: after
020 an older directory can no longer read the log's entries.

The local `.morse/cloudflare/client.env` contains only the deployed URLs and public
keys. Source it before building the native client. Its transparency, witness, and
delivery keys must be baked into the native security configuration; an OTA update
alone cannot change them. The privacy edge uses proof-of-work difficulty `16`.

`client-env.mjs` pins a witness set in that file (security config v2,
[plan §6.1](../../../WITNESS_NETWORK_PLAN.md)). From the repository root, give it the
JSON files holding the public keys and one `<id>:<label>` per witness; the label
`Morse` marks a Morse-run witness:

```sh
node mesh-private-messenger/ops/cloudflare/client-env.mjs \
  --env .morse/cloudflare/client.env --keys .morse/cloudflare/secrets.json \
  witness-a:Morse witness-b:Morse
```

Witness `witness-a` takes `MESSENGER_WITNESS_A_PUBLIC_KEY_HEX` (the id upper-cased,
`-` as `_`). Put an outside operator's key in a second `--keys` file, for example
`{"MESSENGER_ACME_1_PUBLIC_KEY_HEX": "…"}` for `acme-1`. The script writes
`MESSENGER_WITNESSES`, refreshes the transparency and delivery public keys when the
key files have them (and the OHTTP gateway key, as `MESSENGER_OHTTP_KEY` with
`MESSENGER_OHTTP_RELAY`), and keeps every other line. It reads only `*_PUBLIC_KEY_HEX`
fields and the OHTTP key id, so seeds are never copied or printed. It refuses a set that would not
build a valid frame, and prints the set's `set_id` and trust profile. Edit the
anchor, RPC, relay, credit-issuer, log-origin and minimum-suite variables
([apps/mobile/RELEASING.md](../../apps/mobile/RELEASING.md)) by hand; the
script validates them on its next run.

## Witness network jobs

The backend Worker also runs the chain writers and scheduled jobs of the witness
network ([plan](../../../WITNESS_NETWORK_PLAN.md) §3 "Jobs Worker", Phases 0.3,
0.5, 1, 3 and 5). They live in their own Durable Object, `NetworkJobs`
(`network.mjs`, binding `NETWORK`), so a chain or outside-witness outage never
fails the witness job or public `/health`'s scheduler check. Chain access uses
`@solana/kit`; `judge.mjs` is the client for
[morse-judge-v1.md](../../protocol/morse-judge-v1.md), a byte-for-byte copy of
`ops/relay/judge.mjs` (a test keeps the two equal: edit the relay's, then copy).

| Trigger | Work | Reaches |
|---|---|---|
| Each new checkpoint (the `witness` job) | Invoke the registry's Cloudflare witnesses; then, in `NetworkJobs`' alarm: C2SP push, anchor poster, cosign crank | Directory (already awake), witnesses, chain |
| Cron `* * * * *` | Bond counter snapshot; cosign follow-ups while a cosign window is open; settlement check; a due burn chunk; fee payer balance | Chain; the directory only while a cosign window (about 10 minutes after an anchor) is open |
| Cron `0 * * * *` | Anchor heartbeat: a fresh checkpoint (a `KTS` v2 query for the current tree, refreshed as a lookup would), then the poster; anchor-gap check | Directory once an hour, chain |

### Registry-driven witness jobs

After each checkpoint the `witness` scheduler reads
`GET /internal/v1/transparency/push-witnesses` (every shadow and pinned registry
entry) and asks each Morse-run `software: mesh` entry this Worker can reach to
check the directory. The entry's ID names its configuration: `witness-a` uses
`WITNESS_A_URL` and `WITNESS_A_INVOKE_TOKEN` (isolated witnesses), or the
`WITNESS_A` Durable Object binding (combined development). `push_url` plays no
part: it is a C2SP witness's `add-checkpoint` endpoint only. So the legacy-seeded
`witness-a` and `witness-b` keep being asked with no registry change, and a
Morse witness with neither (witness C, the canary's T1-T3) runs in pull mode and
is skipped. An empty list, or zero outside witnesses, is a normal state. One
failing witness still lets the others sign, then fails the job so it retries; a
URL without its token (or the reverse) is a configuration error. A configured
`WITNESS_<ID>_INVOKE_TOKEN` with no shadow or pinned Morse-run Mesh entry is
logged on every run.

### Flags and configuration

Worker variables (plan §11.2); none needs a release to change.

| Variable | Values | Safe value's effect |
|---|---|---|
| `MORSE_ANCHOR_MODE` | `off` (default), `devnet`, `mainnet` | `off`: no anchors, cosigns, settlement, burns or bond counter; phones show "stale" after 2 h and nothing blocks. `status.json` keeps the last snapshot and the slash history |
| `MORSE_COSIGN_CRANK` | `on`, `off` (default) | `off`: witnesses may still self-submit `cosign` |
| `MORSE_C2SP_PUSH` | `on`, `off` (default) | `off`: C2SP witnesses stop receiving checkpoints |
| `MORSE_BURN_MODE` | `on`, `off` (default) | `off`: the burn share accumulates in the burn wallet |
| `MORSE_LOG_ID` | log name, default `morse-main` | The judge log this backend anchors (`morse-canary` for the canary) |
| `MORSE_SWAP_API` | URL, default `https://lite-api.jup.ag/swap/v1` | The burn crank's quote and swap API |

`MORSE_CHAIN_DEVNET` and `MORSE_CHAIN_MAINNET` hold each mode's chain as JSON;
the mode picks one. Keep them as secrets when an RPC URL carries an API key:

```json
{"rpc": ["https://rpc-provider-one.example/?key=…", "https://rpc-provider-two.example/"],
 "judge": "<morse-judge program id>", "rewards": "<morse-rewards program id>"}
```

The first RPC URL sends transactions; the bond counter reads the first two,
which must be different providers. The Log account is derived from the judge ID
and `MORSE_LOG_ID`.

Secrets (solana-keygen JSON arrays of 64 numbers), each a separate key:

- `MORSE_FEE_PAYER_KEYPAIR`: pays anchor, cosign, settlement and burn fees. Keep at
  most 1 SOL on it; it can do nothing else (plan §13.2).
- `MORSE_ANCHOR_AUTHORITY_KEYPAIR`: the Log's anchor authority, the only signer of
  `post_anchor`. It holds no SOL. Rotate it with
  `morse-admin gov set-anchor-authority` if it leaks.
- `MORSE_BURN_WALLET_KEYPAIR` (Phase 5): holds the week's USDC burn share and
  signs the swaps. Fund it with the weekly share only.

### C2SP push

With `MORSE_C2SP_PUSH=on`, every registry entry with `software: c2sp`, a
`c2sp_name` and a `push_url` (the `add-checkpoint` URL, or its submission prefix)
receives `GET /v1/transparency/checkpoint.note` as a tlog-witness
`add-checkpoint`: `old <size>`, the RFC 6962 consistency proof from that size
(`POST /v1/transparency/consistency`, `KTS` v2, tree 2), a blank line, the note. A
`409` names the size the witness holds; the push is retried once from there. No
push carries more than 63 proof lines (a longer proof is reported, not sent).
The cosignature lines under the witness's key name go to
`POST /v1/transparency/witnesses` as `text/x-c2sp-cosignature`. Each witness's
last cosigned size is kept in `NetworkJobs`' SQLite. One witness failing never
blocks another.

### Anchor poster

After each checkpoint, and from the hourly heartbeat, the poster posts the
directory's current checkpoint with `post_anchor` (an Ed25519 instruction with
the service signature at index 0, signed by the fee payer and the anchor
authority), at most once a minute: a checkpoint arriving sooner waits for an
alarm exactly a minute after the previous anchor. `DuplicateAnchor` means an
earlier attempt landed: the poster finds its ring entry and records it.
`StaleAnchor` is skipped. Each anchor is recorded with
`POST /internal/v1/transparency/anchors`
(`{"sequence","tree_size","checkpoint_hash","ring_index","tx_signature","slot"}`),
retried until the directory stores it.

### Cosign crank

With `MORSE_COSIGN_CRANK=on`, the crank reads each anchored checkpoint's
attestations by sequence (`GET /v1/transparency/witnesses/{sequence}`, `KTW` v2,
so signatures stored after the directory moved to a newer checkpoint still
count; a `404` means the checkpoint is gone and drops it) and submits `cosign`
for every kind-1 (Morse) signature on an anchored checkpoint still within 1,500
slots, four per transaction (one Ed25519 instruction with four entries, then four
`cosign`s), fewer when long IDs don't fit 1,232 bytes. It skips unlisted and
Slashed or Withdrawn witnesses, bits already set, and signatures that do not
verify (one bad signature would sink its whole transaction). It runs right after
each anchor and every minute while a window is open, so pull-mode signatures
arriving within the minute still count. C2SP cosignatures do not go on-chain.

### Weekly settlement and pool funding

On `morse-main` (with `rewards` configured) the minute cron calls `settle_epoch`
for the last finished epoch once it may (15 minutes after the Thursday 00:00 UTC
boundary), and for the one before it if that was missed. If an epoch is still
unsettled an hour after its boundary the job logs
`WARN settle_epoch_late epoch=<n>` once. `fund_pool` moves treasury money, so no
job sends it: `node ../drills/fund-pool.mjs --rewards <ID> --usdc <MINT> --funder
<TREASURY> --amount <base units>` prints the instruction and an unsigned message
for the treasury's signers.

### Bond counter

Every minute the job reads `morse-main` from the first two RPC providers: the
Log (owner-checked), the ring header's last slot and its block time, the judge
Config, every listed witness and each bond vault (token bonds valued at the
rewards price feed, plan §6.12). The two reads must be identical, else they are
retried once and then reported as unavailable: never a number. The canary log is
never read. A new `Proof` account of `morse-main` (found when a party turns
Slashed) is confirmed on the second provider and added to the slash history with
its transaction link, and the history is kept for good, whatever later reads say.

`GET /v1/network/status.json` serves the latest snapshot from the Durable Object
(never a chain read per request), `Cache-Control: public, max-age=60`,
`Access-Control-Allow-Origin: *`, with explorer links for every number:

```json
{"log": "morse-main", "status": "ok", "generated_at": "…", "cluster": "mainnet-beta",
 "judge_program": "…", "log_account": {"address": "…", "link": "…"},
 "last_public_checkpoint": {"slot": "…", "sequence": "…", "tree_size": "…", "time": "…", "age_seconds": 40, "link": "…"},
 "bonded": {"directory": {"status": "Active", "amount": "50000000000", "mint": "…", "usd": "50000.00", "account": "…", "link": "…"},
            "witnesses": [{"witness_id": "…", "status": "Active", "excluded": true, "amount": "…", "mint": "…", "usd": "…", "account": "…", "vault": "…", "link": "…"}]},
 "slashed": {"service": false, "witnesses": 0, "never": true, "link": "…"},
 "slash_history": [{"proof": "…", "kind": 1, "slot": "…", "paid_to": "…", "tx_signature": "…", "link": "…", "account_link": "…"}],
 "stale": false,
 "operations": {"anchor_mode": "mainnet", "log": "morse-main", "last_anchor": {…}, "fee_payer": {…}, "settled_epoch": 2940, "burns": […], "pages": []}}
```

When the providers disagree or fail, `status` is `unavailable` with a `reason`
(`rpc_disagree`, `rpc_error`, `needs_two_rpc_providers`), `last_good_at`, the
slash history, and no numbers. Amounts are base-unit strings. The route is
`networkRoute()` in `network.mjs`, wired in `worker.mjs` ahead of the public
route allowlist.

### Burn crank (Phase 5)

With `MORSE_BURN_MODE=on`, the first minute of each week plans the burn wallet's
USDC (the 30% share; half of it when last week had no plan, so a backlog spreads
over two weeks) as at least 24 chunks of random size at random times, and each
minute runs a due chunk: a quote for exactly that trade into the rewards
`["burn"]` PDA's token account (at most 1% slippage and 1% price impact), the
swap transaction signed by the burn wallet only (one with any other signer is
refused), then `burn`. A received amount more than 1% below the quote is logged;
a chunk failing three times stays in the wallet. Every burn is listed with its
transaction in `status.json` (`operations.burns`).

### Canary log

The canary log (plan §11.3) is a second backend with its own Worker, database,
service key, origin and log account, and witnesses T1-T3 that Morse runs in pull
mode on separate hosts ([ops/witness](../witness/README.md)). Release builds
never pin it, and the bond counter never reads it.

```sh
# with the canary deployment's own credentials
npm run deploy:canary      # prepare-build.mjs --canary: morse-backend-canary
```

`canaryConfig()` names the Worker `morse-backend-canary`, sets
`MORSE_LOG_ID=morse-canary` and
`MESSENGER_TRANSPARENCY_LOG_ORIGIN=morseapp.io/log/canary`, gives it its own R2
bucket (`morse-canary-encrypted-objects`), and binds no Cloudflare witness or
privacy edge. Give it its own secrets: `MESSENGER_DATABASE_URL` (a separate
database), a new `MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX`, the canary
`MESSENGER_WITNESS_REGISTRY` (T1-T3, `software: mesh`, no `push_url`), and its own
`MORSE_FEE_PAYER_KEYPAIR` and `MORSE_ANCHOR_AUTHORITY_KEYPAIR` (the canary Log's).
Register `morse-canary` as a canary-kind log (`--canary`, kind 1) with that
service key and anchor authority ([morse-judge-v1.md](../../protocol/morse-judge-v1.md)
§12). The monthly fork drill is `ops/drills/canary-fork.mjs`
([ops/drills](../drills/README.md)). A slashed directory bond is final and a
slashed canary log refuses anchors (the poster stops and logs
`WARN anchor_log_slashed` once), so each drill that slashes the canary directory
is followed by a fresh canary log (new name and service key, then `MORSE_LOG_ID`
and the signing seed pointed at it). 28 days after the slash governance reclaims
the old ring's rent with `close_log` (`ops/drills/close-log.mjs` builds it).

### Alerting

The jobs log these lines (plan §12); a page-level one also turns public
`/health` to 503:

| Signal | Line | `/health` |
|---|---|---|
| Fee payer below 0.2 SOL / 0.05 SOL / above 1 SOL | `WARN fee_payer_warn`, `PAGE fee_payer_page`, `WARN fee_payer_over_limit` | 503 at 0.05 SOL |
| No anchor for 65 minutes while anchoring is on (the hour plus the heartbeat's run) | `PAGE anchor_gap minutes=<n>` | 503 |
| `settle_epoch` not run within an hour of the boundary | `WARN settle_epoch_late epoch=<n>` | |
| Bond counter providers disagree or fail | `WARN bond_counter_rpc_disagree` / `_rpc_error`; `status.json` `stale: true` after 5 minutes without a snapshot | |
| Burn chunk slippage above 1%, or a failed chunk | `WARN burn_slippage`, `WARN burn_chunk_failed` | |
| C2SP push, anchor poster or cosign crank failure | `C2SP push to <id> failed`, `Anchor poster failed`, `Cosign crank failed` | |

Fork evidence and a relay paying the wrong finder are the relay's alerts
([ops/relay](../relay/README.md)). [ops/acceptance](../acceptance/README.md#alerting)
routes all of these, with the thresholds of plan §12, to Morse and the operators.

## Cutover to separate accounts (§22 M1)

One operator and one Cloudflare account run every deployment today, so the site
and the pitch make no claim about the edge/core split (plan §22.6, the S1 gate).
This runbook moves each deployment into its own account. It needs the accounts
and the people who will hold their credentials, so it has **not run**.

**Target.**

| Deployment | Worker | Holds |
|---|---|---|
| backend | `morse-backend` | delivery, transparency, object and chain secrets, R2, the delivery and object databases, the ingress hostname's zone |
| edge | `morse-privacy-edge` | `MESSENGER_DELIVERY_INTERNAL_TOKEN`, the ingress client certificate (M2) |
| push broker | `morse-push-broker` | its seed, its bearer, `PUSH_DATABASE_URL`, the Expo token |
| credit issuer | `morse-credit-issuer` | its key-wrapping and deposit seeds, `CREDIT_DATABASE_URL`, its two bearers, the LND macaroon |
| witness A, witness B | `morse-witness-a`, `morse-witness-b` | each its own signing seed, invoke token and checkpoint store |

"Separately held" means each account is owned by a different Cloudflare user,
with two-factor authentication, and its API tokens exist only with that person.
Two accounts under one login, or every token in one CI, is one credential
holder. The edge's account and holder are what M1 requires; the broker and the
witnesses follow the same pattern. The backend operator keeps the backend's
release workflow; each other holder deploys from a checkout of the released
commit with its verification evidence (see "Deploy from a workstation").

**Before starting.** The release with this build is live in the current account
(backend isolated; edge, broker and witnesses as their own Workers). Record a
baseline: with the current account ID for all five `MORSE_ISOLATION_<ID>_ACCOUNT_ID`
and the current token as `MORSE_ISOLATION_BACKEND_TOKEN`,
`node isolation-check.mjs` fails every `denied …` check (they share an account).

**Steps.** Each deployment moves while its old copy keeps serving, so each step
can be undone by pointing back at the old origin.

1. **Accounts.** Each new holder creates their account, enables Workers Paid and
   Containers, and creates an account-owned API token for that account only:
   Workers Scripts: Edit, Containers: Edit, Account Settings: Read, and for the
   edge also SSL and Certificates: Edit. No token may list a second account.
   A key that moves keeps clients working, but its old holder had it: once it
   is handed over, the backend operator deletes their recovery copy of it. A
   fresh key instead needs new client builds or a witness registry change.
2. **Witnesses** (one at a time). The witness holder provisions the same signing
   seed and public key (clients pin it), `MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX`,
   a new `WITNESS_INVOKE_TOKEN` (given to the backend operator, since it only
   asks for a check), and `WITNESS_INITIAL_CHECKPOINT_HEX` set to the
   witness's last signed checkpoint (continuity, as in "Separate witness
   deployments"), then deploys with `npm run deploy:witness-a`. The backend
   operator sets `WITNESS_A_INVOKE_TOKEN` to the new token and `WITNESS_A_URL` to
   the new origin, and releases. Verify the next checkpoint gets witness A's
   signature and `/health` stays `200`, then remove
   `WITNESS_INITIAL_CHECKPOINT_HEX` and delete the old `morse-witness-a` Worker
   from the backend account (`npx wrangler delete --name morse-witness-a`).
3. **Push broker.** The broker holder provisions the same seed (provider tokens
   are sealed to its public key; a new key needs new client builds), a new
   `MESSENGER_PUSH_BROKER_INTERNAL_TOKEN` and `PUSH_DATABASE_URL`, and runs
   `npm run deploy:push-broker`. The backend operator sets the new bearer and
   `MORSE_PUSH_BROKER_URL`, releases, and checks a push arrives. Delete the old
   `morse-push-broker` Worker. The queue rows are sealed to the broker's key, so
   the database can stay; moving `morse_push` to a Neon project the broker holder
   owns also hides queue timing from the backend operator.
4. **Edge.** Clients have the edge origin built in
   (`EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL`), and a new account gets a new
   workers.dev subdomain. Give the new edge a hostname on a zone in the edge's
   own account, deploy it there (`npm run deploy:edge` with
   `MESSENGER_DELIVERY_INTERNAL_TOKEN` and `MORSE_DELIVERY_URL`), ship client
   builds that use it, and keep the old edge until builds pointing at it have
   aged out. The split isn't complete while the old edge runs in the backend's
   account. Then delete it and rotate `MESSENGER_DELIVERY_INTERNAL_TOKEN`: set
   the new value on the edge and the backend, then release the backend (sends
   fail for the minutes in between).
5. **Clean the backend account.** Delete the old container applications
   (`morse-backend-pushbroker`, `morse-backend-privacyedge`,
   `morse-backend-witnessa`, `morse-backend-witnessb`) and every secret the
   backend doesn't need (`MESSENGER_PUSH_BROKER_SEED_HEX`, `PUSH_DATABASE_URL`,
   `MESSENGER_EXPO_ACCESS_TOKEN`, `MESSENGER_WITNESS_A_SIGNING_SEED_HEX`,
   `MESSENGER_WITNESS_B_SIGNING_SEED_HEX`). Replace the repository's
   `CLOUDFLARE_API_TOKEN`, which could reach the old copies. In the same commit,
   remove the witness, edge and broker deploy lines from
   `.github/workflows/backend-release.yml` (keep their origins, which
   `smoke.mjs` still checks): their holders deploy them now, and the backend
   token can't reach their accounts.
6. **M2.** Provision the edge credential ("Sealed ingress edge credential":
   signed requests work today; the client certificate has a platform
   limitation). The S1 gate needs it.
7. **Verify.** Each holder runs, with their own token only and all five account
   IDs:

   ```sh
   MORSE_ISOLATION_BACKEND_ACCOUNT_ID=… MORSE_ISOLATION_EDGE_ACCOUNT_ID=… \
   MORSE_ISOLATION_PUSH_BROKER_ACCOUNT_ID=… MORSE_ISOLATION_WITNESS_A_ACCOUNT_ID=… \
   MORSE_ISOLATION_WITNESS_B_ACCOUNT_ID=… MORSE_ISOLATION_EDGE_TOKEN=… node isolation-check.mjs
   ```

   It makes read-only API calls and prints no token. Their token must list
   exactly their own account; their account must hold their own Worker and no
   other deployment's Worker, container application or R2 bucket; their Worker
   may hold only its own secrets and bindings (the backend: none of the
   broker's, witnesses' or edge's); and every Worker, secret, settings,
   container and bucket listing in the other four accounts must be refused
   (`401`/`403`/`404`; a `5xx`, `429` or network error fails). Also check each
   account's Members page lists only its holder, `node smoke.mjs` passes with
   the new origins, and a message and a push arrive.

**Rollback.** Until an old copy is deleted, point the backend's variable (and
bearer) back at it and release. After deletion, a rollback is a redeploy into the
backend account with the holder's secrets, which undoes the split; a witness
moved back needs its latest checkpoint transferred again.

**When the split may be claimed.** Only when every step above is done, all five
holders' runs of `isolation-check.mjs` pass (the `M2` checks included), and the
rest of S1 is done (M5, D1, D2 and the §22.5 corrections). Until then the site and
the pitch make no metadata claim about the edge/core split. Even then the claim
is "separate accounts with separately held credentials", not independent
operators (that follows D20); Cloudflare terminates TLS for every deployment and
can correlate them by timing; and only message submission goes through the edge
(M3). Landing-page wording must trace to `protocol/sealed-delivery-v1.md` and
`protocol/privacy-contract.md`, updated in the same change.

## GitHub Actions

Pushes to `release` run `.github/workflows/backend-release.yml`: build the verified Mesh
release, run protocol/storage/event-driven integration tests, deploy both witness
Workers, the privacy-edge Worker and the push-broker Worker, apply migrations, deploy the backend's service
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
- `MORSE_PUSH_BROKER_URL` (the push-broker Worker's HTTPS origin)
- Only once credits are set up: `MORSE_CREDIT_ISSUER_URL` (the credit-issuer
  Worker's HTTPS origin), with the secret `CREDIT_DATABASE_URL`
- Only once the sealed-ingress edge credential is provisioned:
  `MORSE_EDGE_INGRESS_PUBLIC_KEY` (signed requests), or `MORSE_INGRESS_HOSTNAME`,
  `MORSE_INGRESS_CLIENT_CERT_SHA256`, `MORSE_INGRESS_CLIENT_CERT_ISSUER`
  (optional) and `MORSE_EDGE_CLIENT_CERT_ID` (client certificate). Never the
  edge's signing key: that is the edge Worker's own secret.

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

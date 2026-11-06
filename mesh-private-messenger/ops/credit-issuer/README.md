# Persistent credit issuer

The issuer needs its own persistent Linux host and separate PostgreSQL database.
The Cloudflare image already contains `/app/credit-issuer`; use the immutable
image digest that passed release verification with the exact published Mesh
revision. The current local Mesh additions have not been published, so this
configuration is prepared deployment material, not evidence of a deployed or
release-ready issuer.

Apply `services/credit-issuer/migrations/*.sql` in lexical order to the issuer
database only. Use a dedicated database role with no access to the core database. Copy
`issuer.env.example` outside the repository, restrict it to the operator, and
supply the native service/witness pins, mint, RPC, Pyth account and two distinct
credentials. The edge gets the purchase credential; the core and issuer get
the administration credential. Set the backend's issuer ingress switch and
credential as described in `ops/cloudflare/README.md`, or use direct private
HTTPS and `MESSENGER_CREDIT_ADMIN_TRANSPORT=direct`.

Set `MORSE_ISSUER_IMAGE` to the verified image **digest** and
`MORSE_ISSUER_ENV_FILE` to the protected absolute file path. Review
`docker compose -f ops/credit-issuer/compose.yaml config --quiet` before startup.
Do not print expanded Compose configuration: it contains credentials. Startup
is an explicit deployment step:

```sh
docker compose -f ops/credit-issuer/compose.yaml up -d
```

The image initializes the key-volume mount point as UID/GID 65532 with mode0700.
Docker copies those permissions into a new named volume. An existing volume
must retain those ownership/permissions; the runtime refuses a mismatch. The
service runs as that unprivileged user, publishes HTTP only on loopback, and
has a read-only root filesystem. Install the supplied Caddy virtual host on
the same machine, set `MORSE_ISSUER_HOST`, and validate/reload Caddy using its
normal operator procedure. Only the two authenticated purchase endpoints are
published. The edge's `MORSE_CREDIT_ISSUER_URL` names that HTTPS origin. No Caddy
access log is enabled. Internal service health is available only on loopback.

Keep the `morse-credit-issuer-keys` volume outside database rollback/restore.
Never restore an old copy of its key/counter, delete the volume during an
upgrade, or run `compose down --volumes`. A lost key directory makes sealed
issuer and deposit keys unrecoverable. Follow the public
[StorageKey.file contract](../../../../mesh-lang/docs/security/storage-key-file.md)
for backup and crash boundaries. No command here performs a deployment,
credential installation, payment, sweep or database mutation automatically.

Treasury settlement has an independent default-off mode, explicit opaque signer
provisioning and bounded recovery worker. Follow
[`ops/credit-treasury/OPERATIONS.md`](../credit-treasury/OPERATIONS.md) for pins,
original-payer refunds, weekly snapshots and the separately held treasury owner's
rewards funding handoff. Keeping credit purchases off does not disable an
explicitly enabled treasury recovery worker.

The Compose schema and Caddy 2.10.2 configuration have been checked locally
(the Caddy validation container had no network). TLS reload, Linux image startup,
permission-denial drills, independent host isolation, production database
restore drills and live purchase acceptance still require their operational
checks; passing the local HTTP proof does not establish these properties.

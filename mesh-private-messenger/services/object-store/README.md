# Object store

`object-store` is one deliberately small service shared by private-messenger attachments and backups. Both are already encrypted opaque objects when they arrive. The service implements anonymous proof-of-work grants, capability-authorized binary part transfer, completion, deletion, and bounded expiry cleanup.

The canonical protocol is [opaque-object-wire-v1.md](../../protocol/opaque-object-wire-v1.md).

## Configuration

| Variable | Meaning |
| --- | --- |
| `MESSENGER_OBJECT_DATABASE_URL` | PostgreSQL connection URL; required |
| `MESSENGER_OBJECT_STORAGE_ROOT` | Existing absolute local directory or private HTTP storage endpoint; required, without a trailing slash |
| `MESSENGER_BIND_ADDRESS` | IPv4/IPv6 literal to bind; default `::`; use `127.0.0.1` to accept local connections |
| `MESSENGER_OBJECT_PORT` | HTTP port, default `18089` |
| `MESSENGER_OBJECT_WORK_DIFFICULTY` | Leading-zero proof-of-work bits, 1 through 24; default `16` |
| `MESSENGER_JOBS_URL` | Optional private durable scheduler; enables event-driven expiry |
| `MESSENGER_OBJECT_INTERNAL_TOKEN` | Required with external scheduling; authenticates private expiry execution |

Startup fails closed when the database URL or storage root is invalid. Provision the database role and, when using local files, the storage directory before starting the process. Initialization creates the PostgreSQL tables idempotently. Existing SQLite databases are not imported or deleted; migrate their data separately before switching an existing installation.

Each part is named only `{64 lowercase object-ID hex}.{index}`, where the index is 0 through 256. A single part is at most 65,608 bytes and an object is at most 16,795,830 bytes across 1 through 257 parts. The aggregate ceiling is exactly one 182-byte encrypted backup manifest plus 256 maximum-size 65,608-byte encrypted backup chunks; attachment objects remain below the same shared bound. PostgreSQL stores typed BYTEA identifiers and hashes; it never stores raw capabilities, object bytes, filenames, MIME types, keys, identities, mailboxes, devices, or conversations.

Completion verifies every part’s exact file size and stored SHA-256 hash. Downloads reject missing, truncated, extended, or changed part files.

Local operation starts one shutdown-aware expiry worker that removes at most 32 expired objects per minute. With `MESSENGER_JOBS_URL`, grant transactions register durable wakeups before committing; Cloudflare alarms invoke bounded expiry work only when due. A PostgreSQL transaction advisory lock serializes storage operations, including part I/O, so concurrent first uploads cannot overwrite or remove a committed replay. This limits throughput; use per-object locks if that becomes a measured bottleneck.

## Production storage boundary

Local filesystem and private HTTP calls live in `store/files.mpl`, PostgreSQL metadata
in `store/database.mpl`, and request handling in `store/service.mpl`. The service
has no storage-provider abstraction.

The [Cloudflare deployment](../../ops/cloudflare/README.md) routes the private HTTP endpoint to R2. Only the object-store container can use it. It uses a fixed bucket and `opaque/` prefix, conditional creation, exact-byte replay checks, bounded bodies, and idempotent deletion. Authorization and metadata stay in this service. R2 lifecycle expiry after eight days removes orphan parts beyond the protocol's seven-day maximum lifetime. The public wire is unchanged.

## Development

```sh
export MESSENGER_STORAGE_TEST_DATABASE_URL='postgres://localhost/morse_storage_test?sslmode=disable'
../mesh-lang/target/debug/meshc test services/object-store/tests/object_store.test.mpl
../mesh-lang/target/debug/meshc build services/object-store
```

Use an isolated test database. The focused tests cover anonymous grant denial, exact and changed replay, concurrent first upload, part and aggregate limits, repeated initialization, incomplete or corrupted completion, trailing-file corruption, download authorization, metadata opacity, delete authorization, expiry equality, and bounded purge. The Cloudflare tests exercise R2 through both JavaScript and the native Mesh HTTP storage boundary.

## Paid large attachment namespace

The [paid attachment profile](../../protocol/paid-attachment-v1.md) adds a
separate namespace for attachments larger than 16 MiB through 512 MiB. Existing
free attachment and backup grants keep their bounds. Creation defaults off;
set `MORSE_PAID_LARGE_ATTACHMENTS=on` only after the matching client streaming
and recovery integration has been qualified.

The object store requires `MESSENGER_OBJECT_CREDIT_CORE_URL`,
`MESSENGER_OBJECT_CREDIT_SERVICE_PUBLIC_KEY_HEX` (the release-pinned core key),
and the consuming-service `MESSENGER_DELIVERY_INTERNAL_TOKEN`. Core URLs must
be HTTPS origins, canonical local proof addresses `http://127.0.0.1:PORT`, or
the fixed private container origin `http://credit-core.internal`. No other
plaintext hostname is accepted. Cloudflare supplies the pin from its required
transparency public-key configuration and restricts the private hop to the
single attachment-grant route.

Paid part files use `large-{object-ID}.{index}` with indices through 8,192.
Each is at most 65,576 bytes. The service checks exact layout and total budget,
and stores capability hashes, exact size/expiry and a signed core receipt.
No filenames, MIME types, attachment keys or raw capabilities enter metadata.
One unique core object-to-hold binding prevents a changed request from charging
another frame when the first local commit is uncertain. Exact CAP replay
recovers the original signed entitlement without charging again.

Completion verifies at most 128 part files per transaction: repeat the same
OCP after each 202 until 200. Deletion and expiry use another durable cursor
and remove at most 128 paid parts per transaction. New grants alone are flag-gated; access and cleanup of existing
paid objects remain available when the flag is turned off.

`node --test services/object-store/tests/paid-attachments-live.test.mjs` creates
its own temporary PostgreSQL cluster and directories, builds actual services,
and verifies cross-process recovery and 17 MiB+1 encrypted streaming. It also
runs the existing free object suite. It never resets a shared database.

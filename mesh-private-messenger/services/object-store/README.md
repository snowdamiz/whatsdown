# Object store

`object-store` is one deliberately small service shared by private-messenger attachments and backups. Both are already encrypted opaque objects when they arrive. The service implements anonymous proof-of-work grants, capability-authorized binary part transfer, completion, deletion, and bounded expiry cleanup.

The canonical protocol is [opaque-object-wire-v1.md](../../protocol/opaque-object-wire-v1.md).

## Configuration

| Variable | Meaning |
| --- | --- |
| `MESSENGER_OBJECT_DATABASE_URL` | PostgreSQL connection URL; required |
| `MESSENGER_OBJECT_STORAGE_ROOT` | Existing absolute local directory or private HTTP storage endpoint; required, without a trailing slash |
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

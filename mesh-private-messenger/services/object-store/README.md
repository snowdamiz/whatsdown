# Object store

`object-store` is one deliberately small service shared by private-messenger attachments and backups. Both are already encrypted opaque objects when they arrive. The service implements anonymous proof-of-work grants, capability-authorized binary part transfer, completion, deletion, and bounded expiry cleanup.

The canonical protocol is [opaque-object-wire-v1.md](../../protocol/opaque-object-wire-v1.md).

## Configuration

| Variable | Meaning |
| --- | --- |
| `MESSENGER_OBJECT_DATABASE_PATH` | SQLite metadata database path; required and not `:memory:` |
| `MESSENGER_OBJECT_STORAGE_ROOT` | Existing absolute local directory; required |
| `MESSENGER_OBJECT_PORT` | HTTP port, default `18089` |
| `MESSENGER_OBJECT_WORK_DIFFICULTY` | Leading-zero proof-of-work bits, 1 through 24; default `16` |

Startup fails closed when the database path or storage root is invalid. The service does not create the storage root. Provision it with the intended owner and permissions before starting the process. Initialization transactionally upgrades stores that use the previous 65,576-byte part and 16,777,216-byte aggregate checks, preserving object and part rows; repeated initialization is idempotent, and unrecognized ceiling constraint values fail closed.

Each part is a local file named only `{64 lowercase object-ID hex}.{index}`, where the index is 0 through 256. A single part is at most 65,608 bytes and an object is at most 16,795,830 bytes across 1 through 257 parts. The aggregate ceiling is exactly one 182-byte encrypted backup manifest plus 256 maximum-size 65,608-byte encrypted backup chunks; attachment objects remain below the same shared bound. SQLite stores typed BLOB identifiers and hashes; it never stores raw capabilities, object bytes, filenames, MIME types, keys, identities, mailboxes, devices, or conversations.

The process starts one shutdown-aware expiry worker. Once per minute it locks the metadata writer, removes at most 32 expired objects, and yields between runs. Upload, completion, deletion, and purge mutations use an immediate SQLite writer transaction so concurrent first uploads cannot overwrite or remove a committed replay.

## Production storage boundary

This version intentionally has no storage-provider abstraction: local filesystem calls are the simplest complete implementation and remain in one service module.

A production S3 deployment belongs behind the same opaque part contract at the storage boundary only. It must use a fixed operator-configured bucket and prefix; use only `{object_id_hex}.{index}` as the variable key leaf; disable user-controlled object metadata; keep capabilities and their hashes out of S3; preserve exact-body conditional creation/replay behavior; and keep grant authorization, completion state, expiry, and typed metadata in this service. The public wire and clients must not vary by storage provider. Add that backend only with integration coverage for concurrent conditional writes and bounded deletion.

## Development

```sh
../mesh-lang/target/debug/meshc test services/object-store/tests/object_store.test.mpl
../mesh-lang/target/debug/meshc build services/object-store
```

The focused tests cover anonymous grant denial, exact and changed replay, concurrent first upload, exact and one-byte-over part and aggregate limits on fresh and migrated stores, lossless and idempotent legacy-schema upgrade, incomplete completion, download authorization, metadata opacity, delete authorization, expiry equality, and bounded purge.

# Local encrypted-record indexes, version 2

The development native core addresses encrypted records with
`StorageKey.index_tag`, an HMAC-based public Mesh primitive that borrows the
opaque platform storage key. TypeScript never receives the key. A random
32-byte database ID separates namespaces:

```text
index = hex(index_tag(key,
  UTF8("morse/local-blob-index/v2/") || database_id,
  SHA256(UTF8(record_label))))
key_check = index_tag(key, UTF8("morse/local-blob-index-key/v2"), database_id)
```

`encrypted_blob_index` stores one checked version-2/database-ID/key-check row.
`encrypted_blobs` has only `record_hash` and `ciphertext`, in a strict table
without row IDs. There is no clear `updated_at` column. Known labels cannot be
looked up using an unkeyed label hash alone.

Opening a legacy database authenticates its sealed profile anchor, or its
pending-link anchor when no profile exists, before binding the new index. An
atomic transaction transforms every existing label digest, preserves encrypted
record bytes and their wrapping context, and removes the legacy table. It does
not need to recover the original labels. Wrong custody, corrupted anchors or
nonempty unanchored state fail closed. Existing version-2 state must pass its
key check on every opening; reopening is idempotent. Old native writers cannot
be used after this forward migration.

Host migration, rollback, malformed-schema, bounded-lock and compare-and-swap
tests are supplemented by actual previous-to-current native upgrades on a
physical Android phone and iOS Simulator. Each retains OS custody and the same
data path, preserves all 12 fixture ciphertexts and identity, rejects a foreign
account's write, and reads new writes after cold restart. These are owned local
upgrades, not store-delivered or physical-iOS upgrade acceptance.

The database still exposes ciphertext lengths, record count and change
correlation. Previously copied databases, SQLite pages/WAL, OS snapshots and
backups may retain old hashes or timestamps; migration is not forensic erasure.
An attacker controlling the unlocked endpoint remains outside this protection.

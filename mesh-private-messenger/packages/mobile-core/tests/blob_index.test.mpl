import File
from Storage.Blobs import (
  blob_record_hash,
  blob_record_key_with_key,
  ensure_schema,
  ensure_schema_with_key,
  insert_blob,
  load_blob,
  load_blob_with_key
)
from Storage.Keys import local_context, seal_local
from Storage.Records import compare_and_swap_blobs, delete_blob, erase_local_state
from Tests.Support import database_path, repeated

fn text(row :: Map<String, DbValue>, column :: String) -> String!String do
  case Map.get(row, column) do
    Text(value) -> Ok(value)
    _ -> Err("expected text")
  end
end

fn binary(row :: Map<String, DbValue>, column :: String) -> Bytes!String do
  case Map.get(row, column) do
    Binary(value) -> Ok(value)
    _ -> Err("expected binary")
  end
end

fn legacy_hash(label :: String) -> String do
  Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
end

fn create_legacy(path :: String, textual :: Bool) -> SqliteConn!String do
  let db = Sqlite.open(path)?
  let schema = if textual do
    "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY, ciphertext TEXT NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
  else
    "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)"
  end
  Sqlite.execute(db, schema, [])?
  Ok(db)
end

fn legacy_put(db :: SqliteConn,
  digest :: String,
  blob :: Bytes,
  textual :: Bool) -> Result<(), String> do
  let value = if textual do
    Text(Bytes.to_base64(blob))
  else
    Binary(blob)
  end
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, '2026-01-02 03:04:05')",
    [Text(digest), value])?
  Ok(nil)
end

fn seal_anchor(key :: borrow StorageKey, label :: String) -> Bytes!String do
  seal_local(Bytes.from_utf8("synthetic authenticated anchor"), key, local_context(label)?)
end

fn schema_names(db :: SqliteConn) -> List<Map<String, DbValue>>!String do
  Sqlite.query_values(db,
    "SELECT name FROM sqlite_master WHERE name IN ('encrypted_blob_index', 'encrypted_blobs_index_migration') ORDER BY name",
    [])
end

fn failed_unchanged(path :: String,
  key :: borrow StorageKey,
  count :: Int,
  stale_table :: Bool) -> Bool!String do
  assert(Result.is_err(ensure_schema_with_key(path, key)))
  let db = Sqlite.open(path)?
  let rows = Sqlite.query_values(db, "SELECT record_hash FROM encrypted_blobs", [])?
  let columns = Sqlite.query_values(db,
    "SELECT name FROM pragma_table_info('encrypted_blobs') ORDER BY cid",
    [])?
  let metadata = schema_names(db)?
  Sqlite.close(db)
  assert(List.length(rows) == count)
  assert(List.length(columns) == 3)
  assert(text(List.get(columns, 2), "name")? == "updated_at")
  assert(List.length(metadata) == if stale_table do
      1
    else
      0
    end)
  if stale_table do
    assert(text(List.head(metadata), "name")? == "encrypted_blobs_index_migration")
  end
  Ok(true)
end

fn fresh() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("d1_fresh")?
  ensure_schema(path)?
  let db = Sqlite.open(path)?
  insert_blob(db, "private-known-label", Bytes.from_utf8("synthetic record"))?
  let address = blob_record_hash(db, "private-known-label")?
  let rows = Sqlite.query_values(db,
    "SELECT record_hash FROM encrypted_blobs WHERE record_hash = ?",
    [Text(legacy_hash("private-known-label"))])?
  let timestamps = Sqlite.query_values(db,
    "SELECT name FROM pragma_table_info('encrypted_blobs') WHERE name = 'updated_at'",
    [])?
  Sqlite.close(db)
  assert(List.length(rows) == 0)
  assert(List.length(timestamps) == 0)
  ensure_schema(path)?
  assert(load_blob(path, "private-known-label")? == Bytes.from_utf8("synthetic record"))
  let reopened = Sqlite.open(path)?
  assert(address == blob_record_hash(reopened, "private-known-label")?)
  Sqlite.close(reopened)
  compare_and_swap_blobs(path,
    ["private-known-label"],
    [Bytes.from_utf8("updated")],
    Bytes.from_utf8("synthetic record"))?
  assert(Result.is_err(compare_and_swap_blobs(path,
    ["private-known-label"],
    [Bytes.from_utf8("stale")],
    Bytes.from_utf8("synthetic record"))))
  let deleting = Sqlite.open(path)?
  delete_blob(deleting, "private-known-label")?
  # A late legacy-address row can never resurrect the deleted modern value.
  Sqlite.execute_values(deleting,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(legacy_hash("private-known-label")), Binary(Bytes.from_utf8("old"))])?
  Sqlite.close(deleting)
  assert(Result.is_err(load_blob(path, "private-known-label")))
  erase_local_state(path)?
  let erased = Sqlite.open(path)?
  assert(address == blob_record_hash(erased, "private-known-label")?)
  Sqlite.close(erased)
  File.delete(path)?
  Ok(true)
end

fn migrate(textual :: Bool, anchor_label :: String) -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_legacy")?
  let db = create_legacy(path, textual)?
  let anchor = seal_anchor(key, anchor_label)?
  let unknown_digest = Bytes.repeat(171, 32)
    |> Result.unwrap_or(Bytes.empty())
    |> Bytes.to_hex()
  let unknown_blob = Bytes.from_hex("00ff80")?
  legacy_put(db, legacy_hash(anchor_label), anchor, textual)?
  legacy_put(db, unknown_digest, unknown_blob, textual)?
  Sqlite.close(db)
  ensure_schema_with_key(path, key)?
  ensure_schema_with_key(path, key)?
  assert(load_blob_with_key(path, anchor_label, key)? == anchor)
  let opened = case StorageKey.unseal_bytes(anchor, key, local_context(anchor_label)?) do
    Err(_) -> return Err("anchor changed")
    Ok(value) -> value
  end
  assert(opened == Bytes.from_utf8("synthetic authenticated anchor"))
  let migrated = Sqlite.open(path)?
  let rows = Sqlite.query_values(migrated,
    "SELECT record_hash, ciphertext, typeof(ciphertext) AS storage_type FROM encrypted_blobs ORDER BY record_hash",
    [])?
  assert(List.length(rows) == 2)
  for row in rows do
    let hash = text(row, "record_hash")?
    assert(hash != legacy_hash(anchor_label) && hash != unknown_digest)
    assert(text(row, "storage_type")? == "blob")
    let blob = binary(row, "ciphertext")?
    assert(blob == anchor || blob == unknown_blob)
  end
  assert(List.length(schema_names(migrated)?) == 1)
  assert(List.length(Sqlite.query_values(migrated,
    "SELECT name FROM pragma_table_info('encrypted_blobs')",
    [])?) == 2)
  Sqlite.close(migrated)
  Secret.destroy(key)
  File.delete(path)?
  Ok(true)
end

fn wrong_keys() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let wrong = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_wrong_key")?
  let db = create_legacy(path, true)?
  let anchor = seal_anchor(key, "profile/v1")?
  legacy_put(db, legacy_hash("profile/v1"), anchor, true)?
  Sqlite.close(db)
  assert(failed_unchanged(path, wrong, 1, false)?)
  ensure_schema_with_key(path, key)?
  assert(Result.is_err(ensure_schema_with_key(path, wrong)))
  assert(Result.is_err(load_blob_with_key(path, "profile/v1", wrong)))
  assert(load_blob_with_key(path, "profile/v1", key)? == anchor)
  let other = database_path("d1_other_database")?
  ensure_schema_with_key(other, key)?
  let first = Sqlite.open(path)?
  let second = Sqlite.open(other)?
  assert(blob_record_key_with_key(first,
    key,
    Bytes.from_utf8("profile/v1"))? != blob_record_key_with_key(second,
      key,
      Bytes.from_utf8("profile/v1"))?)
  Sqlite.close(first)
  Sqlite.close(second)
  Secret.destroy(wrong)
  Secret.destroy(key)
  File.delete(path)?
  File.delete(other)?
  Ok(true)
end

fn unauthenticated() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_no_anchor")?
  let db = create_legacy(path, false)?
  legacy_put(db, legacy_hash("unknown/v1"), Bytes.from_utf8("opaque"), false)?
  Sqlite.close(db)
  assert(failed_unchanged(path, key, 1, false)?)
  let corrupt = database_path("d1_corrupt_anchor")?
  let bad = create_legacy(corrupt, false)?
  legacy_put(bad, legacy_hash("profile/v1"), Bytes.from_utf8("corrupt"), false)?
  legacy_put(bad,
    legacy_hash("pending-link-request/v1"),
    seal_anchor(key, "pending-link-request/v1")?,
    false)?
  Sqlite.close(bad)
  assert(failed_unchanged(corrupt, key, 2, false)?)
  Secret.destroy(key)
  File.delete(path)?
  File.delete(corrupt)?
  Ok(true)
end

fn malformed() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  # These schemas admit invalid digests, so migration must validate every row.
  for digest in [
    "",
    "f",
    "GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGG",
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  ] do
    let path = database_path("d1_bad_digest")?
    let db = create_legacy(path, false)?
    legacy_put(db, legacy_hash("profile/v1"), seal_anchor(key, "profile/v1")?, false)?
    legacy_put(db, digest, Bytes.from_utf8("opaque"), false)?
    Sqlite.close(db)
    assert(failed_unchanged(path, key, 2, false)?)
    File.delete(path)?
  end
  let path = database_path("d1_bad_base64")?
  let db = create_legacy(path, true)?
  legacy_put(db, legacy_hash("profile/v1"), seal_anchor(key, "profile/v1")?, true)?
  legacy_put(db,
    "0000000000000000000000000000000000000000000000000000000000000000",
    Bytes.from_utf8("copied before failure"),
    true)?
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"), Text("not-base64")])?
  Sqlite.close(db)
  assert(failed_unchanged(path, key, 3, false)?)
  let unchanged = Sqlite.open(path)?
  let bad = Sqlite.query_values(unchanged,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")])?
  assert(text(List.head(bad), "ciphertext")? == "not-base64")
  Sqlite.close(unchanged)
  File.delete(path)?
  Secret.destroy(key)
  Ok(true)
end

fn collisions() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let stale = database_path("d1_stale_migration")?
  let db = create_legacy(stale, false)?
  legacy_put(db, legacy_hash("profile/v1"), seal_anchor(key, "profile/v1")?, false)?
  Sqlite.execute(db, "CREATE TABLE encrypted_blobs_index_migration (sentinel TEXT)", [])?
  Sqlite.execute(db, "INSERT INTO encrypted_blobs_index_migration VALUES ('retain me')", [])?
  Sqlite.close(db)
  assert(failed_unchanged(stale, key, 1, true)?)
  let remaining = Sqlite.open(stale)?
  assert(text(List.head(Sqlite.query_values(remaining,
      "SELECT sentinel FROM encrypted_blobs_index_migration",
      [])?),
    "sentinel")? == "retain me")
  Sqlite.close(remaining)
  File.delete(stale)?
  # Duplicate source addresses are refused, never collapsed with INSERT OR REPLACE.
  let duplicate = database_path("d1_duplicate_digest")?
  let repeated = Sqlite.open(duplicate)?
  Sqlite.execute(repeated,
    "CREATE TABLE encrypted_blobs (record_hash TEXT, ciphertext BLOB NOT NULL, updated_at TEXT)",
    [])?
  legacy_put(repeated, legacy_hash("profile/v1"), seal_anchor(key, "profile/v1")?, false)?
  legacy_put(repeated, legacy_hash("profile/v1"), Bytes.from_utf8("duplicate"), false)?
  Sqlite.close(repeated)
  assert(failed_unchanged(duplicate, key, 2, false)?)
  File.delete(duplicate)?
  Secret.destroy(key)
  Ok(true)
end

fn packed_migration() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_packed_legacy")?
  let db = create_legacy(path, false)?
  let anchor = seal_anchor(key, "profile/v1")?
  legacy_put(db, legacy_hash("profile/v1"), anchor, false)?
  # Existing packed sealed histories may exceed the generic 64KiB seal API.
  # The index migration must not reinterpret or truncate these opaque bytes.
  let packed = repeated(173, 8388609)?
  legacy_put(db, legacy_hash("packed-history-fixture"), packed, false)?
  for index in 0..128 do
    legacy_put(db,
      legacy_hash("unknown-original-label/#{index}"),
      Bytes.from_utf8("opaque #{index}"),
      false)?
  end
  Sqlite.close(db)
  ensure_schema_with_key(path, key)?
  assert(load_blob_with_key(path, "packed-history-fixture", key)? == packed)
  let reopened = Sqlite.open(path)?
  assert(List.length(Sqlite.query_values(reopened,
    "SELECT record_hash FROM encrypted_blobs",
    [])?) == 130)
  assert(List.length(Sqlite.query_values(reopened,
    "SELECT record_hash FROM encrypted_blobs WHERE record_hash = ?",
    [Text(legacy_hash("profile/v1"))])?) == 0)
  Sqlite.close(reopened)
  File.delete(path)?
  Secret.destroy(key)
  Ok(true)
end

fn malformed_metadata() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_metadata")?
  ensure_schema_with_key(path, key)?
  let db = Sqlite.open(path)?
  let before = Sqlite.query_values(db,
    "SELECT database_id, key_check FROM encrypted_blob_index",
    [])?
  let original_id = binary(List.head(before), "database_id")?
  let original_check = binary(List.head(before), "key_check")?
  Sqlite.execute_values(db,
    "UPDATE encrypted_blob_index SET database_id = ?",
    [Binary(repeated(0, 32)?)])?
  Sqlite.close(db)
  assert(Result.is_err(ensure_schema_with_key(path, key)))
  let restore = Sqlite.open(path)?
  Sqlite.execute_values(restore,
    "UPDATE encrypted_blob_index SET database_id = ?, key_check = ?",
    [Binary(original_id), Binary(original_check)])?
  Sqlite.close(restore)
  ensure_schema_with_key(path, key)?
  let erased = Sqlite.open(path)?
  Sqlite.execute(erased, "DELETE FROM encrypted_blob_index", [])?
  Sqlite.close(erased)
  assert(Result.is_err(ensure_schema_with_key(path, key)))
  File.delete(path)?
  Secret.destroy(key)
  Ok(true)
end

fn require(result :: Bool!String) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("new local blobs hide known labels, omit clear time, preserve CAS and never revive old addresses") do
  require(fresh())
end

test("all unknown TEXT legacy labels migrate atomically with original ciphertext and AD") do
  require(migrate(true, "profile/v1"))
end

test("legacy BLOB pre-account linking authenticates and migrates without changing pending AD") do
  require(migrate(false, "pending-link-request/v1"))
end

test("wrong keys cannot bind legacy state or open a rekeyed database; per-database indexes differ") do
  require(wrong_keys())
end

test("nonempty anchorless state and corrupt preferred anchors fail closed without fallback") do
  require(unauthenticated())
end

test("malformed digests and base64 roll back copied rows and metadata") do
  require(malformed())
end

test("stale migration tables and duplicate source addresses cannot overwrite records") do
  require(collisions())
end

test("migration preserves a packed record larger than 8MiB and all unknown digest rows") do
  require(packed_migration())
end

test("missing or substituted keyed metadata fails closed without silently rebinding") do
  require(malformed_metadata())
end

import File
from Storage.Blobs import ensure_schema_with_key, blob_record_hash_with_key, insert_blob_with_key
from Storage.Keys import seal_local, local_context
from Tests.Support import database_path

fn key() -> StorageKey!String do
  case StorageKey.ephemeral() do
    Err(_) -> Err("synthetic key generation failed")
    Ok(value)
  end
end

fn absent_rowid(database :: SqliteConn) -> Bool do
  Result.is_err(Sqlite.query_values(database, "SELECT rowid FROM encrypted_blobs", []))
end

fn binary(row :: Map<String, DbValue>, column :: String) -> Bytes!String do
  case Map.get(row, column) do
    Binary(value) -> Ok(value)
    _ -> Err("invalid synthetic binary column")
  end
end

fn text(row :: Map<String, DbValue>, column :: String) -> String!String do
  case Map.get(row, column) do
    Text(value) -> Ok(value)
    _ -> Err("invalid synthetic text column")
  end
end

fn fresh_table() -> Result<(), String> do
  let wrapping = key()?
  let path = database_path("d1_fresh_without_rowid")?
  ensure_schema_with_key(path, wrapping)?
  let original = Bytes.from_utf8("synthetic authenticated record")
  let sealed = seal_local(original, wrapping, local_context("private-record/v1")?)?
  let database = Sqlite.open(path)?
  insert_blob_with_key(database, wrapping, "private-record/v1", sealed)?
  let rows = Sqlite.query_values(database, "SELECT ciphertext FROM encrypted_blobs", [])?
  let hidden_order = absent_rowid(database)
  Sqlite.close(database)
  assert(List.length(rows) == 1)
  assert(case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> Bytes.secure_equals(value, sealed)
    _ -> false
  end)
  assert(case StorageKey.unseal_bytes(sealed, wrapping, local_context("private-record/v1")?) do
    Ok(value) -> Bytes.secure_equals(value, original)
    Err(_) -> false
  end)
  File.delete(path)?
  Secret.destroy(wrapping)
  assert(hidden_order)
  Ok(nil)
end

fn migrated_table() -> Result<(), String> do
  let wrapping = key()?
  let path = database_path("d1_migrated_without_rowid")?
  let labels = ["profile/v1", "unknown-private-row/b", "unknown-private-row/a"]
  let payloads = for label in labels do
    seal_local(Bytes.from_utf8("synthetic #{label}"), wrapping, local_context(label)?)?
  end
  let database = Sqlite.open(path)?
  Sqlite.execute(database,
    "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, updated_at TEXT)",
    [])?
  for index in 0..3 do
    Sqlite.execute_values(database,
      "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, ?)",
      [
        Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(List.get(labels, index))))),
        Binary(List.get(payloads, index)),
        Text("legacy clear timestamp")
      ])?
  end
  assert(!absent_rowid(database))
  Sqlite.close(database)
  ensure_schema_with_key(path, wrapping)?
  let reopened = Sqlite.open(path)?
  let hidden_order = absent_rowid(reopened)
  assert(List.length(Sqlite.query_values(reopened,
    "SELECT record_hash FROM encrypted_blobs",
    [])?) == 3)
  for index in 0..3 do
    let label = List.get(labels, index)
    let hash = blob_record_hash_with_key(reopened, wrapping, label)?
    let rows = Sqlite.query_values(reopened,
      "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
      [Text(hash)])?
    assert(List.length(rows) == 1)
    let sealed = case Map.get(List.head(rows), "ciphertext") do
      Binary(value) -> value
      _ -> return Err("missing original ciphertext")
    end
    assert(Bytes.secure_equals(sealed, List.get(payloads, index)))
    assert(case StorageKey.unseal_bytes(sealed, wrapping, local_context(label)?) do
      Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("synthetic #{label}"))
      Err(_) -> false
    end)
    assert(Result.is_err(StorageKey.unseal_bytes(sealed,
      wrapping,
      local_context(label <> "/wrong")?)))
  end
  Sqlite.close(reopened)
  ensure_schema_with_key(path, wrapping)?
  File.delete(path)?
  Secret.destroy(wrapping)
  assert(hidden_order)
  Ok(nil)
end

fn keyed_rowid_refused() -> Result<(), String> do
  let wrapping = key()?
  let path = database_path("d1_noncanonical_keyed_rowid")?
  ensure_schema_with_key(path, wrapping)?
  let database = Sqlite.open(path)?
  let sealed = seal_local(Bytes.from_utf8("synthetic authenticated record"),
    wrapping,
    local_context("record/v1")?)?
  insert_blob_with_key(database, wrapping, "record/v1", sealed)?
  let old_rows = Sqlite.query_values(database,
    "SELECT record_hash, ciphertext FROM encrypted_blobs",
    [])?
  let old_metadata = Sqlite.query_values(database,
    "SELECT version, database_id, key_check FROM encrypted_blob_index",
    [])?
  # Reproduce the prior keyed-but-rowid layout while keeping actual keyed
  # addresses, ciphertext and authenticated metadata byte-for-byte unchanged.
  Sqlite.begin(database)?
  Sqlite.execute(database,
    "CREATE TABLE prior_keyed_table (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0)) STRICT",
    [])?
  Sqlite.execute(database, "INSERT INTO prior_keyed_table SELECT * FROM encrypted_blobs", [])?
  Sqlite.execute(database, "DROP TABLE encrypted_blobs", [])?
  Sqlite.execute(database, "ALTER TABLE prior_keyed_table RENAME TO encrypted_blobs", [])?
  Sqlite.commit(database)?
  assert(!absent_rowid(database))
  Sqlite.close(database)
  let refused = Result.is_err(ensure_schema_with_key(path, wrapping))
  let reopened = Sqlite.open(path)?
  let new_rows = Sqlite.query_values(reopened,
    "SELECT record_hash, ciphertext FROM encrypted_blobs",
    [])?
  let new_metadata = Sqlite.query_values(reopened,
    "SELECT version, database_id, key_check FROM encrypted_blob_index",
    [])?
  let same_rows = List.length(new_rows) == 1
    && text(List.head(old_rows), "record_hash")? == text(List.head(new_rows), "record_hash")?
    && Bytes.secure_equals(binary(List.head(old_rows), "ciphertext")?,
      binary(List.head(new_rows), "ciphertext")?)
  let same_metadata = List.length(new_metadata) == 1
    && text(List.head(old_metadata), "version")? == text(List.head(new_metadata), "version")?
    && Bytes.secure_equals(binary(List.head(old_metadata), "database_id")?,
      binary(List.head(new_metadata), "database_id")?)
    && Bytes.secure_equals(binary(List.head(old_metadata), "key_check")?,
      binary(List.head(new_metadata), "key_check")?)
  assert(!absent_rowid(reopened))
  Sqlite.close(reopened)
  assert(same_rows && same_metadata)
  assert(case StorageKey.unseal_bytes(sealed, wrapping, local_context("record/v1")?) do
    Ok(value) -> Bytes.secure_equals(value, Bytes.from_utf8("synthetic authenticated record"))
    Err(_) -> false
  end)
  File.delete(path)?
  Secret.destroy(wrapping)
  assert(refused)
  Ok(nil)
end

test("fresh v2 storage has no rowid rank and preserves authenticated ciphertext") do
  assert(Result.is_ok(fresh_table()))
end

test("legacy rekey drops SHA sort rank while preserving every ciphertext and original AD") do
  assert(Result.is_ok(migrated_table()))
end

test("keyed rowid layouts are refused without modifying authenticated records or metadata") do
  assert(Result.is_ok(keyed_rowid_refused()))
end

import File
from Storage.Blobs import ensure_schema_with_key
from Storage.Keys import local_context, seal_local
from Tests.Support import database_path

fn proof() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_composite_collision")?
  let db = Sqlite.open(path)?
  # record_hash has pk ordinal1 but is not unique by itself.
  Sqlite.execute(db,
    "CREATE TABLE encrypted_blobs (record_hash TEXT, ciphertext BLOB NOT NULL, updated_at TEXT, PRIMARY KEY(record_hash, ciphertext))",
    [])?
  let anchor = seal_local(Bytes.from_utf8("synthetic authenticated profile"),
    key,
    local_context("profile/v1")?)?
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("profile/v1")))), Binary(anchor)])?
  let duplicate = "0000000000000000000000000000000000000000000000000000000000000000"
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(duplicate), Binary(Bytes.from_utf8("first"))])?
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(duplicate), Binary(Bytes.from_utf8("second"))])?
  Sqlite.close(db)
  let refused = Result.is_err(ensure_schema_with_key(path, key))
  let reopened = Sqlite.open(path)?
  let rows = Sqlite.query_values(reopened, "SELECT record_hash FROM encrypted_blobs", [])?
  let metadata = Sqlite.query_values(reopened,
    "SELECT name FROM sqlite_master WHERE name IN ('encrypted_blob_index', 'encrypted_blobs_index_migration')",
    [])?
  Sqlite.close(reopened)
  File.delete(path)?
  Secret.destroy(key)
  println("duplicate digest: refused=#{refused}, rows=#{List.length(rows)}, metadata=#{List.length(metadata)}")
  assert(refused)
  assert(List.length(rows) == 3)
  assert(List.length(metadata) == 0)
  Ok(true)
end

test("composite legacy primary keys cannot silently collapse duplicate digest records") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn null_digest() -> Bool!String do
  let key = case StorageKey.ephemeral() do
    Err(_) -> return Err("key")
    Ok(value) -> value
  end
  let path = database_path("d1_null_digest")?
  let db = Sqlite.open(path)?
  Sqlite.execute(db,
    "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY, ciphertext BLOB NOT NULL, updated_at TEXT)",
    [])?
  let anchor = seal_local(Bytes.from_utf8("synthetic authenticated profile"),
    key,
    local_context("profile/v1")?)?
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("profile/v1")))), Binary(anchor)])?
  Sqlite.execute_values(db,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Null, Binary(Bytes.from_utf8("must not be skipped"))])?
  Sqlite.close(db)
  assert(Result.is_err(ensure_schema_with_key(path, key)))
  let reopened = Sqlite.open(path)?
  assert(List.length(Sqlite.query_values(reopened,
    "SELECT ciphertext FROM encrypted_blobs",
    [])?) == 2)
  assert(List.length(Sqlite.query_values(reopened,
    "SELECT name FROM sqlite_master WHERE name IN ('encrypted_blob_index', 'encrypted_blobs_index_migration')",
    [])?) == 0)
  Sqlite.close(reopened)
  File.delete(path)?
  Secret.destroy(key)
  Ok(true)
end

test("NULL legacy digests cannot be skipped by the migration cursor") do
  case null_digest() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

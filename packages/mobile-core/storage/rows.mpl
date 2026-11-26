from Mobile.Codec import mobile_append, mobile_byte, mobile_join, random_bytes
from Storage.Keys import local_context, open_local, platform_key, seal_local

##! Storage.Rows: local record format 2, the rows of `encrypted_blobs`
##! (`protocol/storage-wrapping-v1.md`, "Local record format 2").
##!
##! Each database has a label key, 32 random bytes sealed under the platform
##! StorageKey as local data (purpose 14, object `storage-label-key/v1`) in
##! `storage_label_key`. A record is kept under the HMAC-SHA-256, keyed by it, of
##! its label's SHA-256. The first 64 bytes of its value, which hold the
##! storage-wrap header with its write counter and context binding, are masked
##! under the same key with a fresh salt. Nothing is timestamped. Without the
##! platform key the database shows how many records there are and how large,
##! and not which labels, and so which accounts, they are for, or when or in
##! what order they were written.
##!
##! A record keeps its row: a backup restored on another device is written
##! through this API there, under that device's own label key.

pub struct StorageRowKey do
  inner :: Bytes
  outer :: Bytes
end

fn run(database :: SqliteConn, sql :: String) -> Result<(), String> do
  case Sqlite.execute(database, sql, []) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

fn run_values(database :: SqliteConn,
  sql :: String,
  values :: List<DbValue>) -> Result<(), String> do
  case Sqlite.execute_values(database, sql, values) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

fn select(database :: SqliteConn,
  sql :: String,
  values :: List<DbValue>) -> List<Map<String, DbValue>>!String do
  case Sqlite.query_values(database, sql, values) do
    Err(_) -> Err("database_read_failed")
    Ok(rows)
  end
end

# Mesh has no bitwise operators, so bits are combined arithmetically. No branch
# depends on the key.

fn xor_byte(left :: Int, right :: Int, bit :: Int) -> Int do
  if bit > 128 do
    0
  else
    let a = (left / bit) % 2
    let b = (right / bit) % 2
    (a + b - 2 * a * b) * bit + xor_byte(left, right, bit * 2)
  end
end

fn byte_list(values :: List<Int>) -> Bytes!String do
  case Bytes.from_list(values) do
    Err(_) -> Err("storage_key_failed")
    Ok(value)
  end
end

fn key_pad(material :: List<Int>, fill :: Int) -> Bytes!String do
  let length = List.length(material)
  byte_list(for index in 0..64 do
    if index < length do
      xor_byte(List.get(material, index), fill, 1)
    else
      fill
    end
  end)
end

## An HMAC-SHA-256 key (RFC 2104) of at most 64 bytes, as its two padded blocks.

pub fn storage_row_key(material :: Bytes) -> StorageRowKey!String do
  if Bytes.length(material) > 64 do
    Err("storage_key_failed")
  else
    let values = Bytes.to_list(material)
    Ok(StorageRowKey { inner: key_pad(values, 54)?, outer: key_pad(values, 92)? })
  end
end

pub fn storage_hmac(key :: StorageRowKey, message :: Bytes) -> Bytes!String do
  let inner = Crypto.sha256(mobile_append(key.inner, message)?)
  Ok(Crypto.sha256(mobile_append(key.outer, inner)?))
end

## The row a label is kept under, from the label's SHA-256.

pub fn storage_hash_row(key :: StorageRowKey, hash :: Bytes) -> String!String do
  let message = mobile_append(Bytes.from_utf8("mesh-msg/mobile/storage-row/v1"), hash)?
  Ok(Bytes.to_hex(storage_hmac(key, message)?))
end

pub fn storage_label_row(key :: StorageRowKey, label :: String) -> String!String do
  storage_hash_row(key, Crypto.sha256(Bytes.from_utf8(label)))
end

fn masked(key :: StorageRowKey, row :: String, salt :: Bytes, value :: Bytes) -> Bytes!String do
  let prefix = mobile_join([
      Bytes.from_utf8("mesh-msg/mobile/storage-mask/v1"),
      Bytes.from_utf8(row),
      salt
    ],
    0,
    Bytes.empty())?
  let first = storage_hmac(key, mobile_append(prefix, mobile_byte(1)?)?)?
  let second = storage_hmac(key, mobile_append(prefix, mobile_byte(2)?)?)?
  let stream = Bytes.to_list(mobile_append(first, second)?)
  let length = Bytes.length(value)
  let count = if length < 64 do
    length
  else
    64
  end
  let head = Bytes.to_list(Bytes.slice(value, 0, count)?)
  let mixed = byte_list(for index in 0..count do
    xor_byte(List.get(head, index), List.get(stream, index), 1)
  end)?
  mobile_append(mixed, Bytes.slice(value, count, length - count)?)
end

## What a row holds: a 16-byte salt, then the value with its first 64 bytes
## masked.

pub fn storage_hide(key :: StorageRowKey, row :: String, value :: Bytes) -> Bytes!String do
  if Bytes.length(value) == 0 do
    Err("database_write_failed")
  else
    let salt = random_bytes(16)?
    mobile_append(salt, masked(key, row, salt, value)?)
  end
end

pub fn storage_show(key :: StorageRowKey, row :: String, stored :: Bytes) -> Bytes!String do
  if Bytes.length(stored) <= 16 do
    Err("invalid_local_state")
  else
    masked(key,
      row,
      Bytes.slice(stored, 0, 16)?,
      Bytes.slice(stored, 16, Bytes.length(stored) - 16)?)
  end
end

fn label_key_context() -> Bytes!String do
  local_context("storage-label-key/v1")
end

pub fn storage_open_key(database :: SqliteConn,
  wrapping_key :: borrow StorageKey) -> StorageRowKey!String do
  let rows = select(database, "SELECT sealed FROM storage_label_key WHERE id = 1", [])?
  if List.length(rows) != 1 do
    Err("database_read_failed")
  else
    case Map.get(List.head(rows), "sealed") do
      Binary(sealed) -> storage_row_key(open_local(sealed, wrapping_key, label_key_context()?)?)
      Text(_) -> Err("invalid_local_state")
      Null -> Err("invalid_local_state")
    end
  end
end

## Format 2 is marked by SQLite's user_version, set in the transaction that
## makes the label key and moves the rows.

pub fn storage_rows_current(database :: SqliteConn) -> Bool!String do
  let rows = select(database,
    "SELECT CAST(user_version AS TEXT) AS version FROM pragma_user_version",
    [])?
  if List.length(rows) != 1 do
    Err("database_read_failed")
  else
    case Map.get(List.head(rows), "version") do
      Text(version) -> Ok(version == "2")
      Binary(_) -> Err("database_read_failed")
      Null -> Err("database_read_failed")
    end
  end
end

fn legacy_text(row :: Map<String, DbValue>, column :: String) -> String!String do
  case Map.get(row, column) do
    Binary(_) -> Err("invalid_legacy_blob")
    Null -> Err("invalid_legacy_blob")
    Text(value) -> Ok(value)
  end
end

fn legacy_hash(text :: String) -> Bytes!String do
  let hash = case Bytes.from_hex(text) do
    Err(_) -> Err("invalid_legacy_blob")
    Ok(value)
  end?
  if Bytes.length(hash) != 32 do
    Err("invalid_legacy_blob")
  else
    Ok(hash)
  end
end

# The first databases kept values as base64 text.

fn legacy_base64(encoded :: String) -> Bytes!String do
  let blob = case Bytes.from_base64(encoded) do
    Err(_) -> Err("invalid_legacy_blob")
    Ok(value)
  end?
  if Bytes.length(blob) == 0 || Bytes.to_base64(blob) != encoded do
    Err("invalid_legacy_blob")
  else
    Ok(blob)
  end
end

fn legacy_value(row :: Map<String, DbValue>) -> Bytes!String do
  case Map.get(row, "ciphertext") do
    Binary(value) -> if Bytes.length(value) == 0 do
      Err("invalid_legacy_blob")
    else
      Ok(value)
    end
    Null -> Err("invalid_legacy_blob")
    Text(encoded) -> legacy_base64(encoded)
  end
end

fn migrate_rows(database :: SqliteConn,
  key :: StorageRowKey,
  rows :: List<Map<String, DbValue>>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(rows) do
    Ok(nil)
  else
    let row = List.get(rows, index)
    let old = legacy_text(row, "record_hash")?
    let target = storage_hash_row(key, legacy_hash(old)?)?
    run_values(database,
      "INSERT INTO encrypted_blobs_keyed (record_hash, ciphertext) VALUES (?, ?)",
      [Text(target), Binary(storage_hide(key, target, legacy_value(row)?)?)])?
    run_values(database, "DELETE FROM encrypted_blobs WHERE record_hash = ?", [Text(old)])?
    migrate_rows(database, key, rows, index + 1)
  end
end

# A few hundred rows at a time, so a large history is never held at once.

fn migrate_batches(database :: SqliteConn, key :: StorageRowKey) -> Result<(), String> do
  let rows = select(database,
    "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash LIMIT 256",
    [])?
  if List.length(rows) == 0 do
    Ok(nil)
  else
    migrate_rows(database, key, rows, 0)?
    migrate_batches(database, key)
  end
end

fn move_legacy(database :: SqliteConn, key :: StorageRowKey) -> Result<(), String> do
  let tables = select(database,
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'encrypted_blobs'",
    [])?
  if List.length(tables) == 0 do
    Ok(nil)
  else
    migrate_batches(database, key)?
    run(database, "DROP TABLE encrypted_blobs")
  end
end

# Inside the caller's transaction: every row moves, or none does. Tables a
# non-transactional crash could have left are made again.

fn create_rows(database :: SqliteConn, wrapping_key :: borrow StorageKey) -> Result<(), String> do
  let material = random_bytes(32)?
  let sealed = seal_local(material, wrapping_key, label_key_context()?)?
  let key = storage_row_key(material)?
  run(database, "DROP TABLE IF EXISTS encrypted_blobs_keyed")?
  run(database, "DROP TABLE IF EXISTS storage_label_key")?
  run(database,
    "CREATE TABLE storage_label_key (id INTEGER PRIMARY KEY CHECK(id = 1), sealed BLOB NOT NULL CHECK(length(sealed) > 0)) STRICT")?
  run_values(database,
    "INSERT INTO storage_label_key (id, sealed) VALUES (1, ?)",
    [Binary(sealed)])?
  run(database,
    "CREATE TABLE encrypted_blobs_keyed (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 16)) STRICT")?
  move_legacy(database, key)?
  run(database, "ALTER TABLE encrypted_blobs_keyed RENAME TO encrypted_blobs")?
  run(database, "PRAGMA user_version = 2")
end

fn prepare_in_transaction(database :: SqliteConn) -> Result<(), String> do
  if storage_rows_current(database)? do
    Ok(nil)
  else
    let wrapping_key = platform_key()?
    create_rows(database, wrapping_key)
  end
end

# secure_delete zeroes the pages the old rows leave, so their labels' hashes,
# write counters and times do not stay in the file's free space.

fn prepare_open(database :: SqliteConn) -> Result<(), String> do
  if storage_rows_current(database)? do
    Ok(nil)
  else
    run(database, "PRAGMA secure_delete = ON")?
    let result = case Sqlite.begin(database) do
      Err(error)
      Ok(_) -> case prepare_in_transaction(database) do
        Err(error)
        Ok(_) -> Sqlite.commit(database)
      end
    end
    case result do
      Err(error) -> do
        Sqlite.rollback(database)
        Err(error)
      end
      Ok(_) -> Ok(nil)
    end
  end
end

## Makes a new database, or moves an older one's rows, once. Every open goes
## through it; an up-to-date database costs one read.

pub fn storage_prepare(database_path :: String) -> Result<(), String> do
  case Sqlite.open(database_path) do
    Err(_) -> Err("database_open_failed")
    Ok(database) -> do
      let result = prepare_open(database)
      Sqlite.close(database)
      case result do
        Err(_) -> Err("database_schema_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
end

## A connection to a database in format 2, moving an older one first.

pub fn storage_connect(database_path :: String) -> SqliteConn!String do
  let database = case Sqlite.open(database_path) do
    Err(_) -> Err("database_open_failed")
    Ok(value)
  end?
  case storage_rows_current(database) do
    Ok(true) -> Ok(database)
    _ -> do
      Sqlite.close(database)
      storage_prepare(database_path)?
      case Sqlite.open(database_path) do
        Err(_) -> Err("database_open_failed")
        Ok(value)
      end
    end
  end
end

pub fn storage_insert(database :: SqliteConn,
  key :: StorageRowKey,
  label :: String,
  value :: Bytes) -> Result<(), String> do
  let row = storage_label_row(key, label)?
  run_values(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(row), Binary(storage_hide(key, row, value)?)])
end

fn put_row(database :: SqliteConn,
  key :: StorageRowKey,
  row :: String,
  value :: Bytes) -> Result<(), String> do
  run_values(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext",
    [Text(row), Binary(storage_hide(key, row, value)?)])
end

pub fn storage_put(database :: SqliteConn,
  key :: StorageRowKey,
  label :: String,
  value :: Bytes) -> Result<(), String> do
  put_row(database, key, storage_label_row(key, label)?, value)
end

## A value kept under a hash its caller chose; returns the row.

pub fn storage_put_hash(database :: SqliteConn,
  key :: StorageRowKey,
  hash :: Bytes,
  value :: Bytes) -> String!String do
  let row = storage_hash_row(key, hash)?
  put_row(database, key, row, value)?
  Ok(row)
end

pub fn storage_delete(database :: SqliteConn,
  key :: StorageRowKey,
  label :: String) -> Result<(), String> do
  run_values(database,
    "DELETE FROM encrypted_blobs WHERE record_hash = ?",
    [Text(storage_label_row(key, label)?)])
end

pub fn storage_insert_all(database :: SqliteConn,
  key :: StorageRowKey,
  labels :: List<String>,
  values :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if List.length(labels) != List.length(values) do
    Err("invalid_local_state")
  else if index >= List.length(labels) do
    Ok(nil)
  else
    storage_insert(database, key, List.get(labels, index), List.get(values, index))?
    storage_insert_all(database, key, labels, values, index + 1)
  end
end

pub fn storage_put_all(database :: SqliteConn,
  key :: StorageRowKey,
  labels :: List<String>,
  values :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if List.length(labels) != List.length(values) do
    Err("invalid_local_state")
  else if index >= List.length(labels) do
    Ok(nil)
  else
    storage_put(database, key, List.get(labels, index), List.get(values, index))?
    storage_put_all(database, key, labels, values, index + 1)
  end
end

pub fn storage_delete_all(database :: SqliteConn,
  key :: StorageRowKey,
  labels :: List<String>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(labels) do
    Ok(nil)
  else
    storage_delete(database, key, List.get(labels, index))?
    storage_delete_all(database, key, labels, index + 1)
  end
end

fn load_open(database :: SqliteConn,
  label :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let key = storage_open_key(database, wrapping_key)?
  let row = storage_label_row(key, label)?
  let rows = select(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(row)])?
  if List.length(rows) != 1 do
    Err("local_state_not_found")
  else
    case Map.get(List.head(rows), "ciphertext") do
      Binary(stored) -> storage_show(key, row, stored)
      Text(_) -> Err("invalid_local_state")
      Null -> Err("invalid_local_state")
    end
  end
end

## A record's value, for a caller that already holds the platform key.

pub fn storage_load(database_path :: String,
  label :: String,
  wrapping_key :: borrow StorageKey) -> Bytes!String do
  let database = storage_connect(database_path)?
  let result = load_open(database, label, wrapping_key)
  Sqlite.close(database)
  result
end

## The row a label is kept under in this database, for tests and tools that
## look at the table itself.

pub fn storage_row_for(database_path :: String, label :: String) -> String!String do
  let database = storage_connect(database_path)?
  let wrapping_key = platform_key()?
  let result = case storage_open_key(database, wrapping_key) do
    Err(error)
    Ok(key) -> storage_label_row(key, label)
  end
  Sqlite.close(database)
  result
end

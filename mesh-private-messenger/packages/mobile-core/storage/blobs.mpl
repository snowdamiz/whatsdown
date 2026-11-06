from Storage.Keys import local_context, platform_key

## Version2 record addresses key the existing label digest. This permits an
## atomic rekey of every legacy digest without recovering its original label.
## The wrapping context and ciphertext bytes are never changed here.

fn text(row :: Map<String, DbValue>, column :: String) -> String!String do
  case Map.get(row, column) do
    Text(value) -> Ok(value)
    _ -> Err("invalid_blob_schema")
  end
end

fn binary(row :: Map<String, DbValue>, column :: String) -> Bytes!String do
  case Map.get(row, column) do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_blob_index")
  end
end

fn legacy_blob(row :: Map<String, DbValue>) -> Bytes!String do
  let value = case Map.get(row, "ciphertext") do
    Binary(value) -> value
    Text(encoded) -> do
      let decoded = case Bytes.from_base64(encoded) do
        Err(_) -> return Err("invalid_legacy_blob")
        Ok(value) -> value
      end
      if Bytes.to_base64(decoded) != encoded do
        return Err("invalid_legacy_blob")
      end
      decoded
    end
    Null -> return Err("invalid_legacy_blob")
  end
  if Bytes.length(value) == 0 do
    Err("invalid_legacy_blob")
  else
    Ok(value)
  end
end

fn tag(key :: borrow StorageKey, namespace :: Bytes, value :: Bytes) -> Bytes!String do
  case StorageKey.index_tag(key, namespace, value) do
    Err(_) -> Err("blob_index_key_unavailable")
    Ok(value)
  end
end

fn namespace(database_id :: Bytes) -> Bytes!String do
  case Bytes.concat(Bytes.from_utf8("morse/local-blob-index/v2/"), database_id) do
    Err(_) -> Err("invalid_blob_index")
    Ok(value)
  end
end

fn key_check(key :: borrow StorageKey, database_id :: Bytes) -> Bytes!String do
  tag(key, Bytes.from_utf8("morse/local-blob-index-key/v2"), database_id)
end

fn read_index(database :: SqliteConn, key :: borrow StorageKey) -> Bytes!String do
  let rows = Sqlite.query_values(database,
    "SELECT CASE WHEN typeof(version) = 'integer' AND version = 2 THEN 2 ELSE NULL END AS version, CASE WHEN typeof(database_id) = 'blob' AND length(database_id) = 32 THEN database_id ELSE NULL END AS database_id, CASE WHEN typeof(key_check) = 'blob' AND length(key_check) = 32 THEN key_check ELSE NULL END AS key_check FROM encrypted_blob_index LIMIT 2",
    [])?
  if List.length(rows) != 1 do
    return Err("invalid_blob_index")
  end
  let row = List.head(rows)
  let database_id = binary(row, "database_id")?
  let expected = binary(row, "key_check")?
  if text(row, "version")? != "2"
    || Bytes.length(database_id) != 32
    || Bytes.length(expected) != 32
    || !Bytes.secure_equals(key_check(key, database_id)?, expected) do
    Err("blob_index_key_mismatch")
  else
    Ok(database_id)
  end
end

fn digest_index(key :: borrow StorageKey, database_id :: Bytes, digest :: Bytes) -> String!String do
  if Bytes.length(digest) != 32 do
    return Err("invalid_blob_digest")
  end
  Ok(Bytes.to_hex(tag(key, namespace(database_id)?, digest)?))
end

pub fn blob_record_key_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  record_key :: Bytes) -> String!String do
  if Bytes.length(record_key) > 65536 do
    return Err("invalid_blob_key")
  end
  digest_index(key, read_index(database, key)?, Crypto.sha256(record_key))
end

pub fn blob_record_key(database :: SqliteConn, record_key :: Bytes) -> String!String do
  let key = platform_key()?
  let result = blob_record_key_with_key(database, key, record_key)
  Secret.destroy(key)
  result
end

pub fn blob_record_hash_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  label :: String) -> String!String do
  blob_record_key_with_key(database, key, Bytes.from_utf8(label))
end

## Authenticate this database once for a bounded caller-owned label batch. Only
## public keyed addresses are returned; the borrowed key remains actor-owned.
pub fn blob_record_hashes_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>) -> List<String>!String do
  let database_id = read_index(database, key)?
  let output = for label in labels do
    let bytes = Bytes.from_utf8(label)
    if Bytes.length(bytes) > 65536 do
      return Err("invalid_blob_key")
    end
    digest_index(key, database_id, Crypto.sha256(bytes))?
  end
  Ok(output)
end

pub fn blob_record_hash(database :: SqliteConn, label :: String) -> String!String do
  blob_record_key(database, Bytes.from_utf8(label))
end

fn create_index(database :: SqliteConn, key :: borrow StorageKey) -> Bytes!String do
  let database_id = case Crypto.random_bytes(32) do
    Err(_) -> return Err("blob_index_entropy_unavailable")
    Ok(value) -> value
  end
  Sqlite.execute(database,
    "CREATE TABLE encrypted_blob_index (version INTEGER PRIMARY KEY CHECK(version = 2), database_id BLOB NOT NULL CHECK(length(database_id) = 32), key_check BLOB NOT NULL CHECK(length(key_check) = 32)) STRICT",
    [])?
  Sqlite.execute_values(database,
    "INSERT INTO encrypted_blob_index (version, database_id, key_check) VALUES (2, ?, ?)",
    [Binary(database_id), Binary(key_check(key, database_id)?)])?
  Ok(database_id)
end

fn valid_columns(columns :: List<Map<String, DbValue>>, modern :: Bool) -> Bool!String do
  if List.length(columns) != 2 && (modern || List.length(columns) != 3) do
    return Ok(false)
  end
  let hash = List.get(columns, 0)
  let value = List.get(columns, 1)
  if text(hash, "name")? != "record_hash"
    || text(hash, "type")? != "TEXT"
    || text(hash, "pk")? != "1"
    || text(value, "pk")? != "0"
    || text(value, "name")? != "ciphertext"
    || !List.contains(if modern do
        ["BLOB"]
      else
        ["BLOB", "TEXT"]
      end,
      text(value, "type")?) do
    return Ok(false)
  end
  if List.length(columns) == 3 do
    let timestamp = List.get(columns, 2)
    if text(timestamp, "name")? != "updated_at"
      || text(timestamp, "type")? != "TEXT"
      || text(timestamp, "pk")? != "0" do
      return Ok(false)
    end
  end
  Ok(true)
end

# An old database has no stored keyed identity. Authenticate the current key
# before binding it: normal accounts have a sealed profile; pre-account linking
# has a sealed pending request. A nonempty database with neither fails closed.
fn authenticate_legacy(database :: SqliteConn, key :: borrow StorageKey) -> Result<(), String> do
  for label in ["profile/v1", "pending-link-request/v1"] do
    let rows = Sqlite.query_values(database,
      "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
      [Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label))))])?
    if List.length(rows) > 1 do
      return Err("invalid_legacy_blob")
    end
    if List.length(rows) == 1 do
      let blob = legacy_blob(List.head(rows))?
      case StorageKey.unseal_bytes(blob, key, local_context(label)?) do
        Err(_) -> return Err("legacy_blob_key_mismatch")
        Ok(_) -> return Ok(nil)
      end
    end
  end
  Err("legacy_blob_authentication_required")
end

fn authenticate_legacy_bounded(database :: SqliteConn,
  key :: borrow StorageKey,
  maximum :: Int) -> Result<(), String> do
  let encoded_maximum = ((maximum + 2) / 3) * 4
  let wire_limit = if encoded_maximum > 33554432 do
    33554432
  else
    encoded_maximum
  end
  let quota = if wire_limit < 64 do
    64
  else
    wire_limit
  end
  let rows = Sqlite.query_values_v2(database,
    "SELECT CASE WHEN typeof(ciphertext) = 'blob' AND length(ciphertext) > 0 AND length(ciphertext) <= CAST(? AS INTEGER) THEN ciphertext WHEN typeof(ciphertext) = 'text' AND length(CAST(ciphertext AS BLOB)) > 0 AND length(CAST(ciphertext AS BLOB)) <= CAST(? AS INTEGER) AND length(CAST(ciphertext AS BLOB)) % 4 = 0 AND (length(CAST(ciphertext AS BLOB)) / 4) * 3 - CASE WHEN substr(ciphertext, -2) = '==' THEN 2 WHEN substr(ciphertext, -1) = '=' THEN 1 ELSE 0 END <= CAST(? AS INTEGER) THEN ciphertext ELSE NULL END AS ciphertext FROM encrypted_blobs WHERE record_hash = ? LIMIT 2",
    [
      Text(Int.to_string(maximum)),
      Text(Int.to_string(wire_limit)),
      Text(Int.to_string(maximum)),
      Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("profile/v1"))))
    ],
    quota)?
  if List.length(rows) == 0 do
    return Err("legacy_blob_authentication_required")
  end
  if List.length(rows) != 1 do
    return Err("invalid_legacy_blob")
  end
  let row = List.head(rows)
  case Map.get(row, "ciphertext") do
    Null -> return Err("account_source_limit")
    _ -> nil
  end
  let blob = legacy_blob(row)?
  if Bytes.length(blob) > maximum do
    return Err("account_source_limit")
  end
  case StorageKey.unseal_bytes(blob, key, local_context("profile/v1")?) do
    Err(_) -> Err("legacy_blob_key_mismatch")
    Ok(_) -> Ok(nil)
  end
end

fn rekey_rows(database :: SqliteConn,
  key :: borrow StorageKey,
  database_id :: Bytes,
  cursor :: String) -> Result<(), String> do
  # One row bounds temporary memory by one existing ciphertext, including the
  # maximum packed history. The transaction commits all addresses or none.
  let rows = if cursor == "" do
    Sqlite.query_values(database,
      "SELECT record_hash, ciphertext FROM encrypted_blobs ORDER BY record_hash LIMIT 1",
      [])
  else
    Sqlite.query_values(database,
      "SELECT record_hash, ciphertext FROM encrypted_blobs WHERE record_hash > ? ORDER BY record_hash LIMIT 1",
      [Text(cursor)])
  end?
  if List.length(rows) == 0 do
    return Ok(nil)
  end
  let row = List.head(rows)
  let previous = text(row, "record_hash")?
  let digest = case Bytes.from_hex(previous) do
    Err(_) -> return Err("invalid_blob_digest")
    Ok(value) -> value
  end
  if Bytes.length(digest) != 32 || Bytes.to_hex(digest) != previous do
    return Err("invalid_blob_digest")
  end
  let next = digest_index(key, database_id, digest)?
  Sqlite.execute_values(database,
    "INSERT INTO encrypted_blobs_index_migration (record_hash, ciphertext) VALUES (?, ?)",
    [Text(next), Binary(legacy_blob(row)?)])?
  rekey_rows(database, key, database_id, previous)
end

## Schema setup precedes selected-source capture. Opaque BLOBs move inside
## SQLite; encoded legacy TEXT has a separate fixed32-MiB wire cap before Mesh
## materialization, independent of the caller's selected-record quota. Failure
## rolls back the whole setup, including any addresses already migrated.
fn rekey_rows_bounded(database :: SqliteConn,
  key :: borrow StorageKey,
  database_id :: Bytes,
  cursor :: String) -> Result<(), String> do
  let rows = if cursor == "" do
    Sqlite.query_values_v2(database,
      "SELECT CASE WHEN typeof(record_hash) = 'text' AND length(CAST(record_hash AS BLOB)) = 64 THEN record_hash ELSE NULL END AS record_hash, typeof(ciphertext) AS kind, CASE WHEN typeof(ciphertext) = 'text' AND length(CAST(ciphertext AS BLOB)) > 0 AND length(CAST(ciphertext AS BLOB)) <= 33554432 THEN ciphertext ELSE NULL END AS ciphertext, CASE WHEN typeof(ciphertext) = 'text' THEN length(CAST(ciphertext AS BLOB)) WHEN typeof(ciphertext) = 'blob' THEN length(ciphertext) ELSE -1 END AS wire_size FROM encrypted_blobs ORDER BY record_hash LIMIT 1",
      [],
      33554432)
  else
    Sqlite.query_values_v2(database,
      "SELECT CASE WHEN typeof(record_hash) = 'text' AND length(CAST(record_hash AS BLOB)) = 64 THEN record_hash ELSE NULL END AS record_hash, typeof(ciphertext) AS kind, CASE WHEN typeof(ciphertext) = 'text' AND length(CAST(ciphertext AS BLOB)) > 0 AND length(CAST(ciphertext AS BLOB)) <= 33554432 THEN ciphertext ELSE NULL END AS ciphertext, CASE WHEN typeof(ciphertext) = 'text' THEN length(CAST(ciphertext AS BLOB)) WHEN typeof(ciphertext) = 'blob' THEN length(ciphertext) ELSE -1 END AS wire_size FROM encrypted_blobs WHERE record_hash > ? ORDER BY record_hash LIMIT 1",
      [Text(cursor)],
      33554432)
  end?
  if List.length(rows) == 0 do
    return Ok(nil)
  end
  if List.length(rows) != 1 do
    return Err("invalid_legacy_blob")
  end
  let row = List.head(rows)
  let previous = text(row, "record_hash")?
  let digest = case Bytes.from_hex(previous) do
    Err(_) -> return Err("invalid_blob_digest")
    Ok(value) -> value
  end
  if Bytes.length(digest) != 32 || Bytes.to_hex(digest) != previous do
    return Err("invalid_blob_digest")
  end
  let size = case String.to_int(text(row, "wire_size")?) do
    None -> return Err("invalid_legacy_blob")
    Some(value) -> value
  end
  if size < 1 do
    return Err("invalid_legacy_blob")
  end
  let next = digest_index(key, database_id, digest)?
  let changed = if text(row, "kind")? == "blob" do
    Sqlite.execute_values_v2(database,
      "INSERT INTO encrypted_blobs_index_migration (record_hash, ciphertext) SELECT ?, ciphertext FROM encrypted_blobs WHERE record_hash = ? AND typeof(ciphertext) = 'blob'",
      [Text(next), Text(previous)],
      64)?
  else if text(row, "kind")? == "text" do
    if size > 33554432 do
      return Err("account_source_limit")
    end
    Sqlite.execute_values_v2(database,
      "INSERT INTO encrypted_blobs_index_migration (record_hash, ciphertext) VALUES (?, ?)",
      [Text(next), Binary(legacy_blob(row)?)],
      33554432)?
  else
    return Err("invalid_legacy_blob")
  end
  if changed != 1 do
    return Err("database_write_failed")
  end
  rekey_rows_bounded(database, key, database_id, previous)
end

fn ensure_schema_on(database :: SqliteConn,
  key :: borrow StorageKey,
  profile_limit :: Option<Int>) -> Result<(), String> do
  let columns = Sqlite.query_values(database,
    "SELECT CASE WHEN length(CAST(name AS BLOB)) <= 64 THEN name ELSE NULL END AS name, CASE WHEN length(CAST(type AS BLOB)) <= 16 THEN upper(type) ELSE NULL END AS type, pk FROM pragma_table_info('encrypted_blobs') ORDER BY cid LIMIT 4",
    [])?
  let metadata = Sqlite.query_values(database,
    "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'encrypted_blob_index'",
    [])?
  if List.length(metadata) != 0 do
    let tables = Sqlite.query_values(database,
      "SELECT wr FROM pragma_table_list WHERE schema = 'main' AND name = 'encrypted_blobs'",
      [])?
    # A keyed rowid table is not canonical v2: its migration insertion order
    # may preserve the legacy SHA sort rank. Refuse without altering its rows.
    if !valid_columns(columns, true)?
      || List.length(tables) != 1
      || text(List.head(tables), "wr")? != "1" do
      return Err("invalid_blob_schema")
    end
    let _ = read_index(database, key)?
    return Ok(nil)
  end
  if List.length(columns) == 0 do
    Sqlite.execute(database,
      "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0)) STRICT, WITHOUT ROWID",
      [])?
    let _ = create_index(database, key)?
    return Ok(nil)
  end
  if !valid_columns(columns, false)? do
    return Err("invalid_blob_schema")
  end
  let any = Sqlite.query_values(database, "SELECT 1 AS present FROM encrypted_blobs LIMIT 1", [])?
  if List.length(any) > 0 do
    case profile_limit do
      None -> authenticate_legacy(database, key)?
      Some(maximum) -> authenticate_legacy_bounded(database, key, maximum)?
    end
  end
  # A stale/malicious migration table is not silently discarded or reused.
  Sqlite.execute(database,
    "CREATE TABLE encrypted_blobs_index_migration (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0)) STRICT, WITHOUT ROWID",
    [])?
  let database_id = create_index(database, key)?
  case profile_limit do
    None -> rekey_rows(database, key, database_id, "")?
    Some(_) -> rekey_rows_bounded(database, key, database_id, "")?
  end
  Sqlite.execute(database, "DROP TABLE encrypted_blobs", [])?
  Sqlite.execute(database,
    "ALTER TABLE encrypted_blobs_index_migration RENAME TO encrypted_blobs",
    [])?
  Ok(nil)
end

fn ensure_schema_with_key_mode(database_path :: String,
  key :: borrow StorageKey,
  profile_limit :: Option<Int>) -> Result<(), String> do
  let database = case Sqlite.open(database_path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  let result = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> case Sqlite.execute(database, "PRAGMA secure_delete = ON", []) do
      Err(error)
      Ok(_) -> case Sqlite.begin(database) do
        Err(error)
        Ok(_) -> case ensure_schema_on(database, key, profile_limit) do
          Err(error)
          Ok(_) -> Sqlite.commit(database)
        end
      end
    end
  end
  case result do
    Err(error) -> do
      Sqlite.rollback(database)
      Sqlite.close(database)
      if error == "account_source_limit" do
        Err(error)
      else
        Err("database_schema_failed")
      end
    end
    Ok(_) -> do
      Sqlite.close(database)
      Ok(nil)
    end
  end
end

pub fn ensure_schema_with_key(database_path :: String,
  key :: borrow StorageKey) -> Result<(), String> do
  ensure_schema_with_key_mode(database_path, key, None)
end

pub fn ensure_schema_with_key_bounded(database_path :: String,
  key :: borrow StorageKey,
  max_profile_bytes :: Int) -> Result<(), String> do
  if max_profile_bytes < 1 || max_profile_bytes > 33554432 do
    return Err("invalid_account_commit")
  end
  ensure_schema_with_key_mode(database_path, key, Some(max_profile_bytes))
end

pub fn ensure_schema(database_path :: String) -> Result<(), String> do
  let key = platform_key()?
  let result = ensure_schema_with_key(database_path, key)
  Secret.destroy(key)
  result
end

pub fn insert_blob_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  label :: String,
  blob :: Bytes) -> Result<(), String> do
  let record_hash = blob_record_hash_with_key(database, key, label)?
  case Sqlite.execute_values(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?)",
    [Text(record_hash), Binary(blob)]) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

pub fn insert_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result<(), String> do
  let key = platform_key()?
  let result = insert_blob_with_key(database, key, label, blob)
  Secret.destroy(key)
  result
end

pub fn put_blob_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  label :: String,
  blob :: Bytes) -> Result<(), String> do
  let record_hash = blob_record_hash_with_key(database, key, label)?
  case Sqlite.execute_values(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext",
    [Text(record_hash), Binary(blob)]) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

pub fn put_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result<(), String> do
  let key = platform_key()?
  let result = put_blob_with_key(database, key, label, blob)
  Secret.destroy(key)
  result
end

fn bounded_blob_write(label :: String, blob :: Bytes, maximum :: Int) -> Result<(), String> do
  if String.length(label) < 1 || String.length(label) > 256 || maximum < 1 || maximum > 33554432 do
    return Err("invalid_account_commit")
  end
  if Bytes.length(blob) == 0 || Bytes.length(blob) > maximum do
    Err("account_source_limit")
  else
    Ok(nil)
  end
end

pub fn put_blob_bounded_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  label :: String,
  blob :: Bytes,
  max_value_bytes :: Int) -> Result<(), String> do
  bounded_blob_write(label, blob, max_value_bytes)?
  let record_hash = blob_record_hash_with_key(database, key, label)?
  let quota = if max_value_bytes < 64 do
    64
  else
    max_value_bytes
  end
  case Sqlite.execute_values_v2(database,
    "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext",
    [Text(record_hash), Binary(blob)],
    quota) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

pub fn put_blob_bounded(database :: SqliteConn,
  label :: String,
  blob :: Bytes,
  max_value_bytes :: Int) -> Result<(), String> do
  bounded_blob_write(label, blob, max_value_bytes)?
  let key = platform_key()?
  let result = put_blob_bounded_with_key(database, key, label, blob, max_value_bytes)
  Secret.destroy(key)
  result
end

pub fn load_blob_with_key(database_path :: String,
  label :: String,
  key :: borrow StorageKey) -> Bytes!String do
  ensure_schema_with_key(database_path, key)?
  let database = case Sqlite.open(database_path) do
    Err(_) -> return Err("database_open_failed")
    Ok(value) -> value
  end
  let queried = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(_) -> Err("database_read_failed")
    Ok(_) -> case blob_record_key_with_key(database, key, Bytes.from_utf8(label)) do
      Err(error)
      Ok(record_hash) -> case Sqlite.query_values(database,
        "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
        [Text(record_hash)]) do
        Err(_) -> Err("database_read_failed")
        Ok(value)
      end
    end
  end
  Sqlite.close(database)
  let rows = queried?
  if List.length(rows) != 1 do
    return Err("local_state_not_found")
  end
  case Map.get(List.head(rows), "ciphertext") do
    Binary(value) -> Ok(value)
    _ -> Err("invalid_local_state")
  end
end

pub fn load_blob(database_path :: String, label :: String) -> Bytes!String do
  let key = platform_key()?
  let result = load_blob_with_key(database_path, label, key)
  Secret.destroy(key)
  result
end

from Storage.Blobs import blob_record_hash_with_key
from Storage.Keys import platform_key

pub struct OutboxBasis do
  profile :: Bytes
  index :: Bytes
  postage :: Bytes
  delivery :: Bytes
end

pub struct PreparedOutboxIndex do
  value :: Bytes
  before :: OutboxBasis
end

pub fn record_snapshot_by_hash(database :: SqliteConn, record_hash :: String) -> Bytes!String do
  let rows = case Sqlite.query_values(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(record_hash)]) do
    Err(_) -> return Err("database_read_failed")
    Ok(value) -> value
  end
  if List.length(rows) == 0 do
    Ok(Bytes.empty())
  else if List.length(rows) != 1 do
    Err("invalid_local_state")
  else
    case Map.get(List.head(rows), "ciphertext") do
      Binary(blob) -> Ok(blob)
      Text(_) -> Err("invalid_local_state")
      Null -> Err("invalid_local_state")
    end
  end
end

fn bounded_snapshot_limit(record_hash :: String, maximum :: Int) -> Result<(), String> do
  if String.length(record_hash) != 64 || maximum < 0 || maximum > 33554432 do
    Err("invalid_account_commit")
  else
    Ok(nil)
  end
end

fn bounded_snapshot_integer(row :: Map<String, DbValue>, column :: String) -> Int!String do
  case Map.get(row, column) do
    Text(value) -> case String.to_int(value) do
      None -> Err("invalid_local_state")
      Some(number) -> Ok(number)
    end
    _ -> Err("invalid_local_state")
  end
end

## Admission and value projection share the caller's SQLite snapshot. An
## oversized or malformed row is never projected as a Mesh BLOB or as absence.
pub fn record_snapshot_by_hash_bounded(database :: SqliteConn,
  record_hash :: String,
  maximum :: Int) -> Bytes!String do
  bounded_snapshot_limit(record_hash, maximum)?
  let quota = if maximum < 64 do
    64
  else
    maximum
  end
  let rows = case Sqlite.query_values_v2(database,
    "SELECT CASE WHEN typeof(ciphertext) = 'blob' THEN CASE WHEN length(ciphertext) > 0 AND length(ciphertext) <= CAST(? AS INTEGER) THEN ciphertext ELSE NULL END ELSE NULL END AS ciphertext, CASE WHEN typeof(ciphertext) = 'blob' THEN length(ciphertext) ELSE -1 END AS byte_count FROM encrypted_blobs WHERE record_hash = ? LIMIT 2",
    [Text(Int.to_string(maximum)), Text(record_hash)],
    quota) do
    Err(_) -> return Err("database_read_failed")
    Ok(value) -> value
  end
  if List.length(rows) == 0 do
    return Ok(Bytes.empty())
  end
  if List.length(rows) != 1 do
    return Err("invalid_local_state")
  end
  let row = List.head(rows)
  let length = bounded_snapshot_integer(row, "byte_count")?
  if length <= 0 do
    return Err("invalid_local_state")
  end
  if length > maximum do
    return Err("account_source_limit")
  end
  case Map.get(row, "ciphertext") do
    Binary(value) -> if Bytes.length(value) == length do
      Ok(value)
    else
      Err("invalid_local_state")
    end
    _ -> Err("invalid_local_state")
  end
end

## Compare only bounded scalar results. The database never returns a winning
## replacement BLOB, including an oversized row inserted into captured absence.
pub fn require_record_snapshot_by_hash_bounded(database :: SqliteConn,
  record_hash :: String,
  expected :: Bytes,
  maximum :: Int) -> Result<(), String> do
  bounded_snapshot_limit(record_hash, maximum)?
  let size = Bytes.length(expected)
  if size > maximum do
    return Err("account_source_limit")
  end
  let quota = if size < 64 do
    64
  else
    size
  end
  let rows = if size == 0 do
    Sqlite.query_values_v2(database,
      "SELECT 1 AS present FROM encrypted_blobs WHERE record_hash = ? LIMIT 2",
      [Text(record_hash)],
      quota)?
  else
    Sqlite.query_values_v2(database,
      "SELECT CASE WHEN typeof(ciphertext) = 'blob' AND length(ciphertext) = CAST(? AS INTEGER) THEN CASE WHEN ciphertext = ? THEN 1 ELSE 0 END ELSE 0 END AS matches FROM encrypted_blobs WHERE record_hash = ? LIMIT 2",
      [Text(Int.to_string(size)), Binary(expected), Text(record_hash)],
      quota)?
  end
  if size == 0 && List.length(rows) == 0 do
    return Ok(nil)
  end
  if size > 0
    && List.length(rows) == 1
    && bounded_snapshot_integer(List.head(rows), "matches")? == 1 do
    Ok(nil)
  else
    Err("account_state_changed")
  end
end

pub fn record_snapshot_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  label :: String) -> Bytes!String do
  record_snapshot_by_hash(database, blob_record_hash_with_key(database, key, label)?)
end

pub fn record_snapshot(database :: SqliteConn, label :: String) -> Bytes!String do
  let key = platform_key()?
  let result = record_snapshot_with_key(database, key, label)
  Secret.destroy(key)
  result
end

pub fn record_matches_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  label :: String,
  previous :: Bytes) -> Bool!String do
  Ok(Bytes.secure_equals(record_snapshot_with_key(database, key, label)?, previous))
end

pub fn record_matches(database :: SqliteConn, label :: String, previous :: Bytes) -> Bool!String do
  Ok(Bytes.secure_equals(record_snapshot(database, label)?, previous))
end

## Lock and compare exact custody before any prepared outbox write. The remaining
## snapshots are checked under the same SQLite write lock; no network work occurs
## inside this transaction. Empty optional snapshots require record absence.
fn require_basis_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: OutboxBasis) -> Result<(), String> do
  if Bytes.length(before.profile) == 0 do
    return Err("invalid_outbox_commit")
  end
  Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
  let changed = case Sqlite.execute_values(database,
    "UPDATE encrypted_blobs SET ciphertext = ciphertext WHERE record_hash = ? AND ciphertext = ?",
    [Text(blob_record_hash_with_key(database, key, "profile/v1")?), Binary(before.profile)]) do
    Err(_) -> return Err("database_write_failed")
    Ok(value) -> value
  end
  if changed != 1
    || !record_matches_with_key(database, key, "outbox/v1", before.index)?
    || !record_matches_with_key(database, key, "postage-queue/v1", before.postage)?
    || !record_matches_with_key(database, key, "delivery/v1", before.delivery)? do
    return Err("outbox_state_changed")
  end
  Ok(nil)
end

pub fn require_outbox_basis(database :: SqliteConn, before :: OutboxBasis) -> Result<(), String> do
  if Bytes.length(before.profile) == 0 do
    return Err("invalid_outbox_commit")
  end
  let key = platform_key()?
  let result = require_basis_with_key(database, key, before)
  Secret.destroy(key)
  result
end

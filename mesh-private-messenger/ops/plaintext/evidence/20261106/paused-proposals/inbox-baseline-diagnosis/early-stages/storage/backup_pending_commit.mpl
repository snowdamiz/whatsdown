##! Bounded two-row pending ciphertext snapshots. No account authority or payload crypto.
from Storage.Blobs import (
  ensure_schema_with_key_bounded,
  blob_record_hashes_with_key,
  put_blob_bounded_with_key
)
from Storage.AccountGuard import AccountBasis, require_account_basis_bounded_with_key
from Storage.OutboxGuard import (
  record_snapshot_by_hash_bounded,
  require_record_snapshot_by_hash_bounded
)

pub struct PendingCipherRow do
  present :: Bool
  admitted :: Bool
  value :: Bytes
  sql_type :: String
  byte_count :: Int
end

pub struct PendingCipherBasis do
  profile :: Bytes
  wire_label :: String
  descriptor_label :: String
  wire :: PendingCipherRow
  descriptor :: PendingCipherRow
end

fn pending_integer(row :: Map<String, DbValue>, name :: String) -> Int!String do
  case Map.get(row, name) do
    Text(value) -> case String.to_int(value) do
      None -> Err("invalid_pending_storage")
      Some(number) -> Ok(number)
    end
    _ -> Err("invalid_pending_storage")
  end
end

fn pending_row_on(database :: SqliteConn,
  hash :: String,
  maximum :: Int,
  available :: Int) -> PendingCipherRow!String do
  let projection = if available < maximum do
    available
  else
    maximum
  end
  let quota = if projection < 64 do
    64
  else
    projection
  end
  let rows = Sqlite.query_values_v2(database,
    "SELECT typeof(ciphertext) AS sql_type, CASE WHEN typeof(ciphertext) = 'blob' THEN length(ciphertext) ELSE -1 END AS byte_count, CASE WHEN typeof(ciphertext) = 'blob' THEN CASE WHEN length(ciphertext) > 0 AND length(ciphertext) <= CAST(? AS INTEGER) THEN ciphertext ELSE NULL END ELSE NULL END AS admitted_value FROM encrypted_blobs WHERE record_hash = ? LIMIT 2",
    [Text(Int.to_string(projection)), Text(hash)],
    quota)?
  if List.length(rows) == 0 do
    return Ok(PendingCipherRow {
      present: false,
      admitted: false,
      value: Bytes.empty(),
      sql_type: "absent",
      byte_count: 0
    })
  end
  if List.length(rows) != 1 do
    return Err("invalid_pending_storage")
  end
  let row = List.head(rows)
  let kind = case Map.get(row, "sql_type") do
    Text(value) -> value
    _ -> return Err("invalid_pending_storage")
  end
  let count = pending_integer(row, "byte_count")?
  let admitted = kind == "blob" && count > 0 && count <= maximum
  if admitted && count > available do
    return Err("backup_source_limit")
  end
  let value = if admitted do
    case Map.get(row, "admitted_value") do
      Binary(value) -> if Bytes.length(value) == count do
        value
      else
        return Err("invalid_pending_storage")
      end
      _ -> return Err("invalid_pending_storage")
    end
  else
    case Map.get(row, "admitted_value") do
      Null -> Bytes.empty()
      _ -> return Err("invalid_pending_storage")
    end
  end
  Ok(PendingCipherRow {
    present: true,
    admitted: admitted,
    value: value,
    sql_type: kind,
    byte_count: count
  })
end

fn pending_labels_valid(wire :: String, descriptor :: String) -> Bool do
  wire != descriptor
    && String.length(wire) > 0
    && String.length(wire) <= 256
    && String.length(descriptor) > 0
    && String.length(descriptor) <= 256
end

fn pending_capture_on(database :: SqliteConn,
  key :: borrow StorageKey,
  wire :: String,
  descriptor :: String,
  available :: Int) -> PendingCipherBasis!String do
  let hashes = blob_record_hashes_with_key(database, key, ["profile/v1", wire, descriptor])?
  let profile = record_snapshot_by_hash_bounded(database, List.get(hashes, 0), 40000)?
  if Bytes.length(profile) == 0 do
    return Err("local_state_not_found")
  end
  let wire_row = pending_row_on(database, List.get(hashes, 1), 16796864, available)?
  let descriptor_row = pending_row_on(database,
    List.get(hashes, 2),
    4096,
    available - Bytes.length(wire_row.value))?
  Ok(PendingCipherBasis {
    profile: profile,
    wire_label: wire,
    descriptor_label: descriptor,
    wire: wire_row,
    descriptor: descriptor_row
  })
end

pub fn capture_pending_cipher_basis_with_key(path :: String,
  key :: borrow StorageKey,
  wire :: String,
  descriptor :: String,
  available :: Int) -> PendingCipherBasis!String do
  if available < 0 || available > 33554432 do
    return Err("backup_source_limit")
  end
  if !pending_labels_valid(wire, descriptor) do
    return Err("invalid_pending_storage")
  end
  ensure_schema_with_key_bounded(path, key, 40000)?
  let database = Sqlite.open(path)?
  let result = case Sqlite.begin(database) do
    Err(_) -> Err("database_read_failed")
    Ok(_) -> pending_capture_on(database, key, wire, descriptor, available)
  end
  Sqlite.rollback(database)
  Sqlite.close(database)
  result
end

fn require_pending_row(database :: SqliteConn,
  hash :: String,
  before :: PendingCipherRow,
  maximum :: Int) -> Result<(), String> do
  if !before.present || before.admitted do
    return require_record_snapshot_by_hash_bounded(database, hash, before.value, maximum)
  end
  # Invalid values are never materialized. A same-kind/length replacement remains
  # invalid; a bounded valid replacement or changed companion refuses the fence.
  let rows = Sqlite.query_values_v2(database,
    "SELECT CASE WHEN typeof(ciphertext) = ? THEN CASE WHEN typeof(ciphertext) = 'blob' THEN CASE WHEN length(ciphertext) = CAST(? AS INTEGER) AND (length(ciphertext) = 0 OR length(ciphertext) > CAST(? AS INTEGER)) THEN 1 ELSE 0 END ELSE 1 END ELSE 0 END AS matches FROM encrypted_blobs WHERE record_hash = ? LIMIT 2",
    [
      Text(before.sql_type),
      Text(Int.to_string(before.byte_count)),
      Text(Int.to_string(maximum)),
      Text(hash)
    ],
    64)?
  if List.length(rows) == 1 && pending_integer(List.head(rows), "matches")? == 1 do
    Ok(nil)
  else
    Err("account_state_changed")
  end
end

pub fn require_pending_cipher_basis_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: PendingCipherBasis) -> Result<(), String> do
  if !pending_labels_valid(before.wire_label, before.descriptor_label) do
    return Err("invalid_pending_storage")
  end
  require_account_basis_bounded_with_key(database,
    key,
    AccountBasis { profile: before.profile, labels: [], records: [] },
    40000,
    0,
    40000)?
  let hashes = blob_record_hashes_with_key(database,
    key,
    [before.wire_label, before.descriptor_label])?
  require_pending_row(database, List.get(hashes, 0), before.wire, 16796864)?
  require_pending_row(database, List.get(hashes, 1), before.descriptor, 4096)
end

pub fn publish_pending_cipher_pair_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: PendingCipherBasis,
  wire :: Bytes,
  descriptor :: Bytes) -> Result<(), String> do
  if before.wire.present || before.descriptor.present do
    return Err("pending_export_exists")
  end
  put_blob_bounded_with_key(database, key, before.wire_label, wire, 16796864)?
  put_blob_bounded_with_key(database, key, before.descriptor_label, descriptor, 4096)
end

pub fn delete_pending_cipher_pair_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: PendingCipherBasis) -> Result<(), String> do
  let hashes = blob_record_hashes_with_key(database,
    key,
    [before.wire_label, before.descriptor_label])?
  for index in 0..2 do
    let present = if index == 0 do
      before.wire.present
    else
      before.descriptor.present
    end
    let changed = Sqlite.execute(database,
      "DELETE FROM encrypted_blobs WHERE record_hash = ?",
      [List.get(hashes, index)])?
    if changed != (if present do
        1
      else
        0
      end) do
      return Err("account_state_changed")
    end
  end
  Ok(nil)
end

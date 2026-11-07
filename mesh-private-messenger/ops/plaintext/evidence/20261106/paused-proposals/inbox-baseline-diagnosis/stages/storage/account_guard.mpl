from Storage.Blobs import (
  blob_record_hashes_with_key,
  ensure_schema_with_key,
  ensure_schema_with_key_bounded
)
from Storage.Keys import platform_key
from Storage.OutboxGuard import (
  record_snapshot_by_hash,
  record_snapshot_by_hash_bounded,
  require_record_snapshot_by_hash_bounded
)
from Storage.Records import with_record_transaction, put_blobs, delete_blobs

pub struct AccountBasis do
  profile :: Bytes
  labels :: List<String>
  records :: List<Bytes>
end

fn read_records(database :: SqliteConn,
  record_hashes :: List<String>,
  index :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(record_hashes) do
    Ok(output)
  else
    read_records(database,
      record_hashes,
      index + 1,
      List.append(output, record_snapshot_by_hash(database, List.get(record_hashes, index))?))
  end
end

fn distinct_labels(labels :: List<String>, index :: Int) -> Bool do
  if index >= List.length(labels) do
    true
  else
    !List.contains(List.take(labels, index), List.get(labels, index))
      && distinct_labels(labels, index + 1)
  end
end

fn valid_labels(labels :: List<String>) -> Bool do
  List.length(labels) <= 64
    && List.all(labels, fn(label) -> String.length(label) > 0 && String.length(label) <= 256 end)
    && distinct_labels(labels, 0)
end

fn basis_on(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>) -> AccountBasis!String do
  let record_hashes = blob_record_hashes_with_key(database, key, ["profile/v1"] ++ labels)?
  let profile = record_snapshot_by_hash(database, List.head(record_hashes))?
  if Bytes.length(profile) == 0 do
    Err("local_state_not_found")
  else
    Ok(AccountBasis {
      profile: profile,
      labels: labels,
      records: read_records(database, List.drop(record_hashes, 1), 0, [])?
    })
  end
end

## Read custody and its mutable renewal records in one SQLite snapshot. No
## transaction or database handle survives the return to cryptographic work.
fn load_basis_with_key(path :: String,
  key :: borrow StorageKey,
  labels :: List<String>) -> AccountBasis!String do
  ensure_schema_with_key(path, key)?
  let database = Sqlite.open(path)?
  let result = case Sqlite.begin(database) do
    Err(_) -> Err("database_read_failed")
    Ok(_) -> basis_on(database, key, labels)
  end
  Sqlite.rollback(database)
  Sqlite.close(database)
  result
end

pub fn load_account_basis(path :: String, labels :: List<String>) -> AccountBasis!String do
  if !valid_labels(labels) || List.contains(labels, "profile/v1") do
    return Err("invalid_account_commit")
  end
  let key = platform_key()?
  let result = load_basis_with_key(path, key, labels)
  Secret.destroy(key)
  result
end

pub fn same_account_basis(left :: AccountBasis, right :: AccountBasis) -> Bool do
  left.labels == right.labels
    && Bytes.secure_equals(left.profile, right.profile)
    && List.length(left.records) == List.length(right.records)
    && List.all(for index in 0..List.length(left.records) do
        Bytes.secure_equals(List.get(left.records, index), List.get(right.records, index))
      end,
      fn(value) -> value end)
end

pub fn account_basis_current(path :: String, before :: AccountBasis) -> Bool do
  case load_account_basis(path, before.labels) do
    Err(_) -> false
    Ok(value) -> same_account_basis(value, before)
  end
end

fn require_basis_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: AccountBasis) -> Result<(), String> do
  if Bytes.length(before.profile) == 0
    || !valid_labels(before.labels)
    || List.length(before.labels) != List.length(before.records) do
    return Err("invalid_account_commit")
  end
  Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
  let record_hashes = blob_record_hashes_with_key(database, key, ["profile/v1"] ++ before.labels)?
  let changed = Sqlite.execute_values(database,
    "UPDATE encrypted_blobs SET ciphertext = ciphertext WHERE record_hash = ? AND ciphertext = ?",
    [Text(List.head(record_hashes)), Binary(before.profile)])?
  if changed != 1 do
    return Err("account_state_changed")
  end
  for index in 0..List.length(before.labels) do
    if !Bytes.secure_equals(record_snapshot_by_hash(database, List.get(record_hashes, index + 1))?,
      List.get(before.records, index)) do
      return Err("account_state_changed")
    end
  end
  Ok(nil)
end

pub fn require_account_basis(database :: SqliteConn,
  before :: AccountBasis) -> Result<(), String> do
  if Bytes.length(before.profile) == 0
    || !valid_labels(before.labels)
    || List.length(before.labels) != List.length(before.records) do
    return Err("invalid_account_commit")
  end
  let key = platform_key()?
  let result = require_basis_with_key(database, key, before)
  Secret.destroy(key)
  result
end

## The profile comparison obtains a write lock before any state comparison or
## mutation. A stale renewal cannot recreate custody or overwrite a newer plan.
pub fn commit_account_changes(path :: String,
  before :: AccountBasis,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> Result<(), String> do
  if !valid_labels(labels)
    || !valid_labels(removed)
    || List.length(labels) != List.length(blobs)
    || List.any(labels, fn(label) -> List.contains(removed, label) end)
    || List.any(blobs, fn(blob) -> Bytes.length(blob) == 0 end) do
    return Err("invalid_account_commit")
  end
  with_record_transaction(path,
    fn(database) do
      require_account_basis(database, before)?
      put_blobs(database, labels, blobs, 0)?
      delete_blobs(database, removed, 0)
    end)
end

pub fn erase_account_if_current(path :: String, profile :: Bytes) -> Result<(), String> do
  with_record_transaction(path,
    fn(database) do
      require_account_basis(database, AccountBasis { profile: profile, labels: [], records: [] })?
      Sqlite.execute(database, "DELETE FROM encrypted_blobs", [])?
      Ok(nil)
    end)?
  # Best effort page rewriting happens only after the guarded erase committed.
  case Sqlite.open(path) do
    Err(_) -> Ok(nil)
    Ok(database) -> do
      Sqlite.execute(database, "VACUUM", [])
      Sqlite.close(database)
      Ok(nil)
    end
  end
end

## Bounded snapshot admission for backup source capture.
fn bounded_basis_limits(max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> Result<(), String> do
  if max_profile_bytes < 1
    || max_profile_bytes > 33554432
    || max_record_bytes < 0
    || max_record_bytes > 33554432
    || max_total_bytes < 1
    || max_total_bytes > 67108864 do
    Err("invalid_account_commit")
  else
    Ok(nil)
  end
end

fn bounded_basis_minimum(left :: Int, right :: Int) -> Int do
  if left < right do
    left
  else
    right
  end
end

fn read_records_bounded(database :: SqliteConn,
  hashes :: List<String>,
  index :: Int,
  max_record_bytes :: Int,
  remaining :: Int,
  output :: List<Bytes>) -> List<Bytes>!String do
  if index >= List.length(hashes) do
    return Ok(output)
  end
  let value = record_snapshot_by_hash_bounded(database,
    List.get(hashes, index),
    bounded_basis_minimum(max_record_bytes, remaining))?
  read_records_bounded(database,
    hashes,
    index + 1,
    max_record_bytes,
    remaining - Bytes.length(value),
    List.append(output, value))
end

fn basis_on_bounded(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> AccountBasis!String do
  let hashes = blob_record_hashes_with_key(database, key, ["profile/v1"] ++ labels)?
  let profile = record_snapshot_by_hash_bounded(database,
    List.head(hashes),
    bounded_basis_minimum(max_profile_bytes, max_total_bytes))?
  if Bytes.length(profile) == 0 do
    return Err("local_state_not_found")
  end
  Ok(AccountBasis {
    profile: profile,
    labels: labels,
    records: read_records_bounded(database,
      List.drop(hashes, 1),
      0,
      max_record_bytes,
      max_total_bytes - Bytes.length(profile),
      [])?
  })
end

fn load_basis_with_key_bounded(path :: String,
  key :: borrow StorageKey,
  labels :: List<String>,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> AccountBasis!String do
  ensure_schema_with_key_bounded(path,
    key,
    bounded_basis_minimum(max_profile_bytes, max_total_bytes))?
  let database = Sqlite.open(path)?
  let result = case Sqlite.begin(database) do
    Err(_) -> Err("database_read_failed")
    Ok(_) -> basis_on_bounded(database,
      key,
      labels,
      max_profile_bytes,
      max_record_bytes,
      max_total_bytes)
  end
  Sqlite.rollback(database)
  Sqlite.close(database)
  result
end

pub fn load_account_basis_bounded(path :: String,
  labels :: List<String>,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> AccountBasis!String do
  bounded_basis_limits(max_profile_bytes, max_record_bytes, max_total_bytes)?
  if !valid_labels(labels) || List.contains(labels, "profile/v1") do
    return Err("invalid_account_commit")
  end
  let key = platform_key()?
  let result = load_basis_with_key_bounded(path,
    key,
    labels,
    max_profile_bytes,
    max_record_bytes,
    max_total_bytes)
  Secret.destroy(key)
  result
end

pub fn load_account_basis_bounded_with_key(path :: String,
  key :: borrow StorageKey,
  labels :: List<String>,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> AccountBasis!String do
  bounded_basis_limits(max_profile_bytes, max_record_bytes, max_total_bytes)?
  if !valid_labels(labels) || List.contains(labels, "profile/v1") do
    return Err("invalid_account_commit")
  end
  load_basis_with_key_bounded(path,
    key,
    labels,
    max_profile_bytes,
    max_record_bytes,
    max_total_bytes)
end

fn require_original_record_bounds(records :: List<Bytes>,
  index :: Int,
  max_record_bytes :: Int,
  remaining :: Int) -> Result<(), String> do
  if index >= List.length(records) do
    return Ok(nil)
  end
  let size = Bytes.length(List.get(records, index))
  if size > max_record_bytes || size > remaining do
    return Err("account_source_limit")
  end
  require_original_record_bounds(records, index + 1, max_record_bytes, remaining - size)
end

fn require_basis_with_key_bounded(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: AccountBasis,
  max_record_bytes :: Int) -> Result<(), String> do
  Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
  let hashes = blob_record_hashes_with_key(database, key, ["profile/v1"] ++ before.labels)?
  let size = Bytes.length(before.profile)
  let quota = if size < 64 do
    64
  else
    size
  end
  let changed = Sqlite.execute_values_v2(database,
    "UPDATE encrypted_blobs SET ciphertext = ciphertext WHERE record_hash = ? AND ciphertext = ?",
    [Text(List.head(hashes)), Binary(before.profile)],
    quota)?
  if changed != 1 do
    return Err("account_state_changed")
  end
  for index in 0..List.length(before.labels) do
    require_record_snapshot_by_hash_bounded(database,
      List.get(hashes, index + 1),
      List.get(before.records, index),
      max_record_bytes)?
  end
  Ok(nil)
end

fn require_bounded_original(before :: AccountBasis,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> Result<(), String> do
  bounded_basis_limits(max_profile_bytes, max_record_bytes, max_total_bytes)?
  if Bytes.length(before.profile) == 0
    || !valid_labels(before.labels)
    || List.length(before.labels) != List.length(before.records) do
    return Err("invalid_account_commit")
  end
  let size = Bytes.length(before.profile)
  if size > max_profile_bytes || size > max_total_bytes do
    return Err("account_source_limit")
  end
  require_original_record_bounds(before.records, 0, max_record_bytes, max_total_bytes - size)
end

pub fn require_account_basis_bounded_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  before :: AccountBasis,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> Result<(), String> do
  require_bounded_original(before, max_profile_bytes, max_record_bytes, max_total_bytes)?
  require_basis_with_key_bounded(database, key, before, max_record_bytes)
end

pub fn require_account_basis_bounded(database :: SqliteConn,
  before :: AccountBasis,
  max_profile_bytes :: Int,
  max_record_bytes :: Int,
  max_total_bytes :: Int) -> Result<(), String> do
  require_bounded_original(before, max_profile_bytes, max_record_bytes, max_total_bytes)?
  let key = platform_key()?
  let result = require_basis_with_key_bounded(database, key, before, max_record_bytes)
  Secret.destroy(key)
  result
end

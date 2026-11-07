##! Backup-only supplied-connection predicates; no caller-prepared publication.
from Storage.FanoutCommit import FanoutSnapshot
from Storage.AccountGuard import AccountBasis, require_account_basis_bounded_with_key
from Storage.Keys import platform_key

pub fn backup_archive_label(account :: Bytes, backup_id :: Bytes) -> String!String do
  if Bytes.length(account) != 32 || Bytes.length(backup_id) != 32 do
    Err("invalid_backup_archive_identity")
  else
    Ok("backup-archive/v1/#{Bytes.to_hex(account)}/#{Bytes.to_hex(backup_id)}")
  end
end

pub fn backup_archive_index_label(account :: Bytes) -> String!String do
  if Bytes.length(account) != 32 do
    Err("invalid_backup_archive_identity")
  else
    Ok("backup-archives/v1/#{Bytes.to_hex(account)}")
  end
end

fn backup_record_extent(records :: List<Bytes>, index :: Int, extent :: Int) -> Int!String do
  if index >= List.length(records) do
    return Ok(extent)
  end
  let length = Bytes.length(List.get(records, index))
  if length > 33554432 || extent + length > 33554432 do
    return Err("backup_source_limit")
  end
  backup_record_extent(records, index + 1, extent + length)
end

fn backup_snapshot_extent(bases :: List<AccountBasis>,
  index :: Int,
  profile :: Bytes,
  labels :: Int,
  extent :: Int) -> Int!String do
  if index >= List.length(bases) do
    return Ok(extent)
  end
  let basis = List.get(bases, index)
  let next_labels = labels + List.length(basis.labels)
  if !Bytes.secure_equals(basis.profile, profile)
    || List.length(basis.labels) > 64
    || List.length(basis.labels) != List.length(basis.records) do
    return Err("invalid_backup_snapshot")
  end
  if next_labels > 192 do
    return Err("backup_source_limit")
  end
  backup_snapshot_extent(bases,
    index + 1,
    profile,
    next_labels,
    backup_record_extent(basis.records, 0, extent)?)
end

## Require both internally derived destinations, including captured absence.
## The supplied writer checks every original source; it never captures a new one.
pub fn require_backup_archive_snapshot(database :: SqliteConn,
  original :: FanoutSnapshot,
  account :: Bytes,
  backup_id :: Bytes) -> Result<(), String> do
  let key = platform_key()?
  let result = require_backup_archive_snapshot_with_key(database, original, account, backup_id, key)
  Secret.destroy(key)
  result
end

pub fn require_backup_archive_snapshot_with_key(database :: SqliteConn,
  original :: FanoutSnapshot,
  account :: Bytes,
  backup_id :: Bytes,
  key :: borrow StorageKey) -> Result<(), String> do
  let row = backup_archive_label(account, backup_id)?
  let index = backup_archive_index_label(account)?
  if List.length(original.bases) == 0 || List.length(original.bases) > 8 do
    return Err("invalid_backup_snapshot")
  end
  let profile = List.head(original.bases).profile
  if Bytes.length(profile) > 33554432 do
    return Err("backup_source_limit")
  end
  backup_snapshot_extent(original.bases, 0, profile, 0, Bytes.length(profile))?
  let labels = List.flatten(for basis in original.bases do
    basis.labels
  end)
  if !List.contains(labels, row) || !List.contains(labels, index) do
    return Err("invalid_backup_snapshot")
  end
  # Existing keyed index lookup and ciphertext comparisons use this connection.
  # No payload opening/encryption, KDF, network, rediscovery or second connection.
  for basis in original.bases do
    require_account_basis_bounded_with_key(database, key, basis, 40000, 33554432, 33554432)?
  end
  Ok(nil)
end

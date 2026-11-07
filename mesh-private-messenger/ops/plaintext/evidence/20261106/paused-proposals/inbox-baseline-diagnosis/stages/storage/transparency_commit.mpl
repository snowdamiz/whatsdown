from Storage.AccountGuard import AccountBasis, require_account_basis
from Storage.Blobs import blob_record_hash
from Storage.Records import with_record_transaction, put_blobs

## Commit a verified checkpoint and its caches only while the exact profile and
## checkpoint ciphertexts still match the verification basis. The first insert
## checks profile custody in the same SQL statement, so erasure cannot recreate
## an account's cache through a late first-lookup response.
pub fn commit_transparency_cache(path :: String,
  profile :: Bytes,
  previous_checkpoint :: Bytes,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  commit_cache(path, profile, previous_checkpoint, labels, blobs, None)
end

pub fn commit_transparency_cache_guarded(path :: String,
  profile :: Bytes,
  previous_checkpoint :: Bytes,
  labels :: List<String>,
  blobs :: List<Bytes>,
  before :: AccountBasis) -> Result<(), String> do
  if !Bytes.secure_equals(profile, before.profile) do
    return Err("invalid_transparency_commit")
  end
  commit_cache(path, profile, previous_checkpoint, labels, blobs, Some(before))
end

fn commit_cache(path :: String,
  profile :: Bytes,
  previous_checkpoint :: Bytes,
  labels :: List<String>,
  blobs :: List<Bytes>,
  before :: Option<AccountBasis>) -> Result<(), String> do
  if List.length(labels) == 0
    || List.length(labels) != List.length(blobs)
    || List.head(labels) != "transparency-checkpoint/v1"
    || List.any(labels, fn(label) -> label == "profile/v1" end)
    || List.any(blobs, fn(blob) -> Bytes.length(blob) == 0 end) do
    return Err("invalid_transparency_commit")
  end
  with_record_transaction(path,
    fn(database) do
      case before do
        None -> nil
        Some(value) -> require_account_basis(database, value)?
      end
      Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
      let checkpoint_hash = blob_record_hash(database, "transparency-checkpoint/v1")?
      let profile_hash = blob_record_hash(database, "profile/v1")?
      let count = if Bytes.length(previous_checkpoint) == 0 do
        Sqlite.execute_values(database,
          "INSERT INTO encrypted_blobs (record_hash, ciphertext) SELECT ?, ? WHERE (length(?) = 0 AND NOT EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ?)) OR EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ? AND ciphertext = ?) ON CONFLICT(record_hash) DO NOTHING",
          [
            Text(checkpoint_hash),
            Binary(List.head(blobs)),
            Binary(profile),
            Text(profile_hash),
            Text(profile_hash),
            Binary(profile)
          ])?
      else
        Sqlite.execute_values(database,
          "UPDATE encrypted_blobs SET ciphertext = ? WHERE record_hash = ? AND ciphertext = ? AND ((length(?) = 0 AND NOT EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ?)) OR EXISTS (SELECT 1 FROM encrypted_blobs WHERE record_hash = ? AND ciphertext = ?))",
          [
            Binary(List.head(blobs)),
            Text(checkpoint_hash),
            Binary(previous_checkpoint),
            Binary(profile),
            Text(profile_hash),
            Text(profile_hash),
            Binary(profile)
          ])?
      end
      if count != 1 do
        return Err("transparency_state_changed")
      end
      put_blobs(database, labels, blobs, 1)
    end)
end

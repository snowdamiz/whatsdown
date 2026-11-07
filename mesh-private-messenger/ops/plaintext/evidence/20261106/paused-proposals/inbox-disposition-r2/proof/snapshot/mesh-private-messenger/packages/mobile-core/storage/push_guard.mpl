from Storage.Blobs import blob_record_hash, ensure_schema, put_blob
from Storage.OutboxGuard import record_snapshot, record_matches
from Storage.Records import with_record_transaction

pub struct PushBasis do
  profile :: Bytes
  push :: Bytes
end

fn basis_on(database :: SqliteConn) -> PushBasis!String do
  let profile = record_snapshot(database, "profile/v1")?
  if Bytes.length(profile) == 0 do
    return Err("local_state_not_found")
  end
  Ok(PushBasis { profile: profile, push: record_snapshot(database, "push-binding/v1")? })
end

## Read the profile and encrypted push state in the same SQLite snapshot.
pub fn load_push_basis(path :: String) -> PushBasis!String do
  ensure_schema(path)?
  let database = Sqlite.open(path)?
  let result = case Sqlite.begin(database) do
    Err(error)
    Ok(_) -> basis_on(database)
  end
  Sqlite.rollback(database)
  Sqlite.close(database)
  result
end

fn require_basis(database :: SqliteConn, before :: PushBasis) -> Result<(), String> do
  if Bytes.length(before.profile) == 0 do
    return Err("push_state_changed")
  end
  Sqlite.execute(database, "PRAGMA busy_timeout = 1000", [])?
  let changed = Sqlite.execute_values(database,
    "UPDATE encrypted_blobs SET ciphertext = ciphertext WHERE record_hash = ? AND ciphertext = ?",
    [Text(blob_record_hash(database, "profile/v1")?), Binary(before.profile)])?
  if changed != 1 || !record_matches(database, "push-binding/v1", before.push)? do
    return Err("push_state_changed")
  end
  Ok(nil)
end

## No network call holds this lock. A delayed response must still own both the
## exact account and the exact durable intent before it may settle anything.
pub fn commit_push_basis(path :: String,
  before :: PushBasis,
  sealed :: Bytes) -> Result<(), String> do
  with_record_transaction(path,
    fn(database) do
      require_basis(database, before)?
      put_blob(database, "push-binding/v1", sealed)
    end)
end

pub fn require_current_push(path :: String, before :: PushBasis) -> Result<(), String> do
  let current = load_push_basis(path)?
  if !Bytes.secure_equals(current.profile, before.profile)
    || !Bytes.secure_equals(current.push, before.push) do
    Err("push_state_changed")
  else
    Ok(nil)
  end
end

## Installation identity is created before provider HTTP and never overwritten.
## A losing concurrent creator reads the winner; an old account cannot create it.
pub fn reserve_push_install(path :: String,
  before :: PushBasis,
  candidate :: Bytes) -> Result<(), String> do
  with_record_transaction(path,
    fn(database) do
      require_basis(database, before)?
      if Bytes.length(record_snapshot(database, "push-install-id/v1")?) == 0 do
        put_blob(database, "push-install-id/v1", candidate)
      else
        Ok(nil)
      end
    end)
end

from Storage.Keys import platform_key
from Storage.OutboxGuard import PreparedOutboxIndex, require_outbox_basis
from Mobile.Codec import canonical_outer
from Mobile.Types import MobilePreparedSend, MobileStoreRequest
from Protocol.V1 import OuterEnvelope
from Storage.Blobs import (
  blob_record_key,
  blob_record_hash,
  blob_record_hash_with_key,
  ensure_schema,
  insert_blob,
  insert_blob_with_key,
  load_blob,
  put_blob,
  put_blob_with_key
)

##! Storage.Records implementation.

fn insert_blobs_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>,
  blobs :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(labels) do
    Ok(nil)
  else
    insert_blob_with_key(database, key, List.get(labels, index), List.get(blobs, index))?
    insert_blobs_with_key(database, key, labels, blobs, index + 1)
  end
end

fn insert_blobs(database :: SqliteConn,
  labels :: List<String>,
  blobs :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if List.length(labels) != List.length(blobs) do
    return Err("invalid_local_state")
  end
  if index >= List.length(labels) do
    return Ok(nil)
  end
  let key = platform_key()?
  let result = insert_blobs_with_key(database, key, labels, blobs, index)
  Secret.destroy(key)
  result
end

fn put_blobs_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>,
  blobs :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(labels) do
    Ok(nil)
  else
    put_blob_with_key(database, key, List.get(labels, index), List.get(blobs, index))?
    put_blobs_with_key(database, key, labels, blobs, index + 1)
  end
end

pub fn put_blobs(database :: SqliteConn,
  labels :: List<String>,
  blobs :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if List.length(labels) != List.length(blobs) do
    return Err("invalid_local_state")
  end
  if index >= List.length(labels) do
    return Ok(nil)
  end
  let key = platform_key()?
  let result = put_blobs_with_key(database, key, labels, blobs, index)
  Secret.destroy(key)
  result
end

pub fn delete_blob(database :: SqliteConn, label :: String) -> Result<(), String> do
  let record_hash = blob_record_hash(database, label)?
  case Sqlite.execute(database,
    "DELETE FROM encrypted_blobs WHERE record_hash = ?",
    [record_hash]) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

fn delete_blobs_with_key(database :: SqliteConn,
  key :: borrow StorageKey,
  labels :: List<String>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(labels) do
    Ok(nil)
  else
    let record_hash = blob_record_hash_with_key(database, key, List.get(labels, index))?
    case Sqlite.execute(database,
      "DELETE FROM encrypted_blobs WHERE record_hash = ?",
      [record_hash]) do
      Err(_) -> return Err("database_write_failed")
      Ok(_) -> nil
    end
    delete_blobs_with_key(database, key, labels, index + 1)
  end
end

pub fn delete_blobs(database :: SqliteConn,
  labels :: List<String>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(labels) do
    return Ok(nil)
  end
  let key = platform_key()?
  let result = delete_blobs_with_key(database, key, labels, index)
  Secret.destroy(key)
  result
end

pub fn store_linked_blobs(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      insert_blobs(database, labels, blobs, 0)?
      delete_blobs(database,
        [
          "pending-link-request/v1",
          "pending-device-signing-key/v1",
          "pending-device-identity-key/v1",
          "pending-post-quantum-prekey/v1"
        ],
        0)
    end)
end

fn delete_every_record(database :: SqliteConn) -> Result<(), String> do
  case Sqlite.execute(database, "DELETE FROM encrypted_blobs", []) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

## A new account's records replace whatever else the table holds. With no
## profile that can only be what an erased or abandoned account left, and a
## leftover under one of the new labels would otherwise refuse every new account.
## An existing profile is never replaced.

pub fn store_new_account(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      let profiles = case Sqlite.query_values(database,
        "SELECT record_hash FROM encrypted_blobs WHERE record_hash = ?",
        [Text(blob_record_hash(database, "profile/v1")?)]) do
        Err(_) -> Err("database_read_failed")
        Ok(rows)
      end?
      if List.length(profiles) > 0 do
        Err("account_already_exists")
      else
        delete_every_record(database)?
        insert_blobs(database, labels, blobs, 0)
      end
    end)
end

## Everything this device stores for its account, in one transaction. VACUUM
## then rewrites the file so the records do not linger in its free pages; it
## needs spare disk, and the erase stands without it.

pub fn erase_local_state(database_path :: String) -> Result<(), String> do
  ensure_schema(database_path)?
  with_record_transaction(database_path, fn(database) do delete_every_record(database) end)?
  case Sqlite.open(database_path) do
    Err(_) -> Ok(nil)
    Ok(database) -> do
      Sqlite.execute(database, "VACUUM", [])
      Sqlite.close(database)
      Ok(nil)
    end
  end
end

pub fn store_blobs(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do insert_blobs(database, labels, blobs, 0) end)
end

pub fn store_updated_blobs(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path, fn(database) do put_blobs(database, labels, blobs, 0) end)
end

## Replace a bundle only if its first record still has the value that was read.
## Key-package rotation uses this to keep the advertised keys and their sealed
## private material together, without overwriting a concurrent rotation.
## An empty previous value means the record must not exist; insert it atomically
## or fail the comparison. Stored ciphertext is always nonempty.
pub fn compare_and_swap_blobs(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  previous :: Bytes) -> Result<(), String> do
  if List.length(labels) == 0 || List.length(labels) != List.length(blobs) do
    return Err("invalid_local_state")
  end
  with_record_transaction(database_path,
    fn(database) do # Concurrent reservations wait briefly for the winning writer, then
      # compare its committed value. A longer lock remains a durable error.
      case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
        Err(_) -> return Err("database_write_failed")
        Ok(_) -> nil
      end
      let record_hash = blob_record_hash(database, List.head(labels))?
      let changed = if Bytes.length(previous) == 0 do
        Sqlite.execute_values(database,
          "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO NOTHING",
          [Text(record_hash), Binary(List.head(blobs))])
      else
        Sqlite.execute_values(database,
          "UPDATE encrypted_blobs SET ciphertext = ? WHERE record_hash = ? AND ciphertext = ?",
          [Binary(List.head(blobs)), Text(record_hash), Binary(previous)])
      end
      let count = case changed do
        Err(_) -> Err("database_write_failed")
        Ok(value)
      end?
      if count != 1 do
        Err("local_state_changed")
      else
        put_blobs(database, labels, blobs, 1)
      end
    end)
end

pub fn store_record_changes(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      put_blobs(database, labels, blobs, 0)?
      delete_blobs(database, removed, 0)
    end)
end

pub fn store_prekey_batch(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed_labels :: List<String>,
  index_blob :: Bytes,
  active_blob :: Bytes,
  next_id_blob :: Bytes,
  delete_legacy :: Bool) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      delete_blobs(database, removed_labels, 0)?
      insert_blobs(database, labels, blobs, 0)?
      put_blob(database, "one-time-prekeys/v1", index_blob)?
      put_blob(database, "one-time-prekey-active/v1", active_blob)?
      put_blob(database, "one-time-prekey-next-id/v1", next_id_blob)?
      if delete_legacy do
        delete_blob(database, "one-time-prekey/v1")
      else
        Ok(nil)
      end
    end)
end

# A new last-resort key with, when it replaces one, the list of the keys it and
# its predecessors replaced, and the secret of any dropped from that list.

pub fn store_last_resort_prekey(database_path :: String,
  secret_label :: String,
  secret_blob :: Bytes,
  record_blob :: Bytes,
  retired_blob :: Bytes,
  removed_labels :: List<String>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      insert_blob(database, secret_label, secret_blob)?
      put_blob(database, "last-resort-prekey/v1", record_blob)?
      delete_blobs(database, removed_labels, 0)?
      if Bytes.length(retired_blob) == 0 do
        Ok(nil)
      else
        put_blob(database, "last-resort-retired/v1", retired_blob)
      end
    end)
end

pub fn store_prekey_reconciliation(database_path :: String,
  removed_labels :: List<String>,
  index_blob :: Bytes,
  active_blob :: Bytes) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      delete_blobs(database, removed_labels, 0)?
      put_blob(database, "one-time-prekeys/v1", index_blob)?
      put_blob(database, "one-time-prekey-active/v1", active_blob)
    end)
end

fn store_prepared_sessions(database :: SqliteConn,
  prepared :: List<MobilePreparedSend>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(prepared) do
    Ok(nil)
  else
    let value = List.get(prepared, index)
    let stored = if value.new_session do
      insert_blob(database, value.session_label, value.session_blob)
    else
      put_blob(database, value.session_label, value.session_blob)
    end
    stored?
    store_prepared_sessions(database, prepared, index + 1)
  end
end

pub fn store_outbound(database_path :: String,
  prepared :: List<MobilePreparedSend>,
  removed_labels :: List<String>,
  session_index_blob :: Bytes,
  history_keys :: List<String>,
  history_blobs :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index_blob :: PreparedOutboxIndex) -> Result<(), String> do
  store_outbound_after_guard(database_path,
    prepared,
    removed_labels,
    session_index_blob,
    history_keys,
    history_blobs,
    outbox_labels,
    outbox_blobs,
    outbox_index_blob,
    fn(_database) -> Ok(nil) end)
end

pub fn store_outbound_after_guard(database_path :: String,
  prepared :: List<MobilePreparedSend>,
  removed_labels :: List<String>,
  session_index_blob :: Bytes,
  history_keys :: List<String>,
  history_blobs :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index_blob :: PreparedOutboxIndex,
  guard :: Fun(SqliteConn) -> Result<(), String>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      guard(database)?
      require_outbox_basis(database, outbox_index_blob.before)?
      store_prepared_sessions(database, prepared, 0)?
      put_blob(database, "sessions/v1", session_index_blob)?
      put_blobs(database, history_keys, history_blobs, 0)?
      put_blobs(database, outbox_labels, outbox_blobs, 0)?
      put_blob(database, "outbox/v1", outbox_index_blob.value)?
      delete_blobs(database, removed_labels, 0)
    end)
end

pub fn ensure_account_missing(database_path :: String) -> Result<(), String> do
  case load_blob(database_path, "profile/v1") do
    Ok(_) -> Err("account_already_exists")
    Err(error) -> if error == "local_state_not_found" do
      Ok(nil)
    else
      Err(error)
    end
  end
end

pub fn store_new_session(database_path :: String,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      insert_blob(database, label, blob)?
      put_blob(database, "sessions/v1", index_blob)
    end)
end

pub fn store_received_session(database_path :: String,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes,
  updated_labels :: List<String>,
  updated_blobs :: List<Bytes>,
  removed_labels :: List<String>,
  prekey_labels :: List<String>,
  prekey_blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      insert_blob(database, label, blob)?
      put_blob(database, "sessions/v1", index_blob)?
      put_blobs(database, updated_labels, updated_blobs, 0)?
      delete_blobs(database, removed_labels, 0)?
      put_blobs(database, prekey_labels, prekey_blobs, 0)
    end)
end

pub fn store_updated_session(database_path :: String,
  label :: String,
  blob :: Bytes) -> Result<(), String> do
  case Sqlite.open(database_path) do
    Err(_) -> Err("database_open_failed")
    Ok(database) -> case put_blob(database, label, blob) do
      Err(error) -> do
        Sqlite.close(database)
        Err(error)
      end
      Ok(_) -> do
        Sqlite.close(database)
        Ok(nil)
      end
    end
  end
end

pub fn store_updated_session_and_history(database_path :: String,
  session_key :: String,
  session_blob :: Bytes,
  history_keys :: List<String>,
  history_blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      put_blob(database, session_key, session_blob)?
      put_blobs(database, history_keys, history_blobs, 0)
    end)
end

pub fn store_envelope(request :: MobileStoreRequest) -> Bytes!String do
  let envelope = canonical_outer(request.envelope)?
  if Bytes.length(envelope.ciphertext) < 16 do
    Err("ciphertext_too_short")
  else
    ensure_schema(request.database_path)?
    case Sqlite.open(request.database_path) do
      Err(_) -> Err("database_open_failed")
      Ok(database) -> do
        let result = case blob_record_key(database, request.record_key) do
          Err(error)
          Ok(record_hash) -> case Sqlite.execute_values(database,
            "INSERT INTO encrypted_blobs (record_hash, ciphertext) VALUES (?, ?) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext",
            [Text(record_hash), Binary(envelope.ciphertext)]) do
            Err(_) -> Err("database_write_failed")
            Ok(_) -> Ok(Bytes.from_utf8(record_hash))
          end
        end
        Sqlite.close(database)
        result
      end
    end
  end
end

## The callback's `?` returns here, so rollback and close run for every outcome.

pub fn with_record_transaction(path :: String,
  operation :: Fun(SqliteConn) -> Result<(), String>) -> Result<(), String> do
  let database = case Sqlite.open(path) do
    Err(_) -> Err("database_open_failed")
    Ok(value)
  end?
  # Keyed address lookup reads catalog metadata. Acquire the writer lock first
  # so concurrent deferred readers cannot fail while upgrading to a writer.
  let started = case Sqlite.execute(database, "PRAGMA busy_timeout = 1000", []) do
    Err(error)
    Ok(_) -> Sqlite.execute(database, "BEGIN IMMEDIATE", [])
  end
  let result = case started do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case operation(database) do
      Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end

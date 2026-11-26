from Mobile.Codec import canonical_outer
from Mobile.Types import MobilePreparedSend, MobileStoreRequest
from Protocol.V1 import OuterEnvelope
from Storage.Blobs import blob_row_key, ensure_schema, load_blob
from Storage.Rows import (
  StorageRowKey,
  storage_connect,
  storage_delete,
  storage_delete_all,
  storage_insert,
  storage_insert_all,
  storage_label_row,
  storage_put,
  storage_put_all,
  storage_put_hash
)

##! Storage.Records implementation.

pub fn put_blobs(database :: SqliteConn,
  labels :: List<String>,
  blobs :: List<Bytes>,
  index :: Int) -> Result<(), String> do
  if List.length(labels) == List.length(blobs) && index >= List.length(labels) do
    Ok(nil)
  else
    storage_put_all(database, blob_row_key(database)?, labels, blobs, index)
  end
end

pub fn delete_blob(database :: SqliteConn, label :: String) -> Result<(), String> do
  storage_delete(database, blob_row_key(database)?, label)
end

pub fn delete_blobs(database :: SqliteConn,
  labels :: List<String>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(labels) do
    Ok(nil)
  else
    storage_delete_all(database, blob_row_key(database)?, labels, index)
  end
end

## A transaction whose writes share one read of the label key.

pub fn with_keyed_transaction(path :: String,
  operation :: Fun(SqliteConn, StorageRowKey) -> Result<(), String>) -> Result<(), String> do
  with_record_transaction(path, fn(database) do operation(database, blob_row_key(database)?) end)
end

pub fn store_linked_blobs(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_insert_all(database, key, labels, blobs, 0)?
      storage_delete_all(database,
        key,
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      let profiles = case Sqlite.query_values(database,
        "SELECT record_hash FROM encrypted_blobs WHERE record_hash = ?",
        [Text(storage_label_row(key, "profile/v1")?)]) do
        Err(_) -> Err("database_read_failed")
        Ok(rows)
      end?
      if List.length(profiles) > 0 do
        Err("account_already_exists")
      else
        delete_every_record(database)?
        storage_insert_all(database, key, labels, blobs, 0)
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
  with_keyed_transaction(database_path,
    fn(database, key) do storage_insert_all(database, key, labels, blobs, 0) end)
end

pub fn store_updated_blobs(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do storage_put_all(database, key, labels, blobs, 0) end)
end

pub fn store_record_changes(database_path :: String,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_put_all(database, key, labels, blobs, 0)?
      storage_delete_all(database, key, removed, 0)
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_delete_all(database, key, removed_labels, 0)?
      storage_insert_all(database, key, labels, blobs, 0)?
      storage_put(database, key, "one-time-prekeys/v1", index_blob)?
      storage_put(database, key, "one-time-prekey-active/v1", active_blob)?
      storage_put(database, key, "one-time-prekey-next-id/v1", next_id_blob)?
      if delete_legacy do
        storage_delete(database, key, "one-time-prekey/v1")
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_insert(database, key, secret_label, secret_blob)?
      storage_put(database, key, "last-resort-prekey/v1", record_blob)?
      storage_delete_all(database, key, removed_labels, 0)?
      if Bytes.length(retired_blob) == 0 do
        Ok(nil)
      else
        storage_put(database, key, "last-resort-retired/v1", retired_blob)
      end
    end)
end

pub fn store_prekey_reconciliation(database_path :: String,
  removed_labels :: List<String>,
  index_blob :: Bytes,
  active_blob :: Bytes) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_delete_all(database, key, removed_labels, 0)?
      storage_put(database, key, "one-time-prekeys/v1", index_blob)?
      storage_put(database, key, "one-time-prekey-active/v1", active_blob)
    end)
end

fn store_prepared_sessions(database :: SqliteConn,
  key :: StorageRowKey,
  prepared :: List<MobilePreparedSend>,
  index :: Int) -> Result<(), String> do
  if index >= List.length(prepared) do
    Ok(nil)
  else
    let value = List.get(prepared, index)
    let stored = if value.new_session do
      storage_insert(database, key, value.session_label, value.session_blob)
    else
      storage_put(database, key, value.session_label, value.session_blob)
    end
    stored?
    store_prepared_sessions(database, key, prepared, index + 1)
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
  outbox_index_blob :: Bytes) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      store_prepared_sessions(database, key, prepared, 0)?
      storage_put(database, key, "sessions/v1", session_index_blob)?
      storage_put_all(database, key, history_keys, history_blobs, 0)?
      storage_put_all(database, key, outbox_labels, outbox_blobs, 0)?
      storage_put(database, key, "outbox/v1", outbox_index_blob)?
      storage_delete_all(database, key, removed_labels, 0)
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_insert(database, key, label, blob)?
      storage_put(database, key, "sessions/v1", index_blob)
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_insert(database, key, label, blob)?
      storage_put(database, key, "sessions/v1", index_blob)?
      storage_put_all(database, key, updated_labels, updated_blobs, 0)?
      storage_delete_all(database, key, removed_labels, 0)?
      storage_put_all(database, key, prekey_labels, prekey_blobs, 0)
    end)
end

pub fn store_updated_session(database_path :: String,
  label :: String,
  blob :: Bytes) -> Result<(), String> do
  let database = storage_connect(database_path)?
  let result = case blob_row_key(database) do
    Err(error)
    Ok(key) -> storage_put(database, key, label, blob)
  end
  Sqlite.close(database)
  result
end

pub fn store_updated_session_and_history(database_path :: String,
  session_key :: String,
  session_blob :: Bytes,
  history_keys :: List<String>,
  history_blobs :: List<Bytes>) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_put(database, key, session_key, session_blob)?
      storage_put_all(database, key, history_keys, history_blobs, 0)
    end)
end

pub fn store_envelope(request :: MobileStoreRequest) -> Bytes!String do
  let envelope = canonical_outer(request.envelope)?
  if Bytes.length(envelope.ciphertext) < 16 do
    Err("ciphertext_too_short")
  else
    let database = storage_connect(request.database_path)?
    let stored = case blob_row_key(database) do
      Err(error)
      Ok(key) -> storage_put_hash(database,
        key,
        Crypto.sha256(request.record_key),
        envelope.ciphertext)
    end
    Sqlite.close(database)
    case stored do
      Err(_) -> Err("database_write_failed")
      Ok(row) -> Ok(Bytes.from_utf8(row))
    end
  end
end

## The callback's `?` returns here, so rollback and close run for every outcome.

pub fn with_record_transaction(path :: String,
  operation :: Fun(SqliteConn) -> Result<(), String>) -> Result<(), String> do
  let database = storage_connect(path)?
  let result = case Sqlite.begin(database) do
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

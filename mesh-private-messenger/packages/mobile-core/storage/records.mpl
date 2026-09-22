from Mobile.Codec import canonical_outer
from Mobile.Types import MobilePreparedSend, MobileStoreRequest
from Protocol.V1 import OuterEnvelope
from Storage.Blobs import ensure_schema, insert_blob, load_blob, put_blob

##! Storage.Records implementation.

fn insert_blobs(database :: SqliteConn,
labels :: List < String >,
blobs :: List < Bytes >,
index :: Int) -> Result <(), String > do
  if List.length(labels) != List.length(blobs) do
    Err("invalid_local_state")
  else
    if index >= List.length(labels) do
      Ok(nil)
    else
      insert_blob(database, List.get(labels, index), List.get(blobs, index)) ?
      insert_blobs(database, labels, blobs, index + 1)
    end
  end
end

pub fn put_blobs(database :: SqliteConn,
labels :: List < String >,
blobs :: List < Bytes >,
index :: Int) -> Result <(), String > do
  if List.length(labels) != List.length(blobs) do
    Err("invalid_local_state")
  else if index >= List.length(labels) do
    Ok(nil)
  else
    put_blob(database, List.get(labels, index), List.get(blobs, index)) ?
    put_blobs(database, labels, blobs, index + 1)
  end
end

pub fn delete_blob(database :: SqliteConn, label :: String) -> Result <(), String > do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.execute(database, "DELETE FROM encrypted_blobs WHERE record_hash = ?", [record_hash]) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> Ok(nil)
  end
end

pub fn delete_blobs(database :: SqliteConn, labels :: List < String >, index :: Int) -> Result <(), String > do
  if index >= List.length(labels) do
    Ok(nil)
  else
    delete_blob(database, List.get(labels, index)) ?
    delete_blobs(database, labels, index + 1)
  end
end

pub fn store_linked_blobs(database_path :: String,
labels :: List < String >,
blobs :: List < Bytes >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    insert_blobs(database, labels, blobs, 0) ?
    delete_blobs(database,
    ["pending-link-request/v1", "pending-device-signing-key/v1", "pending-device-identity-key/v1", "pending-post-quantum-prekey/v1"],
    0)
  end)
end

fn delete_every_record(database :: SqliteConn) -> Result <(), String > do
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
labels :: List < String >,
blobs :: List < Bytes >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    let profiles = case Sqlite.query_values(database,
    "SELECT record_hash FROM encrypted_blobs WHERE record_hash = ?",
    [Text(Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("profile/v1"))))]) do
      Err(_) -> Err("database_read_failed")
      Ok(rows) -> Ok(rows)
    end ?
    if List.length(profiles) > 0 do
      Err("account_already_exists")
    else
      delete_every_record(database) ?
      insert_blobs(database, labels, blobs, 0)
    end
  end)
end

## Everything this device stores for its account, in one transaction. VACUUM
## then rewrites the file so the records do not linger in its free pages; it
## needs spare disk, and the erase stands without it.

pub fn erase_local_state(database_path :: String) -> Result <(), String > do
  ensure_schema(database_path) ?
  with_record_transaction(database_path, fn (database) do delete_every_record(database) end) ?
  case Sqlite.open(database_path) do
    Err(_) -> Ok(nil)
    Ok(database) -> do
      let _ = Sqlite.execute(database, "VACUUM", [])
      Sqlite.close(database)
      Ok(nil)
    end
  end
end

pub fn store_blobs(database_path :: String, labels :: List < String >, blobs :: List < Bytes >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do insert_blobs(database, labels, blobs, 0) end)
end

pub fn store_updated_blobs(database_path :: String,
labels :: List < String >,
blobs :: List < Bytes >) -> Result <(), String > do
  with_record_transaction(database_path, fn (database) do put_blobs(database, labels, blobs, 0) end)
end

pub fn store_record_changes(database_path :: String,
labels :: List < String >,
blobs :: List < Bytes >,
removed :: List < String >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    put_blobs(database, labels, blobs, 0) ?
    delete_blobs(database, removed, 0)
  end)
end

pub fn store_prekey_batch(database_path :: String,
labels :: List < String >,
blobs :: List < Bytes >,
removed_labels :: List < String >,
index_blob :: Bytes,
active_blob :: Bytes,
next_id_blob :: Bytes,
delete_legacy :: Bool) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    delete_blobs(database, removed_labels, 0) ?
    insert_blobs(database, labels, blobs, 0) ?
    put_blob(database, "one-time-prekeys/v1", index_blob) ?
    put_blob(database, "one-time-prekey-active/v1", active_blob) ?
    put_blob(database, "one-time-prekey-next-id/v1", next_id_blob) ?
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
removed_labels :: List < String >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    insert_blob(database, secret_label, secret_blob) ?
    put_blob(database, "last-resort-prekey/v1", record_blob) ?
    delete_blobs(database, removed_labels, 0) ?
    if Bytes.length(retired_blob) == 0 do
      Ok(nil)
    else
      put_blob(database, "last-resort-retired/v1", retired_blob)
    end
  end)
end

pub fn store_prekey_reconciliation(database_path :: String,
removed_labels :: List < String >,
index_blob :: Bytes,
active_blob :: Bytes) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    delete_blobs(database, removed_labels, 0) ?
    put_blob(database, "one-time-prekeys/v1", index_blob) ?
    put_blob(database, "one-time-prekey-active/v1", active_blob)
  end)
end

fn store_prepared_sessions(database :: SqliteConn,
prepared :: List < MobilePreparedSend >,
index :: Int) -> Result <(), String > do
  if index >= List.length(prepared) do
    Ok(nil)
  else
    let value = List.get(prepared, index)
    let stored = if value.new_session do
      insert_blob(database, value.session_label, value.session_blob)
    else
      put_blob(database, value.session_label, value.session_blob)
    end
    stored ?
    store_prepared_sessions(database, prepared, index + 1)
  end
end

pub fn store_outbound(database_path :: String,
prepared :: List < MobilePreparedSend >,
removed_labels :: List < String >,
session_index_blob :: Bytes,
history_keys :: List < String >,
history_blobs :: List < Bytes >,
outbox_labels :: List < String >,
outbox_blobs :: List < Bytes >,
outbox_index_blob :: Bytes) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    store_prepared_sessions(database, prepared, 0) ?
    put_blob(database, "sessions/v1", session_index_blob) ?
    put_blobs(database, history_keys, history_blobs, 0) ?
    put_blobs(database, outbox_labels, outbox_blobs, 0) ?
    put_blob(database, "outbox/v1", outbox_index_blob) ?
    delete_blobs(database, removed_labels, 0)
  end)
end

pub fn ensure_account_missing(database_path :: String) -> Result <(), String > do
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
index_blob :: Bytes) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    insert_blob(database, label, blob) ?
    put_blob(database, "sessions/v1", index_blob)
  end)
end

pub fn store_received_session(database_path :: String,
label :: String,
blob :: Bytes,
index_blob :: Bytes,
updated_labels :: List < String >,
updated_blobs :: List < Bytes >,
removed_labels :: List < String >,
prekey_labels :: List < String >,
prekey_blobs :: List < Bytes >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    insert_blob(database, label, blob) ?
    put_blob(database, "sessions/v1", index_blob) ?
    put_blobs(database, updated_labels, updated_blobs, 0) ?
    delete_blobs(database, removed_labels, 0) ?
    put_blobs(database, prekey_labels, prekey_blobs, 0)
  end)
end

pub fn store_updated_session(database_path :: String, label :: String, blob :: Bytes) -> Result <(), String > do
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
history_keys :: List < String >,
history_blobs :: List < Bytes >) -> Result <(), String > do
  with_record_transaction(database_path,
  fn (database) do
    put_blob(database, session_key, session_blob) ?
    put_blobs(database, history_keys, history_blobs, 0)
  end)
end

pub fn store_envelope(request :: MobileStoreRequest) -> Bytes ! String do
  let envelope = canonical_outer(request.envelope) ?
  if Bytes.length(envelope.ciphertext) < 16 do
    Err("ciphertext_too_short")
  else
    ensure_schema(request.database_path) ?
    let record_hash = Bytes.to_hex(Crypto.sha256(request.record_key))
    case Sqlite.open(request.database_path) do
      Err(_) -> Err("database_open_failed")
      Ok(database) -> case Sqlite.execute_values(database,
      "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP",
      [Text(record_hash), Binary(envelope.ciphertext)]) do
        Err(_) -> do
          Sqlite.close(database)
          Err("database_write_failed")
        end
        Ok(_) -> do
          Sqlite.close(database)
          Ok(Bytes.from_utf8(record_hash))
        end
      end
    end
  end
end

## The callback's `?` returns here, so rollback and close run for every outcome.

fn with_record_transaction(path :: String, operation :: Fun(SqliteConn) -> Result <(), String >) -> Result <(), String > do
  let database = case Sqlite.open(path) do
    Err(_) -> Err("database_open_failed")
    Ok(value) -> Ok(value)
  end ?
  let result = case Sqlite.begin(database) do
    Err(_) -> Err("database_write_failed")
    Ok(_) -> case operation(database) do
      Err(error) -> Err(error)
      Ok(_) -> case Sqlite.commit(database) do
        Err(_) -> Err("database_write_failed")
        Ok(_) -> Ok(nil)
      end
    end
  end
  case result do
    Err(_) -> do
      let _ = Sqlite.rollback(database)
      nil
    end
    Ok(_) -> nil
  end
  Sqlite.close(database)
  result
end

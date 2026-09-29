from Storage.Blobs import insert_blob, put_blob
from Storage.Records import delete_blobs, put_blobs, with_record_transaction

##! Storage.Groups implementation.

pub fn store_new_group(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  index_blob :: Bytes,
  baseline_label :: String,
  baseline_blob :: Bytes) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      insert_blob(database, state_label, state_blob)?
      insert_blob(database, baseline_label, baseline_blob)?
      put_blob(database, "groups/v1", index_blob)
    end)
end

pub fn store_group_outbound(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index_blob :: Bytes,
  extra_labels :: List<String>,
  extra_blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      put_blob(database, state_label, state_blob)?
      put_blobs(database, outbox_labels, outbox_blobs, 0)?
      put_blob(database, "outbox/v1", outbox_index_blob)?
      put_blobs(database, extra_labels, extra_blobs, 0)
    end)
end

pub fn store_group_message_outbound(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  history_labels :: List<String>,
  history_blobs :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index_blob :: Bytes) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      put_blob(database, state_label, state_blob)?
      put_blobs(database, history_labels, history_blobs, 0)?
      put_blobs(database, outbox_labels, outbox_blobs, 0)?
      put_blob(database, "outbox/v1", outbox_index_blob)
    end)
end

pub fn store_group_state_history(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  history_labels :: List<String>,
  history_blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      put_blob(database, state_label, state_blob)?
      put_blobs(database, history_labels, history_blobs, 0)
    end)
end

pub fn store_group_join(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  index_blob :: Bytes,
  baseline_label :: String,
  baseline_blob :: Bytes,
  package_label :: String,
  init_label :: String,
  leaf_label :: String) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      insert_blob(database, state_label, state_blob)?
      insert_blob(database, baseline_label, baseline_blob)?
      put_blob(database, "groups/v1", index_blob)?
      delete_blobs(database, [package_label, init_label, leaf_label], 0)
    end)
end

from Storage.Records import with_keyed_transaction
from Storage.Rows import storage_delete_all, storage_insert, storage_put, storage_put_all

##! Storage.Groups implementation.

pub fn store_new_group(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  index_blob :: Bytes,
  baseline_label :: String,
  baseline_blob :: Bytes) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_insert(database, key, state_label, state_blob)?
      storage_insert(database, key, baseline_label, baseline_blob)?
      storage_put(database, key, "groups/v1", index_blob)
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_put(database, key, state_label, state_blob)?
      storage_put_all(database, key, outbox_labels, outbox_blobs, 0)?
      storage_put(database, key, "outbox/v1", outbox_index_blob)?
      storage_put_all(database, key, extra_labels, extra_blobs, 0)
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_put(database, key, state_label, state_blob)?
      storage_put_all(database, key, history_labels, history_blobs, 0)?
      storage_put_all(database, key, outbox_labels, outbox_blobs, 0)?
      storage_put(database, key, "outbox/v1", outbox_index_blob)
    end)
end

pub fn store_group_state_history(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  history_labels :: List<String>,
  history_blobs :: List<Bytes>) -> Result<(), String> do
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_put(database, key, state_label, state_blob)?
      storage_put_all(database, key, history_labels, history_blobs, 0)
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
  with_keyed_transaction(database_path,
    fn(database, key) do
      storage_insert(database, key, state_label, state_blob)?
      storage_insert(database, key, baseline_label, baseline_blob)?
      storage_put(database, key, "groups/v1", index_blob)?
      storage_delete_all(database, key, [package_label, init_label, leaf_label], 0)
    end)
end

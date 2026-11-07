from Storage.OutboxGuard import PreparedOutboxIndex, require_outbox_basis
from Storage.Blobs import insert_blob, put_blob
from Storage.Records import delete_blobs, put_blobs, with_record_transaction
from Storage.FanoutCommit import FanoutSnapshot, require_fanout_snapshot, commit_fanout_records

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
  outbox_index_blob :: PreparedOutboxIndex,
  extra_labels :: List<String>,
  extra_blobs :: List<Bytes>) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      require_outbox_basis(database, outbox_index_blob.before)?
      put_blob(database, state_label, state_blob)?
      put_blobs(database, outbox_labels, outbox_blobs, 0)?
      put_blob(database, "outbox/v1", outbox_index_blob.value)?
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
  outbox_index_blob :: PreparedOutboxIndex) -> Result<(), String> do
  with_record_transaction(database_path,
    fn(database) do
      require_outbox_basis(database, outbox_index_blob.before)?
      put_blob(database, state_label, state_blob)?
      put_blobs(database, history_labels, history_blobs, 0)?
      put_blobs(database, outbox_labels, outbox_blobs, 0)?
      put_blob(database, "outbox/v1", outbox_index_blob.value)
    end)
end

pub fn store_group_message_outbound_guarded(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  history_labels :: List<String>,
  history_blobs :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index_blob :: PreparedOutboxIndex,
  before :: FanoutSnapshot) -> Result<(), String> do
  let captured = List.flatten(for basis in before.bases do
    basis.labels
  end)
  if !List.contains(captured, state_label)
    || List.any(history_labels, fn(label) -> !List.contains(captured, label) end) do
    return Err("invalid_group_send_guard")
  end
  with_record_transaction(database_path,
    fn(database) do
      require_fanout_snapshot(database, before)?
      require_outbox_basis(database, outbox_index_blob.before)?
      put_blob(database, state_label, state_blob)?
      put_blobs(database, history_labels, history_blobs, 0)?
      put_blobs(database, outbox_labels, outbox_blobs, 0)?
      put_blob(database, "outbox/v1", outbox_index_blob.value)
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

pub fn store_group_state_history_guarded(database_path :: String,
  state_label :: String,
  state_blob :: Bytes,
  history_labels :: List<String>,
  history_blobs :: List<Bytes>,
  before :: FanoutSnapshot) -> Result<(), String> do
  let captured = List.flatten(for basis in before.bases do
    basis.labels
  end)
  if !List.contains(captured, "groups/v1")
    || !List.contains(captured, state_label)
    || List.any(history_labels, fn(label) -> !List.contains(captured, label) end) do
    return Err("invalid_group_receive_guard")
  end
  # The existing guarded commit validates every original source under the
  # writer lock, including history absence and the group index. A stale receive
  # cannot restore expired history or recreate state after a local forget.
  commit_fanout_records(database_path,
    before,
    [state_label] ++ history_labels,
    [state_blob] ++ history_blobs,
    [])
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

from Mobile.SessionPolicy import NativeSessionPolicy, require_current_session_policy
from Storage.AccountGuard import (
  AccountBasis,
  load_account_basis,
  require_account_basis,
  account_basis_current
)
from Storage.OutboxGuard import PreparedOutboxIndex
from Storage.Records import (
  store_outbound_after_guard,
  with_record_transaction,
  put_blobs,
  delete_blobs
)
from Mobile.Types import MobilePreparedSend

pub struct FanoutSnapshot do
  bases :: List<AccountBasis>
end

fn capture_chunks(path :: String,
  profile :: Bytes,
  labels :: List<String>,
  offset :: Int,
  bases :: List<AccountBasis>) -> FanoutSnapshot!String do
  if offset >= List.length(labels) && List.length(bases) > 0 do
    Ok(FanoutSnapshot { bases: bases })
  else
    let next = load_account_basis(path, List.take(List.drop(labels, offset), 64))?
    if !Bytes.secure_equals(next.profile, profile) do
      return Err("account_state_changed")
    end
    capture_chunks(path, profile, labels, offset + 64, List.append(bases, next))
  end
end

## Capture at most256 relevant source rows in bounded64-row read snapshots.
## All chunks share exact encrypted custody; crypto begins only after the whole
## captured source set is checked, and commit checks all chunks under one lock.
pub fn capture_fanout_snapshot(path :: String,
  profile :: Bytes,
  labels :: List<String>) -> FanoutSnapshot!String do
  if Bytes.length(profile) == 0 || List.length(labels) > 256 do
    return Err("invalid_fanout_snapshot")
  end
  for index in 0..List.length(labels) do
    if List.contains(List.take(labels, index), List.get(labels, index)) do
      return Err("invalid_fanout_snapshot")
    end
  end
  let value = capture_chunks(path, profile, labels, 0, [])?
  if !List.all(value.bases, fn(before) -> account_basis_current(path, before) end) do
    return Err("account_state_changed")
  end
  Ok(value)
end

## A new conversation can be selected after session-source discovery. Capture
## its exact history row (including absence) before reading that history, while
## retaining every earlier source used to prepare the outbound message.
pub fn capture_fanout_history(path :: String,
  before :: FanoutSnapshot,
  conversation_id :: Bytes) -> FanoutSnapshot!String do
  if Bytes.length(conversation_id) != 16
    || List.length(before.bases) == 0
    || List.length(before.bases) > 8 do
    return Err("invalid_fanout_snapshot")
  end
  let label = "history/v1/#{Bytes.to_hex(conversation_id)}"
  if List.any(before.bases, fn(basis) -> List.contains(basis.labels, label) end) do
    return Ok(before)
  end
  let history = capture_fanout_snapshot(path, List.head(before.bases).profile, [label])?
  let captured = combine_fanout_snapshots(before, history)?
  if !List.all(before.bases, fn(basis) -> account_basis_current(path, basis) end) do
    return Err("account_state_changed")
  end
  Ok(captured)
end

pub fn require_fanout_snapshot(database :: SqliteConn,
  before :: FanoutSnapshot) -> Result<(), String> do
  if List.length(before.bases) == 0 || List.length(before.bases) > 8 do
    return Err("invalid_fanout_snapshot")
  end
  let profile = List.head(before.bases).profile
  for basis in before.bases do
    if !Bytes.secure_equals(basis.profile, profile) do
      return Err("invalid_fanout_snapshot")
    end
    require_account_basis(database, basis)?
  end
  Ok(nil)
end

pub fn commit_fanout_snapshot(path :: String,
  before :: FanoutSnapshot,
  prepared :: List<MobilePreparedSend>,
  removed :: List<String>,
  sessions :: Bytes,
  history_labels :: List<String>,
  histories :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index :: PreparedOutboxIndex) -> Result<(), String> do
  commit_fanout_snapshot_with_policy(path,
    before,
    prepared,
    removed,
    sessions,
    history_labels,
    histories,
    outbox_labels,
    outbox_blobs,
    outbox_index,
    None)
end

pub fn commit_fanout_snapshot_at_policy(path :: String,
  before :: FanoutSnapshot,
  policy :: NativeSessionPolicy,
  prepared :: List<MobilePreparedSend>,
  removed :: List<String>,
  sessions :: Bytes,
  history_labels :: List<String>,
  histories :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index :: PreparedOutboxIndex) -> Result<(), String> do
  commit_fanout_snapshot_with_policy(path,
    before,
    prepared,
    removed,
    sessions,
    history_labels,
    histories,
    outbox_labels,
    outbox_blobs,
    outbox_index,
    Some(policy))
end

fn commit_fanout_snapshot_with_policy(path :: String,
  before :: FanoutSnapshot,
  prepared :: List<MobilePreparedSend>,
  removed :: List<String>,
  sessions :: Bytes,
  history_labels :: List<String>,
  histories :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index :: PreparedOutboxIndex,
  policy :: Option<NativeSessionPolicy>) -> Result<(), String> do
  let guarded = List.flatten(for basis in before.bases do
    basis.labels
  end)
  if List.any(history_labels,
    fn(label) -> String.starts_with(label, "history/v1/") && !List.contains(guarded, label) end) do
    return Err("invalid_fanout_history_commit")
  end
  store_outbound_after_guard(path,
    prepared,
    removed,
    sessions,
    history_labels,
    histories,
    outbox_labels,
    outbox_blobs,
    outbox_index,
    fn(database) do
      require_fanout_snapshot(database, before)?
      case policy do
        None -> Ok(nil)
        Some(value) -> require_current_session_policy(value)
      end
    end)
end

pub fn commit_fanout(path :: String,
  before :: AccountBasis,
  prepared :: List<MobilePreparedSend>,
  removed :: List<String>,
  sessions :: Bytes,
  history_labels :: List<String>,
  histories :: List<Bytes>,
  outbox_labels :: List<String>,
  outbox_blobs :: List<Bytes>,
  outbox_index :: PreparedOutboxIndex) -> Result<(), String> do
  commit_fanout_snapshot(path,
    FanoutSnapshot { bases: [before] },
    prepared,
    removed,
    sessions,
    history_labels,
    histories,
    outbox_labels,
    outbox_blobs,
    outbox_index)
end

## Prekey claim IDs and validated reservations are written only against the
## same source snapshot used to prepare them. Every changed row must have been
## captured, including absence, so racing callers cannot silently replace IDs.
pub fn commit_fanout_records(path :: String,
  before :: FanoutSnapshot,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> Result<(), String> do
  commit_fanout_records_with_policy(path, before, labels, blobs, removed, None)
end

pub fn commit_fanout_records_at_policy(path :: String,
  before :: FanoutSnapshot,
  policy :: NativeSessionPolicy,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>) -> Unit!String do
  commit_fanout_records_with_policy(path, before, labels, blobs, removed, Some(policy))
end

fn commit_fanout_records_with_policy(path :: String,
  before :: FanoutSnapshot,
  labels :: List<String>,
  blobs :: List<Bytes>,
  removed :: List<String>,
  policy :: Option<NativeSessionPolicy>) -> Result<(), String> do
  if List.length(labels) != List.length(blobs)
    || List.any(blobs, fn(value) -> Bytes.length(value) == 0 end) do
    return Err("invalid_fanout_commit")
  end
  let guarded = List.flatten(for basis in before.bases do
    basis.labels
  end)
  let changed = labels ++ removed
  for index in 0..List.length(changed) do
    let label = List.get(changed, index)
    if !List.contains(guarded, label)
      || List.contains(List.take(changed, index), label)
      || label == "profile/v1" do
      return Err("invalid_fanout_commit")
    end
  end
  with_record_transaction(path,
    fn(database) do
      require_fanout_snapshot(database, before)?
      case policy do
        None -> Ok(nil)
        Some(value) -> require_current_session_policy(value)
      end?
      put_blobs(database, labels, blobs, 0)?
      delete_blobs(database, removed, 0)
    end)
end

## Preserve an earlier group/action basis alongside the later ratchet basis.
## Both are checked in the same final transaction; capture cannot bless a stale
## prepared invitation by reading its replacement after crypto has begun.
pub fn combine_fanout_snapshots(first :: FanoutSnapshot,
  second :: FanoutSnapshot) -> FanoutSnapshot!String do
  if List.length(first.bases) == 0
    || List.length(second.bases) == 0
    || List.length(first.bases) + List.length(second.bases) > 8
    || !Bytes.secure_equals(List.head(first.bases).profile, List.head(second.bases).profile) do
    return Err("invalid_fanout_snapshot")
  end
  Ok(FanoutSnapshot { bases: first.bases ++ second.bases })
end

from Mobile.Expiry import message_unexpired
from Mobile.HistoryWire import decode_history, encode_history
from Mobile.Sessions import contains_session_id, decode_session_ids, parse_session_record
from Mobile.Types import MobileHistoryEntry
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.FanoutCommit import FanoutSnapshot, commit_fanout_records
from Storage.HistoryBlobs import open_history_blob, seal_history_blob
from Storage.Keys import local_context, open_local, platform_key

pub struct HistoryExpiryPlan do
  before :: FanoutSnapshot
  conversation_id :: Bytes
  labels :: List<String>
  blobs :: List<Bytes>
  removed :: List<String>
end

struct IndexedConversation do
  before :: AccountBasis
  conversation_id :: Bytes
end

fn indexed_sessions(basis :: AccountBasis, key :: borrow StorageKey) -> List<Bytes>!String do
  let blob = List.head(basis.records)
  if Bytes.length(blob) == 0 do
    Ok([])
  else
    decode_session_ids(open_local(blob, key, local_context("sessions/v1")?)?)
  end
end

fn retain_unexpired(entries :: List<MobileHistoryEntry>,
  now :: U64,
  index :: Int,
  visible :: List<MobileHistoryEntry>) -> List<MobileHistoryEntry>!String do
  if index >= List.length(entries) do
    Ok(visible)
  else
    let entry = List.get(entries, index)
    let next = if message_unexpired(entry.inner.client_timestamp, entry.inner.disappearing_seconds, now)? do
      List.append(visible, entry)
    else
      visible
    end
    retain_unexpired(entries, now, index + 1, next)
  end
end

pub fn unexpired_history(entries :: List<MobileHistoryEntry>,
  now :: U64) -> List<MobileHistoryEntry>!String do
  retain_unexpired(entries, now, 0, [])
end

fn indexed_conversation(path :: String,
  key :: borrow StorageKey,
  index_basis :: AccountBasis,
  session_id :: Bytes) -> IndexedConversation!String do
  let session_label = "session/v1/#{Bytes.to_hex(session_id)}"
  let session_basis = load_account_basis(path, [session_label])?
  if !Bytes.secure_equals(session_basis.profile, index_basis.profile) do
    return Err("account_state_changed")
  end
  let session = parse_session_record(open_local(List.head(session_basis.records),
    key,
    local_context(session_label)?)?)?
  Ok(IndexedConversation {
    before: session_basis,
    conversation_id: session.conversation_id
  })
end

fn prepare_indexed_history_expiry(path :: String,
  key :: borrow StorageKey,
  index_basis :: AccountBasis,
  conversation :: IndexedConversation,
  now :: U64) -> HistoryExpiryPlan!String do
  let label = "history/v1/#{Bytes.to_hex(conversation.conversation_id)}"
  let history_basis = load_account_basis(path, [label])?
  if !Bytes.secure_equals(history_basis.profile, index_basis.profile) do
    return Err("account_state_changed")
  end
  let plan = HistoryExpiryPlan {
    before: FanoutSnapshot { bases: [index_basis, conversation.before, history_basis] },
    conversation_id: conversation.conversation_id,
    labels: [],
    blobs: [],
    removed: []
  }
  let blob = List.head(history_basis.records)
  if Bytes.length(blob) == 0 do
    return Ok(plan)
  end
  let entries = decode_history(open_history_blob(blob, key, label)?)?
  let visible = unexpired_history(entries, now)?
  if List.length(visible) == List.length(entries) do
    Ok(plan)
  else if List.length(visible) == 0 do
    Ok(%{plan | removed: [label]})
  else
    let sealed = seal_history_blob(encode_history(visible)?, key, label)?
    Ok(%{plan | labels: [label], blobs: [sealed]})
  end
end

pub fn prepare_direct_history_expiry(path :: String,
  key :: borrow StorageKey,
  session_id :: Bytes,
  now :: U64) -> HistoryExpiryPlan!String do
  let index_basis = load_account_basis(path, ["sessions/v1"])?
  let ids = indexed_sessions(index_basis, key)?
  if !contains_session_id(ids, session_id, 0) do
    return Err("session_not_found")
  end
  prepare_indexed_history_expiry(path,
    key,
    index_basis,
    indexed_conversation(path, key, index_basis, session_id)?,
    now)
end

## Every source ciphertext, including the session index and account custody,
## is checked under the same write lock as the history update/removal.
pub fn commit_history_expiry(path :: String, plan :: HistoryExpiryPlan) -> Result<(), String> do
  if List.length(plan.labels) == 0 && List.length(plan.removed) == 0 do
    Ok(nil)
  else
    commit_fanout_records(path, plan.before, plan.labels, plan.blobs, plan.removed)
  end
end

fn expire_indexed_history(path :: String,
  key :: borrow StorageKey,
  index_basis :: AccountBasis,
  ids :: List<Bytes>,
  now :: U64,
  index :: Int,
  seen :: List<String>) -> Result<(), String> do
  if index >= List.length(ids) do
    Ok(nil)
  else
    let selected = indexed_conversation(path, key, index_basis, List.get(ids, index))?
    let conversation = Bytes.to_hex(selected.conversation_id)
    # Resolve each authenticated alias, but open and filter its shared history
    # only once. Keep the exact selected session basis in the eventual commit.
    let next = if !List.contains(seen, conversation) do
      let plan = prepare_indexed_history_expiry(path, key, index_basis, selected, now)?
      commit_history_expiry(path, plan)?
      List.append(seen, conversation)
    else
      seen
    end
    expire_indexed_history(path, key, index_basis, ids, now, index + 1, next)
  end
end

pub fn expire_direct_history(path :: String, now :: U64) -> Result<(), String> do
  let key = platform_key()?
  let index_basis = load_account_basis(path, ["sessions/v1"])?
  expire_indexed_history(path, key, index_basis, indexed_sessions(index_basis, key)?, now, 0, [])
end

from Mobile.SiblingMembership import require_sibling_observation
from Mobile.SessionPolicy import NativeSessionPolicy, require_current_session_policy
from Mobile.ReceiveSources import ReceiveSources, require_receive_writes, require_receive_sources
from Storage.AccountGuard import AccountBasis, load_account_basis
from Storage.Keys import one_time_prekey_label, open_local, local_context
from Storage.Records import store_received_session, with_record_transaction, put_blobs, delete_blobs
from Storage.AccountGuard import require_account_basis
from Storage.Blobs import insert_blob, put_blob
from Mobile.Sessions import (
  prepared_conversation_alias,
  decode_session_ids,
  seal_session_ids,
  contains_session_id
)
from Mobile.HeaderCapabilities import require_new_header_capacity
from Mobile.Types import MobileSyncPayload
from Transport.Packet import ClientProfile

## Capture before the initial receiver reads its index or prekey pools.
## The exact profile and source ciphertexts are the final admission authority.
pub fn capture_header_initial(path :: String,
  key :: borrow StorageKey,
  public_profile :: Bytes,
  prekey_id :: U64) -> AccountBasis!String do
  let before = load_account_basis(path,
    [
      "sessions/v1",
      "one-time-prekeys/v1",
      "one-time-prekey-active/v1",
      "last-resort-prekey/v1",
      "last-resort-retired/v1",
      "last-resort-replays/v1",
      one_time_prekey_label(prekey_id)
    ])?
  if !Bytes.secure_equals(open_local(before.profile, key, local_context("profile/v1")?)?,
    public_profile) do
    return Err("account_state_changed")
  end
  Ok(before)
end

pub fn commit_initial_admission(path :: String,
  before :: Option<AccountBasis>,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes,
  updated_labels :: List<String>,
  updated_blobs :: List<Bytes>,
  removed_labels :: List<String>,
  prekey_labels :: List<String>,
  prekey_blobs :: List<Bytes>) -> Result<(), String> do
  commit_initial_admission_with_sources(path,
    before,
    None,
    label,
    blob,
    index_blob,
    updated_labels,
    updated_blobs,
    removed_labels,
    prekey_labels,
    prekey_blobs)
end

pub fn commit_initial_admission_with_sources(path :: String,
  before :: Option<AccountBasis>,
  sources :: Option<ReceiveSources>,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes,
  updated_labels :: List<String>,
  updated_blobs :: List<Bytes>,
  removed_labels :: List<String>,
  prekey_labels :: List<String>,
  prekey_blobs :: List<Bytes>) -> Result<(), String> do
  commit_initial_admission_policy(path,
    before,
    sources,
    label,
    blob,
    index_blob,
    updated_labels,
    updated_blobs,
    removed_labels,
    prekey_labels,
    prekey_blobs,
    None,
    None)
end

pub fn commit_initial_admission_at_policy(path :: String,
  before :: Option<AccountBasis>,
  sources :: Option<ReceiveSources>,
  policy :: NativeSessionPolicy,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes,
  updated_labels :: List<String>,
  updated_blobs :: List<Bytes>,
  removed_labels :: List<String>,
  prekey_labels :: List<String>,
  prekey_blobs :: List<Bytes>) -> Result<(), String> do
  commit_initial_admission_at_sibling(path,
    before,
    sources,
    policy,
    label,
    blob,
    index_blob,
    updated_labels,
    updated_blobs,
    removed_labels,
    prekey_labels,
    prekey_blobs,
    None)
end

pub fn commit_initial_admission_at_sibling(path :: String,
  before :: Option<AccountBasis>,
  sources :: Option<ReceiveSources>,
  policy :: NativeSessionPolicy,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes,
  updated_labels :: List<String>,
  updated_blobs :: List<Bytes>,
  removed_labels :: List<String>,
  prekey_labels :: List<String>,
  prekey_blobs :: List<Bytes>,
  fresh_through :: Option<U64>) -> Result<(), String> do
  if Option.is_none(before) || Option.is_none(sources) do
    return Err("invalid_receive_commit")
  end
  commit_initial_admission_policy(path,
    before,
    sources,
    label,
    blob,
    index_blob,
    updated_labels,
    updated_blobs,
    removed_labels,
    prekey_labels,
    prekey_blobs,
    Some(policy),
    fresh_through)
end

fn commit_initial_admission_policy(path :: String,
  before :: Option<AccountBasis>,
  sources :: Option<ReceiveSources>,
  label :: String,
  blob :: Bytes,
  index_blob :: Bytes,
  updated_labels :: List<String>,
  updated_blobs :: List<Bytes>,
  removed_labels :: List<String>,
  prekey_labels :: List<String>,
  prekey_blobs :: List<Bytes>,
  policy :: Option<NativeSessionPolicy>,
  fresh_through :: Option<U64>) -> Result<(), String> do
  case before do
    None -> do
      if Option.is_some(sources)
        || List.any(updated_labels,
          fn(value) -> String.starts_with(value, "session/v1/")
            || String.starts_with(value, "view-once/v2/")
            || String.starts_with(value, "view-once/id/v2/")
            || String.starts_with(value, "view-once/message/v2/") end) do
        return Err("invalid_receive_commit")
      end
      store_received_session(path,
        label,
        blob,
        index_blob,
        updated_labels,
        updated_blobs,
        removed_labels,
        prekey_labels,
        prekey_blobs)
    end
    Some(basis) -> do
      if !List.contains(basis.labels, "sessions/v1")
        || List.any(updated_labels,
          fn(value) -> String.starts_with(value, "history/v1/")
            && !List.contains(basis.labels, value) end) do
        return Err("invalid_header_initial_commit")
      end
      require_receive_writes(basis,
        sources,
        updated_labels
          ++ List.filter(prekey_labels,
            fn(label) -> String.starts_with(label, "sibling-session/v1/") end))?
      with_record_transaction(path,
        fn(database) do
          require_receive_sources(database, basis, sources)?
          case policy do
            None -> Ok(nil)
            Some(value) -> require_current_session_policy(value)
          end?
          let observation = case policy do
            None
            Some(value) -> case fresh_through do
              None
              Some(deadline) -> Some((value, deadline))
            end
          end
          require_sibling_observation(observation)?
          insert_blob(database, label, blob)?
          put_blob(database, "sessions/v1", index_blob)?
          put_blobs(database, updated_labels, updated_blobs, 0)?
          delete_blobs(database, removed_labels, 0)?
          put_blobs(database, prekey_labels, prekey_blobs, 0)
        end)
    end
  end
end

## A self-sync first message may create a conversation alias too. Prepare
## both IDs in one index so no pre-commit alias write defeats the source fence. Legacy readers retain their existing unbounded admission.
pub fn prepared_header_initial_alias(path :: String,
  key :: borrow StorageKey,
  local :: ClientProfile,
  sync :: MobileSyncPayload,
  ids :: List<Bytes>,
  session_id :: Bytes,
  headers :: Bool) -> Result<(Bytes, Bytes, List<String>, List<Bytes>), String> do
  let (conversation, labels, blobs) = prepared_conversation_alias(path, key, local, sync, ids)?
  if contains_session_id(ids, session_id, 0) do
    return Err("invalid_header_initial_commit")
  end
  if List.length(labels) == 0 && List.length(blobs) == 0 do
    if headers do
      require_new_header_capacity(List.length(ids), 1)?
    end
    return Ok((conversation, seal_session_ids(List.append(ids, session_id), key)?, [], []))
  end
  if List.length(labels) != 2 || List.length(blobs) != 2 || List.get(labels, 1) != "sessions/v1" do
    return Err("invalid_header_initial_commit")
  end
  let added = decode_session_ids(open_local(List.get(blobs, 1),
    key,
    local_context("sessions/v1")?)?)?
  if List.length(added) != List.length(ids) + 1
    || !List.all(for index in 0..List.length(ids) do
        Bytes.secure_equals(List.get(ids, index), List.get(added, index))
      end,
      fn(value) -> value end)
    || contains_session_id(ids, List.last(added), 0)
    || Bytes.secure_equals(List.last(added), session_id)
    || List.head(labels) != "session/v1/#{Bytes.to_hex(List.last(added))}" do
    return Err("invalid_header_initial_commit")
  end
  if headers do
    require_new_header_capacity(List.length(ids), 2)?
  end
  Ok((conversation,
    seal_session_ids(List.append(added, session_id), key)?,
    [List.head(labels)],
    [List.head(blobs)]))
end

## Extend an immutable HE source basis before reading its history. A coherent
## snapshot may add the row (including absence), but may never bless changed
## profile/index/prekey/ratchet/cursor sources from earlier cryptographic work.
pub fn capture_header_history(path :: String,
  before :: Option<AccountBasis>,
  conversation_id :: Bytes) -> Option<AccountBasis>!String do
  if Bytes.length(conversation_id) != 16 do
    return Err("invalid_header_receive_basis")
  end
  capture_header_record(path, before, "history/v1/#{Bytes.to_hex(conversation_id)}")
end

## Extend the original transaction authority, retaining the first observation
## of every prior source while capturing this exact row, including absence.
pub fn capture_header_record(path :: String,
  before :: Option<AccountBasis>,
  label :: String) -> Option<AccountBasis>!String do
  case before do
    None -> Ok(None)
    Some(basis) -> do
      if String.length(label) == 0 || List.length(basis.labels) != List.length(basis.records) do
        return Err("invalid_header_receive_basis")
      end
      if List.contains(basis.labels, label) do
        return Ok(Some(basis))
      end
      let captured = load_account_basis(path, basis.labels ++ [label])?
      if !Bytes.secure_equals(captured.profile, basis.profile)
        || !List.all(for index in 0..List.length(basis.records) do
            Bytes.secure_equals(List.get(basis.records, index), List.get(captured.records, index))
          end,
          fn(value) -> value end) do
        return Err("account_state_changed")
      end
      Ok(Some(AccountBasis {
        profile: basis.profile,
        labels: basis.labels ++ [label],
        records: basis.records ++ [List.last(captured.records)]
      }))
    end
  end
end

## Legacy wire selection uses a clear SID; capture its source before opening
## that row. This changes concurrency only, not reader formats or admission.
pub fn capture_legacy_receive(path :: String,
  key :: borrow StorageKey,
  public_profile :: Bytes,
  session_id :: Bytes) -> AccountBasis!String do
  if Bytes.length(session_id) != 32 do
    return Err("invalid_ratchet_message")
  end
  let before = load_account_basis(path, ["sessions/v1", "session/v1/#{Bytes.to_hex(session_id)}"])?
  if !Bytes.secure_equals(open_local(before.profile, key, local_context("profile/v1")?)?,
    public_profile) do
    return Err("account_state_changed")
  end
  Ok(before)
end

pub fn commit_legacy_receive(path :: String,
  before :: AccountBasis,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  commit_legacy_receive_with_sources(path, before, None, labels, blobs)
end

pub fn commit_legacy_receive_with_sources(path :: String,
  before :: AccountBasis,
  sources :: Option<ReceiveSources>,
  labels :: List<String>,
  blobs :: List<Bytes>) -> Result<(), String> do
  commit_legacy_receive_with_observation(path, before, sources, labels, blobs, None)
end

pub fn commit_legacy_receive_with_observation(path :: String,
  before :: AccountBasis,
  sources :: Option<ReceiveSources>,
  labels :: List<String>,
  blobs :: List<Bytes>,
  observation :: Option<(NativeSessionPolicy, U64)>) -> Result<(), String> do
  if List.length(labels) != List.length(blobs)
    || List.any(blobs, fn(value) -> Bytes.length(value) == 0 end)
    || List.any(labels,
      fn(value) -> String.starts_with(value, "history/v1/")
        && !List.contains(before.labels, value) end) do
    return Err("invalid_receive_commit")
  end
  require_receive_writes(before, sources, labels)?
  with_record_transaction(path,
    fn(database) do
      require_receive_sources(database, before, sources)?
      require_sibling_observation(observation)?
      put_blobs(database, labels, blobs, 0)
    end)
end

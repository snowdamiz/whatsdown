from Mobile.ContactAddress import rotated_contact_address_writes
from Mobile.Sessions import (
  decode_session_ids,
  parse_session_record,
  preferred_session,
  updated_session_record
)
from Mobile.Types import MobileLoadedSession, MobileSessionRecord
from Storage.AccountGuard import AccountBasis, load_account_basis, require_account_basis
from Storage.Keys import local_context, open_local, seal_local
from Storage.Records import with_record_transaction, put_blobs

pub struct ConversationPolicyPlan do
  before :: List<AccountBasis>
  labels :: List<String>
  blobs :: List<Bytes>
end

struct PolicySources do
  before :: List<AccountBasis>
  peers :: List<MobileLoadedSession>
end

fn updated_policy(record :: MobileSessionRecord,
  action :: Int,
  value :: Int) -> MobileSessionRecord!String do
  if action == 1 do
    Ok(%{record | request_state: 1})
  else if action == 2 do
    Ok(%{record | blocked: true})
  else if action == 3 do
    Ok(%{record | blocked: false})
  else if action == 4 && Bytes.length(record.safety_number) == 64 do
    Ok(%{record | verified: true, key_changed: false})
  else if action == 5 && value >= 0 && value <= 2592000 do
    Ok(%{record | disappearing_seconds: value})
  else
    Err("invalid_conversation_policy")
  end
end

# Each chunk is bounded by AccountBasis, while legacy indexes retain their
# existing capacity. Parse the captured ciphertext itself; rereading mutable
# rows after capture could authorize a rewrite from another ratchet generation.
fn capture_sources(path :: String,
  key :: borrow StorageKey,
  index_basis :: AccountBasis,
  ids :: List<Bytes>,
  peer_id :: Bytes,
  offset :: Int,
  before :: List<AccountBasis>,
  peers :: List<MobileLoadedSession>) -> PolicySources!String do
  if offset >= List.length(ids) do
    return Ok(PolicySources { before: before, peers: peers })
  end
  let chunk = List.take(List.drop(ids, offset), 64)
  let labels = for id in chunk do
    "session/v1/#{Bytes.to_hex(id)}"
  end
  let captured = load_account_basis(path, labels)?
  if !Bytes.secure_equals(captured.profile, index_basis.profile) do
    return Err("account_state_changed")
  end
  let loaded = for index in 0..List.length(chunk) do
    let label = List.get(labels, index)
    MobileLoadedSession {
      session_id: List.get(chunk, index),
      label: label,
      record: parse_session_record(open_local(List.get(captured.records, index),
        key,
        local_context(label)?)?)?
    }
  end
  capture_sources(path,
    key,
    index_basis,
    ids,
    peer_id,
    offset + 64,
    List.append(before, captured),
    peers
      ++ List.filter(loaded,
        fn(value) -> Bytes.secure_equals(value.record.peer_account_id, peer_id) end))
end

fn select_preferred(peers :: List<MobileLoadedSession>, index :: Int) -> MobileLoadedSession do
  let current = List.get(peers, index)
  if index + 1 >= List.length(peers) do
    current
  else
    preferred_session(current, select_preferred(peers, index + 1))
  end
end

pub fn prepare_conversation_policy(path :: String,
  key :: borrow StorageKey,
  peer_id :: Bytes,
  action :: Int,
  value :: Int) -> ConversationPolicyPlan!String do
  let index_basis = load_account_basis(path,
    if action == 2 do
      ["sessions/v1", "contact-address-pending/v1"]
    else
      ["sessions/v1"]
    end)?
  let encoded_index = List.head(index_basis.records)
  if Bytes.length(encoded_index) == 0 do
    return Err("session_not_found")
  end
  let ids = decode_session_ids(open_local(encoded_index, key, local_context("sessions/v1")?)?)?
  let sources = capture_sources(path, key, index_basis, ids, peer_id, 0, [index_basis], [])?
  if List.length(sources.peers) == 0 do
    return Err("session_not_found")
  end
  let preferred = select_preferred(sources.peers, 0)
  if action == 4 && Bytes.length(preferred.record.safety_number) != 64 do
    return Err("safety_number_unavailable")
  end
  let labels = for loaded in sources.peers do
    loaded.label
  end
  let blobs = for loaded in sources.peers do
    let record = if action == 4
      && !Bytes.secure_equals(loaded.record.safety_number, preferred.record.safety_number) do
      Ok(%{loaded.record | verified: false, key_changed: true})
    else
      updated_policy(loaded.record, action, value)
    end?
    seal_local(updated_session_record(record.snapshot, record)?, key, local_context(loaded.label)?)?
  end
  # The pending address is captured too: a stale block cannot overwrite a newer
  # rotation already prepared by another local action.
  let (rotation_labels, rotation_blobs) = if action == 2 do
    rotated_contact_address_writes(key)
  else
    Ok(([], []))
  end?
  Ok(ConversationPolicyPlan {
    before: sources.before,
    labels: labels ++ rotation_labels,
    blobs: blobs ++ rotation_blobs
  })
end

pub fn commit_conversation_policy(path :: String,
  prepared :: ConversationPolicyPlan) -> Result<(), String> do
  if List.length(prepared.before) == 0
    || List.length(prepared.labels) != List.length(prepared.blobs)
    || List.any(prepared.blobs, fn(value) -> Bytes.length(value) == 0 end) do
    return Err("invalid_conversation_policy_commit")
  end
  let profile = List.head(prepared.before).profile
  let guarded = List.flatten(for basis in prepared.before do
    basis.labels
  end)
  if !List.contains(guarded, "sessions/v1") do
    return Err("invalid_conversation_policy_commit")
  end
  for index in 0..List.length(prepared.labels) do
    let label = List.get(prepared.labels, index)
    if !List.contains(guarded, label)
      || List.contains(List.take(prepared.labels, index), label)
      || label == "profile/v1" do
      return Err("invalid_conversation_policy_commit")
    end
  end
  with_record_transaction(path,
    fn(database) do
      for basis in prepared.before do
        if !Bytes.secure_equals(basis.profile, profile) do
          return Err("invalid_conversation_policy_commit")
        end
        require_account_basis(database, basis)?
      end
      put_blobs(database, prepared.labels, prepared.blobs, 0)
    end)
end

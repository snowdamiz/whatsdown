from Mobile.Sessions import (
  decode_session_ids,
  parse_session_record,
  preferred_session,
  updated_session_record
)
from Mobile.Types import MobileLoadedSession
from Storage.AccountGuard import load_account_basis
from Storage.FanoutCommit import (
  FanoutSnapshot,
  capture_fanout_snapshot,
  combine_fanout_snapshots,
  commit_fanout_records
)
from Storage.Keys import local_context, open_local, seal_local

pub struct SafetyVerificationPlan do
  before :: FanoutSnapshot
  labels :: List<String>
  blobs :: List<Bytes>
end

pub fn canonical_safety_number(value :: Bytes) -> Bool do
  if Bytes.length(value) != 64 do
    return false
  end
  for index in 0..64 do
    let byte = case Bytes.get(value, index) do
      Err(_) -> return false
      Ok(value) -> value
    end
    if !(byte >= 48 && byte <= 57) && !(byte >= 97 && byte <= 102) do
      return false
    end
  end
  true
end

fn select_preferred(values :: List<MobileLoadedSession>, index :: Int) -> MobileLoadedSession do
  let current = List.get(values, index)
  if index + 1 >= List.length(values) do
    current
  else
    preferred_session(current, select_preferred(values, index + 1))
  end
end

## Verify against the exact ciphertext snapshot that supplies the displayed
## identity. The original index is guarded too: a new session cannot appear
## between comparison and commit and inherit verification for another key.
pub fn prepare_safety_verification(path :: String,
  key :: borrow StorageKey,
  peer_id :: Bytes,
  expected :: Bytes) -> SafetyVerificationPlan!String do
  if !canonical_safety_number(expected) || Bytes.length(peer_id) != 32 do
    return Err("invalid_safety_code")
  end
  let index_basis = load_account_basis(path, ["sessions/v1"])?
  let encoded_index = List.head(index_basis.records)
  if Bytes.length(encoded_index) == 0 do
    return Err("session_not_found")
  end
  let ids = decode_session_ids(open_local(encoded_index, key, local_context("sessions/v1")?)?)?
  let labels = for id in ids do
    "session/v1/#{Bytes.to_hex(id)}"
  end
  let captured = capture_fanout_snapshot(path, index_basis.profile, labels)?
  let records = List.flatten(for basis in captured.bases do
    basis.records
  end)
  let loaded = for index in 0..List.length(ids) do
    let label = List.get(labels, index)
    MobileLoadedSession {
      session_id: List.get(ids, index),
      label: label,
      record: parse_session_record(open_local(List.get(records, index),
        key,
        local_context(label)?)?)?
    }
  end
  let peer_sessions = List.filter(loaded,
    fn(value) -> Bytes.secure_equals(value.record.peer_account_id, peer_id) end)
  if List.length(peer_sessions) == 0 do
    return Err("session_not_found")
  end
  let preferred = select_preferred(peer_sessions, 0)
  if !Bytes.secure_equals(expected, preferred.record.safety_number) do
    return Err("safety_number_mismatch")
  end
  let blobs = for session in peer_sessions do
    let matches = Bytes.secure_equals(expected, session.record.safety_number)
    let record = %{session.record | verified: matches, key_changed: !matches}
    seal_local(updated_session_record(record.snapshot, record)?,
      key,
      local_context(session.label)?)?
  end
  Ok(SafetyVerificationPlan {
    before: combine_fanout_snapshots(FanoutSnapshot { bases: [index_basis] }, captured)?,
    labels: for session in peer_sessions do
      session.label
    end,
    blobs: blobs
  })
end

pub fn commit_safety_verification(path :: String,
  prepared :: SafetyVerificationPlan) -> Result<(), String> do
  case commit_fanout_records(path, prepared.before, prepared.labels, prepared.blobs, []) do
    Err("account_state_changed") -> Err("safety_verification_changed")
    other -> other
  end
end

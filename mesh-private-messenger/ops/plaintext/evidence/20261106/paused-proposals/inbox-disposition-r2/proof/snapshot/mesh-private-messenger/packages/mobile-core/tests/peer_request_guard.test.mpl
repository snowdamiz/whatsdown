from Mobile.HeaderAdmission import capture_legacy_receive, commit_legacy_receive
from Mobile.History import accepted_request_writes, update_conversation
from Mobile.Sessions import load_session_record, seal_session_ids, updated_session_record
from Mobile.Types import MobilePolicyRequest, MobileSessionRecord
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.Support import database_path

fn bytes(value :: String) -> Bytes do
  Bytes.from_utf8(value)
end

fn id(value :: Int, size :: Int) -> Bytes!String do
  case Bytes.repeat(value, size) do
    Err(_) -> Err("fixture bytes")
    Ok(value)
  end
end

fn record(peer :: Bytes, conversation :: Bytes) -> MobileSessionRecord!String do
  Ok(MobileSessionRecord {
    snapshot: Bytes.empty(),
    local_account_id: id(1, 32)?,
    local_device_id: id(2, 16)?,
    peer_account_id: peer,
    peer_device_id: id(4, 16)?,
    peer_username: "peer",
    peer_mailbox: id(5, 32)?,
    conversation_id: conversation,
    request_state: 0,
    blocked: false,
    verified: false,
    key_changed: false,
    disappearing_seconds: 0,
    strongest_suite: 1,
    safety_number: id(97, 64)?,
    peer_transport_key: Bytes.empty()
  })
end

# Exercise the real accepted-request serializer and a competing real policy
# update. The selected self-sync ratchet is deliberately not the peer row that
# the accepted-request helper also rewrites.
fn stale_acceptance() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let path = database_path("linked-device-acceptance-peer-guard")?
  ensure_schema(path)?
  let key = platform_key()?
  let profile = bytes("public profile")
  let self_id = id(11, 32)?
  let peer_id = id(12, 32)?
  let self_label = "session/v1/#{Bytes.to_hex(self_id)}"
  let peer_label = "session/v1/#{Bytes.to_hex(peer_id)}"
  let peer_account = id(3, 32)?
  let self_record = record(id(1, 32)?, id(6, 16)?)?
  let peer_record = record(peer_account, id(7, 16)?)?
  for action in [2, 5] do
    store_updated_blobs(path,
      ["profile/v1", "sessions/v1", self_label, peer_label],
      [
        seal_local(profile, key, local_context("profile/v1")?)?,
        seal_session_ids([self_id, peer_id], key)?,
        seal_local(updated_session_record(self_record.snapshot, self_record)?,
          key,
          local_context(self_label)?)?,
        seal_local(updated_session_record(peer_record.snapshot, peer_record)?,
          key,
          local_context(peer_label)?)?
      ])?
    let before = capture_legacy_receive(path, key, profile, self_id)?
    let (labels, blobs) = accepted_request_writes(path, key, peer_account, [self_id, peer_id])?
    assert(List.length(labels) == 1 && List.head(labels) == peer_label)
    let source_self = load_blob(path, self_label)?
    update_conversation(MobilePolicyRequest {
      database_path: path,
      peer_profile: peer_account,
      action: action,
      value: 60,
      expected_safety: Bytes.empty()
    })?
    let newer_peer = load_blob(path, peer_label)?
    let updated = load_session_record(path, key, peer_id)?
    assert(if action == 2 do
      updated.record.blocked
    else
      updated.record.disappearing_seconds == 60
    end)
    let result = commit_legacy_receive(path,
      before,
      [self_label] ++ labels,
      [bytes("next self ratchet")] ++ blobs)
    assert(Result.is_err(result))
    assert(Bytes.secure_equals(load_blob(path, peer_label)?, newer_peer))
    assert(Bytes.secure_equals(load_blob(path, self_label)?, source_self))
  end
  erase_local_state(path)
end

test("linked-device acceptance cannot overwrite a newer peer block or expiry policy") do
  case stale_acceptance() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Mobile.ReceiveSources import capture_receive_sources
from Mobile.History import accepted_request_writes_from_sources
from Mobile.HeaderAdmission import commit_legacy_receive_with_sources
from Mobile.Messages import (
  start_conversation,
  receive_initial_message,
  send_message,
  receive_message
)
from Mobile.Sessions import (
  load_session_ids,
  load_session_record,
  seal_session_ids,
  updated_session_record
)
from Mobile.Profile import load_profile
from Mobile.Types import MobileStartRequest, MobileReceiveRequest
from Storage.AccountGuard import load_account_basis
from Storage.Keys import platform_key, seal_local, local_context
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = group_account_fixture()?
  let signed = signed_transparency_view([
    leaf_hash(fixture.alice_set)?,
    leaf_hash(fixture.bob_set)?
  ])?
  for path in [fixture.alice_path, fixture.bob_path] do
    assert(install_signed_transparency(path, signed, fixture.alice_set)?)
    assert(install_signed_transparency(path, signed, fixture.bob_set)?)
  end
  let bob_profile = load_profile(fixture.bob_path)?
  let bob = decode_client_profile(bob_profile)?
  let hello = start_conversation(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("real first HE"),
    attachment: Bytes.empty()
  })?
  assert(Bytes.secure_equals(receive_initial_message(MobileReceiveRequest {
      database_path: fixture.bob_path,
      outer: hello
    })?,
    Bytes.from_utf8("real first HE")))
  let key = platform_key()?
  let ids = load_session_ids(fixture.bob_path, key)?
  assert(List.length(ids) == 1)
  let peer_id = List.head(ids)
  let peer = load_session_record(fixture.bob_path, key, peer_id)?
  assert(peer.record.request_state == 0)
  let self_id = Crypto.sha256(Bytes.from_utf8("selected self source"))
  let self_label = "session/v1/#{Bytes.to_hex(self_id)}"
  # This independent selected-source row is an opaque boundary fixture. The
  # peer row it must not overwrite is the real ratchet created above.
  let self_record = %{peer.record | peer_account_id: bob.account_id, snapshot: Bytes.empty()}
  let own = seal_local(updated_session_record(Bytes.empty(), self_record)?,
    key,
    local_context(self_label)?)?
  let all_ids = [self_id] ++ ids
  store_updated_blobs(fixture.bob_path,
    [self_label, "sessions/v1"],
    [own, seal_session_ids(all_ids, key)?])?
  let before = load_account_basis(fixture.bob_path, ["sessions/v1", self_label])?
  let sources = capture_receive_sources(fixture.bob_path,
    key,
    before,
    all_ids,
    peer.record.peer_account_id)?
  let (labels, blobs) = accepted_request_writes_from_sources(key,
    peer.record.peer_account_id,
    sources)?
  assert(List.length(labels) == 1 && List.head(labels) == peer.label)
  let next = send_message(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("genuine concurrent ratchet advance"),
    attachment: Bytes.empty()
  })?
  assert(Bytes.secure_equals(receive_message(MobileReceiveRequest {
      database_path: fixture.bob_path,
      outer: next
    })?,
    Bytes.from_utf8("genuine concurrent ratchet advance")))
  let winner = load_blob(fixture.bob_path, peer.label)?
  let advanced = load_session_record(fixture.bob_path, key, peer_id)?
  assert(advanced.record.request_state == 0)
  assert(!Bytes.secure_equals(advanced.record.snapshot, peer.record.snapshot))
  assert(case commit_legacy_receive_with_sources(fixture.bob_path,
    before,
    Some(sources),
    [self_label] ++ labels,
    [own] ++ blobs) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, peer.label)?, winner))
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, self_label)?, own))
  # A fresh preparation accepts the request while preserving the exact new
  # authenticated ratchet snapshot, including its DH/header-key generation.
  let fresh = capture_receive_sources(fixture.bob_path,
    key,
    before,
    all_ids,
    peer.record.peer_account_id)?
  let (labels, blobs) = accepted_request_writes_from_sources(key,
    peer.record.peer_account_id,
    fresh)?
  commit_legacy_receive_with_sources(fixture.bob_path,
    before,
    Some(fresh),
    [self_label] ++ labels,
    [own] ++ blobs)?
  let accepted = load_session_record(fixture.bob_path, key, peer_id)?
  assert(accepted.record.request_state == 1)
  assert(Bytes.secure_equals(accepted.record.snapshot, advanced.record.snapshot))
  erase_local_state(fixture.alice_path)?
  erase_local_state(fixture.bob_path)?
  Ok(true)
end

test("self-sync acceptance preserves a genuinely advanced HE peer ratchet and fresh retry keeps its exact snapshot") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

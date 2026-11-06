from Mobile.ReceiveSources import (
  capture_receive_sessions,
  receive_captured_peer,
  receive_captured_strongest,
  require_receive_sources
)
from Mobile.HeaderAdmission import capture_header_initial, commit_initial_admission_with_sources
from Mobile.Messages import start_conversation, receive_initial_message
from Mobile.History import update_conversation
from Mobile.Sessions import load_session_ids
from Mobile.Profile import load_profile
from Mobile.Types import MobileStartRequest, MobileReceiveRequest, MobilePolicyRequest
from Mobile.Codec import mobile_append
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs, with_record_transaction, erase_local_state
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view
from Transparency.Merkle import leaf_hash
from Transport.Packet import decode_client_profile

fn assert_received_fixture(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic initial message delivery before source-guard checks; no application disclosure"))
end

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
  let alice_profile = load_profile(fixture.alice_path)?
  let bob_profile = load_profile(fixture.bob_path)?
  let alice = decode_client_profile(alice_profile)?
  let hello = start_conversation(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_profile,
    body: Bytes.from_utf8("initial policy source"),
    attachment: Bytes.empty()
  })?
  assert_received_fixture(Bytes.secure_equals(receive_initial_message(MobileReceiveRequest {
      database_path: fixture.bob_path,
      outer: hello
    })?,
    Bytes.from_utf8("initial policy source")))
  let key = platform_key()?
  let ids = load_session_ids(fixture.bob_path, key)?
  let before = capture_header_initial(fixture.bob_path, key, bob_profile, U64.parse("9001")?)?
  # A normal initial never needs an alias. Even an unrelated invalid orphan
  # at that deterministic address must not become an alias-admission gate.
  let orphan_id = Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/conversation-alias/v1"),
    alice.account_id)?)
  let orphan_label = "session/v1/#{Bytes.to_hex(orphan_id)}"
  let orphan = Bytes.from_utf8("unrelated orphan fixture")
  store_updated_blobs(fixture.bob_path, [orphan_label], [orphan])?
  let sources = capture_receive_sessions(fixture.bob_path, key, before, ids)?
  assert(sources.alias_label == "" && Bytes.length(sources.peer_account_id) == 0)
  let original = receive_captured_peer(sources, key, alice.account_id)?
  assert(!original.record.blocked && original.record.disappearing_seconds == 0)
  assert(receive_captured_strongest(sources, key, alice.account_id, alice.device_id)? == 2)
  update_conversation(MobilePolicyRequest {
    database_path: fixture.bob_path,
    peer_profile: alice_profile,
    action: 2,
    value: 0,
    expected_safety: Bytes.empty()
  })?
  update_conversation(MobilePolicyRequest {
    database_path: fixture.bob_path,
    peer_profile: alice_profile,
    action: 5,
    value: 60,
    expected_safety: Bytes.empty()
  })?
  let winner = load_blob(fixture.bob_path, original.label)?
  let still_original = receive_captured_peer(sources, key, alice.account_id)?
  assert(!still_original.record.blocked && still_original.record.disappearing_seconds == 0)
  assert(Bytes.secure_equals(still_original.record.conversation_id,
    original.record.conversation_id))
  assert(Bytes.secure_equals(still_original.record.snapshot, original.record.snapshot))
  assert(receive_captured_strongest(sources, key, alice.account_id, alice.device_id)? == 2)
  let candidate_label = "session/v1/#{Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("uncommitted initial")))}"
  assert(case commit_initial_admission_with_sources(fixture.bob_path,
    Some(before),
    Some(sources),
    candidate_label,
    Bytes.from_utf8("opaque candidate"),
    Bytes.from_utf8("candidate index"),
    [],
    [],
    [],
    [],
    []) do
    Err("account_state_changed") -> true
    _ -> false
  end)
  assert(Result.is_err(load_blob(fixture.bob_path, candidate_label)))
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, original.label)?, winner))
  let fresh_before = capture_header_initial(fixture.bob_path, key, bob_profile, U64.parse("9001")?)?
  let fresh = capture_receive_sessions(fixture.bob_path, key, fresh_before, ids)?
  let current = receive_captured_peer(fresh, key, alice.account_id)?
  assert(current.record.blocked && current.record.disappearing_seconds == 60)
  assert(Bytes.secure_equals(current.record.conversation_id, original.record.conversation_id))
  assert(receive_captured_strongest(fresh, key, alice.account_id, alice.device_id)? == 2)
  with_record_transaction(fixture.bob_path,
    fn(database) -> require_receive_sources(database, fresh_before, Some(fresh)) end)?
  assert(Bytes.secure_equals(load_blob(fixture.bob_path, orphan_label)?, orphan))
  erase_local_state(fixture.alice_path)?
  erase_local_state(fixture.bob_path)?
  Ok(true)
end

test("initial policy and strongest suite use captured records; later policy refuses admission and normal initial ignores alias absence") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

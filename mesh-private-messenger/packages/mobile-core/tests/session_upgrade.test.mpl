import File
from MobileCore import (
  create_account_export,
  directory_entry_export,
  fanout_prekey_claims_export,
  has_fanout_prekey_state_for_test,
  install_classical_session_for_test,
  install_group_transparency_for_test,
  load_history_export,
  outbox_ack_export,
  receive_initial_export,
  receive_message_export,
  remove_safety_binding_for_test,
  reserve_fanout_prekey_export,
  send_fanout_export,
  send_message_export,
  test_inner_suite,
  update_conversation_export
)
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.DirectoryWire import decode_directory_entry, encode_device_set
from Protocol.PrekeyWire import decode_prekey_bundle, encode_prekey_bundle
from Protocol.V1 import DeviceSet, DirectoryEntry, PrekeyBundle
from Tests.GroupConsistencySupport import request, signed_transparency_view, wide
from Tests.GroupLifecycleWire import outer, output_list
from Tests.Support import database_path, write_u32
from Transparency.Merkle import leaf_hash

fn entry(input :: Bytes) -> DirectoryEntry ! String do
  case decode_directory_entry(input) do
    Err( _) -> Err("directory entry decode failed")
    Ok( value) -> Ok(value)
  end
end

fn bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err( _) -> Err("prekey bundle decode failed")
    Ok( value) -> Ok(value)
  end
end

fn base_entry(value :: DirectoryEntry) -> DirectoryEntry ! String do
  let normalized = case normalize_prekey_bundle(bundle(value.prekey_bundle) ?) do
    Err( _) -> Err("prekey bundle normalization failed")
    Ok( result) -> Ok(result)
  end ?
  let wire = case encode_prekey_bundle(normalized) do
    Err( _) -> Err("prekey bundle encoding failed")
    Ok( result) -> Ok(result)
  end ?
  Ok(% { value | prekey_bundle : wire })
end

fn device_set(username :: String, entry_value :: DirectoryEntry, sequence :: Int) -> Bytes ! String do
  case encode_device_set(DeviceSet {
    version : 1,
    username : username,
    account_identity : entry_value.account_identity,
    sequence : wide(sequence) ?,
    devices : [entry_value],
    revoked_device_ids : List.new()
  }) do
    Err( _) -> Err("device set encoding failed")
    Ok( value) -> Ok(value)
  end
end

fn install_view(path :: String, peer_set :: Bytes, local_set :: Bytes) -> Bool ! String do
  let view = signed_transparency_view([leaf_hash(peer_set) ?, leaf_hash(local_set) ?]) ?
  assert(install_group_transparency_for_test(path,
  view.checkpoint,
  view.consistency,
  view.service_public_key,
  view.witness_a_public_key,
  view.witness_b_public_key,
  peer_set) ?)
  assert(install_group_transparency_for_test(path,
  view.checkpoint,
  view.consistency,
  view.service_public_key,
  view.witness_a_public_key,
  view.witness_b_public_key,
  local_set) ?)
  Ok(true)
end

fn acknowledge(path :: String, envelope :: Bytes) -> Bool ! String do
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(path), envelope]) ?) ?) == 0)
  Ok(true)
end

fn byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("test byte allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn proof() -> Bool ! String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("session-upgrade-alice") ?
  let bob_path = database_path("session-upgrade-bob") ?
  let alice_profile = create_account_export(request([Bytes.from_utf8(alice_path), Bytes.from_utf8("alice")]) ?) ?
  let bob_profile = create_account_export(request([Bytes.from_utf8(bob_path), Bytes.from_utf8("bob")]) ?) ?
  let classical_fixture = output_list(install_classical_session_for_test(alice_path, bob_path) ?) ?
  assert(List.length(classical_fixture) == 3)
  let delayed = List.get(classical_fixture, 0)
  let classical_bob = entry(List.get(classical_fixture, 1)) ?
  let classical_bob_profile = List.get(classical_fixture, 2)
  assert(remove_safety_binding_for_test(alice_path, classical_bob_profile) ?)
  assert(outer(delayed) ?.suite == 1)
  let claimed_alice = entry(directory_entry_export(Bytes.from_utf8(alice_path)) ?) ?
  let claimed_bob_wire = directory_entry_export(Bytes.from_utf8(bob_path)) ?
  let claimed_bob = entry(claimed_bob_wire) ?
  let alice_set = device_set("alice", base_entry(claimed_alice) ?, 1) ?
  let bob_set = device_set("bob", base_entry(claimed_bob) ?, 1) ?
  assert(install_view(alice_path, bob_set, alice_set) ?)
  assert(install_view(bob_path, alice_set, bob_set) ?)
  let claims_request = request([Bytes.from_utf8(alice_path), bob_set, alice_set]) ?
  assert(List.length(output_list(fanout_prekey_claims_export(claims_request) ?) ?) == 1)
  assert(Bytes.length(reserve_fanout_prekey_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, claimed_bob.prekey_bundle]) ?) ?) == 0)
  let upgraded_body = Bytes.from_utf8("suite-2 upgrade")
  let upgraded = List.head(output_list(send_fanout_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, upgraded_body]) ?) ?) ?)
  # Delivery sees only the sealed transport; the recipient alone reads suite 2.
  assert(outer(upgraded) ?.suite == 4)
  assert(test_inner_suite(bob_path, upgraded) ? == 2)
  assert(acknowledge(alice_path, upgraded) ?)
  let bob_claims_request = request([Bytes.from_utf8(bob_path), alice_set, bob_set]) ?
  assert(List.length(output_list(fanout_prekey_claims_export(bob_claims_request) ?) ?) == 1)
  assert(Bytes.length(reserve_fanout_prekey_export(request([Bytes.from_utf8(bob_path), alice_set, bob_set, claimed_alice.prekey_bundle]) ?) ?) == 0)
  assert(has_fanout_prekey_state_for_test(bob_path, alice_profile) ?)
  assert(Bytes.secure_equals(update_conversation_export(request([Bytes.from_utf8(bob_path), alice_profile, byte(2) ?, write_u32(0) ?]) ?) ?,
  Bytes.from_utf8("ok")))
  case receive_initial_export(request([Bytes.from_utf8(bob_path), upgraded]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "blocked_message")
  end
  assert(!has_fanout_prekey_state_for_test(bob_path, alice_profile) ?)
  assert(Bytes.secure_equals(update_conversation_export(request([Bytes.from_utf8(alice_path), bob_profile, byte(4) ?, write_u32(0) ?]) ?) ?,
  Bytes.from_utf8("ok")))
  assert(Bytes.secure_equals(update_conversation_export(request([Bytes.from_utf8(bob_path), alice_profile, byte(3) ?, write_u32(0) ?]) ?) ?,
  Bytes.from_utf8("ok")))
  let preferred_body = Bytes.from_utf8("suite-2 preferred")
  let preferred = List.head(output_list(send_fanout_export(request([Bytes.from_utf8(alice_path), bob_set, alice_set, preferred_body]) ?) ?) ?)
  assert(outer(preferred) ?.suite == 4)
  assert(test_inner_suite(bob_path, preferred) ? == 2)
  assert(acknowledge(alice_path, preferred) ?)
  assert(Bytes.secure_equals(receive_message_export(request([Bytes.from_utf8(bob_path), preferred]) ?) ?,
  preferred_body))
  case send_message_export(request([Bytes.from_utf8(alice_path), classical_bob_profile, Bytes.from_utf8("legacy direct send")]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "peer_keys_changed")
  end
  assert(Bytes.secure_equals(update_conversation_export(request([Bytes.from_utf8(alice_path), bob_profile, byte(2) ?, write_u32(0) ?]) ?) ?,
  Bytes.from_utf8("ok")))
  let history_request = request([Bytes.from_utf8(alice_path), bob_profile]) ?
  let history_before_delayed = load_history_export(history_request) ?
  case receive_message_export(request([Bytes.from_utf8(alice_path), delayed]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "blocked_message")
  end
  assert(Bytes.secure_equals(load_history_export(history_request) ?, history_before_delayed))
  case receive_message_export(request([Bytes.from_utf8(alice_path), delayed]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "message_rejected")
  end
  let downgraded_set = device_set("bob", classical_bob, 2) ?
  assert(install_view(alice_path, downgraded_set, alice_set) ?)
  case fanout_prekey_claims_export(request([Bytes.from_utf8(alice_path), downgraded_set, alice_set]) ?) do
    Ok( _) -> assert(false)
    Err( error) -> assert(error == "peer_keys_changed")
  end
  File.delete(alice_path) ?
  File.delete(bob_path) ?
  Ok(true)
end

test("mobile session upgrades enforce conversation blocks on delayed suite-1 traffic") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

##! Authenticated device-identity receive regressions; no network or object fetches.
import File
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message
from Mobile.Profile import load_profile, open_device, policy
from Mobile.Sessions import (
  initial_bytes,
  inner_bytes,
  load_session_ids,
  find_peer_session,
  updated_session_record
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileReceiveRequest
from MobileCore import create_account_export, replenish_prekeys_export
from Prekeys.Pool import decode_prekey_publish
from Protocol.V1 import InnerEnvelope
from Session.Handshake import initiate_at_minimum_suite
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, seal_local, one_time_prekey_label
from Storage.Records import erase_local_state, store_updated_blobs
from Tests.GroupConsistencySupport import request
from Tests.Support import database_path, repeated, write_u32
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import (
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  pending_label,
  identity_label,
  history_label,
  pending_and_history
)
from Tests.WitnessedSessionFixture import install_witnessed_session_fixtures
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  direct_conversation_id,
  encode_initial_plaintext,
  encode_packet
)

fn device_identity_check(value :: Plaintext<Bool>, error :: String) -> Unit!String do
  if declassify(value, "test-only observation of synthetic authenticated device identity") do
    Ok(nil)
  else
    Err(error)
  end
end

fn device_identity_inner(sender :: ClientProfile,
  receiver :: ClientProfile,
  conversation :: Bytes,
  id :: Bytes,
  reference :: Bytes) -> InnerEnvelope!String do
  Ok(InnerEnvelope {
    version: 1,
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    recipient_device_id: receiver.device_id,
    conversation_id: conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  })
end

fn device_identity_binding(sender :: ClientProfile,
  receiver :: ClientProfile,
  conversation :: Bytes,
  id :: Bytes) -> ViewOnceBinding do
  ViewOnceBinding {
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    receiver_account_id: receiver.account_id,
    receiver_device_id: receiver.device_id,
    conversation_id: conversation,
    message_id: id
  }
end

# Use the real recipient's published reusable prekey so two independent initial
# handshakes do not compete for the same consumed one-time prekey.
fn device_identity_reusable_carrier(sender_path :: String,
  receiver_path :: String,
  inner :: InnerEnvelope) -> Bytes!String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([
    Bytes.from_utf8(receiver_path),
    write_u32(0)?
  ])?)?)?
  let reusable = case publication.last_resort do
    None -> return Err("device identity fixture has no reusable prekey")
    Some(value) -> value
  end
  let key = platform_key()?
  let sender_wire = load_profile(sender_path)?
  let sender = decode_client_profile(sender_wire)?
  let receiver = decode_client_profile(load_profile(receiver_path)?)?
  let device = open_device(sender, key, sender_path)?
  let now = current_time()?
  let bundle = %{receiver.bundle |
    one_time_prekey_id: reusable.id,
    one_time_prekey: reusable.public_key
  }
  let plaintext = encode_initial_plaintext(sender_wire, inner_bytes(inner)?)?
  let (_state, initial) = case initiate_at_minimum_suite(device,
    sender.credential,
    receiver.account,
    bundle,
    policy(receiver, now),
    0,
    1,
    plaintext) do
    Err(_) -> return Err("device identity fixture handshake failed")
    Ok(value) -> value
  end
  let packet = encode_packet(InitialPacket(sender.entry.account_identity, initial_bytes(initial)?))?
  sealed_outer_bytes(receiver.entry.mailbox_token, packet, receiver.credential.dh_public_key, now)
end

fn device_identity_receive(path :: String, wire :: Bytes) -> Bytes!String do
  receive_initial_message(MobileReceiveRequest { database_path: path, outer: wire })
end

fn sender_device_body(alice_path :: String,
  linked_path :: String,
  bob_path :: String) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(alice_path)?)?
  let linked = decode_client_profile(load_profile(linked_path)?)?
  let bob = decode_client_profile(load_profile(bob_path)?)?
  device_identity_check(Bytes.secure_equals(alice.account_id, linked.account_id)
      && !Bytes.secure_equals(alice.device_id, linked.device_id),
    "fixture does not contain two devices of the same peer")?
  let receiver = open_device(bob, key, bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let id = repeated(181, 16)?
  let first_binding = device_identity_binding(alice, bob, conversation, id)
  let (first_reference, _chunk, _png) = view_once_receive_material(receiver, first_binding)?
  let first_inner = device_identity_inner(alice, bob, conversation, id, first_reference)?
  let (_state, first_wire) = initial_carrier(alice_path, bob_path, first_inner)?
  device_identity_check(Bytes.secure_equals(device_identity_receive(bob_path, first_wire)?,
      first_inner.body),
    "first authenticated sender device was not admitted")?
  device_identity_check(pending_and_history(bob_path, conversation, id, first_reference, 1)?,
    "first sender did not create pending and sanitized history")?
  device_identity_check(Result.is_ok(load_blob(bob_path, identity_label(first_binding)?)),
    "first sender did not create its identity marker")?
  # Retain the old records while selecting a different local history alias.
  # The wire conversation, peer account, receiver and message ID remain fixed.
  let peer = find_peer_session(bob_path,
    key,
    alice.account_id,
    load_session_ids(bob_path, key)?,
    0)?
  let alias = repeated(182, 16)?
  device_identity_check(!Bytes.secure_equals(conversation, alias), "fixture alias did not change")?
  let changed = %{peer.record | conversation_id: alias, request_state: 0}
  let changed_blob = seal_local(updated_session_record(changed.snapshot, changed)?,
    key,
    local_context(peer.label)?)?
  store_updated_blobs(bob_path, [peer.label], [changed_blob])?
  let second_binding = device_identity_binding(linked, bob, conversation, id)
  let (second_reference, _chunk2, _png2) = view_once_receive_material(receiver, second_binding)?
  device_identity_check(!Bytes.secure_equals(first_reference, second_reference)
      && identity_label(first_binding)? != identity_label(second_binding)?,
    "fixture did not produce a fresh reference and distinct device marker")?
  let second_inner = device_identity_inner(linked, bob, conversation, id, second_reference)?
  let second_wire = device_identity_reusable_carrier(linked_path, bob_path, second_inner)?
  let labels = [
    "sessions/v1",
    peer.label,
    pending_label(conversation, id),
    pending_label(alias, id),
    history_label(conversation),
    history_label(alias),
    identity_label(first_binding)?,
    identity_label(second_binding)?,
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    "last-resort-replays/v1"
  ]
  let before = load_account_basis(bob_path, labels)?
  let rejected = device_identity_receive(bob_path, second_wire)
  device_identity_check(case rejected do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "fresh reference from a second authenticated sender device did not conflict")?
  device_identity_check(same_account_basis(before, load_account_basis(bob_path, labels)?),
    "sender-device conflict changed session, prekeys, pending, history or identity")?
  device_identity_check(pending_and_history(bob_path, conversation, id, first_reference, 1)?,
    "sender-device conflict changed the original pending or history")?
  device_identity_check(Result.is_err(load_blob(bob_path, pending_label(alias, id)))
      && Result.is_err(load_blob(bob_path, history_label(alias)))
      && Result.is_err(load_blob(bob_path, identity_label(second_binding)?)),
    "sender-device conflict created a second pending, history or device marker")?
  # The linked sender can complete the same authenticated path with a new ID.
  let control_id = repeated(183, 16)?
  let control_binding = device_identity_binding(linked, bob, conversation, control_id)
  let (control_reference, _chunk3, _png3) = view_once_receive_material(receiver, control_binding)?
  let control = device_identity_inner(linked, bob, conversation, control_id, control_reference)?
  let control_wire = device_identity_reusable_carrier(linked_path, bob_path, control)?
  device_identity_check(Bytes.secure_equals(device_identity_receive(bob_path, control_wire)?,
      control.body),
    "linked sender's fresh control failed authentication or delivery")?
  device_identity_check(pending_and_history(bob_path, alias, control_id, control_reference, 1)?,
    "linked sender control did not create its own pending and history")
end

fn sender_device_case() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = sender_device_body(fixture.alice_path, fixture.linked_path, fixture.bob_path)
  clear_initial_sync_fixture(fixture)?
  result
end

fn wrong_receiver_body(alice_path :: String,
  linked_path :: String,
  bob_path :: String) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(alice_path)?)?
  let linked = decode_client_profile(load_profile(linked_path)?)?
  let bob = decode_client_profile(load_profile(bob_path)?)?
  let receiver = open_device(alice, key, alice_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let id = repeated(184, 16)?
  let expected = device_identity_binding(bob, alice, conversation, id)
  let wrong = %{expected | receiver_device_id: linked.device_id}
  device_identity_check(Bytes.secure_equals(alice.account_id, linked.account_id)
      && !Bytes.secure_equals(alice.device_id, linked.device_id),
    "receiver devices are not distinct")?
  # The HPKE key is Alice's real key, but the independently authenticated VOR
  # binding claims her linked device. The transport itself targets Alice.
  let (bad_reference, _chunk, _png) = view_once_receive_material(receiver, wrong)?
  let bad = device_identity_inner(bob, alice, conversation, id, bad_reference)?
  let (_state, wire) = initial_carrier(bob_path, alice_path, bad)?
  let labels = [
    "sessions/v1",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(alice.bundle.one_time_prekey_id),
    pending_label(conversation, id),
    history_label(conversation),
    identity_label(expected)?,
    identity_label(wrong)?
  ]
  let before = load_account_basis(alice_path, labels)?
  device_identity_check(case device_identity_receive(alice_path, wire) do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "authenticated wrong receiver-device binding was accepted")?
  device_identity_check(same_account_basis(before, load_account_basis(alice_path, labels)?),
    "wrong receiver-device binding changed captured state")?
  let (good_reference, _chunk2, _png2) = view_once_receive_material(receiver, expected)?
  let good = device_identity_inner(bob, alice, conversation, id, good_reference)?
  let (_next, good_wire) = initial_carrier(bob_path, alice_path, good)?
  device_identity_check(Bytes.secure_equals(device_identity_receive(alice_path, good_wire)?,
      good.body),
    "correct receiver-device control failed")?
  device_identity_check(pending_and_history(alice_path, conversation, id, good_reference, 1)?,
    "correct receiver-device control lacks pending or history")
end

fn wrong_receiver_case() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = wrong_receiver_body(fixture.alice_path, fixture.linked_path, fixture.bob_path)
  clear_initial_sync_fixture(fixture)?
  result
end

fn different_peers_body(alice_path :: String,
  carol_path :: String,
  bob_path :: String) -> Unit!String do
  for (path, name) in [(alice_path, "alice"), (carol_path, "carol"), (bob_path, "bob")] do
    create_account_export(request([Bytes.from_utf8(path), Bytes.from_utf8(name)])?)?
  end
  install_witnessed_session_fixtures([alice_path, carol_path, bob_path])?
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(alice_path)?)?
  let carol = decode_client_profile(load_profile(carol_path)?)?
  let bob = decode_client_profile(load_profile(bob_path)?)?
  let receiver = open_device(bob, key, bob_path)?
  let id = repeated(185, 16)?
  let first_conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let second_conversation = direct_conversation_id(carol.account_id, bob.account_id)?
  device_identity_check(!Bytes.secure_equals(alice.account_id, carol.account_id)
      && !Bytes.secure_equals(first_conversation, second_conversation),
    "fixture peers are not distinct")?
  let first_binding = device_identity_binding(alice, bob, first_conversation, id)
  let second_binding = device_identity_binding(carol, bob, second_conversation, id)
  let (first_reference, _chunk, _png) = view_once_receive_material(receiver, first_binding)?
  let (second_reference, _chunk2, _png2) = view_once_receive_material(receiver, second_binding)?
  let first = device_identity_inner(alice, bob, first_conversation, id, first_reference)?
  let second = device_identity_inner(carol, bob, second_conversation, id, second_reference)?
  let (_state, first_wire) = initial_carrier(alice_path, bob_path, first)?
  let second_wire = device_identity_reusable_carrier(carol_path, bob_path, second)?
  device_identity_check(Bytes.secure_equals(device_identity_receive(bob_path, first_wire)?,
      first.body),
    "first peer failed authenticated admission")?
  device_identity_check(Bytes.secure_equals(device_identity_receive(bob_path, second_wire)?,
      second.body),
    "different peer with same ID failed authenticated admission")?
  device_identity_check(pending_and_history(bob_path, first_conversation, id, first_reference, 1)?
      && pending_and_history(bob_path, second_conversation, id, second_reference, 1)?,
    "different peers did not retain independent pending and history")?
  device_identity_check(Result.is_ok(load_blob(bob_path, identity_label(first_binding)?))
      && Result.is_ok(load_blob(bob_path, identity_label(second_binding)?)),
    "different peers did not retain both identities")
end

fn different_peers_case() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let alice = database_path("vo-device-identity-alice")?
  let carol = database_path("vo-device-identity-carol")?
  let bob = database_path("vo-device-identity-bob")?
  let result = different_peers_body(alice, carol, bob)
  for path in [alice, carol, bob] do
    erase_local_state(path)?
    File.delete(path)?
  end
  result
end

fn assert_device_identity(result :: Unit!String) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("a second authenticated sender device cannot create a new view-once identity") do
  assert_device_identity(sender_device_case())
end

test("an authenticated carrier with a wrong receiver device binding is refused") do
  assert_device_identity(wrong_receiver_case())
end

test("different authenticated peers can use the same view-once message ID") do
  assert_device_identity(different_peers_case())
end

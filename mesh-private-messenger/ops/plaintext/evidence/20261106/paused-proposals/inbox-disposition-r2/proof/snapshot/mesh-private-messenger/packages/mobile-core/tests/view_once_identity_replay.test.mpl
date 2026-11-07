##! Authenticated synthetic carriers: identity scope, alias migration and legacy rows.
import File
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device, policy
from Mobile.Sessions import (
  encode_sync_payload,
  self_sync_conversation_id,
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
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Session.Handshake import initiate_at_minimum_suite
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, seal_local, one_time_prekey_label
from Storage.Records import erase_local_state, store_updated_blobs
from Storage.ViewOnce import ViewOnceRecord, ViewOnceAvailable, encode_view_once_record
from Tests.GroupConsistencySupport import request
from Tests.Support import database_path, repeated, write_u32
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import (
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  sibling_carrier,
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

fn identity_replay_check(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value, "test-only observation of synthetic view-once receive state") do
    Ok(nil)
  else
    Err(message)
  end
end

fn identity_replay_inner(sender :: ClientProfile,
  receiver :: ClientProfile,
  conversation :: Bytes,
  id :: Bytes) -> InnerEnvelope!String do
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
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  })
end

fn identity_replay_binding(sender :: ClientProfile,
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

fn identity_replay_receive(path :: String, wire :: Bytes, initial :: Bool) -> Bytes!String do
  let value = MobileReceiveRequest { database_path: path, outer: wire }
  if initial do
    receive_initial_message(value)
  else
    receive_message(value)
  end
end

## Same public bundle, with the recipient's real reusable prekey in its one-time slot.
fn identity_replay_reusable_carrier(sender_path :: String,
  recipient_path :: String,
  inner :: InnerEnvelope) -> Bytes!String do
  let publication = decode_prekey_publish(replenish_prekeys_export(request([
    Bytes.from_utf8(recipient_path),
    write_u32(0)?
  ])?)?)?
  let reusable = case publication.last_resort do
    None -> return Err("identity replay fixture has no reusable prekey")
    Some(value) -> value
  end
  let key = platform_key()?
  let sender_wire = load_profile(sender_path)?
  let sender = decode_client_profile(sender_wire)?
  let recipient = decode_client_profile(load_profile(recipient_path)?)?
  let device = open_device(sender, key, sender_path)?
  let now = current_time()?
  let plaintext = encode_initial_plaintext(sender_wire, inner_bytes(inner)?)?
  let bundle = %{recipient.bundle |
    one_time_prekey_id: reusable.id,
    one_time_prekey: reusable.public_key
  }
  let (_state, initial) = case initiate_at_minimum_suite(device,
    sender.credential,
    recipient.account,
    bundle,
    policy(recipient, now),
    0,
    1,
    plaintext) do
    Err(_) -> return Err("identity replay fixture handshake failed")
    Ok(value) -> value
  end
  let packet = encode_packet(InitialPacket(sender.entry.account_identity, initial_bytes(initial)?))?
  sealed_outer_bytes(recipient.entry.mailbox_token, packet, recipient.credential.dh_public_key, now)
end

fn identity_replay_peers_body(alice_path :: String,
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
  let device = open_device(bob, key, bob_path)?
  let id = repeated(101, 16)?
  let alice_conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let carol_conversation = direct_conversation_id(carol.account_id, bob.account_id)?
  identity_replay_check(!Bytes.secure_equals(alice_conversation, carol_conversation),
    "fixture conversations unexpectedly equal")?
  let first_binding = identity_replay_binding(alice, bob, alice_conversation, id)
  let second_binding = identity_replay_binding(carol, bob, carol_conversation, id)
  let (first_reference, _chunk1, _png1) = view_once_receive_material(device, first_binding)?
  let (second_reference, _chunk2, _png2) = view_once_receive_material(device, second_binding)?
  let first = %{identity_replay_inner(alice, bob, alice_conversation, id)? |
    attachment_manifest: first_reference
  }
  let second = %{identity_replay_inner(carol, bob, carol_conversation, id)? |
    attachment_manifest: second_reference
  }
  let (_state, first_wire) = initial_carrier(alice_path, bob_path, first)?
  let second_wire = identity_replay_reusable_carrier(carol_path, bob_path, second)?
  identity_replay_check(Bytes.secure_equals(identity_replay_receive(bob_path, first_wire, true)?,
      first.body),
    "first peer was not admitted")?
  identity_replay_check(Bytes.secure_equals(identity_replay_receive(bob_path, second_wire, true)?,
      second.body),
    "second authenticated peer with same message id was not admitted")?
  identity_replay_check(pending_and_history(bob_path, alice_conversation, id, first_reference, 1)?,
    "first peer pending or history missing")?
  identity_replay_check(pending_and_history(bob_path, carol_conversation, id, second_reference, 1)?,
    "second peer pending or history missing")?
  identity_replay_check(Result.is_ok(load_blob(bob_path, identity_label(first_binding)?))
      && Result.is_ok(load_blob(bob_path, identity_label(second_binding)?)),
    "both peer identities were not retained")
end

fn identity_replay_peers() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("vo-identity-alice")?
  let carol_path = database_path("vo-identity-carol")?
  let bob_path = database_path("vo-identity-bob")?
  let result = identity_replay_peers_body(alice_path, carol_path, bob_path)
  for path in [alice_path, carol_path, bob_path] do
    erase_local_state(path)?
    File.delete(path)?
  end
  result
end

fn identity_replay_sync_body(alice_path :: String,
  sibling_path :: String,
  bob_path :: String) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(alice_path)?)?
  let sibling = decode_client_profile(load_profile(sibling_path)?)?
  let bob = decode_client_profile(load_profile(bob_path)?)?
  let device = open_device(sibling, key, sibling_path)?
  let wire_conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let transport_conversation = self_sync_conversation_id(alice.account_id)?
  let id = repeated(102, 16)?
  let binding = identity_replay_binding(alice, sibling, wire_conversation, id)
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let original = identity_replay_inner(alice, bob, wire_conversation, id)?
  let envelope = %{original |
    recipient_device_id: sibling.device_id,
    conversation_id: transport_conversation,
    client_message_id: repeated(103, 16)?,
    message_type: 2,
    body: encode_sync_payload(alice, bob, original)?,
    attachment_manifest: reference
  }
  let (state, first_wire) = initial_carrier(alice_path, sibling_path, envelope)?
  identity_replay_check(Bytes.secure_equals(identity_replay_receive(sibling_path,
        first_wire,
        true)?,
      original.body),
    "first sibling sync was not delivered")?
  identity_replay_check(pending_and_history(sibling_path, wire_conversation, id, reference, 1)?,
    "first sync missing pending or history")?
  let marker = identity_label(binding)?
  let peer = find_peer_session(sibling_path,
    key,
    bob.account_id,
    load_session_ids(sibling_path, key)?,
    0)?
  let migrated = repeated(104, 16)?
  identity_replay_check(!Bytes.secure_equals(migrated, wire_conversation), "alias did not change")?
  let changed = %{peer.record | conversation_id: migrated, request_state: 0}
  let changed_blob = seal_local(updated_session_record(changed.snapshot, changed)?,
    key,
    local_context(peer.label)?)?
  store_updated_blobs(sibling_path, [peer.label], [changed_blob])?
  let offered = repeated(105, 32)?
  let contact_label = "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(alice.entry.mailbox_token))}"
  let owner_label = "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(offered))}"
  let duplicate = %{envelope |
    client_message_id: repeated(106, 16)?,
    extensions: [ProtocolExtension { id: 1, mandatory: false, value: offered }]
  }
  let (_next, duplicate_wire) = sibling_carrier(state, sibling, duplicate)?
  let labels = [
    "sessions/v1",
    peer.label,
    history_label(wire_conversation),
    history_label(migrated),
    pending_label(wire_conversation, id),
    pending_label(migrated, id),
    marker,
    contact_label,
    owner_label,
    "contact-address/v1",
    "contact-address-pending/v1"
  ]
  let before = load_account_basis(sibling_path, labels)?
  let delivered = identity_replay_receive(sibling_path, duplicate_wire, false)?
  identity_replay_check(Bytes.length(delivered) == 0, "duplicate was delivered twice")?
  identity_replay_check(same_account_basis(before, load_account_basis(sibling_path, labels)?),
    "duplicate changed alias, request, contact, history, pending or marker")?
  identity_replay_check(pending_and_history(sibling_path, wire_conversation, id, reference, 1)?,
    "original pending or history changed")?
  identity_replay_check(Result.is_err(load_blob(sibling_path, pending_label(migrated, id)))
      && Result.is_err(load_blob(sibling_path, history_label(migrated))),
    "duplicate created a second pending row or history")
end

fn identity_replay_sync() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = identity_replay_sync_body(fixture.alice_path, fixture.linked_path, fixture.bob_path)
  clear_initial_sync_fixture(fixture)?
  result
end

fn identity_replay_legacy_body(alice_path :: String, bob_path :: String) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(alice_path)?)?
  let bob = decode_client_profile(load_profile(bob_path)?)?
  let device = open_device(bob, key, bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  for mode in [1, 2] do
    let id = repeated(106 + mode, 16)?
    let binding = identity_replay_binding(alice, bob, conversation, id)
    let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
    let inner = %{identity_replay_inner(alice, bob, conversation, id)? |
      attachment_manifest: reference
    }
    let label = "view-once/v1/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(id)}"
    let record = if mode == 1 do
      Available(ViewOnceAvailable {
        reference: reference,
        chunk_hashes: [repeated(4, 32)?],
        message_expiry: None
      })
    else
      Consumed(repeated(5, 32)?)
    end
    let blob = seal_local(encode_view_once_record(record)?, key, local_context(label)?)?
    store_updated_blobs(bob_path, [label], [blob])?
    let (_state, wire) = initial_carrier(alice_path, bob_path, inner)?
    let labels = [
      "sessions/v1",
      "one-time-prekeys/v1",
      "one-time-prekey-active/v1",
      one_time_prekey_label(bob.bundle.one_time_prekey_id),
      label,
      pending_label(conversation, id),
      history_label(conversation),
      identity_label(binding)?
    ]
    let before = load_account_basis(bob_path, labels)?
    let refused = case identity_replay_receive(bob_path, wire, true) do
      Err("view_once_reference_refused") -> true
      _ -> false
    end
    identity_replay_check(refused, "unknown legacy row did not fail closed")?
    identity_replay_check(same_account_basis(before, load_account_basis(bob_path, labels)?),
      "legacy refusal changed captured state")?
  end
  Ok(nil)
end

fn identity_replay_legacy() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = identity_replay_legacy_body(fixture.alice_path, fixture.bob_path)
  clear_initial_sync_fixture(fixture)?
  result
end

test("the same message id is independently admitted from different authenticated peers") do
  case identity_replay_peers() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("a sibling replay after local alias migration creates no second message or side effects") do
  case identity_replay_sync() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("unknown legacy available and consumed rows fail closed on fresh receive") do
  case identity_replay_legacy() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

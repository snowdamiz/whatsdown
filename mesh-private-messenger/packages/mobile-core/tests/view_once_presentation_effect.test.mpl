##! Synthetic recipient-bound VOR carried by a real authenticated direct ratchet.
import File
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time, mobile_join, mobile_vector, mobile_write_u64, mobile_wide
from Mobile.HistoryWire import decode_history
from Mobile.Messages import start_conversation, receive_initial_message, receive_message
from Mobile.Presentation import encode_presented_message, load_presentation_record
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  find_peer_session,
  inner_bytes,
  load_session_ids,
  ratchet_bytes,
  restore_session,
  seal_updated_session
)
from Mobile.Transport import sealed_outer_bytes
from Mobile.Types import MobileHistoryAttachment, MobileReceiveRequest, MobileStartRequest
from Protocol.V1 import InnerEnvelope
from Session.Ratchet import encrypt_sealed
from Storage.AccountGuard import load_account_basis, commit_account_changes
from Storage.Blobs import load_blob
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import platform_key, seal_local, open_local, local_context
from Storage.Records import store_updated_blobs
from Storage.ViewOnce import ViewOnceRecord, decode_view_once_record
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.Support import repeated
from Tests.ViewOnceFixture import view_once_receive_material
from Transparency.Merkle import leaf_hash
from Transport.Packet import TransportPacket, decode_client_profile, encode_packet, session_aad

fn profile_record(name :: String, revision :: Int) -> Bytes!String do
  mobile_join([
      mobile_vector(Bytes.from_utf8(name))?,
      mobile_vector(Bytes.empty())?,
      mobile_vector(mobile_write_u64(mobile_wide(Int.to_string(revision))?)?)?
    ],
    0,
    Bytes.empty())
end

fn ratchet_carrier(path :: String, peer_wire :: Bytes, inner :: InnerEnvelope) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(peer_wire)?
  let loaded = find_peer_session(path, key, peer.account_id, load_session_ids(path, key)?, 0)?
  let before = load_account_basis(path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("presentation_effect_encrypt")
    Ok(value) -> value
  end
  let outer = sealed_outer_bytes(peer.entry.mailbox_token,
    encode_packet(RatchetPacket(ratchet_bytes(message)?))?,
    peer.credential.dh_public_key,
    current_time()?)?
  commit_account_changes(path,
    before,
    [loaded.label],
    [seal_updated_session(next, loaded, key)?],
    [])?
  Ok(outer)
end

fn check_effect(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value,
    "test-only assertion about synthetic authenticated presentation and view-once fixtures") do
    Ok(nil)
  else
    Err(message)
  end
end

fn presentation_receive_proof() -> Unit!String do
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
  let alice_wire = load_profile(fixture.alice_path)?
  let bob_wire = load_profile(fixture.bob_path)?
  let alice = decode_client_profile(alice_wire)?
  let bob = decode_client_profile(bob_wire)?
  let hello = start_conversation(MobileStartRequest {
    database_path: fixture.alice_path,
    peer_profile: bob_wire,
    body: Bytes.from_utf8("establish ratchet"),
    attachment: Bytes.empty()
  })?
  let _ = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: hello
  })?
  let key = platform_key()?
  let session = find_peer_session(fixture.alice_path,
    key,
    bob.account_id,
    load_session_ids(fixture.alice_path, key)?,
    0)?
  let message_id = repeated(44, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: session.record.conversation_id,
    message_id: message_id
  }
  let device = open_device(bob, key, fixture.bob_path)?
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let profile_key = Bytes.from_utf8("user/" <> Bytes.to_hex(alice.account_id))
  let profile_label = "presentation/v1/user/#{Bytes.to_hex(alice.account_id)}"
  let existing = profile_record("Existing receiver profile", 1)?
  let incoming = profile_record("VOR sender profile", 2)?
  let original = seal_local(existing, key, local_context(profile_label)?)?
  store_updated_blobs(fixture.bob_path, [profile_label], [original])?
  let body = Bytes.from_utf8("view once caption")
  let framed = encode_presented_message(body, incoming, Bytes.empty())?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: binding.conversation_id,
    client_message_id: message_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: framed,
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let outer = ratchet_carrier(fixture.alice_path, bob_wire, inner)?
  let delivered = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: outer
  })?
  check_effect(Bytes.secure_equals(delivered, body),
    "view-once body was not normalized and delivered")?
  let row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(message_id)}"
  let pending_blob = load_blob(fixture.bob_path, row)?
  let pending = decode_view_once_record(open_local(pending_blob, key, local_context(row)?)?)?
  check_effect(case pending do
      PendingFetch(value) -> Bytes.secure_equals(value.reference, reference)
      _ -> false
    end,
    "view-once pending record missing or incorrect")?
  let history_label = "history/v1/#{Bytes.to_hex(binding.conversation_id)}"
  let history_blob = load_blob(fixture.bob_path, history_label)?
  let history = decode_history(open_history_blob(history_blob, key, history_label)?)?
  let latest = List.last(history)
  check_effect(Bytes.secure_equals(latest.inner.client_message_id, message_id)
      && Bytes.secure_equals(latest.inner.body, body)
      && Bytes.length(latest.inner.attachment_manifest) == 0
      && latest.attachment_kind == HistoryViewOnce,
    "view-once history did not retain the sanitized normalized message")?
  check_effect(Bytes.secure_equals(load_blob(fixture.bob_path, profile_label)?, original),
    "view-once receive rewrote pre-existing presentation ciphertext")?
  let duplicate_wire = ratchet_carrier(fixture.alice_path, bob_wire, inner)?
  let duplicate = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: duplicate_wire
  })?
  check_effect(Bytes.length(duplicate) == 0
      && Bytes.secure_equals(load_blob(fixture.bob_path, row)?, pending_blob)
      && Bytes.secure_equals(load_blob(fixture.bob_path, history_label)?, history_blob)
      && Bytes.secure_equals(load_blob(fixture.bob_path, profile_label)?, original),
    "duplicate changed delivery, pending, history, or presentation")?
  let ordinary_profile = profile_record("Ordinary sender profile", 3)?
  let ordinary_body = Bytes.from_utf8("ordinary caption")
  let ordinary = %{inner |
    client_message_id: repeated(45, 16)?,
    body: encode_presented_message(ordinary_body, ordinary_profile, Bytes.empty())?,
    attachment_manifest: Bytes.empty()
  }
  let ordinary_wire = ratchet_carrier(fixture.alice_path, bob_wire, ordinary)?
  let ordinary_received = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: ordinary_wire
  })?
  check_effect(Bytes.secure_equals(ordinary_received, ordinary_body)
      && Bytes.secure_equals(load_presentation_record(fixture.bob_path, key, profile_key)?,
        ordinary_profile)
      && !Bytes.secure_equals(load_blob(fixture.bob_path, profile_label)?, original),
    "ordinary presentation did not update the profile and deliver its body")?
  File.delete(fixture.alice_path)?
  File.delete(fixture.bob_path)?
  File.delete(fixture.linked_path)?
  Ok(nil)
end

test("authenticated view-once presentation preserves profile ciphertext while ordinary presentation updates it") do
  case presentation_receive_proof() do
    Ok(_) -> assert(true)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

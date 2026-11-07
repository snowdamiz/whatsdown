##! Synthetic, authenticated direct receives; never print reference or key material.
import File
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference
from Mobile.Codec import current_time, mobile_join, mobile_vector, mobile_write_u64, mobile_wide
from Mobile.Messages import start_conversation, receive_initial_message, receive_message
from Mobile.Presentation import encode_presented_message
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
from Mobile.Types import MobileReceiveRequest, MobileStartRequest
from MobileCore import load_history_export
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Session.Ratchet import encrypt_sealed
from Storage.AccountGuard import load_account_basis, commit_account_changes, same_account_basis
from Storage.Keys import platform_key
from Storage.Records import erase_local_state
from Tests.GroupConsistencySupport import request, signed_transparency_view
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.Support import repeated
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import identity_label, logical_label
from Transparency.Merkle import leaf_hash
from Transport.Packet import TransportPacket, decode_client_profile, encode_packet, session_aad

fn body_privacy_carrier(path :: String,
  peer_wire :: Bytes,
  inner :: InnerEnvelope) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(peer_wire)?
  let loaded = find_peer_session(path, key, peer.account_id, load_session_ids(path, key)?, 0)?
  let before = load_account_basis(path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("body_privacy_encrypt")
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

fn body_privacy_contains(input :: Bytes, needle :: Bytes, offset :: Int) -> Bool!String do
  if Bytes.length(needle) == 0 || offset + Bytes.length(needle) > Bytes.length(input) do
    Ok(false)
  else if Bytes.secure_equals(Bytes.slice(input, offset, Bytes.length(needle))?, needle) do
    Ok(true)
  else
    body_privacy_contains(input, needle, offset + 1)
  end
end

fn body_privacy_profile() -> Bytes!String do
  mobile_join([
      mobile_vector(Bytes.from_utf8("Synthetic profile"))?,
      mobile_vector(Bytes.empty())?,
      mobile_vector(mobile_write_u64(mobile_wide("2")?)?)?
    ],
    0,
    Bytes.empty())
end

## Each case has a fresh account pair and an independently authenticated VOR.
## The same VOR is both the actual direct attachment and part of the body.
fn body_privacy_proof(mode :: Int) -> Result<(Bool, Bool, Bool, Bool), String> do
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
    body: Bytes.from_utf8("initial ordinary text"),
    attachment: Bytes.empty()
  })?
  let _ = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: hello
  })?
  let key = platform_key()?
  let sender_session = find_peer_session(fixture.alice_path,
    key,
    bob.account_id,
    load_session_ids(fixture.alice_path, key)?,
    0)?
  let receiver_session = find_peer_session(fixture.bob_path,
    key,
    alice.account_id,
    load_session_ids(fixture.bob_path, key)?,
    0)?
  let message_id = repeated(44, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: sender_session.record.conversation_id,
    message_id: message_id
  }
  let device = open_device(bob, key, fixture.bob_path)?
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let parsed = decode_view_once_reference(reference)?
  let material = if mode == 2 do
    parsed.download_capability
  else if mode == 3 do
    parsed.wrapped_key
  else if mode == 4 do
    parsed.encrypted_manifest
  else if mode == 5 do
    parsed.object_id
  else
    reference
  end
  let body = if mode != 0 do
    encode_presented_message(material, body_privacy_profile()?, Bytes.empty())?
  else
    # Prefix plus a canonical VOR cannot be parsed as bounded presentation vectors.
    mobile_join([Bytes.from_utf8("MORSE-PRESENTATION/1\n"), reference], 0, Bytes.empty())?
  end
  let offered = repeated(80, 32)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: binding.conversation_id,
    client_message_id: message_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: body,
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: [ProtocolExtension { id: 1, mandatory: false, value: offered }]
  }
  # Prove this account pair and fixture can admit a genuine view-once message.
  let positive_id = repeated(46, 16)?
  let positive_binding = %{binding | message_id: positive_id}
  let (positive_reference, _positive_chunk, _positive_png) = view_once_receive_material(device,
    positive_binding)?
  let positive_text = Bytes.from_utf8("ordinary view once caption")
  let positive = %{inner |
    client_message_id: positive_id,
    body: positive_text,
    attachment_manifest: positive_reference,
    extensions: List.new()
  }
  let positive_wire = body_privacy_carrier(fixture.alice_path, bob_wire, positive)?
  let positive_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: positive_wire
  })
  let positive_delivered = declassify(case positive_result do
      Ok(value) -> Bytes.secure_equals(value, positive_text)
      Err(_) -> false
    end,
    "test-only delivery status for a genuine synthetic view-once control")
  let labels = [
    "sessions/v1",
    receiver_session.label,
    "history/v1/#{Bytes.to_hex(binding.conversation_id)}",
    "view-once/v1/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(message_id)}",
    "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(message_id)}",
    identity_label(binding)?,
    logical_label(bob.account_id, alice.account_id, message_id)?,
    "view-once/admission-epoch/v1",
    "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(alice.entry.mailbox_token))}",
    "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(offered))}",
    "presentation/v1/user/#{Bytes.to_hex(alice.account_id)}"
  ]
  let before = load_account_basis(fixture.bob_path, labels)?
  let history_request = request([Bytes.from_utf8(fixture.bob_path), alice_wire])?
  let history_before = load_history_export(history_request)?
  let outer = body_privacy_carrier(fixture.alice_path, bob_wire, inner)?
  let result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: outer
  })
  let refused = declassify(case result do
      Err(_) -> true
      Ok(_) -> false
    end,
    "test-only refusal status for a synthetic authenticated direct receive")
  let unchanged = same_account_basis(before, load_account_basis(fixture.bob_path, labels)?)
  let history_after = load_history_export(history_request)?
  let contains_reference = body_privacy_contains(history_after, reference, 0)
  let contains_capability = body_privacy_contains(history_after, parsed.download_capability, 0)
  let contains_wrapped = body_privacy_contains(history_after, parsed.wrapped_key, 0)
  let safe_history = declassify(Bytes.secure_equals(history_before, history_after)
      && !Result.unwrap_or(contains_reference, true)
      && !Result.unwrap_or(contains_capability, true)
      && !Result.unwrap_or(contains_wrapped, true),
    "test-only equality and absence of synthetic reference material in history export")
  # A subsequent unrelated ordinary presentation must still traverse the real
  # ratchet and be visible in the exported history after the refused message.
  let control_text = Bytes.from_utf8("ordinary control delivered")
  let control = %{inner |
    client_message_id: repeated(45, 16)?,
    body: encode_presented_message(control_text, body_privacy_profile()?, Bytes.empty())?,
    attachment_manifest: Bytes.empty(),
    extensions: List.new()
  }
  let control_wire = body_privacy_carrier(fixture.alice_path, bob_wire, control)?
  let control_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: control_wire
  })
  let control_delivered = declassify(case control_result do
      Ok(value) -> Bytes.secure_equals(value, control_text)
      Err(_) -> false
    end,
    "test-only delivery status for unrelated synthetic ordinary text")
  let final_history = load_history_export(history_request)?
  let control_visible = declassify(Result.unwrap_or(body_privacy_contains(final_history,
        control_text,
        0),
      false),
    "test-only visibility of an unrelated synthetic ordinary message")
  for path in [fixture.alice_path, fixture.bob_path, fixture.linked_path] do
    erase_local_state(path)?
    File.delete(path)?
  end
  Ok((refused, unchanged, safe_history, positive_delivered && control_delivered && control_visible))
end

test("direct view-once rejects malformed presentation containing its canonical reference") do
  case body_privacy_proof(0) do
    Err(_) -> assert(false)
    Ok((refused, unchanged, safe_history, control)) -> do
      assert(refused)
      assert(unchanged)
      assert(safe_history)
      assert(control)
    end
  end
end

test("direct view-once rejects valid presentation whose user body contains its reference") do
  case body_privacy_proof(1) do
    Err(_) -> assert(false)
    Ok((refused, unchanged, safe_history, control)) -> do
      assert(refused)
      assert(unchanged)
      assert(safe_history)
      assert(control)
    end
  end
end

test("direct view-once rejects its raw capability in the displayed body") do
  case body_privacy_proof(2) do
    Err(_) -> assert(false)
    Ok((refused, unchanged, safe_history, control)) -> do
      assert(refused)
      assert(unchanged)
      assert(safe_history)
      assert(control)
    end
  end
end

test("direct view-once rejects its wrapped key in the displayed body") do
  case body_privacy_proof(3) do
    Err(_) -> assert(false)
    Ok((refused, unchanged, safe_history, control)) -> do
      assert(refused)
      assert(unchanged)
      assert(safe_history)
      assert(control)
    end
  end
end

test("direct view-once rejects its encrypted manifest in the displayed body") do
  case body_privacy_proof(4) do
    Err(_) -> assert(false)
    Ok((refused, unchanged, safe_history, control)) -> do
      assert(refused)
      assert(unchanged)
      assert(safe_history)
      assert(control)
    end
  end
end

test("direct view-once rejects its object id in the displayed body") do
  case body_privacy_proof(5) do
    Err(_) -> assert(false)
    Ok((refused, unchanged, safe_history, control)) -> do
      assert(refused)
      assert(unchanged)
      assert(safe_history)
      assert(control)
    end
  end
end

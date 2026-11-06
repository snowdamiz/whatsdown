from Tests.HistoryFixture import fixture_direct_history
import File
from Mobile.History import decode_conversation_summary
from Mobile.HistoryWire import decode_history, encode_history
from Mobile.Inbox import process_delivery_batch
from Mobile.Types import MobileBatchRequest
from Protocol.MailboxWire import encode_delivery_batch, decode_mailbox_ack
from Protocol.V1 import DeliveredEnvelope
from Storage.Blobs import load_blob
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import platform_key
from Mobile.Types import ConversationSummary
from MobileCore import (
  create_account_export,
  list_conversations_export,
  outbox_ack_export,
  receive_initial_export,
  receive_message_export,
  remove_safety_binding_for_test,
  safety_number_export,
  send_message_export,
  start_conversation_export,
  update_conversation_export
)
from Prekeys.Bundle import normalize_prekey_bundle
from Protocol.PrekeyWire import encode_prekey_bundle
from Tests.GroupConsistencySupport import encode_set, signed_transparency_view
from Tests.GroupLifecycleSupport import install_signed_transparency
from Tests.Support import append, database_path, vector, write_u32
from Transparency.Merkle import leaf_hash
from Protocol.EnvelopeWire import decode_outer_envelope
from Protocol.IdentityWire import encode_account_identity
from Protocol.V1 import AccountIdentity, DeviceSet, DirectoryEntry, OuterEnvelope
from Transport.Packet import ClientProfile, decode_client_profile, encode_client_profile

fn assert_received_body(value :: Bool) do
  assert(declassify(value,
    "test-only Boolean assertion of controlled synthetic conversation message bodies; no application disclosure"))
end

fn encode_vectors(values :: List<Bytes>, index :: Int, output :: Bytes) -> Bytes!String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_vectors(values, index + 1, append(output, vector(List.get(values, index))?)?)
  end
end

fn request(values :: List<Bytes>) -> Bytes!String do
  encode_vectors(values, 0, Bytes.empty())
end

# The witnessed directory logs the current signed bundle without its claimed
# one-time prekey. Both HE senders need the exact own and peer sets in one view.
fn logged_set(profile :: ClientProfile) -> Bytes!String do
  let bundle = case normalize_prekey_bundle(profile.bundle) do
    Err(_) -> return Err("fixture bundle normalization failed")
    Ok(value) -> value
  end
  let wire = case encode_prekey_bundle(bundle) do
    Err(_) -> return Err("fixture bundle encoding failed")
    Ok(value) -> value
  end
  let entry = %{profile.entry | prekey_bundle: wire}
  encode_set(DeviceSet {
    version: 1,
    username: entry.username,
    account_identity: entry.account_identity,
    sequence: profile.account.directory_sequence,
    devices: [entry],
    revoked_device_ids: []
  })
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("test byte allocation failed")
    Ok(output)
  end
end

fn acknowledge(path :: String, envelope :: Bytes) -> Bool!String do
  assert(Bytes.length(outbox_ack_export(request([Bytes.from_utf8(path), envelope])?)?) == 0)
  Ok(true)
end

fn policy(path :: String, profile :: Bytes, action :: Int, value :: Int) -> Bytes!String do
  update_conversation_export(request([
    Bytes.from_utf8(path),
    profile,
    byte(action)?,
    write_u32(value)?
  ])?)
end

fn assert_summary(value :: ConversationSummary,
  username :: String,
  safety_number :: Bytes,
  request_state :: Int,
  blocked :: Bool,
  disappearing_seconds :: Int) -> Bool do
  assert(Bytes.length(value.conversation_id) == 16)
  assert(value.username == username)
  assert(Bytes.length(value.peer_account_id) == 32)
  assert(Bytes.length(value.peer_device_id) == 16)
  assert(Bytes.length(value.safety_number) == 64)
  assert(Bytes.secure_equals(value.safety_number, safety_number))
  assert(value.request_state == request_state)
  assert(value.blocked == blocked)
  assert(!value.verified)
  assert(!value.key_changed)
  assert(value.disappearing_seconds == disappearing_seconds)
  true
end

fn proof() -> Bool!String do
  assert(Test.install_in_memory_secure_store())
  let alice_path = database_path("conversation-policy-alice")?
  let bob_path = database_path("conversation-policy-bob")?
  let alice_profile = create_account_export(request([
    Bytes.from_utf8(alice_path),
    Bytes.from_utf8("alice")
  ])?)?
  let bob_profile = create_account_export(request([
    Bytes.from_utf8(bob_path),
    Bytes.from_utf8("bob")
  ])?)?
  let alice_set = logged_set(decode_client_profile(alice_profile)?)?
  let bob_set = logged_set(decode_client_profile(bob_profile)?)?
  let view = signed_transparency_view([leaf_hash(alice_set)?, leaf_hash(bob_set)?])?
  for path in [alice_path, bob_path] do
    for device_set in [alice_set, bob_set] do
      assert(install_signed_transparency(path, view, device_set)?)
    end
  end
  let greeting = Bytes.from_utf8("hello bob")
  let initial = start_conversation_export(request([
    Bytes.from_utf8(alice_path),
    bob_profile,
    greeting
  ])?)?
  assert(acknowledge(alice_path, initial)?)
  assert_received_body(Bytes.secure_equals(receive_initial_export(request([
      Bytes.from_utf8(bob_path),
      initial
    ])?)?,
    greeting))
  let alice_safety = safety_number_export(request([Bytes.from_utf8(alice_path), bob_profile])?)?
  let bob_safety = safety_number_export(request([Bytes.from_utf8(bob_path), alice_profile])?)?
  assert(Bytes.secure_equals(alice_safety, bob_safety))
  let alice_identity = decode_client_profile(alice_profile)?.account
  let bob_identity = decode_client_profile(bob_profile)?.account
  let alice_fingerprint = append(alice_identity.account_id,
    alice_identity.authorization_public_key)?
  let bob_fingerprint = append(bob_identity.account_id, bob_identity.authorization_public_key)?
  let label = Bytes.from_utf8("mesh-msg/mobile/account-safety/v2")
  let forward = Bytes.from_utf8(Bytes.to_hex(Crypto.sha256(append(label,
    append(alice_fingerprint, bob_fingerprint)?)?)))
  let reverse = Bytes.from_utf8(Bytes.to_hex(Crypto.sha256(append(label,
    append(bob_fingerprint, alice_fingerprint)?)?)))
  assert(Bytes.secure_equals(alice_safety, forward) || Bytes.secure_equals(alice_safety, reverse))
  assert(assert_summary(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path))?)?,
    "alice",
    bob_safety,
    0,
    false,
    0))
  let reply = Bytes.from_utf8("hello alice")
  let reply_request = request([Bytes.from_utf8(bob_path), alice_profile, reply])?
  case send_message_export(reply_request) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "message_request_pending")
  end
  assert(Bytes.secure_equals(policy(bob_path, alice_profile, 1, 0)?, Bytes.from_utf8("ok")))
  assert(assert_summary(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path))?)?,
    "alice",
    bob_safety,
    1,
    false,
    0))
  let reply_outer = send_message_export(reply_request)?
  let padded = case decode_outer_envelope(reply_outer) do
    Err(_) -> Err("invalid test envelope")
    Ok(value)
  end?
  assert(Bytes.length(padded.ciphertext) == padded.padding_bucket)
  assert(acknowledge(bob_path, reply_outer)?)
  assert_received_body(Bytes.secure_equals(receive_message_export(request([
      Bytes.from_utf8(alice_path),
      reply_outer
    ])?)?,
    reply))
  assert(Bytes.secure_equals(policy(bob_path, alice_profile, 2, 0)?, Bytes.from_utf8("ok")))
  assert(assert_summary(decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path))?)?,
    "alice",
    bob_safety,
    1,
    true,
    0))
  let blocked_outer = send_message_export(request([
    Bytes.from_utf8(alice_path),
    bob_profile,
    Bytes.from_utf8("blocked")
  ])?)?
  assert(acknowledge(alice_path, blocked_outer)?)
  case receive_message_export(request([Bytes.from_utf8(bob_path), blocked_outer])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "blocked_message")
  end
  assert(Bytes.secure_equals(policy(bob_path, alice_profile, 3, 0)?, Bytes.from_utf8("ok")))
  let history_request = request([Bytes.from_utf8(bob_path), alice_profile])?
  let history_before = fixture_direct_history(history_request)?
  let conversation = decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path))?)?
  let history_label = "history/v1/#{Bytes.to_hex(conversation.conversation_id)}"
  let storage_key = platform_key()?
  let stored_before = encode_history(decode_history(open_history_blob(load_blob(bob_path,
      history_label)?,
    storage_key,
    history_label)?)?)?
  assert(Bytes.secure_equals(policy(alice_path, bob_profile, 5, 1)?, Bytes.from_utf8("ok")))
  let disappearing = Bytes.from_utf8("gone soon")
  let disappearing_outer = send_message_export(request([
    Bytes.from_utf8(alice_path),
    bob_profile,
    disappearing
  ])?)?
  assert(acknowledge(alice_path, disappearing_outer)?)
  assert_received_body(Bytes.secure_equals(receive_message_export(request([
      Bytes.from_utf8(bob_path),
      disappearing_outer
    ])?)?,
    disappearing))
  assert(!Bytes.secure_equals(fixture_direct_history(history_request)?, history_before))
  let late_outer = send_message_export(request([
    Bytes.from_utf8(alice_path),
    bob_profile,
    Bytes.from_utf8("expired before delivery")
  ])?)?
  assert(acknowledge(alice_path, late_outer)?)
  Timer.sleep(2000)
  let late_batch = case encode_delivery_batch([
    DeliveredEnvelope { sequence: U64.parse("1")?, envelope: late_outer }
  ]) do
    Err(_) -> Err("fixture batch encoding failed")
    Ok(value)
  end?
  let ack = process_delivery_batch(MobileBatchRequest {
    database_path: bob_path,
    batch: late_batch
  })?
  let accepted = case decode_mailbox_ack(ack) do
    Err(_) -> Err("fixture ack decoding failed")
    Ok(value)
  end?
  assert(List.length(accepted.envelope_ids) == 1)
  # No display/history export may hide this newly received expired message.
  assert(Bytes.secure_equals(encode_history(decode_history(open_history_blob(load_blob(bob_path,
        history_label)?,
      storage_key,
      history_label)?)?)?,
    stored_before))
  assert(Bytes.secure_equals(fixture_direct_history(history_request)?, history_before))
  case decode_conversation_summary(Bytes.empty()) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  assert(remove_safety_binding_for_test(bob_path, alice_profile)?)
  let legacy = decode_conversation_summary(list_conversations_export(Bytes.from_utf8(bob_path))?)?
  assert(!legacy.verified && legacy.key_changed && Bytes.length(legacy.safety_number) == 0)
  case policy(bob_path, alice_profile, 4, 0) do
    Ok(_) -> assert(false)
    Err(_) -> assert(true)
  end
  let replacement = case encode_account_identity(%{bob_identity |
    authorization_public_key: alice_identity.authorization_public_key
  }) do
    Err(_) -> Err("test account encoding failed")
    Ok(value)
  end?
  let bob = decode_client_profile(bob_profile)?
  let changed_profile = encode_client_profile(%{bob.entry | account_identity: replacement},
    bob.account_id,
    bob.device_id)?
  case send_message_export(request([
    Bytes.from_utf8(alice_path),
    changed_profile,
    Bytes.from_utf8("must not send")
  ])?) do
    Ok(_) -> assert(false)
    Err(error) -> assert(error == "peer_keys_changed")
  end
  File.delete(alice_path)?
  File.delete(bob_path)?
  Ok(true)
end

test("mobile conversation policy and disappearing history are proven in Mesh") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

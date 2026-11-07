##! Synthetic accounts and authenticated carriers; no object-store requests.
import File
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Messages import start_conversation, receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  load_session_ids,
  find_peer_session,
  restore_session,
  seal_updated_session,
  ratchet_bytes,
  inner_bytes
)
from Mobile.Types import MobileStartRequest, MobileReceiveRequest, MobileBatchRequest
from Mobile.Transport import sealed_outer_bytes
from Mobile.Codec import canonical_outer, current_time
from Mobile.Inbox import process_delivery_batch, permanent_direct_delivery_error
from Mobile.InboxState import load_delivery_attempts, load_fetch_cursor
from Mobile.HistoryWire import decode_history
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import platform_key
from Storage.Blobs import load_blob
from Storage.AccountGuard import load_account_basis, commit_account_changes
from Storage.Records import erase_local_state, store_record_changes
from Session.Ratchet import encrypt_sealed
from Transport.Packet import decode_client_profile, encode_packet, session_aad
from Protocol.V1 import InnerEnvelope, DeliveredEnvelope
from Protocol.MailboxWire import (
  encode_delivery_batch,
  decode_mailbox_ack,
  mailbox_ack_signing_bytes
)
from Tests.GroupLifecycleSupport import group_account_fixture, install_signed_transparency
from Tests.GroupConsistencySupport import signed_transparency_view
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import identity_label
from Tests.Support import repeated
from Transparency.Merkle import leaf_hash

## Advance and durably save the sender's real session for each independent carrier.
fn encrypted_carrier(path :: String, peer_wire :: Bytes, inner :: InnerEnvelope) -> Bytes!String do
  let key = platform_key()?
  let peer = decode_client_profile(peer_wire)?
  let loaded = find_peer_session(path, key, peer.account_id, load_session_ids(path, key)?, 0)?
  let before = load_account_basis(path, ["sessions/v1", loaded.label])?
  let (next, message) = case encrypt_sealed(restore_session(loaded, key)?,
    inner_bytes(inner)?,
    session_aad(loaded.session_id)?) do
    Err(_) -> return Err("view_once_epoch_test_encrypt")
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

fn missing(path :: String, label :: String) -> Bool do
  case load_blob(path, label) do
    Err("local_state_not_found") -> true
    _ -> false
  end
end

fn epoch_matches(path :: String, label :: String, corrupt :: Bool, value :: Bytes) -> Bool do
  if corrupt do
    case load_blob(path, label) do
      Ok(stored) -> Bytes.secure_equals(stored, value)
      Err(_) -> false
    end
  else
    missing(path, label)
  end
end

fn proof(corrupt :: Bool) -> Result<(Bool, Bool, Bool, Bool, Bool), String> do
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
    body: Bytes.from_utf8("hello"),
    attachment: Bytes.empty()
  })?
  receive_initial_message(MobileReceiveRequest { database_path: fixture.bob_path, outer: hello })?
  let key = platform_key()?
  let loaded = find_peer_session(fixture.alice_path,
    key,
    bob.account_id,
    load_session_ids(fixture.alice_path, key)?,
    0)?
  let direct_id = repeated(60, 16)?
  let mailbox_id = repeated(61, 16)?
  let later_id = repeated(62, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: loaded.record.conversation_id,
    message_id: direct_id
  }
  let device = open_device(bob, key, fixture.bob_path)?
  let (direct_reference, _direct_chunk, _direct_png) = view_once_receive_material(device, binding)?
  let mailbox_binding = %{binding | message_id: mailbox_id}
  let (mailbox_reference, _mailbox_chunk, _mailbox_png) = view_once_receive_material(device,
    mailbox_binding)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: binding.conversation_id,
    client_message_id: direct_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("private image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: direct_reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let direct = encrypted_carrier(fixture.alice_path, bob_wire, inner)?
  let first = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner | client_message_id: mailbox_id, attachment_manifest: mailbox_reference})?
  let later = encrypted_carrier(fixture.alice_path,
    bob_wire,
    %{inner |
      client_message_id: later_id,
      body: Bytes.from_utf8("later ordinary"),
      attachment_manifest: Bytes.empty()
    })?
  let epoch_label = "view-once/admission-epoch/v1"
  let corrupt_value = Bytes.from_utf8("synthetic corrupt epoch")
  if corrupt do
    store_record_changes(fixture.bob_path, [epoch_label], [corrupt_value], [])?
  else
    store_record_changes(fixture.bob_path, [], [], [epoch_label])?
  end
  let epoch_setup = epoch_matches(fixture.bob_path, epoch_label, corrupt, corrupt_value)
  # A distinct carrier checks the actual receive error and its inbox classification.
  let direct_result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: direct
  })
  let permanent = declassify(case direct_result do
      Err(error) -> error == "view_once_reference_refused" && permanent_direct_delivery_error(error)
      Ok(_) -> false
    end,
    "test-only classification of an authenticated synthetic view-once refusal")
  let epoch_before_batch = epoch_matches(fixture.bob_path, epoch_label, corrupt, corrupt_value)
  let batch = case encode_delivery_batch([
    DeliveredEnvelope { sequence: U64.parse("1")?, envelope: first },
    DeliveredEnvelope { sequence: U64.parse("2")?, envelope: later }
  ]) do
    Err(_) -> return Err("view_once_epoch_test_batch")
    Ok(value) -> value
  end
  let answer = process_delivery_batch(MobileBatchRequest {
    database_path: fixture.bob_path,
    batch: batch
  })?
  let ack = case decode_mailbox_ack(answer) do
    Err(_) -> return Err("view_once_epoch_test_ack")
    Ok(value) -> value
  end
  let first_id = canonical_outer(first)?.envelope_id
  let later_outer_id = canonical_outer(later)?.envelope_id
  let signing_bytes = case mailbox_ack_signing_bytes(ack) do
    Err(_) -> return Err("view_once_epoch_test_ack_signing_bytes")
    Ok(value) -> value
  end
  let signature_valid = case Crypto.verify(SigningPublicKey {
      bytes: bob.credential.signing_public_key
    },
    signing_bytes,
    Signature { bytes: ack.signature }) do
    Ok(value) -> value
    Err(_) -> false
  end
  let acknowledged = List.length(ack.envelope_ids) == 2
    && Bytes.secure_equals(List.get(ack.envelope_ids, 0), first_id)
    && Bytes.secure_equals(List.get(ack.envelope_ids, 1), later_outer_id)
    && Bytes.secure_equals(ack.mailbox_token_hash, Crypto.sha256(bob.entry.mailbox_token))
    && signature_valid
    && Bytes.length(load_delivery_attempts(fixture.bob_path, key)?) == 0
    && U64.compare(load_fetch_cursor(fixture.bob_path, key)?, U64.parse("0")?) == 0
  let direct_row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(direct_id)}"
  let mailbox_row = "view-once/v2/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(mailbox_id)}"
  let direct_legacy = "view-once/v1/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(direct_id)}"
  let mailbox_legacy = "view-once/v1/#{Bytes.to_hex(binding.conversation_id)}/#{Bytes.to_hex(mailbox_id)}"
  let no_pending = missing(fixture.bob_path, direct_row)
    && missing(fixture.bob_path, mailbox_row)
    && missing(fixture.bob_path, direct_legacy)
    && missing(fixture.bob_path, mailbox_legacy)
    && missing(fixture.bob_path, identity_label(binding)?)
    && missing(fixture.bob_path, identity_label(mailbox_binding)?)
  let history_label = "history/v1/#{Bytes.to_hex(binding.conversation_id)}"
  let history = decode_history(open_history_blob(load_blob(fixture.bob_path, history_label)?,
    key,
    history_label)?)?
  let history_ok = List.length(history) == 2
    && Bytes.secure_equals(List.last(history).inner.client_message_id, later_id)
    && Bytes.secure_equals(List.last(history).inner.body, Bytes.from_utf8("later ordinary"))
  let history_ok = declassify(history_ok,
    "test-only synthetic history has the initial and later ordinary messages only")
  erase_local_state(fixture.alice_path)?
  erase_local_state(fixture.bob_path)?
  erase_local_state(fixture.linked_path)?
  File.delete(fixture.alice_path)?
  File.delete(fixture.bob_path)?
  File.delete(fixture.linked_path)?
  Ok((epoch_setup && epoch_before_batch, permanent, acknowledged, no_pending, history_ok))
end

fn check(corrupt :: Bool) do
  let (setup, permanent, acknowledged, no_pending, history) = case proof(corrupt) do
    Err(error) -> do
      println(error)
      (false, false, false, false, false)
    end
    Ok(value) -> value
  end
  assert(setup)
  assert(permanent)
  assert(acknowledged)
  assert(no_pending)
  assert(history)
end

test("missing view-once admission epoch refuses and acknowledges without starving mailbox") do
  check(false)
end

test("corrupt view-once admission epoch refuses and acknowledges without starving mailbox") do
  check(true)
end

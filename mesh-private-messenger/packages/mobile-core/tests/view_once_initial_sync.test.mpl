##! No network: real authenticated initial and linked-device carriers with synthetic images.
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time, mobile_append
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import encode_sync_payload, self_sync_conversation_id
from Mobile.Types import MobileReceiveRequest
from Protocol.V1 import InnerEnvelope
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import one_time_prekey_label, platform_key
from Tests.Support import repeated
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import (
  InitialSyncFixture,
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  sibling_carrier,
  pending_label,
  identity_label,
  logical_label,
  history_label,
  pending_and_history,
  fail_write
)
from Transport.Packet import decode_client_profile, direct_conversation_id

fn check(value :: Plaintext<Bool>, label :: String) -> Unit!String do
  if declassify(value, "test-only observation of a synthetic authenticated view-once admission") do
    Ok(nil)
  else
    Err(label)
  end
end

fn receive_fixture(path :: String, wire :: Bytes, initial :: Bool) -> Bytes!String do
  let request = MobileReceiveRequest { database_path: path, outer: wire }
  if initial do
    receive_initial_message(request)
  else
    receive_message(request)
  end
end

fn rollback(path :: String,
  wire :: Bytes,
  initial :: Bool,
  labels :: List<String>,
  fail_label :: String) -> Unit!String do
  let before = load_account_basis(path, labels)?
  fail_write(path, fail_label, true)?
  let rejected = receive_fixture(path, wire, initial)
  fail_write(path, fail_label, false)?
  let failed = case rejected do
    Err("database_write_failed") -> true
    _ -> false
  end
  check(failed, "injected database failure did not reject receive")?
  check(same_account_basis(before, load_account_basis(path, labels)?),
    "failed receive changed session, prekey, pending, or history")
end

fn direct(fixture :: InitialSyncFixture) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let bob_device = open_device(bob, key, fixture.bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let id = repeated(71, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: conversation,
    message_id: id
  }
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("initial image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let row = pending_label(conversation, id)
  let identity = identity_label(binding)?
  let logical = logical_label(bob.account_id, alice.account_id, id)?
  let history = history_label(conversation)
  let base_labels = [
    "sessions/v1",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(bob.bundle.one_time_prekey_id),
    row,
    identity,
    logical,
    history
  ]
  let before = load_account_basis(fixture.bob_path, base_labels)?
  let forged = [
    %{binding | sender_account_id: repeated(91, 32)?},
    %{binding | sender_device_id: repeated(92, 16)?},
    %{binding | receiver_account_id: repeated(93, 32)?},
    %{binding | receiver_device_id: repeated(94, 16)?},
    %{binding | conversation_id: repeated(95, 16)?},
    %{binding | message_id: repeated(96, 16)?}
  ]
  for bad in forged do
    let (reference, _chunk, _png) = view_once_receive_material(bob_device, bad)?
    let (_state, wire) = initial_carrier(fixture.alice_path,
      fixture.bob_path,
      %{inner | attachment_manifest: reference})?
    let result = receive_fixture(fixture.bob_path, wire, true)
    check(case result do
        Err("view_once_reference_refused") -> true
        _ -> false
      end,
      "forged initial binding accepted")?
    check(same_account_basis(before, load_account_basis(fixture.bob_path, base_labels)?),
      "forged initial binding changed durable state")?
  end
  let (reference, _chunk, _png) = view_once_receive_material(bob_device, binding)?
  let (state, wire) = initial_carrier(fixture.alice_path,
    fixture.bob_path,
    %{inner | attachment_manifest: reference})?
  let session_label = "session/v1/#{Bytes.to_hex(state.session_id)}"
  let labels = base_labels ++ [session_label]
  rollback(fixture.bob_path, wire, true, labels, row)?
  rollback(fixture.bob_path, wire, true, labels, identity)?
  rollback(fixture.bob_path, wire, true, labels, logical)?
  rollback(fixture.bob_path, wire, true, labels, history)?
  let delivered = receive_fixture(fixture.bob_path, wire, true)?
  check(Bytes.secure_equals(delivered, inner.body), "initial body missing")?
  check(pending_and_history(fixture.bob_path, conversation, id, reference, 1)?,
    "initial pending and sanitized history missing")?
  check(Result.is_ok(load_blob(fixture.bob_path, identity)), "initial identity missing")?
  Ok(nil)
end

fn sync(fixture :: InitialSyncFixture) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let sibling = decode_client_profile(load_profile(fixture.linked_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let sibling_device = open_device(sibling, key, fixture.linked_path)?
  let original_conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let transport_conversation = self_sync_conversation_id(alice.account_id)?
  let original_id = repeated(72, 16)?
  let transport_id = repeated(73, 16)?
  let original = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: original_conversation,
    client_message_id: original_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synchronized image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: sibling.account_id,
    receiver_device_id: sibling.device_id,
    conversation_id: original_conversation,
    message_id: original_id
  }
  let envelope = %{original |
    recipient_device_id: sibling.device_id,
    conversation_id: transport_conversation,
    client_message_id: transport_id,
    message_type: 2,
    body: encode_sync_payload(alice, bob, original)?
  }
  let row = pending_label(original_conversation, original_id)
  let identity = identity_label(binding)?
  let logical = logical_label(sibling.account_id, bob.account_id, original_id)?
  let history = history_label(original_conversation)
  let wrong_row = pending_label(transport_conversation, transport_id)
  let alias_id = Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/conversation-alias/v1"),
    bob.account_id)?)
  let alias_label = "session/v1/#{Bytes.to_hex(alias_id)}"
  let base_labels = [
    "sessions/v1",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(sibling.bundle.one_time_prekey_id),
    row,
    identity,
    logical,
    history,
    wrong_row,
    alias_label
  ]
  let before = load_account_basis(fixture.linked_path, base_labels)?
  let forged = [
    %{binding | sender_account_id: repeated(91, 32)?},
    %{binding | sender_device_id: repeated(92, 16)?},
    %{binding | receiver_account_id: repeated(93, 32)?},
    %{binding | receiver_device_id: repeated(94, 16)?},
    %{binding | conversation_id: transport_conversation},
    %{binding | message_id: transport_id}
  ]
  for bad in forged do
    let (reference, _chunk, _png) = view_once_receive_material(sibling_device, bad)?
    let (_state, wire) = initial_carrier(fixture.alice_path,
      fixture.linked_path,
      %{envelope | attachment_manifest: reference})?
    let result = receive_fixture(fixture.linked_path, wire, true)
    check(case result do
        Err("view_once_reference_refused") -> true
        _ -> false
      end,
      "forged initial sync binding accepted")?
    check(same_account_basis(before, load_account_basis(fixture.linked_path, base_labels)?),
      "forged initial sync changed durable state")?
  end
  let (reference, _chunk, _png) = view_once_receive_material(sibling_device, binding)?
  let (state, wire) = initial_carrier(fixture.alice_path,
    fixture.linked_path,
    %{envelope | attachment_manifest: reference})?
  let session_label = "session/v1/#{Bytes.to_hex(state.session_id)}"
  let labels = base_labels ++ [session_label]
  rollback(fixture.linked_path, wire, true, labels, row)?
  rollback(fixture.linked_path, wire, true, labels, identity)?
  rollback(fixture.linked_path, wire, true, labels, logical)?
  rollback(fixture.linked_path, wire, true, labels, history)?
  let delivered = receive_fixture(fixture.linked_path, wire, true)?
  check(Bytes.secure_equals(delivered, original.body), "initial sync body missing")?
  check(pending_and_history(fixture.linked_path, original_conversation, original_id, reference, 1)?,
    "initial sync did not preserve original binding")?
  check(Result.is_ok(load_blob(fixture.linked_path, identity)), "sync identity missing")?
  check(Result.is_err(load_blob(fixture.linked_path, wrong_row)),
    "pending stored under transport binding")?
  # The same VOR and original message cannot be replayed as belonging to a
  # different peer, nor can it create an alias as a side effect of a duplicate.
  let other_peer = %{bob | account_id: repeated(88, 32)?, username: "other-peer"}
  let other_alias_id = Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/conversation-alias/v1"),
    other_peer.account_id)?)
  let other_alias_label = "session/v1/#{Bytes.to_hex(other_alias_id)}"
  let duplicate_transport_id = repeated(76, 16)?
  let duplicate_envelope = %{envelope |
    client_message_id: duplicate_transport_id,
    body: encode_sync_payload(alice, other_peer, original)?,
    attachment_manifest: reference
  }
  let (state, duplicate_wire) = sibling_carrier(state, sibling, duplicate_envelope)?
  let duplicate_labels = [
    "sessions/v1",
    session_label,
    alias_label,
    history,
    row,
    identity,
    other_alias_label
  ]
  let before_duplicate = load_account_basis(fixture.linked_path, duplicate_labels)?
  let duplicate_result = receive_fixture(fixture.linked_path, duplicate_wire, false)
  let rejected = declassify(case duplicate_result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only refusal of a synthetic sibling duplicate with a different peer")
  let alias_safe = same_account_basis(before_duplicate,
    load_account_basis(fixture.linked_path, duplicate_labels)?)
  if !alias_safe do
    println("TEST_SYNTHETIC_SYNC_DUPLICATE_CHANGED_ALIAS_OR_SESSION")
  end
  check(rejected && alias_safe, "sync duplicate with changed peer mutated state")?
  # Continue with the actual initiator ratchet from that handshake.
  let next_id = repeated(74, 16)?
  let next_transport_id = repeated(75, 16)?
  let next_original = %{original | client_message_id: next_id}
  let next_binding = %{binding | message_id: next_id}
  let (forged_reference, _chunk, _png) = view_once_receive_material(sibling_device,
    %{next_binding | conversation_id: transport_conversation, message_id: next_transport_id})?
  let forged_envelope = %{envelope |
    client_message_id: next_transport_id,
    body: encode_sync_payload(alice, bob, next_original)?,
    attachment_manifest: forged_reference
  }
  let (state, forged_wire) = sibling_carrier(state, sibling, forged_envelope)?
  let next_row = pending_label(original_conversation, next_id)
  let next_wrong = pending_label(transport_conversation, next_transport_id)
  let next_labels = ["sessions/v1", session_label, alias_label, history, next_row, next_wrong]
  let before_forgery = load_account_basis(fixture.linked_path, next_labels)?
  check(case receive_fixture(fixture.linked_path, forged_wire, false) do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "ratchet sync accepted the synthetic transport binding")?
  check(same_account_basis(before_forgery, load_account_basis(fixture.linked_path, next_labels)?),
    "forged ratchet sync changed durable state")?
  let (next_reference, _chunk, _png) = view_once_receive_material(sibling_device, next_binding)?
  let next_envelope = %{envelope |
    client_message_id: next_transport_id,
    body: encode_sync_payload(alice, bob, next_original)?,
    attachment_manifest: next_reference
  }
  let (_next, next_wire) = sibling_carrier(state, sibling, next_envelope)?
  rollback(fixture.linked_path, next_wire, false, next_labels, next_row)?
  rollback(fixture.linked_path, next_wire, false, next_labels, history)?
  let next_delivered = receive_fixture(fixture.linked_path, next_wire, false)?
  check(Bytes.secure_equals(next_delivered, original.body), "ratchet sync body missing")?
  check(pending_and_history(fixture.linked_path,
      original_conversation,
      next_id,
      next_reference,
      2)?,
    "ratchet sync did not preserve original binding")?
  check(Result.is_err(load_blob(fixture.linked_path, next_wrong)),
    "ratchet pending stored under transport binding")
end

fn proof() -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = case direct(fixture) do
    Err(error)
    Ok(_) -> sync(fixture)
  end
  let cleanup = clear_initial_sync_fixture(fixture)
  cleanup?
  result
end

test("authenticated initial receive and sibling sync commit pending and sanitized original history atomically") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

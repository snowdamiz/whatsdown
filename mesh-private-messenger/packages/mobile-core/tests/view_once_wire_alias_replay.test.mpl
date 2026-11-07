##! Synthetic linked-device receives across a local peer conversation migration; no network.
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import (
  encode_sync_payload,
  self_sync_conversation_id,
  load_session_ids,
  find_peer_session,
  updated_session_record
)
from Mobile.Types import MobileReceiveRequest
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, seal_local
from Storage.Records import store_updated_blobs
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
  history_label,
  pending_and_history
)
from Transport.Packet import decode_client_profile, direct_conversation_id

fn wire_alias_check(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value, "test-only observation of synthetic view-once replay state") do
    Ok(nil)
  else
    Err(message)
  end
end

fn wire_alias_replay_body(fixture :: InitialSyncFixture, ordinary :: Bool) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let sibling = decode_client_profile(load_profile(fixture.linked_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let device = open_device(sibling, key, fixture.linked_path)?
  let original_conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let migrated_conversation = repeated(144, 16)?
  wire_alias_check(!Bytes.secure_equals(original_conversation, migrated_conversation),
    "fixture wire conversation did not change")?
  let id = repeated(145, 16)?
  let original = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: original_conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic synchronized image"),
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
    message_id: id
  }
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let envelope = %{original |
    recipient_device_id: sibling.device_id,
    conversation_id: self_sync_conversation_id(alice.account_id)?,
    client_message_id: repeated(146, 16)?,
    message_type: 2,
    body: encode_sync_payload(alice, bob, original)?,
    attachment_manifest: reference
  }
  let (state, first_wire) = initial_carrier(fixture.alice_path, fixture.linked_path, envelope)?
  let transport_label = "session/v1/#{Bytes.to_hex(state.session_id)}"
  let first = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: first_wire
  })?
  wire_alias_check(Bytes.secure_equals(first, original.body),
    "initial sibling sync was not accepted")?
  wire_alias_check(pending_and_history(fixture.linked_path,
      original_conversation,
      id,
      reference,
      1)?,
    "initial sync did not retain the original pending and history")?
  let original_marker = identity_label(binding)?
  wire_alias_check(Result.is_ok(load_blob(fixture.linked_path, original_marker)),
    "initial sync did not retain its identity marker")?
  # Change only the legitimate peer session's local conversation selector.
  let peer = find_peer_session(fixture.linked_path,
    key,
    bob.account_id,
    load_session_ids(fixture.linked_path, key)?,
    0)?
  let changed = %{peer.record | conversation_id: migrated_conversation, request_state: 0}
  let changed_blob = seal_local(updated_session_record(changed.snapshot, changed)?,
    key,
    local_context(peer.label)?)?
  store_updated_blobs(fixture.linked_path, [peer.label], [changed_blob])?
  # The replacement is freshly sealed for the same receiver, with a valid new
  # wire binding. It is not a replay of the old reference or transport packet.
  let migrated_binding = %{binding | conversation_id: migrated_conversation}
  let (migrated_reference, _next_chunk, _next_png) = view_once_receive_material(device,
    migrated_binding)?
  wire_alias_check(!Bytes.secure_equals(reference, migrated_reference),
    "replacement reference was not independently created")?
  let migrated_original = %{original | conversation_id: migrated_conversation}
  let offered = repeated(147, 32)?
  let replay = %{envelope |
    client_message_id: repeated(148, 16)?,
    body: encode_sync_payload(alice, bob, migrated_original)?,
    attachment_manifest: if ordinary do
      Bytes.empty()
    else
      migrated_reference
    end,
    extensions: [ProtocolExtension { id: 1, mandatory: false, value: offered }]
  }
  let (_next, replay_wire) = sibling_carrier(state, sibling, replay)?
  let contact_label = "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(alice.entry.mailbox_token))}"
  let owner_label = "peer-contact-owner/v1/#{Bytes.to_hex(Crypto.sha256(offered))}"
  let migrated_marker = identity_label(migrated_binding)?
  let labels = [
    "sessions/v1",
    transport_label,
    peer.label,
    history_label(original_conversation),
    history_label(migrated_conversation),
    pending_label(original_conversation, id),
    pending_label(migrated_conversation, id),
    "view-once/v1/#{Bytes.to_hex(original_conversation)}/#{Bytes.to_hex(id)}",
    "view-once/v1/#{Bytes.to_hex(migrated_conversation)}/#{Bytes.to_hex(id)}",
    original_marker,
    migrated_marker,
    contact_label,
    owner_label,
    "contact-address/v1",
    "contact-address-pending/v1"
  ]
  let before = load_account_basis(fixture.linked_path, labels)?
  let result = receive_message(MobileReceiveRequest {
    database_path: fixture.linked_path,
    outer: replay_wire
  })
  wire_alias_check(case result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "same peer and message id with a new wire conversation was not refused")?
  wire_alias_check(same_account_basis(before, load_account_basis(fixture.linked_path, labels)?),
    "refusal changed session, alias, request, contact, history, pending or identity")?
  wire_alias_check(pending_and_history(fixture.linked_path,
      original_conversation,
      id,
      reference,
      1)?,
    "refusal did not preserve the original pending and history")?
  wire_alias_check(Result.is_err(load_blob(fixture.linked_path,
      pending_label(migrated_conversation, id)))
      && Result.is_err(load_blob(fixture.linked_path, history_label(migrated_conversation)))
      && Result.is_err(load_blob(fixture.linked_path, migrated_marker)),
    "replay created a second pending, history or identity")
end

fn wire_alias_replay(ordinary :: Bool) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = wire_alias_replay_body(fixture, ordinary)
  clear_initial_sync_fixture(fixture)?
  result
end

test("a fresh view-once reference for a migrated wire alias cannot replay a sibling sync") do
  case wire_alias_replay(false) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

test("an ordinary sibling sync for a migrated wire alias cannot bypass a prior view-once") do
  case wire_alias_replay(true) do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

##! Synthetic authenticated direct receives after local history eviction.
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileReceiveRequest
from Protocol.V1 import InnerEnvelope
from Storage.AccountGuard import load_account_basis, same_account_basis, commit_account_changes
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, local_context, seal_local
from Storage.ViewOnce import ViewOnceRecord, encode_view_once_record
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
  pending_and_history
)
from Transport.Packet import decode_client_profile, direct_conversation_id

fn evicted_check(value :: Plaintext<Bool>, reason :: String) -> Unit!String do
  if declassify(value, "test-only result for synthetic evicted view-once receive") do
    Ok(nil)
  else
    Err(reason)
  end
end

fn evicted_duplicate_body(fixture :: InitialSyncFixture,
  field :: Int,
  terminal :: Int) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let device = open_device(bob, key, fixture.bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let id = repeated(211, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: conversation,
    message_id: id
  }
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let original = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic caption"),
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let (first_state, first_wire) = initial_carrier(fixture.alice_path, fixture.bob_path, original)?
  let session = "session/v1/#{Bytes.to_hex(first_state.session_id)}"
  let first = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: first_wire
  })?
  evicted_check(Bytes.secure_equals(first, original.body), "initial receive failed")?
  evicted_check(pending_and_history(fixture.bob_path, conversation, id, reference, 1)?,
    "initial pending and history missing")?
  let pending = pending_label(conversation, id)
  let history = history_label(conversation)
  let identity = identity_label(binding)?
  let logical = logical_label(bob.account_id, alice.account_id, id)?
  let epoch = "view-once/admission-epoch/v1"
  let contact = "peer-contact-address/v1/#{Bytes.to_hex(Crypto.sha256(alice.entry.mailbox_token))}"
  let labels = [
    "sessions/v1",
    session,
    history,
    pending,
    "view-once/v1/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(id)}",
    identity,
    logical,
    epoch,
    contact,
    "contact-address/v1",
    "contact-address-pending/v1"
  ]
  evicted_check(Result.is_ok(load_blob(fixture.bob_path, identity))
      && Result.is_ok(load_blob(fixture.bob_path, logical))
      && Result.is_ok(load_blob(fixture.bob_path, epoch))
      && Result.is_ok(load_blob(fixture.bob_path, session)),
    "initial durable markers, epoch or session missing")?
  # Evict only history. Terminal variants replace the admitted row with the
  # same reference digest, modelling an already consumed or expired item.
  let before_evict = load_account_basis(fixture.bob_path, labels)?
  if terminal == 0 do
    commit_account_changes(fixture.bob_path, before_evict, [], [], [history])?
  else
    let record = if terminal == 1 do
      ConsumedV2(Crypto.sha256(reference))
    else
      Expired(Crypto.sha256(reference))
    end
    let sealed = seal_local(encode_view_once_record(record)?, key, local_context(pending)?)?
    commit_account_changes(fixture.bob_path, before_evict, [pending], [sealed], [history])?
  end
  evicted_check(Result.is_err(load_blob(fixture.bob_path, history))
      && Result.is_ok(load_blob(fixture.bob_path, pending))
      && Result.is_ok(load_blob(fixture.bob_path, identity))
      && Result.is_ok(load_blob(fixture.bob_path, logical)),
    "eviction did not preserve the retained identity")?
  let stable_labels = [
    "sessions/v1",
    history,
    pending,
    "view-once/v1/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(id)}",
    identity,
    logical,
    epoch,
    contact,
    "contact-address/v1",
    "contact-address-pending/v1"
  ]
  let stable_before = load_account_basis(fixture.bob_path, stable_labels)?
  let (second_state, duplicate_wire) = sibling_carrier(first_state, bob, original)?
  let duplicate = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: duplicate_wire
  })?
  evicted_check(Bytes.length(duplicate) == 0, "exact duplicate was delivered")?
  evicted_check(same_account_basis(stable_before,
      load_account_basis(fixture.bob_path, stable_labels)?),
    "exact duplicate changed durable message state")?
  let changed = if field == 1 do
    %{original | body: Bytes.from_utf8("different synthetic caption")}
  else if field == 2 do
    %{original | client_timestamp: U64.add(original.client_timestamp, U64.parse("1")?)?}
  else if field == 3 do
    %{original | disappearing_seconds: 60}
  else if field == 4 do
    %{original | reply_reference: repeated(212, 16)?}
  else
    %{original | receipt_policy: 1}
  end
  let (_third_state, changed_wire) = sibling_carrier(second_state, bob, changed)?
  # Capture after the duplicate: the receiver may have advanced its ratchet.
  let before_refusal = load_account_basis(fixture.bob_path, labels)?
  let result = receive_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: changed_wire
  })
  let refused = declassify(case result do
      Err("view_once_reference_refused") -> true
      _ -> false
    end,
    "test-only synthetic changed duplicate refusal status")
  if !refused do
    println("TEST_CHANGED_DUPLICATE_NOT_REFUSED")
  end
  evicted_check(refused, "changed duplicate was not refused")?
  evicted_check(same_account_basis(before_refusal, load_account_basis(fixture.bob_path, labels)?),
    "refusal changed captured account, session, history, marker, epoch or contact state")
end

fn evicted_duplicate(field :: Int, terminal :: Int) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = evicted_duplicate_body(fixture, field, terminal)
  clear_initial_sync_fixture(fixture)?
  result
end

test("evicted view-once history rejects a changed body") do
  assert(Result.is_ok(evicted_duplicate(1, 0)))
end

test("evicted view-once history rejects a changed timestamp") do
  assert(Result.is_ok(evicted_duplicate(2, 0)))
end

test("evicted view-once history rejects a changed expiry") do
  assert(Result.is_ok(evicted_duplicate(3, 0)))
end

test("evicted view-once history rejects a changed reply") do
  assert(Result.is_ok(evicted_duplicate(4, 0)))
end

test("evicted view-once history rejects a changed receipt policy") do
  assert(Result.is_ok(evicted_duplicate(5, 0)))
end

test("consumed view-once without history rejects a changed body") do
  assert(Result.is_ok(evicted_duplicate(1, 1)))
end

test("expired view-once without history rejects a changed body") do
  assert(Result.is_ok(evicted_duplicate(1, 2)))
end

test("consumed view-once without history rejects a changed expiry") do
  assert(Result.is_ok(evicted_duplicate(3, 1)))
end

test("expired view-once without history rejects a changed expiry") do
  assert(Result.is_ok(evicted_duplicate(3, 2)))
end

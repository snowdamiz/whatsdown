##! Deterministic admission transaction fence and authenticated receive rollback.
from Attachments.ViewOnce import ViewOnceBinding
from Mobile.Codec import current_time
from Mobile.HeaderAdmission import commit_initial_admission
from Mobile.History import captured_history_match, updated_history_with_kind
from Mobile.Messages import receive_initial_message
from Mobile.Profile import load_profile, open_device
from Mobile.Sessions import seal_session_ids
from Mobile.Types import MobileReceiveRequest, MobileHistoryAttachment
from Mobile.ViewOnceAdmission import (
  view_once_epoch_label,
  seal_view_once_epoch,
  require_view_once_epoch,
  prepare_view_once_pending,
  prepare_view_once_write
)
from Protocol.V1 import InnerEnvelope
from Storage.AccountGuard import load_account_basis, same_account_basis
from Storage.Blobs import load_blob
from Storage.Keys import platform_key, seal_local, local_context, one_time_prekey_label
from Storage.Records import store_record_changes
from Tests.Support import repeated
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import (
  InitialSyncFixture,
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  pending_label,
  identity_label,
  logical_label,
  history_label,
  pending_and_history,
  fail_write
)
from Transport.Packet import decode_client_profile, direct_conversation_id

fn fence_check(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value, "test-only observation of synthetic admission transaction state") do
    Ok(nil)
  else
    Err(message)
  end
end

fn epoch_fence(fixture :: InitialSyncFixture) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let device = open_device(bob, key, fixture.bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let id = repeated(221, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: conversation,
    message_id: id
  }
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic fenced image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let row = pending_label(conversation, id)
  let identity = identity_label(binding)?
  let logical = logical_label(bob.account_id, alice.account_id, id)?
  let history = history_label(conversation)
  let session_id = repeated(222, 32)?
  let session = "session/v1/#{Bytes.to_hex(session_id)}"
  let epoch = view_once_epoch_label()
  let labels = [
    "sessions/v1",
    session,
    history,
    "view-once/v1/#{Bytes.to_hex(conversation)}/#{Bytes.to_hex(id)}",
    row,
    identity,
    logical,
    epoch
  ]
  let before = load_account_basis(fixture.bob_path, labels)?
  require_view_once_epoch(key, before, bob.account_id, bob.device_id)?
  let now = current_time()?
  let pending = prepare_view_once_pending(device, binding, reference, None, now)?
  let write = prepare_view_once_write(key,
    before,
    conversation,
    conversation,
    id,
    bob.account_id,
    alice.account_id,
    identity,
    logical,
    pending,
    captured_history_match(key, before, inner, 1),
    Ok(Crypto.sha256(Bytes.from_utf8("synthetic content identity"))),
    now)?
  fence_check(!write.duplicate, "fixture unexpectedly prepared a duplicate")?
  let (history_labels, history_blobs) = updated_history_with_kind(fixture.bob_path,
    key,
    %{inner | attachment_manifest: Bytes.empty()},
    1,
    HistoryViewOnce)?
  let write_labels = history_labels ++ [write.label, write.identity_label, write.logical_label]
  let write_blobs = history_blobs ++ [write.blob, write.identity_blob, write.logical_blob]
  # The commit API accepts prepared opaque session data. This synthetic session
  # isolates the real transaction fence; it is not a ratchet receive race.
  let session_blob = seal_local(Bytes.from_utf8("synthetic session candidate"),
    key,
    local_context(session)?)?
  let index_blob = seal_session_ids([session_id], key)?
  let old_epoch = load_blob(fixture.bob_path, epoch)?
  let newer_epoch = seal_view_once_epoch(key, bob.account_id, bob.device_id)?
  fence_check(!Bytes.secure_equals(old_epoch, newer_epoch), "epoch did not change")?
  store_record_changes(fixture.bob_path, [epoch], [newer_epoch], [])?
  let after_epoch_change = load_account_basis(fixture.bob_path, labels)?
  require_view_once_epoch(key, after_epoch_change, bob.account_id, bob.device_id)?
  let rejected = commit_initial_admission(fixture.bob_path,
    Some(before),
    session,
    session_blob,
    index_blob,
    write_labels,
    write_blobs,
    [],
    [],
    [])
  fence_check(case rejected do
      Err("account_state_changed") -> true
      _ -> false
    end,
    "stale epoch did not reject the guarded admission")?
  fence_check(same_account_basis(after_epoch_change, load_account_basis(fixture.bob_path, labels)?),
    "stale admission changed epoch, session, pending, markers, or history")?
  fence_check(Bytes.secure_equals(load_blob(fixture.bob_path, epoch)?, newer_epoch),
    "stale admission replaced the newer epoch")?
  # A fresh basis and the same prepared writes must reach the real commit path.
  commit_initial_admission(fixture.bob_path,
    Some(after_epoch_change),
    session,
    session_blob,
    index_blob,
    write_labels,
    write_blobs,
    [],
    [],
    [])?
  fence_check(pending_and_history(fixture.bob_path, conversation, id, reference, 1)?,
    "fresh admission did not commit pending and sanitized history")?
  fence_check(Bytes.secure_equals(load_blob(fixture.bob_path, session)?, session_blob)
      && Bytes.secure_equals(load_blob(fixture.bob_path, epoch)?, newer_epoch),
    "fresh admission did not preserve the epoch and commit its session")
end

fn receive_rollback(fixture :: InitialSyncFixture) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let device = open_device(bob, key, fixture.bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let id = repeated(223, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: conversation,
    message_id: id
  }
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: conversation,
    client_message_id: id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("synthetic rollback image"),
    reply_reference: Bytes.empty(),
    attachment_manifest: reference,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let (state, wire) = initial_carrier(fixture.alice_path, fixture.bob_path, inner)?
  let logical = logical_label(bob.account_id, alice.account_id, id)?
  let labels = [
    "sessions/v1",
    "session/v1/#{Bytes.to_hex(state.session_id)}",
    "one-time-prekeys/v1",
    "one-time-prekey-active/v1",
    one_time_prekey_label(bob.bundle.one_time_prekey_id),
    pending_label(conversation, id),
    identity_label(binding)?,
    logical,
    history_label(conversation),
    view_once_epoch_label()
  ]
  let before = load_account_basis(fixture.bob_path, labels)?
  fail_write(fixture.bob_path, logical, true)?
  let received = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: wire
  })
  let removed = fail_write(fixture.bob_path, logical, false)
  removed?
  fence_check(case received do
      Err("database_write_failed") -> true
      _ -> false
    end,
    "logical marker failure did not reject actual receive")?
  fence_check(same_account_basis(before, load_account_basis(fixture.bob_path, labels)?),
    "failed receive changed pending, markers, history, session, prekey, or epoch")?
  let delivered = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: wire
  })?
  fence_check(Bytes.secure_equals(delivered, inner.body), "receive retry did not deliver")?
  fence_check(pending_and_history(fixture.bob_path, conversation, id, reference, 1)?,
    "receive retry did not commit pending and history")
end

fn fence_case(rollback :: Bool) -> Unit!String do
  assert(Test.install_in_memory_secure_store())
  let fixture = initial_sync_fixture()?
  let result = if rollback do
    receive_rollback(fixture)
  else
    epoch_fence(fixture)
  end
  let cleanup = clear_initial_sync_fixture(fixture)
  cleanup?
  result
end

test("a changed captured epoch fences prepared initial admission writes") do
  assert(Result.is_ok(fence_case(false)))
end

test("logical marker write failure rolls back authenticated initial receive") do
  assert(Result.is_ok(fence_case(true)))
end

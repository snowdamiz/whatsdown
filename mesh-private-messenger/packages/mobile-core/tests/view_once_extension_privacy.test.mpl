##! Authenticated synthetic receives and direct inspection of sealed local history.
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference
from Mobile.Codec import current_time
from Mobile.HistoryWire import decode_history
from Mobile.Messages import receive_initial_message
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileHistoryAttachment, MobileReceiveRequest
from Protocol.V1 import InnerEnvelope, ProtocolExtension
from Storage.Blobs import load_blob
from Storage.HistoryBlobs import open_history_blob
from Storage.Keys import platform_key, open_local, local_context
from Storage.ViewOnce import ViewOnceRecord, decode_view_once_record
from Tests.Support import repeated
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import (
  InitialSyncFixture,
  initial_sync_fixture,
  clear_initial_sync_fixture,
  initial_carrier,
  history_label,
  pending_label
)
from Transport.Packet import decode_client_profile, direct_conversation_id

fn extension_privacy_check(value :: Plaintext<Bool>, message :: String) -> Unit!String do
  if declassify(value,
    "TEST ONLY assertion on synthetic authenticated receive and local history; no reference or key material is disclosed") do
    Ok(nil)
  else
    Err(message)
  end
end

fn extension_privacy_contains(input :: Bytes, needle :: Bytes, offset :: Int) -> Bool!String do
  if Bytes.length(needle) == 0 || offset + Bytes.length(needle) > Bytes.length(input) do
    Ok(false)
  else if Bytes.secure_equals(Bytes.slice(input, offset, Bytes.length(needle))?, needle) do
    Ok(true)
  else
    extension_privacy_contains(input, needle, offset + 1)
  end
end

fn extension_privacy_proof(fixture :: InitialSyncFixture, view_once :: Bool) -> Unit!String do
  let key = platform_key()?
  let alice = decode_client_profile(load_profile(fixture.alice_path)?)?
  let bob = decode_client_profile(load_profile(fixture.bob_path)?)?
  let device = open_device(bob, key, fixture.bob_path)?
  let conversation = direct_conversation_id(alice.account_id, bob.account_id)?
  let message_id = repeated(181, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    receiver_account_id: bob.account_id,
    receiver_device_id: bob.device_id,
    conversation_id: conversation,
    message_id: message_id
  }
  # The fixture seals the image key to Bob and authenticates its bound material.
  let (reference, _chunk, _png) = view_once_receive_material(device, binding)?
  let selected = decode_view_once_reference(reference)?
  let ordinary_value = Bytes.from_utf8("ordinary optional extension survives")
  let extensions = if view_once do
    [
      ProtocolExtension { id: 100, mandatory: false, value: selected.download_capability },
      ProtocolExtension { id: 101, mandatory: false, value: reference },
      ProtocolExtension { id: 102, mandatory: false, value: selected.wrapped_key }
    ]
  else
    [ProtocolExtension { id: 100, mandatory: false, value: ordinary_value }]
  end
  let caption = Bytes.from_utf8("safe synthetic caption")
  let inner = InnerEnvelope {
    version: 1,
    sender_account_id: alice.account_id,
    sender_device_id: alice.device_id,
    recipient_device_id: bob.device_id,
    conversation_id: conversation,
    client_message_id: message_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: caption,
    reply_reference: Bytes.empty(),
    attachment_manifest: if view_once do
      reference
    else
      Bytes.empty()
    end,
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: extensions
  }
  let (_state, wire) = initial_carrier(fixture.alice_path, fixture.bob_path, inner)?
  let received = receive_initial_message(MobileReceiveRequest {
    database_path: fixture.bob_path,
    outer: wire
  })?
  extension_privacy_check(Bytes.secure_equals(received, caption),
    "authenticated initial receive did not deliver the caption")?
  if view_once do
    let row = pending_label(conversation, message_id)
    let pending_bytes = open_local(load_blob(fixture.bob_path, row)?, key, local_context(row)?)?
    let pending = case decode_view_once_record(pending_bytes) do
      Ok(PendingFetch(value)) -> Bytes.secure_equals(value.reference, reference)
      _ -> false
    end
    extension_privacy_check(pending, "the selected view-once pending record was not retained")?
  end
  let label = history_label(conversation)
  let plaintext = open_history_blob(load_blob(fixture.bob_path, label)?, key, label)?
  let history = decode_history(plaintext)?
  extension_privacy_check(List.length(history) == 1, "history did not contain one received entry")?
  let entry = List.head(history)
  extension_privacy_check(entry.direction == 2
      && Bytes.secure_equals(entry.inner.client_message_id, message_id)
      && Bytes.secure_equals(entry.inner.body, caption),
    "history did not retain the received message and caption")?
  if view_once do
    extension_privacy_check(entry.attachment_kind == HistoryViewOnce
        && Bytes.length(entry.inner.attachment_manifest) == 0,
      "view-once history retained an attachment")?
    let no_extensions = declassify(List.length(entry.inner.extensions) == 0,
      "TEST ONLY observation of synthetic placeholder extension removal")
    if !no_extensions do
      println("TEST_VIEW_ONCE_HISTORY_EXTENSIONS_RETAINED")
    end
    extension_privacy_check(no_extensions, "view-once history retained protocol extensions")?
    let contains_reference = extension_privacy_contains(plaintext, reference, 0)?
    let contains_capability = extension_privacy_contains(plaintext,
      selected.download_capability,
      0)?
    let contains_wrapped = extension_privacy_contains(plaintext, selected.wrapped_key, 0)?
    extension_privacy_check(!contains_reference && !contains_capability && !contains_wrapped,
      "decrypted history retained selected view-once material")
  else
    extension_privacy_check(entry.attachment_kind == HistoryOrdinary
        && Bytes.length(entry.inner.attachment_manifest) == 0
        && List.length(entry.inner.extensions) == 1,
      "ordinary history lost its optional extension")?
    let saved = List.head(entry.inner.extensions)
    extension_privacy_check(saved.id == 100
        && !saved.mandatory
        && Bytes.secure_equals(saved.value, ordinary_value),
      "ordinary history changed its optional extension")
  end
end

fn extension_privacy_case(view_once :: Bool) -> Unit!String do
  if !Test.install_in_memory_secure_store() do
    return Err("synthetic secure store setup failed")
  end
  let fixture = initial_sync_fixture()?
  let result = extension_privacy_proof(fixture, view_once)
  let cleanup = clear_initial_sync_fixture(fixture)
  cleanup?
  result
end

test("view-once receive excludes selected material copied into optional extensions from sealed history") do
  assert(Result.is_ok(extension_privacy_case(true)))
end

test("ordinary receive preserves an unrelated optional extension in sealed history") do
  assert(Result.is_ok(extension_privacy_case(false)))
end

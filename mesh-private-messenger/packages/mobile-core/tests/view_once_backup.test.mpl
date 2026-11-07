##! Synthetic authenticated direct receive followed by actual attachment-inclusive export.
##! The fixture has no ordinary attachments, so the export makes no object requests.
import File
from Attachments.ViewOnce import ViewOnceBinding, decode_view_once_reference
from Backups.ContentArchive import BackupAttachmentPolicy, decode_content_archive
from Backups.PortableV2 import restore_portable_archive
from Mobile.BackupArchive import D4BackupSelection, create_pending_content_backup_export
from Mobile.BackupAuthority import capture_backup_authority
from Mobile.Codec import current_time
from Mobile.Messages import receive_initial_message, receive_message
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileReceiveRequest
from MobileCore import create_account_export
from Protocol.V1 import InnerEnvelope
from Session.State import RatchetState
from Storage.Keys import platform_key
from Storage.Records import erase_local_state
from Tests.BackupArchiveFixture import D4CoreFixture, d4_core_cleanup
from Tests.BackupAttachmentPreflightFixture import preflight_fixture
from Tests.BackupAttachmentCaptureFixture import capture_configure
from Tests.GroupConsistencySupport import request
from Tests.Support import database_path, repeated
from Tests.ViewOnceFixture import view_once_receive_material
from Tests.ViewOnceInitialSyncFixture import initial_carrier, sibling_carrier, pending_and_history
from Transport.Packet import decode_client_profile, direct_conversation_id

fn vo_backup_retire_state(state :: consume RatchetState) do
  nil
end

fn vo_backup_contains(haystack :: Bytes, needle :: Bytes) -> Bool do
  String.contains(Bytes.to_hex(haystack), Bytes.to_hex(needle))
end

fn vo_backup_body(f :: D4CoreFixture, sender_path :: String) -> Plaintext<Bool>!String do
  let _created_sender = create_account_export(request([
    Bytes.from_utf8(sender_path),
    Bytes.from_utf8("vobackupsender")
  ])?)?
  let sender = decode_client_profile(load_profile(sender_path)?)?
  let recipient = decode_client_profile(f.public_profile)?
  let key = platform_key()?
  let device = open_device(recipient, key, f.path)?
  let conversation = direct_conversation_id(sender.account_id, recipient.account_id)?
  let text_id = repeated(70, 16)?
  let view_id = repeated(71, 16)?
  let binding = ViewOnceBinding {
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    receiver_account_id: recipient.account_id,
    receiver_device_id: recipient.device_id,
    conversation_id: conversation,
    message_id: view_id
  }
  let (reference, chunk, image) = view_once_receive_material(device, binding)?
  let decoded_reference = decode_view_once_reference(reference)?
  let ordinary = InnerEnvelope {
    version: 1,
    sender_account_id: sender.account_id,
    sender_device_id: sender.device_id,
    recipient_device_id: recipient.device_id,
    conversation_id: conversation,
    client_message_id: text_id,
    client_timestamp: current_time()?,
    message_type: 1,
    body: Bytes.from_utf8("ordinary text survives backup"),
    reply_reference: Bytes.empty(),
    attachment_manifest: Bytes.empty(),
    receipt_policy: 0,
    disappearing_seconds: 0,
    extensions: List.new()
  }
  let (state, first_wire) = initial_carrier(sender_path, f.path, ordinary)?
  let first = case receive_initial_message(MobileReceiveRequest {
    database_path: f.path,
    outer: first_wire
  }) do
    Err(_) -> return Err("test_initial_receive_failed")
    Ok(value) -> value
  end
  let view = %{ordinary |
    client_message_id: view_id,
    body: Bytes.from_utf8("synthetic view-once caption"),
    attachment_manifest: reference
  }
  let (next, second_wire) = sibling_carrier(state, recipient, view)?
  vo_backup_retire_state(next)
  let second = case receive_message(MobileReceiveRequest {
    database_path: f.path,
    outer: second_wire
  }) do
    Err(_) -> return Err("test_ratchet_receive_failed")
    Ok(value) -> value
  end
  let pending = pending_and_history(f.path, conversation, view_id, reference, 2)
  let received = declassify(Bytes.secure_equals(first, ordinary.body)
      && Bytes.secure_equals(second, view.body)
      && Result.is_ok(pending)
      && Result.unwrap_or(pending, false),
    "TEST ONLY synthetic view-once receive fixture is complete")
  if !received do
    return Err("view_once_backup_receive_fixture")
  end
  # The runner owns this loopback port and records every attempted request.
  let port = Option.unwrap_or(String.to_int(Env.get("MORSE_VO_BACKUP_PORT", "")), 0)
  if port < 1 || port > 65535 do
    return Err("test_backup_port_missing")
  end
  capture_configure(f, port)?
  if !Test.set_push_token(Bytes.from_utf8("messenger/rpc-tls-roots/v1"), Bytes.from_hex("0100")?) do
    return Err("test_backup_rpc_frame")
  end
  let _authority = capture_backup_authority(f.path, f.public_profile)?
  let selected = [
    D4BackupSelection { kind: 1, scope_id: conversation, from_time: None, through_time: None }
  ]
  let created = case create_pending_content_backup_export(f.path,
    f.public_profile,
    selected,
    RequireArchiveAttachments) do
    Err("backup_attachment_preflight_refused") -> return Err("test_backup_preflight_refused")
    Err("backup_archive_refused") -> return Err("test_backup_archive_refused")
    Err("pending_export_exists") -> return Err("test_backup_already_pending")
    Err("invalid_backup_request") -> return Err("test_backup_invalid_request")
    Err("backup_scope_not_found") -> return Err("test_backup_scope_not_found")
    Err("backup_scope_ambiguous") -> return Err("test_backup_scope_ambiguous")
    Err("backup_source_incomplete") -> return Err("test_backup_source_incomplete")
    Err("backup_authority_expired") -> return Err("test_backup_authority_expired")
    Err("backup_source_missing") -> return Err("test_backup_source_missing")
    Err("backup_source_not_captured") -> return Err("test_backup_source_not_captured")
    Err("backup_source_scope_mismatch") -> return Err("test_backup_scope_mismatch")
    Err("backup_source_account_mismatch") -> return Err("test_backup_account_mismatch")
    Err("backup_preparation_refused") -> return Err("test_backup_preparation_refused")
    Err("backup_custody_invalid") -> return Err("test_backup_custody_invalid")
    Err("transparency_origin_mismatch") -> return Err("test_backup_origin_mismatch")
    Err("invalid_backup_selection") -> return Err("test_backup_selection_invalid")
    Err(_) -> return Err("test_backup_export_failed")
    Ok(value) -> value
  end
  let payload = case restore_portable_archive(created.recovery_code, created.wire) do
    Err(_) -> return Err("view_once_backup_restore")
    Ok(value) -> value
  end
  let archive = case decode_content_archive(payload) do
    Err(_) -> return Err("view_once_backup_decode")
    Ok(value) -> value
  end
  if List.length(archive.scopes) != 1 do
    return Ok(false)
  end
  let scope = List.head(archive.scopes)
  let has_ordinary = List.any(scope.entries,
    fn(entry) -> Bytes.secure_equals(entry.message_id, text_id)
      && Bytes.secure_equals(entry.text, ordinary.body)
      && List.length(entry.attachments) == 0 end)
  let has_view_once = List.length(scope.entries) == 2
    && Bytes.secure_equals(List.get(scope.entries, 1).message_id, view_id)
    && Bytes.secure_equals(List.get(scope.entries, 1).text, view.body)
    && List.get(scope.entries, 1).ordinal == 1
    && List.length(List.get(scope.entries, 1).attachments) == 0
  let no_attachment = List.all(scope.entries, fn(entry) -> List.length(entry.attachments) == 0 end)
  Ok(scope.kind == 1
    && Bytes.secure_equals(scope.id, conversation)
    && archive.attachment_messages == 0
    && has_ordinary
    && has_view_once
    && no_attachment
    && !vo_backup_contains(payload, Bytes.from_utf8("VOR"))
    && !vo_backup_contains(payload, reference)
    && !vo_backup_contains(payload, decoded_reference.object_id)
    && !vo_backup_contains(payload, decoded_reference.download_capability)
    && !vo_backup_contains(payload, decoded_reference.encrypted_manifest)
    && !vo_backup_contains(payload, decoded_reference.wrapped_key)
    && !vo_backup_contains(payload, chunk)
    && !vo_backup_contains(payload, image)
    && !vo_backup_contains(payload, Bytes.from_utf8("image/png"))
    && !vo_backup_contains(payload, Bytes.from_utf8("view-once/v2/"))
    && !vo_backup_contains(payload, Bytes.from_utf8("view-once/id/v2/")))
end

fn vo_backup_case() -> Plaintext<Bool>!String do
  let fixture = preflight_fixture()?
  let sender_path = database_path("vo-backup-sender")?
  let result = vo_backup_body(fixture, sender_path)
  let sender_cleanup = erase_local_state(sender_path)
  let sender_file = if File.exists(sender_path) do
    File.delete(sender_path)
  else
    Ok(nil)
  end
  let fixture_cleanup = d4_core_cleanup(fixture)
  sender_cleanup?
  sender_file?
  fixture_cleanup?
  result
end

test("attachment-inclusive export accepts authenticated view-once caption without exporting its image material") do
  let result = vo_backup_case()
  let observed = declassify(case result do
      Err("test_initial_receive_failed") -> 3
      Err("test_ratchet_receive_failed") -> 4
      Err("test_backup_preflight_refused") -> 5
      Err("test_backup_export_failed") -> 6
      Err("test_backup_archive_refused") -> 7
      Err("test_backup_already_pending") -> 8
      Err("test_backup_invalid_request") -> 9
      Err("test_backup_scope_not_found") -> 10
      Err("test_backup_scope_ambiguous") -> 11
      Err("test_backup_source_incomplete") -> 12
      Err("test_backup_authority_expired") -> 13
      Err("test_backup_source_missing") -> 14
      Err("test_backup_source_not_captured") -> 15
      Err("test_backup_scope_mismatch") -> 16
      Err("test_backup_account_mismatch") -> 17
      Err("test_backup_preparation_refused") -> 18
      Err("test_backup_custody_invalid") -> 19
      Err("test_backup_origin_mismatch") -> 20
      Err("test_backup_selection_invalid") -> 21
      Err(_) -> 0
      Ok(value) -> if value do
        2
      else
        1
      end
    end,
    "TEST ONLY closed result of synthetic authenticated receive and backup exclusion checks")
  if observed == 3 do
    println("TEST_INITIAL_RECEIVE_FAILED")
  end
  if observed == 4 do
    println("TEST_RATCHET_RECEIVE_FAILED")
  end
  if observed == 5 do
    println("TEST_BACKUP_PREFLIGHT_REFUSED")
  end
  if observed == 6 do
    println("TEST_BACKUP_EXPORT_FAILED")
  end
  if observed == 7 do
    println("TEST_BACKUP_ARCHIVE_REFUSED")
  end
  if observed == 8 do
    println("TEST_BACKUP_ALREADY_PENDING")
  end
  if observed == 9 do
    println("TEST_BACKUP_INVALID_REQUEST")
  end
  if observed == 10 do
    println("TEST_BACKUP_SCOPE_NOT_FOUND")
  end
  if observed == 11 do
    println("TEST_BACKUP_SCOPE_AMBIGUOUS")
  end
  if observed == 12 do
    println("TEST_BACKUP_SOURCE_INCOMPLETE")
  end
  if observed == 13 do
    println("TEST_BACKUP_AUTHORITY_EXPIRED")
  end
  if observed == 14 do
    println("TEST_BACKUP_SOURCE_MISSING")
  end
  if observed == 15 do
    println("TEST_BACKUP_SOURCE_NOT_CAPTURED")
  end
  if observed == 16 do
    println("TEST_BACKUP_SCOPE_MISMATCH")
  end
  if observed == 17 do
    println("TEST_BACKUP_ACCOUNT_MISMATCH")
  end
  if observed == 18 do
    println("TEST_BACKUP_PREPARATION_REFUSED")
  end
  if observed == 19 do
    println("TEST_BACKUP_CUSTODY_INVALID")
  end
  if observed == 20 do
    println("TEST_BACKUP_ORIGIN_MISMATCH")
  end
  if observed == 21 do
    println("TEST_BACKUP_SELECTION_INVALID")
  end
  assert(observed != 0)
  assert(observed == 2)
end

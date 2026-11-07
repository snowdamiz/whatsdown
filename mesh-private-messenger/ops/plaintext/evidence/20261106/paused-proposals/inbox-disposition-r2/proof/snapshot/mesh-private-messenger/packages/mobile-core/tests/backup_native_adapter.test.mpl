from Mobile.BackupNative import (
  BackupNativeSummary,
  native_backup_create,
  native_backup_import,
  native_backup_remove,
  native_backup_preview,
  native_backup_list,
  native_backup_overview,
  native_backup_page,
  encode_backup_list_reply,
  encode_backup_overview_reply,
  encode_backup_page_reply
)
from Mobile.BackupArchive import import_backup_archive, read_backup_archive
from Mobile.BackupArchiveView import (
  BackupArchiveConversation,
  BackupArchiveOverview,
  BackupArchivePage
)
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_import_bundle,
  d4_core_backup_id,
  d4_core_install_direct_history,
  d4_core_created_matches,
  d4_core_stored_matches,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Tests.Support import repeated
from Mobile.Codec import current_time, mobile_byte, mobile_vector, mobile_write_u32
from Binary.Reader import reader, read_fixed, read_vector, finish
from Backups.PortableV2 import PortableBackupV2Created
from Backups.TextArchive import BackupArchiveRecord
from Transport.Packet import decode_client_profile

fn adapter_join(parts :: List<Bytes>) -> Bytes!String do
  case Bytes.concat_many(parts, 33554432) do
    Err(_) -> Err("native_adapter_fixture_join")
    Ok(value)
  end
end

fn adapter_action(f :: D4CoreFixture, expected :: Bytes) -> Bytes!String do
  adapter_join([mobile_byte(1)?, mobile_vector(Bytes.from_utf8(f.path))?, mobile_vector(expected)?])
end

fn adapter_archive(f :: D4CoreFixture, id :: Bytes) -> Bytes!String do
  adapter_join([adapter_action(f, f.public_profile)?, id])
end

fn adapter_portable(f :: D4CoreFixture, bundle :: PortableBackupV2Created) -> Bytes!String do
  adapter_join([
    adapter_action(f, f.public_profile)?,
    mobile_vector(bundle.wire)?,
    mobile_vector(Bytes.from_utf8(bundle.recovery_code))?
  ])
end

fn adapter_page(f :: D4CoreFixture, id :: Bytes) -> Bytes!String do
  adapter_join([
    adapter_archive(f, id)?,
    mobile_byte(1)?,
    mobile_vector(repeated(71, 16)?)?,
    mobile_write_u32(0)?,
    mobile_byte(16)?
  ])
end

fn adapter_imported(f :: D4CoreFixture, bundle :: PortableBackupV2Created) -> Bytes!String do
  let id = d4_core_backup_id(bundle.wire)?
  let receipt = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    id)?
  assert(receipt.disposition == 1 && Bytes.secure_equals(receipt.backup_id, id))
  Ok(id)
end

fn adapter_observed(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY authored synthetic native adapter frame equality refusal or unchanged row predicate; no user history recovery code key hash or arbitrary error is disclosed")
end

fn adapter_matches(raw :: Result<Plaintext<Bytes>, String>,
  expected :: Result<Plaintext<Bytes>, String>) -> Bool do
  adapter_observed(case (raw, expected) do
    (Ok(actual), Ok(wanted)) -> Bytes.secure_equals(actual, wanted)
    _ -> false
  end)
end

fn adapter_refused(raw :: Result<Plaintext<Bytes>, String>) -> Bool do
  adapter_observed(Result.is_err(raw))
end

fn adapter_public(raw :: Bytes!String, expected :: Bytes) -> Bool do
  case raw do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, expected)
  end
end

fn adapter_created(raw :: Bytes!String) -> PortableBackupV2Created!String do
  let input = raw?
  case adapter_decode_created(input) do
    Err(_) -> Err("native_adapter_fixture_frame")
    Ok(value)
  end
end

fn adapter_decode_created(input :: Bytes) -> PortableBackupV2Created!String do
  let state = case reader(input, 16801001) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(value) -> value
  end
  let (after_version, version) = case read_fixed(state, 1) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(value) -> value
  end
  if Bytes.to_hex(version) != "02" do
    return Err("native_adapter_fixture_frame")
  end
  let (after_draft, _) = case read_fixed(after_version, 32) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(value) -> value
  end
  let (after_wire, wire) = case read_vector(after_draft, 16796864) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(value) -> value
  end
  let (after_code, code) = case read_vector(after_wire, 4096) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(value) -> value
  end
  case finish(after_code) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(_) -> nil
  end
  let text = case Bytes.to_utf8(code) do
    Err(_) -> return Err("native_adapter_fixture_frame")
    Ok(value) -> value
  end
  Ok(PortableBackupV2Created { wire: wire, recovery_code: text })
end

fn adapter_overview(f :: D4CoreFixture, id :: Bytes) -> BackupArchiveOverview!String do
  Ok(BackupArchiveOverview {
    backup_id: id,
    created_at: f.now,
    included_count: 1,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 0,
    conversations: [
      BackupArchiveConversation {
        kind: 1,
        id: repeated(71, 16)?,
        peer: repeated(37, 32)?,
        name: "",
        message_count: 1
      }
    ]
  })
end

fn adapter_expected_page(f :: D4CoreFixture, id :: Bytes) -> BackupArchivePage!String do
  let profile = decode_client_profile(f.public_profile)?
  Ok(BackupArchivePage {
    backup_id: id,
    kind: 1,
    scope_id: repeated(71, 16)?,
    offset: 0,
    next_offset: None,
    entries: [
      BackupArchiveRecord {
        ordinal: 0,
        direction: 1,
        message_id: repeated(24, 16)?,
        sender_account: f.account_id,
        sender_device: profile.device_id,
        timestamp: f.now,
        attachment_omitted: false,
        text: Bytes.from_utf8("actual captured canonical direct text")
      }
    ]
  })
end

test("native create returns a separately framed real recoverable selected archive and fresh code") do
  let f = d4_core_fixture()?
  d4_core_install_direct_history(f)?
  let selection = adapter_join([
    mobile_byte(1)?,
    mobile_byte(1)?,
    mobile_vector(repeated(71, 16)?)?,
    mobile_byte(0)?,
    mobile_byte(0)?
  ])?
  let input = adapter_join([adapter_action(f, f.public_profile)?, mobile_vector(selection)?])?
  let before = d4_core_all_rows(f)?
  let started = current_time()?
  println("NATIVE_ADAPTER_CREATE_READY")
  let result = adapter_created(native_backup_create(input))
  assert(Result.is_ok(result))
  let created = result?
  assert(d4_core_created_matches(f, created, started, current_time()?))
  assert(Result.is_err(native_backup_create(adapter_join([input, mobile_byte(0)?])?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 2))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("native preview returns only authenticated protected overview without storing an archive") do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let input = adapter_portable(f, bundle)?
  let before = d4_core_all_rows(f)?
  println("NATIVE_ADAPTER_PREVIEW_READY")
  assert(adapter_matches(native_backup_preview(input),
    encode_backup_overview_reply(adapter_overview(f, id)?)))
  let foreign = d4_core_import_bundle(f, true)?
  assert(adapter_refused(native_backup_preview(adapter_portable(f, foreign)?)))
  assert(adapter_refused(native_backup_preview(adapter_join([input, mobile_byte(0)?])?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("native import binds the explicit confirmed ID and returns exact new then identical receipts") do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let portable = adapter_portable(f, bundle)?
  let input = adapter_join([portable, id])?
  println("NATIVE_ADAPTER_IMPORT_READY")
  assert(adapter_public(native_backup_import(input),
    adapter_join([mobile_byte(1)?, id, mobile_byte(1)?])?))
  assert(adapter_public(native_backup_import(input),
    adapter_join([mobile_byte(1)?, id, mobile_byte(2)?])?))
  assert(d4_core_stored_matches(f, id, read_backup_archive(f.path, f.public_profile, id)))
  let before = d4_core_all_rows(f)?
  assert(Result.is_err(native_backup_import(adapter_join([portable, repeated(99, 32)?])?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("native list exposes only protected stored identity and exact time after current account capture") do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = adapter_imported(f, bundle)?
  let before = d4_core_all_rows(f)?
  println("NATIVE_ADAPTER_LIST_READY")
  assert(adapter_matches(native_backup_list(adapter_action(f, f.public_profile)?),
    encode_backup_list_reply([BackupNativeSummary { backup_id: id, created_at: f.now }])))
  assert(adapter_refused(native_backup_list(adapter_action(f,
    Bytes.from_utf8("foreign public profile"))?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("native removal is guarded and idempotent without deleting unrelated account state") do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = adapter_imported(f, bundle)?
  let input = adapter_archive(f, id)?
  println("NATIVE_ADAPTER_REMOVE_READY")
  assert(adapter_public(native_backup_remove(input),
    adapter_join([mobile_byte(1)?, id, mobile_byte(1)?])?))
  let removed_rows = d4_core_all_rows(f)?
  assert(adapter_public(native_backup_remove(input),
    adapter_join([mobile_byte(1)?, id, mobile_byte(1)?])?))
  assert(adapter_matches(native_backup_list(adapter_action(f, f.public_profile)?),
    encode_backup_list_reply([])))
  assert(d4_core_rows_preserved(removed_rows, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("native stored overview preserves authored historical metadata and rejects stale profile") do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = adapter_imported(f, bundle)?
  let before = d4_core_all_rows(f)?
  println("NATIVE_ADAPTER_OVERVIEW_READY")
  assert(adapter_matches(native_backup_overview(adapter_archive(f, id)?),
    encode_backup_overview_reply(adapter_overview(f, id)?)))
  assert(adapter_refused(native_backup_overview(adapter_join([
    adapter_action(f, Bytes.from_utf8("foreign public profile"))?,
    id
  ])?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("native page returns only bounded protected text metadata and exact cursor without mutation") do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = adapter_imported(f, bundle)?
  let input = adapter_page(f, id)?
  let before = d4_core_all_rows(f)?
  println("NATIVE_ADAPTER_PAGE_READY")
  assert(adapter_matches(native_backup_page(input),
    encode_backup_page_reply(adapter_expected_page(f, id)?)))
  assert(adapter_refused(native_backup_page(adapter_join([input, mobile_byte(0)?])?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

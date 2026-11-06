import File
from Mobile.BackupArchive import preview_backup_archive, d4_preview_drift
from Mobile.BackupArchiveReader import preview_backup_archive_overview
from Mobile.BackupArchiveView import BackupArchiveOverview
from Mobile.BackupAuthority import capture_backup_authority
from Backups.PortableV2 import restore_portable_backup
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_import_bundle,
  d4_core_legacy_import_bundle,
  d4_core_backup_id,
  d4_core_stored_matches,
  d4_core_all_rows,
  d4_core_rows_preserved,
  d4_core_foreign_sent_bundle
)
from Tests.Support import repeated, append
from Tests.GroupConsistencySupport import request
from Storage.BackupArchiveCommit import backup_archive_label, backup_archive_index_label
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from MobileCore import create_account_export
from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile

fn d4_preview_observed(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY authored synthetic preview owner/schema/refusal and ID time count scope equality or fixed source-drift refusal; no application archive or arbitrary error is disclosed")
end

fn d4_preview_overview_matches(raw :: Result<Plaintext<BackupArchiveOverview>, String>,
  id :: Bytes,
  time :: U64) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(value) -> do
      if List.length(value.conversations) != 1 do
        return false
      end
      let scope = List.head(value.conversations)
      Bytes.secure_equals(value.backup_id, id)
        && U64.compare(value.created_at, time) == 0
        && value.included_count == 1
        && value.candidate_count == 1
        && value.omitted_timed == 0
        && value.omitted_unknown == 0
        && value.omitted_nontext == 0
        && value.omitted_empty == 0
        && value.attachment_messages == 0
        && scope.kind == 1
        && scope.message_count == 1
        && Bytes.to_hex(scope.id) == "47474747474747474747474747474747"
        && Bytes.to_hex(scope.peer) == "2525252525252525252525252525252525252525252525252525252525252525"
        && scope.name == ""
    end
  end
end

fn d4_preview_valid() -> Result<(), String> do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let legacy = d4_core_legacy_import_bundle(f, id, false)?
  let index = backup_archive_index_label(f.account_id)?
  let ignored_index = Bytes.from_utf8("preview must not open or admit this unrelated local archive index")
  store_updated_blobs(f.path, [index], [ignored_index])?
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_PREVIEW_VALID_FIXTURE_READY")
  assert(d4_core_stored_matches(f,
    id,
    preview_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code)))
  assert(d4_core_stored_matches(f,
    id,
    preview_backup_archive(f.path, f.public_profile, legacy.wire, legacy.recovery_code)))
  assert(d4_preview_observed(d4_preview_overview_matches(preview_backup_archive_overview(f.path,
      f.public_profile,
      bundle.wire,
      bundle.recovery_code),
    id,
    f.now)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  assert(Result.is_err(load_blob(f.path, backup_archive_label(f.account_id, id)?)))
  assert(Bytes.secure_equals(load_blob(f.path, index)?, ignored_index))
  d4_core_cleanup(f)
end

test("authenticated preview returns original private payload and overview without local archive admission or writes") do
  assert(Result.is_ok(d4_preview_valid()))
end

fn d4_preview_tampered(wire :: Bytes) -> Bytes!String do
  let length = Bytes.length(wire)
  let last = case Bytes.get(wire, length - 1) do
    Err(_) -> return Err("preview_fixture_byte")
    Ok(value) -> value
  end
  let prefix = case Bytes.slice(wire, 0, length - 1) do
    Err(_) -> return Err("preview_fixture_slice")
    Ok(value) -> value
  end
  append(prefix,
    repeated(if last == 0 do
        1
      else
        0
      end,
      1)?)
end

fn d4_preview_refusals() -> Result<(), String> do
  let f = d4_core_fixture()?
  let valid = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(valid.wire)?
  let foreign = d4_core_import_bundle(f, true)?
  let foreign_sent = d4_core_foreign_sent_bundle(f, f.archive_id)?
  assert(d4_preview_observed(Result.is_ok(restore_portable_backup(foreign.recovery_code,
    foreign.wire))))
  assert(d4_preview_observed(Result.is_ok(restore_portable_backup(foreign_sent.recovery_code,
    foreign_sent.wire))))
  let damaged = d4_preview_tampered(valid.wire)?
  assert(!Bytes.secure_equals(damaged, valid.wire))
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_PREVIEW_REFUSAL_FIXTURE_READY")
  assert(d4_preview_observed(Result.is_err(preview_backup_archive(f.path,
    f.public_profile,
    foreign.wire,
    foreign.recovery_code))))
  assert(d4_preview_observed(Result.is_err(preview_backup_archive(f.path,
    f.public_profile,
    foreign_sent.wire,
    foreign_sent.recovery_code))))
  assert(d4_preview_observed(Result.is_err(preview_backup_archive(f.path,
    f.public_profile,
    damaged,
    valid.recovery_code))))
  assert(d4_preview_observed(Result.is_err(preview_backup_archive(f.path,
    f.public_profile,
    valid.wire,
    foreign.recovery_code))))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  assert(d4_core_stored_matches(f,
    id,
    preview_backup_archive(f.path, f.public_profile, valid.wire, valid.recovery_code)))
  d4_core_cleanup(f)
end

test("preview refuses authenticated foreign owners foreign group senders damaged wire and wrong code") do
  assert(Result.is_ok(d4_preview_refusals()))
end

fn d4_preview_foreign_expected() -> Result<(), String> do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let foreign_path = f.path <> ".preview-foreign"
  create_account_export(request([
    Bytes.from_utf8(foreign_path),
    Bytes.from_utf8("previewforeign")
  ])?)?
  let foreign = load_profile(foreign_path)?
  let foreign_profile = decode_client_profile(foreign)?
  assert(!Bytes.secure_equals(foreign_profile.account_id, f.account_id))
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_PREVIEW_CUSTODY_FIXTURE_READY")
  assert(d4_preview_observed(Result.is_err(preview_backup_archive(f.path,
    foreign,
    bundle.wire,
    bundle.recovery_code))))
  assert(d4_preview_observed(Result.is_err(preview_backup_archive_overview(f.path,
    foreign,
    bundle.wire,
    bundle.recovery_code))))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  assert(d4_core_stored_matches(f,
    id,
    preview_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code)))
  erase_local_state(foreign_path)?
  File.delete(foreign_path)?
  d4_core_cleanup(f)
end

test("preview reuses actual current custody and refuses another real account under the same key") do
  assert(Result.is_ok(d4_preview_foreign_expected()))
end

fn d4_preview_authority_drift() -> Result<(), String> do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let authority = capture_backup_authority(f.path, f.public_profile)?
  let labels = ["profile/v1", "ohttp-revision/v1"]
  let originals = [load_blob(f.path, List.get(labels, 0))?, load_blob(f.path, List.get(labels, 1))?]
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_PREVIEW_DRIFT_FIXTURE_READY")
  for mode in 0..3 do
    let winner = Bytes.from_utf8("concurrent winning preview authority ciphertext or native frame")
    assert(d4_preview_observed(case d4_preview_drift(f.path,
      f.public_profile,
      bundle.wire,
      bundle.recovery_code,
      winner,
      mode) do
      Err("account_state_changed") -> true
      _ -> false
    end))
    if mode == 2 do
      assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
        authority.context.network_frame))
    else
      let label = List.get(labels, mode)
      assert(Bytes.secure_equals(load_blob(f.path, label)?, winner))
      store_updated_blobs(f.path, [label], [List.get(originals, mode)])?
    end
  end
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  assert(d4_core_stored_matches(f,
    id,
    preview_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code)))
  d4_core_cleanup(f)
end

test("preview final authority fence preserves concurrent profile revision and raw frame winners") do
  assert(Result.is_ok(d4_preview_authority_drift()))
end

from Mobile.BackupArchiveReader import read_backup_archive_overview, read_backup_archive_page
from Mobile.BackupArchiveView import (
  BackupArchiveOverview,
  BackupArchivePage,
  BackupArchivePageRequest
)
from Mobile.BackupArchive import import_backup_archive
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_import_bundle,
  d4_core_backup_id,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Tests.Support import repeated
from Tests.GroupConsistencySupport import request
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs, erase_local_state
from MobileCore import create_account_export
from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile
import File

fn observed(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY guarded synthetic archive overview and text equality or refusal after authored account and ciphertext changes; no user archive or arbitrary error is disclosed")
end

fn imported(f :: D4CoreFixture) -> Bytes!String do
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let receipt = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    id)?
  assert(receipt.disposition == 1 && Bytes.secure_equals(receipt.backup_id, id))
  Ok(id)
end

fn page_request(offset :: Int) -> BackupArchivePageRequest!String do
  Ok(BackupArchivePageRequest { kind: 1, scope_id: repeated(71, 16)?, offset: offset, limit: 16 })
end

fn overview_matches(raw :: Result<Plaintext<BackupArchiveOverview>, String>,
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
        && Bytes.to_hex(scope.id) == "47474747474747474747474747474747"
        && Bytes.to_hex(scope.peer) == "2525252525252525252525252525252525252525252525252525252525252525"
        && scope.name == ""
        && scope.message_count == 1
    end
  end
end

fn page_matches(raw :: Result<Plaintext<BackupArchivePage>, String>,
  id :: Bytes,
  account :: Bytes,
  time :: U64) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(value) -> do
      if List.length(value.entries) != 1 do
        return false
      end
      let message = List.head(value.entries)
      Bytes.secure_equals(value.backup_id, id)
        && value.kind == 1
        && Bytes.to_hex(value.scope_id) == "47474747474747474747474747474747"
        && value.offset == 0
        && value.next_offset == None
        && message.ordinal == 0
        && message.direction == 1
        && Bytes.secure_equals(message.sender_account, account)
        && U64.compare(message.timestamp, time) == 0
        && !message.attachment_omitted
        && Bytes.secure_equals(message.text,
          Bytes.from_utf8("actual captured canonical direct text"))
    end
  end
end

test("guarded viewer reads original imported overview and text without changing stored state") do
  let f = d4_core_fixture()?
  let id = imported(f)?
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_READER_CONTENT_READY")
  assert(observed(overview_matches(read_backup_archive_overview(f.path, f.public_profile, id),
    id,
    f.now)))
  assert(observed(page_matches(read_backup_archive_page(f.path,
      f.public_profile,
      id,
      page_request(0)?),
    id,
    f.account_id,
    f.now)))
  let finished = read_backup_archive_page(f.path, f.public_profile, id, page_request(1)?)
  assert(observed(case finished do
    Err(_) -> false
    Ok(value) -> value.offset == 1 && value.next_offset == None && List.length(value.entries) == 0
  end))
  assert(observed(Result.is_err(read_backup_archive_page(f.path,
    f.public_profile,
    id,
    page_request(2)?))))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("guarded viewer recaptures current account for every page and overview request") do
  let f = d4_core_fixture()?
  let id = imported(f)?
  let other_path = f.path <> ".other"
  create_account_export(request([Bytes.from_utf8(other_path), Bytes.from_utf8("otherbackup")])?)?
  let other = load_profile(other_path)?
  assert(!Bytes.secure_equals(f.account_id, decode_client_profile(other)?.account_id))
  println("ARCHIVE_READER_ACCOUNT_READY")
  assert(observed(overview_matches(read_backup_archive_overview(f.path, f.public_profile, id),
    id,
    f.now)))
  assert(observed(Result.is_err(read_backup_archive_overview(f.path, other, id))))
  let old_profile = load_blob(f.path, "profile/v1")?
  let replacement = load_blob(other_path, "profile/v1")?
  store_updated_blobs(f.path, ["profile/v1"], [replacement])?
  let before = d4_core_all_rows(f)?
  assert(observed(Result.is_err(read_backup_archive_overview(f.path, f.public_profile, id))))
  assert(observed(Result.is_err(read_backup_archive_page(f.path,
    f.public_profile,
    id,
    page_request(0)?))))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  store_updated_blobs(f.path, ["profile/v1"], [old_profile])?
  assert(observed(page_matches(read_backup_archive_page(f.path,
      f.public_profile,
      id,
      page_request(0)?),
    id,
    f.account_id,
    f.now)))
  erase_local_state(other_path)?
  File.delete(other_path)?
  d4_core_cleanup(f)?
  Ok(nil)
end

test("guarded viewer refuses changed archive and index ciphertext after an earlier valid read") do
  let f = d4_core_fixture()?
  let id = imported(f)?
  let row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(id)}"
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  let original = load_blob(f.path, row)?
  let original_index = load_blob(f.path, index)?
  println("ARCHIVE_READER_TAMPER_READY")
  assert(observed(overview_matches(read_backup_archive_overview(f.path, f.public_profile, id),
    id,
    f.now)))
  store_updated_blobs(f.path, [row], [Bytes.from_utf8("damaged archive ciphertext")])?
  let before = d4_core_all_rows(f)?
  assert(observed(Result.is_err(read_backup_archive_overview(f.path, f.public_profile, id))))
  assert(observed(Result.is_err(read_backup_archive_page(f.path,
    f.public_profile,
    id,
    page_request(0)?))))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  store_updated_blobs(f.path, [row, index], [original, Bytes.from_utf8("damaged archive index")])?
  let changed = d4_core_all_rows(f)?
  assert(observed(Result.is_err(read_backup_archive_overview(f.path, f.public_profile, id))))
  assert(observed(Result.is_err(read_backup_archive_page(f.path,
    f.public_profile,
    id,
    page_request(0)?))))
  assert(d4_core_rows_preserved(changed, d4_core_all_rows(f)?, 0))
  store_updated_blobs(f.path, [index], [original_index])?
  assert(observed(page_matches(read_backup_archive_page(f.path,
      f.public_profile,
      id,
      page_request(0)?),
    id,
    f.account_id,
    f.now)))
  d4_core_cleanup(f)?
  Ok(nil)
end

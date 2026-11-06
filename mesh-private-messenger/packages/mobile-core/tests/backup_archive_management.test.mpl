import File
from Mobile.BackupArchive import (
  list_backup_archives,
  remove_backup_archive,
  import_backup_archive,
  read_backup_archive,
  d4_manage_list_matches,
  d4_manage_seed_index,
  d4_manage_index_wire,
  d4_manage_drift
)
from Mobile.BackupAuthority import capture_backup_authority
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  D4CoreAllRows,
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_import_bundle,
  d4_core_backup_id,
  d4_core_all_rows,
  d4_core_rows_preserved,
  d4_core_read_refused
)
from Tests.Support import repeated
from Tests.GroupConsistencySupport import wide, request
from Storage.AccountGuard import load_account_basis, account_basis_current
from Storage.BackupArchiveCommit import backup_archive_label, backup_archive_index_label
from Storage.Blobs import load_blob, blob_record_hash
from Storage.Records import (
  store_updated_blobs,
  with_record_transaction,
  delete_blob,
  erase_local_state
)
from MobileCore import create_account_export
from Mobile.Profile import load_profile
from Transport.Packet import decode_client_profile

fn d4_manage_import(f :: D4CoreFixture) -> Bytes!String do
  let bundle = d4_core_import_bundle(f, false)?
  let id = d4_core_backup_id(bundle.wire)?
  let receipt = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    id)?
  assert(Bytes.secure_equals(receipt.backup_id, id) && receipt.disposition == 1)
  Ok(id)
end

fn d4_manage_drop(path :: String, label :: String) -> Result<(), String> do
  with_record_transaction(path, fn(database) -> delete_blob(database, label) end)
end

fn d4_manage_unrelated(f :: D4CoreFixture, id :: Bytes) -> D4CoreAllRows!String do
  let before = d4_core_all_rows(f)?
  let database = Sqlite.open(f.path)?
  let row = blob_record_hash(database, backup_archive_label(f.account_id, id)?)
  let index = blob_record_hash(database, backup_archive_index_label(f.account_id)?)
  Sqlite.close(database)
  let row_hash = row?
  let index_hash = index?
  Ok(%{before |
    rows: List.filter(before.rows,
      fn(value) -> value.hash != row_hash && value.hash != index_hash end)
  })
end

fn d4_manage_list_bounds() -> Result<(), String> do
  let f = d4_core_fixture()?
  let _authority = capture_backup_authority(f.path, f.public_profile)?
  println("ARCHIVE_MANAGEMENT_LIST_FIXTURE_READY")
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), [], []))
  let ids = for index in 0..8 do
    repeated(90 + index, 32)?
  end
  let times = for index in 0..8 do
    wide(17 + index)?
  end
  d4_manage_seed_index(f.path, f.account_id, ids, times, [])?
  let label = backup_archive_index_label(f.account_id)?
  assert(Bytes.length(load_blob(f.path, label)?) == 648)
  let before = d4_core_all_rows(f)?
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), ids, times))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  let winner = repeated(71, 649)?
  store_updated_blobs(f.path, [label], [winner])?
  let oversized = d4_core_all_rows(f)?
  assert(Result.is_err(list_backup_archives(f.path, f.public_profile)))
  assert(d4_core_rows_preserved(oversized, d4_core_all_rows(f)?, 0))
  assert(Result.is_err(list_backup_archives("", f.public_profile)))
  d4_core_cleanup(f)
end

test("archive list returns only bounded protected IDs and original snapshot times without writes") do
  assert(Result.is_ok(d4_manage_list_bounds()))
end

fn d4_manage_remove_and_retry() -> Result<(), String> do
  let f = d4_core_fixture()?
  let id = d4_manage_import(f)?
  let other = d4_manage_import(f)?
  let row = backup_archive_label(f.account_id, id)?
  let other_row = backup_archive_label(f.account_id, other)?
  let other_ciphertext = load_blob(f.path, other_row)?
  let unrelated = d4_manage_unrelated(f, id)?
  println("ARCHIVE_MANAGEMENT_REMOVE_FIXTURE_READY")
  remove_backup_archive(f.path, f.public_profile, id)?
  assert(Result.is_err(load_blob(f.path, row)))
  assert(Bytes.secure_equals(load_blob(f.path, other_row)?, other_ciphertext))
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), [other], [f.now]))
  assert(d4_core_rows_preserved(unrelated, d4_core_all_rows(f)?, 1))
  let before_retry = d4_core_all_rows(f)?
  remove_backup_archive(f.path, f.public_profile, id)?
  assert(d4_core_rows_preserved(before_retry, d4_core_all_rows(f)?, 0))
  remove_backup_archive(f.path, f.public_profile, other)?
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), [], []))
  d4_core_cleanup(f)
end

test("archive remove changes only selected row and index then retries idempotently") do
  assert(Result.is_ok(d4_manage_remove_and_retry()))
end

fn d4_manage_remove_corrupt() -> Result<(), String> do
  let f = d4_core_fixture()?
  let id = d4_manage_import(f)?
  let row = backup_archive_label(f.account_id, id)?
  let damaged = Bytes.from_utf8("present corrupted archive ciphertext with authorized index ID")
  store_updated_blobs(f.path, [row], [damaged])?
  assert(d4_core_read_refused(read_backup_archive(f.path, f.public_profile, id)))
  let unrelated = d4_manage_unrelated(f, id)?
  println("ARCHIVE_MANAGEMENT_CORRUPT_FIXTURE_READY")
  remove_backup_archive(f.path, f.public_profile, id)?
  assert(Result.is_err(load_blob(f.path, row)))
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), [], []))
  assert(d4_core_rows_preserved(unrelated, d4_core_all_rows(f)?, 1))
  d4_core_cleanup(f)
end

test("archive remove can delete authorized corrupt payload without decoding it") do
  assert(Result.is_ok(d4_manage_remove_corrupt()))
end

fn d4_manage_post_delete_fault(f :: D4CoreFixture,
  id :: Bytes,
  install :: Bool) -> Result<(), String> do
  let row = backup_archive_label(f.account_id, id)?
  let index = backup_archive_index_label(f.account_id)?
  with_record_transaction(f.path,
    fn(database) do
      if install do
        let row_hash = blob_record_hash(database, row)?
        let index_hash = blob_record_hash(database, index)?
        Sqlite.execute(database,
          "CREATE TRIGGER d4_management_remove_fault BEFORE INSERT ON encrypted_blobs WHEN NEW.record_hash = '#{index_hash}' AND NOT EXISTS(SELECT 1 FROM encrypted_blobs WHERE record_hash = '#{row_hash}') BEGIN SELECT RAISE(ABORT, 'd4_management_post_delete_fault'); END",
          [])?
      else
        Sqlite.execute(database, "DROP TRIGGER d4_management_remove_fault", [])?
      end
      Ok(nil)
    end)
end

fn d4_manage_rollback() -> Result<(), String> do
  let f = d4_core_fixture()?
  let id = d4_manage_import(f)?
  let row = backup_archive_label(f.account_id, id)?
  let index = backup_archive_index_label(f.account_id)?
  let original = load_account_basis(f.path, [row, index])?
  d4_manage_post_delete_fault(f, id, true)?
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_MANAGEMENT_ROLLBACK_FIXTURE_READY")
  assert(case remove_backup_archive(f.path, f.public_profile, id) do
    Err("database_write_failed") -> true
    _ -> false
  end)
  assert(account_basis_current(f.path, original))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_manage_post_delete_fault(f, id, false)?
  remove_backup_archive(f.path, f.public_profile, id)?
  assert(Result.is_err(load_blob(f.path, row)))
  d4_core_cleanup(f)
end

test("archive removal rolls deletion back when replacement index write faults") do
  assert(Result.is_ok(d4_manage_rollback()))
end

fn d4_manage_drift_guards() -> Result<(), String> do
  let f = d4_core_fixture()?
  let id = d4_manage_import(f)?
  let row = backup_archive_label(f.account_id, id)?
  let index = backup_archive_index_label(f.account_id)?
  let originals = [load_blob(f.path, row)?, load_blob(f.path, index)?]
  println("ARCHIVE_MANAGEMENT_DRIFT_FIXTURE_READY")
  for mode in 0..3 do
    let target = if mode == 0 do
      row
    else
      index
    end
    let winner = Bytes.from_utf8("concurrent selected archive or index winning ciphertext")
    assert(case d4_manage_drift(f.path, f.public_profile, id, winner, mode) do
      Err("account_state_changed") -> true
      _ -> false
    end)
    assert(Bytes.secure_equals(load_blob(f.path, target)?, winner))
    let untouched = if mode == 0 do
      index
    else
      row
    end
    assert(Bytes.secure_equals(load_blob(f.path, untouched)?,
      List.get(originals,
        if mode == 0 do
          1
        else
          0
        end)))
    store_updated_blobs(f.path,
      [target],
      [
        List.get(originals,
          if mode == 0 do
            0
          else
            1
          end)
      ])?
  end
  remove_backup_archive(f.path, f.public_profile, id)?
  d4_core_cleanup(f)
end

test("archive list and removal final fences preserve concurrent index and row winners") do
  assert(Result.is_ok(d4_manage_drift_guards()))
end

fn d4_manage_malformed_and_inconsistent() -> Result<(), String> do
  let f = d4_core_fixture()?
  let id = d4_manage_import(f)?
  let row = backup_archive_label(f.account_id, id)?
  let index = backup_archive_index_label(f.account_id)?
  let originals = [load_blob(f.path, row)?, load_blob(f.path, index)?]
  d4_manage_index_wire(f.path, f.account_id, Bytes.from_utf8("malformed private index"))?
  let malformed = d4_core_all_rows(f)?
  println("ARCHIVE_MANAGEMENT_INCONSISTENT_FIXTURE_READY")
  assert(Result.is_err(list_backup_archives(f.path, f.public_profile)))
  assert(Result.is_err(remove_backup_archive(f.path, f.public_profile, id)))
  assert(d4_core_rows_preserved(malformed, d4_core_all_rows(f)?, 0))
  store_updated_blobs(f.path, [index], [List.get(originals, 1)])?
  d4_manage_drop(f.path, row)?
  let missing_row = d4_core_all_rows(f)?
  assert(Result.is_err(remove_backup_archive(f.path, f.public_profile, id)))
  assert(d4_core_rows_preserved(missing_row, d4_core_all_rows(f)?, 0))
  store_updated_blobs(f.path, [row], [List.get(originals, 0)])?
  d4_manage_drop(f.path, index)?
  let missing_entry = d4_core_all_rows(f)?
  assert(Result.is_err(remove_backup_archive(f.path, f.public_profile, id)))
  assert(d4_core_rows_preserved(missing_entry, d4_core_all_rows(f)?, 0))
  d4_manage_drop(f.path, row)?
  remove_backup_archive(f.path, f.public_profile, id)?
  assert(Result.is_err(load_blob(f.path, row)) && Result.is_err(load_blob(f.path, index)))
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), [], []))
  d4_core_cleanup(f)
end

test("archive management refuses malformed index and both inconsistent row entry states") do
  assert(Result.is_ok(d4_manage_malformed_and_inconsistent()))
end

fn d4_manage_foreign_account() -> Result<(), String> do
  let f = d4_core_fixture()?
  let id = d4_manage_import(f)?
  let foreign_path = f.path <> ".foreign"
  create_account_export(request([
    Bytes.from_utf8(foreign_path),
    Bytes.from_utf8("foreignbackup")
  ])?)?
  let foreign = load_profile(foreign_path)?
  let foreign_profile = decode_client_profile(foreign)?
  assert(!Bytes.secure_equals(foreign_profile.account_id, f.account_id))
  let before = d4_core_all_rows(f)?
  println("ARCHIVE_MANAGEMENT_FOREIGN_FIXTURE_READY")
  assert(Result.is_err(list_backup_archives(f.path, foreign)))
  assert(Result.is_err(remove_backup_archive(f.path, foreign, id)))
  assert(Result.is_err(remove_backup_archive(f.path, f.public_profile, repeated(1, 31)?)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  assert(d4_manage_list_matches(list_backup_archives(f.path, f.public_profile), [id], [f.now]))
  erase_local_state(foreign_path)?
  File.delete(foreign_path)?
  d4_core_cleanup(f)
end

test("archive management refuses another real account under the same platform key") do
  assert(Result.is_ok(d4_manage_foreign_account()))
end

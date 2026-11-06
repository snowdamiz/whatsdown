from Tests.BackupArchiveFixture import (
  d4_core_fixture,
  d4_core_cleanup,
  d4_core_install_matrix,
  d4_core_matrix_content,
  d4_core_content_matches,
  d4_core_actual_group,
  d4_core_install_group,
  d4_core_group_content,
  d4_core_max_bundle,
  d4_core_max_read_matches,
  d4_core_backup_id,
  d4_core_all_rows,
  d4_core_rows_preserved,
  d4_core_install_direct_history
)
from Mobile.BackupArchive import (
  D4BackupSelection,
  create_backup_archive,
  import_backup_archive,
  read_backup_archive
)
from Storage.AccountGuard import load_account_basis_bounded
from Storage.BackupArchiveCommit import backup_archive_label
from Mobile.Codec import current_time
from Tests.Support import repeated

test("whole backup export preserves inclusive range ordinals exclusive omission precedence and attachment placeholders") do
  let f = d4_core_fixture()?
  d4_core_install_matrix(f)?
  let before = d4_core_all_rows(f)?
  let started = current_time()?
  let created = create_backup_archive(f.path,
    f.public_profile,
    [
      D4BackupSelection {
        kind: 1,
        scope_id: repeated(71, 16)?,
        from_time: Some(U64.parse("10")?),
        through_time: Some(U64.parse("20")?)
      }
    ])?
  let finished = current_time()?
  assert(d4_core_content_matches(created, d4_core_matrix_content(f)?, started, finished))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("whole backup export preserves historical seven eight and current nine group fields and rejects duplicate nonempty IDs") do
  let f = d4_core_fixture()?
  let id = d4_core_actual_group(f)?
  for fields in [7, 8, 9] do
    d4_core_install_group(f, id, fields, false)?
    let before = d4_core_all_rows(f)?
    let started = current_time()?
    let created = create_backup_archive(f.path,
      f.public_profile,
      [D4BackupSelection { kind: 2, scope_id: id, from_time: None, through_time: None }])?
    let finished = current_time()?
    assert(d4_core_content_matches(created,
      d4_core_group_content(f, id, fields)?,
      started,
      finished))
    assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  end
  d4_core_install_group(f, id, 9, true)?
  let before = d4_core_all_rows(f)?
  assert(Result.is_err(create_backup_archive(f.path,
    f.public_profile,
    [D4BackupSelection { kind: 2, scope_id: id, from_time: None, through_time: None }])))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("whole backup maximum canonical payload imports through HCB2 reads exactly and preserves every original row") do
  let f = d4_core_fixture()?
  d4_core_install_direct_history(f)?
  let before = d4_core_all_rows(f)?
  let bundle = d4_core_max_bundle(f)?
  let id = d4_core_backup_id(bundle.wire)?
  let receipt = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    id)?
  assert(receipt.disposition == 1 && Bytes.secure_equals(receipt.backup_id, id))
  assert(d4_core_max_read_matches(f, id, read_backup_archive(f.path, f.public_profile, id)))
  let row = backup_archive_label(f.account_id, id)?
  let captured = load_account_basis_bounded(f.path, [row], 40000, 33554432, 33554432)?
  let blob = List.head(captured.records)
  assert(Bytes.length(blob) > 16777216)
  assert(Bytes.secure_equals(Bytes.slice(blob, 0, 4)?, Bytes.from_utf8("HCB2")))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 2))
  let retry = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    id)?
  assert(retry.disposition == 2)
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 2))
  assert(d4_core_max_read_matches(f, id, read_backup_archive(f.path, f.public_profile, id)))
  d4_core_cleanup(f)?
  Ok(nil)
end

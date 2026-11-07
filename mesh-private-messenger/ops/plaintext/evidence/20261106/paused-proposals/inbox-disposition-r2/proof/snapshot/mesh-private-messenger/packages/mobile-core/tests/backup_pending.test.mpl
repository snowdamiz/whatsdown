from Mobile.BackupArchive import (
  D4BackupSelection,
  create_pending_backup_export,
  pending_backup_export_state,
  resume_pending_backup_export,
  discard_pending_backup_export,
  repair_pending_backup_export
)
from Tests.BackupPendingSupport import (
  pending_fixture,
  pending_install,
  pending_install_with_id,
  pending_set_wire,
  pending_remove_row,
  pending_known_state
)
from Tests.BackupArchiveFixture import (
  d4_core_fixture,
  d4_core_install_direct_history,
  d4_core_cleanup,
  d4_core_all_rows,
  d4_core_rows_preserved,
  d4_core_import_bundle
)
from Tests.Support import repeated

fn pending_case_1() -> Result<(), String> do
  let f = d4_core_fixture()?
  d4_core_install_direct_history(f)?
  println("PENDING_CREATE_FIXTURE_READY")
  let raw = create_pending_backup_export(f.path,
    f.public_profile,
    [
      D4BackupSelection {
        kind: 1,
        scope_id: repeated(71, 16)?,
        from_time: None,
        through_time: None
      }
    ])
  assert(Result.is_ok(raw))
  let created = raw?
  assert(Bytes.length(created.draft_id) == 32
    && Bytes.length(created.wire) > 0
    && String.length(created.recovery_code) > 0)
  let resumed = resume_pending_backup_export(f.path,
    f.public_profile,
    created.draft_id,
    created.recovery_code)?
  assert(Bytes.secure_equals(resumed, created.wire))
  let second = create_pending_backup_export(f.path,
    f.public_profile,
    [
      D4BackupSelection {
        kind: 1,
        scope_id: repeated(71, 16)?,
        from_time: None,
        through_time: None
      }
    ])
  assert(Result.is_err(second))
  d4_core_cleanup(f)?
  Ok(nil)
end

test("pending create persists its own exact encrypted draft before returning") do
  assert(Result.is_ok(pending_case_1()))
end

fn pending_case_2() -> Result<(), String> do
  let f = pending_fixture()?
  println("PENDING_STATE_FIXTURE_READY")
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    1,
    f.draft_id,
    f.base.now,
    Bytes.length(f.bundle.wire)))
  assert(Result.is_err(repair_pending_backup_export(f.base.path, f.base.public_profile)))
  pending_set_wire(f, Bytes.from_utf8("damaged portable wire"), false)?
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    2,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  d4_core_cleanup(f.base)?
  Ok(nil)
end

test("pending state authenticates an independently authored owner bound pair") do
  assert(Result.is_ok(pending_case_2()))
end

fn pending_case_3() -> Result<(), String> do
  let f = pending_fixture()?
  println("PENDING_RESUME_FIXTURE_READY")
  let first = resume_pending_backup_export(f.base.path,
    f.base.public_profile,
    f.draft_id,
    f.bundle.recovery_code)
  assert(Result.is_ok(first))
  assert(Bytes.secure_equals(first?, f.bundle.wire))
  let before = d4_core_all_rows(f.base)?
  assert(Result.is_err(resume_pending_backup_export(f.base.path,
    f.base.public_profile,
    repeated(213, 32)?,
    f.bundle.recovery_code)))
  let other = d4_core_import_bundle(f.base, false)?
  assert(Result.is_err(resume_pending_backup_export(f.base.path,
    f.base.public_profile,
    f.draft_id,
    other.recovery_code)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    1,
    f.draft_id,
    f.base.now,
    Bytes.length(f.bundle.wire)))
  assert(Bytes.secure_equals(resume_pending_backup_export(f.base.path,
      f.base.public_profile,
      f.draft_id,
      f.bundle.recovery_code)?,
    f.bundle.wire))
  d4_core_cleanup(f.base)?
  Ok(nil)
end

test("pending resume returns original wire only and refuses wrong code or action id") do
  assert(Result.is_ok(pending_case_3()))
end

fn pending_case_4() -> Result<(), String> do
  let f = pending_fixture()?
  println("PENDING_DISCARD_FIXTURE_READY")
  let raw = discard_pending_backup_export(f.base.path, f.base.public_profile, f.draft_id)
  assert(Result.is_ok(raw))
  assert(raw? == 1)
  assert(discard_pending_backup_export(f.base.path, f.base.public_profile, f.draft_id)? == 2)
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    0,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  let next = pending_install_with_id(f.base, repeated(213, 32)?)?
  let before = d4_core_all_rows(f.base)?
  assert(Result.is_err(discard_pending_backup_export(f.base.path,
    f.base.public_profile,
    f.draft_id)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  assert(Bytes.secure_equals(resume_pending_backup_export(next.base.path,
      next.base.public_profile,
      next.draft_id,
      next.bundle.recovery_code)?,
    next.bundle.wire))
  d4_core_cleanup(f.base)?
  Ok(nil)
end

test("pending exact id discard is idempotent and cannot erase a valid successor") do
  assert(Result.is_ok(pending_case_4()))
end

fn pending_case_5() -> Result<(), String> do
  let f = pending_fixture()?
  pending_remove_row(f, true)?
  println("PENDING_REPAIR_FIXTURE_READY")
  let raw = repair_pending_backup_export(f.base.path, f.base.public_profile)
  assert(Result.is_ok(raw))
  assert(raw? == 1)
  println("PENDING_REPAIR_PARTIAL_OK")
  assert(repair_pending_backup_export(f.base.path, f.base.public_profile)? == 2)
  println("PENDING_REPAIR_EMPTY_OK")
  let valid = pending_install(f.base)?
  let before = d4_core_all_rows(f.base)?
  assert(Result.is_err(repair_pending_backup_export(f.base.path, f.base.public_profile)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  println("PENDING_REPAIR_VALID_REFUSAL_OK")
  pending_set_wire(valid, Bytes.from_utf8("corrupt"), false)?
  assert(repair_pending_backup_export(f.base.path, f.base.public_profile)? == 1)
  println("PENDING_REPAIR_CORRUPT_OK")
  let wrong = pending_install(f.base)?
  println("PENDING_REPAIR_TEXT_FIXTURE_PREPARED")
  pending_set_wire(wrong, Bytes.empty(), true)?
  println("PENDING_REPAIR_TEXT_INSTALLED")
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    2,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  assert(repair_pending_backup_export(f.base.path, f.base.public_profile)? == 1)
  println("PENDING_REPAIR_TEXT_OK")
  let large = pending_install(f.base)?
  let oversized = case Bytes.repeat(99, 16796865) do
    Err(_) -> return Err("pending_fixture_allocation")
    Ok(value) -> value
  end
  println("PENDING_REPAIR_OVERSIZE_ALLOCATED")
  pending_set_wire(large, oversized, false)?
  println("PENDING_REPAIR_OVERSIZE_INSTALLED")
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    2,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  assert(repair_pending_backup_export(f.base.path, f.base.public_profile)? == 1)
  println("PENDING_REPAIR_OVERSIZE_OK")
  d4_core_cleanup(f.base)?
  Ok(nil)
end

test("pending repair handles partial corrupt wrong type and oversized pairs without deleting valid drafts") do
  assert(Result.is_ok(pending_case_5()))
end

from Tests.BackupPendingSupport import d4_pending_maximum_fixture, d4_pending_descriptor_write_fault
from Mobile.BackupAuthority import capture_backup_authority

fn pending_case_publication_rollback() -> Result<(), String> do
  let f = d4_core_fixture()?
  d4_core_install_direct_history(f)?
  let _ = capture_backup_authority(f.path, f.public_profile)?
  let before = d4_core_all_rows(f)?
  d4_pending_descriptor_write_fault(f, true)?
  println("PENDING_ATOMIC_FIXTURE_READY")
  let selection = [
    D4BackupSelection { kind: 1, scope_id: repeated(71, 16)?, from_time: None, through_time: None }
  ]
  assert(Result.is_err(create_pending_backup_export(f.path, f.public_profile, selection)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 0))
  assert(pending_known_state(pending_backup_export_state(f.path, f.public_profile),
    0,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  d4_pending_descriptor_write_fault(f, false)?
  let created = create_pending_backup_export(f.path, f.public_profile, selection)?
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 2))
  assert(Bytes.secure_equals(resume_pending_backup_export(f.path,
      f.public_profile,
      created.draft_id,
      created.recovery_code)?,
    created.wire))
  d4_core_cleanup(f)
end

test("pending descriptor fault after wire insertion rolls back both rows and later succeeds") do
  assert(Result.is_ok(pending_case_publication_rollback()))
end

fn pending_case_maximum() -> Result<(), String> do
  let f = d4_pending_maximum_fixture()?
  let _ = capture_backup_authority(f.base.path, f.base.public_profile)?
  let before = d4_core_all_rows(f.base)?
  println("PENDING_MAXIMUM_FIXTURE_READY")
  assert(Bytes.length(f.bundle.wire) == 16796864)
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    1,
    f.draft_id,
    f.base.now,
    16796864))
  let resumed = resume_pending_backup_export(f.base.path,
    f.base.public_profile,
    f.draft_id,
    f.bundle.recovery_code)?
  assert(Bytes.secure_equals(resumed, f.bundle.wire))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  assert(discard_pending_backup_export(f.base.path, f.base.public_profile, f.draft_id)? == 1)
  assert(pending_known_state(pending_backup_export_state(f.base.path, f.base.public_profile),
    0,
    Bytes.empty(),
    U64.parse("0")?,
    0))
  d4_core_cleanup(f.base)
end

test("pending maximum portable ciphertext reopens authenticates resumes byte exactly and discards") do
  assert(Result.is_ok(pending_case_maximum()))
end

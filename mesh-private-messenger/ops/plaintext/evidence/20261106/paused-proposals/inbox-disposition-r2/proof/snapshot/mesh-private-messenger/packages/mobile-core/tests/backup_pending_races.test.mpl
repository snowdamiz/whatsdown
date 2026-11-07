from Mobile.BackupArchive import (
  D4BackupSelection,
  d4_pending_race_create,
  d4_pending_race_state,
  d4_pending_race_resume,
  d4_pending_race_discard,
  d4_pending_race_repair,
  resume_pending_backup_export
)
from Tests.BackupPendingSupport import (
  pending_fixture,
  pending_remove_row,
  pending_set_wire,
  d4_pending_descriptor_cipher,
  d4_pending_state_refused
)
from Tests.BackupArchiveFixture import (
  d4_core_cleanup,
  d4_core_install_direct_history,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Tests.Support import repeated
from Mobile.BackupAuthority import capture_backup_authority
from Storage.Blobs import load_blob
from Storage.Records import store_updated_blobs

fn pending_race_pair() -> Result<(), String> do
  for action in 0..3 do
    let f = pending_fixture()?
    let _ = capture_backup_authority(f.base.path, f.base.public_profile)?
    let original_descriptor = load_blob(f.base.path, f.descriptor_label)?
    let before = d4_core_all_rows(f.base)?
    let successor = %{f | draft_id: repeated(213, 32)?}
    let sealed = d4_pending_descriptor_cipher(successor)?
    println("PENDING_PAIR_RACE_FIXTURE_READY")
    let refused = if action == 0 do
      d4_pending_state_refused(d4_pending_race_state(f.base.path,
        f.base.public_profile,
        successor.bundle.wire,
        sealed,
        0))
    else if action == 1 do
      Result.is_err(d4_pending_race_resume(f.base.path,
        f.base.public_profile,
        f.draft_id,
        f.bundle.recovery_code,
        successor.bundle.wire,
        sealed,
        0))
    else
      Result.is_err(d4_pending_race_discard(f.base.path,
        f.base.public_profile,
        f.draft_id,
        successor.bundle.wire,
        sealed,
        0))
    end
    assert(refused)
    assert(Bytes.secure_equals(load_blob(f.base.path, f.wire_label)?, successor.bundle.wire))
    assert(Bytes.secure_equals(load_blob(f.base.path, f.descriptor_label)?, sealed))
    assert(Bytes.secure_equals(resume_pending_backup_export(f.base.path,
        f.base.public_profile,
        successor.draft_id,
        successor.bundle.recovery_code)?,
      successor.bundle.wire))
    store_updated_blobs(f.base.path,
      [f.wire_label, f.descriptor_label],
      [f.bundle.wire, original_descriptor])?
    assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
    d4_core_cleanup(f.base)?
  end
  Ok(nil)
end

test("pending state resume and discard refuse a valid pair replaced after preparation") do
  assert(Result.is_ok(pending_race_pair()))
end

fn pending_race_repair() -> Result<(), String> do
  let f = pending_fixture()?
  let _ = capture_backup_authority(f.base.path, f.base.public_profile)?
  let original_descriptor = load_blob(f.base.path, f.descriptor_label)?
  pending_set_wire(f, Bytes.from_utf8("invalid before repair capture"), false)?
  let before = d4_core_all_rows(f.base)?
  let successor = %{f | draft_id: repeated(213, 32)?}
  let sealed = d4_pending_descriptor_cipher(successor)?
  println("PENDING_REPAIR_RACE_FIXTURE_READY")
  assert(Result.is_err(d4_pending_race_repair(f.base.path,
    f.base.public_profile,
    successor.bundle.wire,
    sealed,
    0)))
  assert(Bytes.secure_equals(load_blob(f.base.path, f.wire_label)?, successor.bundle.wire))
  assert(Bytes.secure_equals(load_blob(f.base.path, f.descriptor_label)?, sealed))
  assert(Bytes.secure_equals(resume_pending_backup_export(f.base.path,
      f.base.public_profile,
      successor.draft_id,
      successor.bundle.recovery_code)?,
    successor.bundle.wire))
  store_updated_blobs(f.base.path,
    [f.wire_label, f.descriptor_label],
    [Bytes.from_utf8("invalid before repair capture"), original_descriptor])?
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  d4_core_cleanup(f.base)
end

test("pending repair cannot erase a valid successor installed after invalid pair capture") do
  assert(Result.is_ok(pending_race_repair()))
end

fn pending_race_create() -> Result<(), String> do
  let f = pending_fixture()?
  d4_core_install_direct_history(f.base)?
  let _ = capture_backup_authority(f.base.path, f.base.public_profile)?
  let sealed = load_blob(f.base.path, f.descriptor_label)?
  pending_remove_row(f, true)?
  pending_remove_row(f, false)?
  let before = d4_core_all_rows(f.base)?
  println("PENDING_CREATE_RACE_FIXTURE_READY")
  assert(Result.is_err(d4_pending_race_create(f.base.path,
    f.base.public_profile,
    [
      D4BackupSelection {
        kind: 1,
        scope_id: repeated(71, 16)?,
        from_time: None,
        through_time: None
      }
    ],
    f.bundle.wire,
    sealed,
    0)))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 2))
  assert(Bytes.secure_equals(load_blob(f.base.path, f.wire_label)?, f.bundle.wire))
  assert(Bytes.secure_equals(load_blob(f.base.path, f.descriptor_label)?, sealed))
  assert(Bytes.secure_equals(resume_pending_backup_export(f.base.path,
      f.base.public_profile,
      f.draft_id,
      f.bundle.recovery_code)?,
    f.bundle.wire))
  d4_core_cleanup(f.base)
end

test("pending create refuses to overwrite a pair published after original absence") do
  assert(Result.is_ok(pending_race_create()))
end

fn pending_race_authority() -> Result<(), String> do
  let f = pending_fixture()?
  let authority = capture_backup_authority(f.base.path, f.base.public_profile)?
  let labels = ["profile/v1", "ohttp-revision/v1"]
  let originals = [
    load_blob(f.base.path, List.get(labels, 0))?,
    load_blob(f.base.path, List.get(labels, 1))?
  ]
  let before = d4_core_all_rows(f.base)?
  println("PENDING_AUTHORITY_RACE_FIXTURE_READY")
  for mode in 1..4 do
    let winner = Bytes.from_utf8("concurrent winning pending authority ciphertext or native frame")
    assert(Result.is_err(d4_pending_race_resume(f.base.path,
      f.base.public_profile,
      f.draft_id,
      f.bundle.recovery_code,
      winner,
      Bytes.empty(),
      mode)))
    if mode == 3 do
      assert(Test.set_push_token(Bytes.from_utf8("messenger/network/v1"),
        authority.context.network_frame))
    else
      let label = List.get(labels, mode - 1)
      assert(Bytes.secure_equals(load_blob(f.base.path, label)?, winner))
      store_updated_blobs(f.base.path, [label], [List.get(originals, mode - 1)])?
    end
  end
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  assert(Bytes.secure_equals(resume_pending_backup_export(f.base.path,
      f.base.public_profile,
      f.draft_id,
      f.bundle.recovery_code)?,
    f.bundle.wire))
  d4_core_cleanup(f.base)
end

test("pending resume fences actual profile revision and raw native frame drift") do
  assert(Result.is_ok(pending_race_authority()))
end

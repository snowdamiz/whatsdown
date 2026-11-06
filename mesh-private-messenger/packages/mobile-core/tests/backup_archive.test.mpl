from Tests.BackupArchiveFixture import d4_core_fixture, d4_core_cleanup
from Mobile.BackupAuthority import capture_backup_authority
from Mobile.Transparency import (
  backup_transparency_proof_label,
  verify_backup_captured_transparency
)
from Storage.AccountGuard import account_basis_current
from Tests.GroupConsistencySupport import wide
from Tests.Support import repeated

fn d4_captured_trust() -> Result<(), String> do
  let f = d4_core_fixture()?
  assert(backup_transparency_proof_label(f.input.device_set_cache,
    f.input.shared_checkpoint)? == "")
  let accepted = verify_backup_captured_transparency(f.input, f.config, f.now)?
  assert(Bytes.secure_equals(accepted.verified.checkpoint, f.input.shared_checkpoint))
  assert(U64.compare(accepted.fresh_through, f.expected_fresh_through) == 0)
  # Inclusive exact signed deadline; the next millisecond is refused below.
  assert(Result.is_ok(verify_backup_captured_transparency(f.input,
    f.config,
    f.expected_fresh_through)))
  # A corrupt otherwise-unused empty third chunk is not ignored.
  assert(Result.is_err(verify_backup_captured_transparency(%{f.input |
      view_chunks: [
        List.get(f.input.view_chunks, 0),
        List.get(f.input.view_chunks, 1),
        repeated(99, 1)?
      ]
    },
    f.config,
    f.now)))
  assert(Result.is_err(verify_backup_captured_transparency(%{f.input | witnesses: Bytes.empty()},
    f.config,
    f.now)))
  # C2SP signer expires before the signed checkpoint's millisecond window.
  let after_expiry = U64.add(f.expected_fresh_through, wide(1)?)?
  assert(Result.is_err(verify_backup_captured_transparency(f.input, f.config, after_expiry)))
  assert(account_basis_current(f.path, List.head(f.original.bases)))
  d4_core_cleanup(f)
end

test("captured backup trust accepts signed split view and refuses altered tails witnesses and C2SP expiry") do
  assert(Result.is_ok(d4_captured_trust()))
end

fn d4_custody_capture() -> Result<(), String> do
  let f = d4_core_fixture()?
  let authority = capture_backup_authority(f.path, f.public_profile)?
  assert(Bytes.secure_equals(authority.public_profile, f.public_profile))
  assert(Bytes.secure_equals(authority.profile.account_id, f.account_id))
  assert(U64.compare(authority.fresh_through, f.expected_fresh_through) <= 0)
  assert(Result.is_err(capture_backup_authority(f.path, repeated(0, 96)?)))
  assert(account_basis_current(f.path, List.head(f.original.bases)))
  d4_core_cleanup(f)
end

test("backup authority captures actual active custody internally and refuses a foreign expected profile") do
  assert(Result.is_ok(d4_custody_capture()))
end

from Tests.BackupArchiveFixture import (
  d4_core_install_direct_history,
  d4_core_corrupt_direct_history,
  d4_core_created_matches
)
from Mobile.Codec import current_time
from Mobile.BackupArchive import D4BackupSelection, create_backup_archive
from Backups.PortableV2 import restore_portable_backup
from Storage.AccountGuard import load_account_basis
from Storage.Blobs import load_blob

fn d4_whole_create_flow() -> Result<(), String> do
  let f = d4_core_fixture()?
  d4_core_install_direct_history(f)?
  let before = load_account_basis(f.path,
    [
      "sessions/v1",
      "session/v1/#{Bytes.to_hex(repeated(21, 32)?)}",
      "session/v1/#{Bytes.to_hex(repeated(22, 32)?)}",
      f.source_label,
      "history/v1/#{Bytes.to_hex(repeated(72, 16)?)}"
    ])?
  let selection = [
    D4BackupSelection { kind: 1, scope_id: repeated(71, 16)?, from_time: None, through_time: None }
  ]
  let started = current_time()?
  let created = create_backup_archive(f.path, f.public_profile, selection)?
  let finished = current_time()?
  assert(d4_core_created_matches(f, created, started, finished))
  assert(String.starts_with(created.recovery_code, "MRC1-"))
  assert(Bytes.length(created.wire) > 293)
  assert(Result.is_ok(restore_portable_backup(created.recovery_code, created.wire)))
  assert(account_basis_current(f.path, before))
  let retry = create_backup_archive(f.path, f.public_profile, selection)?
  assert(retry.recovery_code != created.recovery_code)
  assert(!Bytes.secure_equals(retry.wire, created.wire))
  assert(Result.is_ok(restore_portable_backup(retry.recovery_code, retry.wire)))
  assert(d4_core_created_matches(f, retry, started, current_time()?))
  let corrupted = d4_core_corrupt_direct_history(f)?
  assert(Result.is_err(create_backup_archive(f.path, f.public_profile, selection)))
  assert(Bytes.secure_equals(load_blob(f.path, f.source_label)?, corrupted))
  d4_core_cleanup(f)
end

test("whole backup create captures canonical direct history with fresh codes and refuses protected malformed history") do
  assert(Result.is_ok(d4_whole_create_flow()))
end

from Tests.BackupArchiveFixture import (
  d4_core_import_bundle,
  d4_core_backup_id,
  d4_core_legacy_import_bundle,
  d4_core_stored_matches,
  d4_core_restore_fixture_index,
  d4_core_index_fault
)
from Mobile.BackupArchive import import_backup_archive, read_backup_archive

fn d4_whole_import_flow() -> Result<(), String> do
  let f = d4_core_fixture()?
  let bundle = d4_core_import_bundle(f, false)?
  let confirmed = d4_core_backup_id(bundle.wire)?
  let receipt = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    confirmed)?
  assert(Bytes.secure_equals(receipt.backup_id, confirmed) && receipt.disposition == 1)
  let row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(confirmed)}"
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  let before = load_account_basis(f.path, [row, index])?
  let same = import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    confirmed)?
  assert(Bytes.secure_equals(same.backup_id, confirmed) && same.disposition == 2)
  assert(account_basis_current(f.path, before))
  let legacy_same = d4_core_legacy_import_bundle(f, confirmed, false)?
  assert(Result.is_ok(restore_portable_backup(legacy_same.recovery_code, legacy_same.wire)))
  let legacy_receipt = import_backup_archive(f.path,
    f.public_profile,
    legacy_same.wire,
    legacy_same.recovery_code,
    confirmed)?
  assert(legacy_receipt.disposition == 2)
  assert(account_basis_current(f.path, before))
  let conflicting = d4_core_legacy_import_bundle(f, confirmed, true)?
  assert(Result.is_ok(restore_portable_backup(conflicting.recovery_code, conflicting.wire)))
  assert(Result.is_err(import_backup_archive(f.path,
    f.public_profile,
    conflicting.wire,
    conflicting.recovery_code,
    confirmed)))
  assert(account_basis_current(f.path, before))
  let stored = read_backup_archive(f.path, f.public_profile, confirmed)
  assert(d4_core_stored_matches(f, confirmed, stored))
  assert(Result.is_err(import_backup_archive(f.path,
    f.public_profile,
    bundle.wire,
    bundle.recovery_code,
    repeated(0, 32)?)))
  assert(account_basis_current(f.path, before))
  let foreign = d4_core_import_bundle(f, true)?
  let foreign_id = d4_core_backup_id(foreign.wire)?
  assert(Result.is_err(import_backup_archive(f.path,
    f.public_profile,
    foreign.wire,
    foreign.recovery_code,
    foreign_id)))
  assert(account_basis_current(f.path, before))
  assert(Result.is_err(load_blob(f.path,
    "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(foreign_id)}")))
  d4_core_cleanup(f)
end

test("whole backup import confirms authenticated identity stores isolated rows and retries idempotently") do
  assert(Result.is_ok(d4_whole_import_flow()))
end

fn d4_import_second_write_rollback() -> Result<(), String> do
  let f = d4_core_fixture()?
  let original = d4_core_import_bundle(f, false)?
  let original_id = d4_core_backup_id(original.wire)?
  import_backup_archive(f.path,
    f.public_profile,
    original.wire,
    original.recovery_code,
    original_id)?
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  let original_row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(original_id)}"
  let initial_index = load_blob(f.path, index)?
  let baseline = d4_core_import_bundle(f, false)?
  let baseline_id = d4_core_backup_id(baseline.wire)?
  let baseline_row = "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(baseline_id)}"
  # Prove this exact authenticated file succeeds before introducing the SQL fault.
  let accepted = import_backup_archive(f.path,
    f.public_profile,
    baseline.wire,
    baseline.recovery_code,
    baseline_id)?
  assert(accepted.disposition == 1)
  d4_core_restore_fixture_index(f, baseline_id, initial_index)?
  let before = load_account_basis(f.path, [original_row, index, baseline_row])?
  d4_core_index_fault(f, true)?
  assert(Result.is_err(import_backup_archive(f.path,
    f.public_profile,
    baseline.wire,
    baseline.recovery_code,
    baseline_id)))
  d4_core_index_fault(f, false)?
  assert(account_basis_current(f.path, before))
  assert(Result.is_err(load_blob(f.path, baseline_row)))
  assert(d4_core_stored_matches(f,
    original_id,
    read_backup_archive(f.path, f.public_profile, original_id)))
  d4_core_cleanup(f)
end

test("whole backup import rolls back its archive write when the following index write aborts") do
  assert(Result.is_ok(d4_import_second_write_rollback()))
end

fn d4_import_ninth_archive() -> Result<(), String> do
  let f = d4_core_fixture()?
  let ids = for count in 0..8 do
    let bundle = d4_core_import_bundle(f, false)?
    let id = d4_core_backup_id(bundle.wire)?
    let receipt = import_backup_archive(f.path,
      f.public_profile,
      bundle.wire,
      bundle.recovery_code,
      id)?
    assert(receipt.disposition == 1)
    id
  end
  let index = "backup-archives/v1/#{Bytes.to_hex(f.account_id)}"
  let existing = load_blob(f.path, index)?
  let ninth = d4_core_import_bundle(f, false)?
  let ninth_id = d4_core_backup_id(ninth.wire)?
  assert(Result.is_err(import_backup_archive(f.path,
    f.public_profile,
    ninth.wire,
    ninth.recovery_code,
    ninth_id)))
  assert(Bytes.secure_equals(load_blob(f.path, index)?, existing))
  assert(Result.is_err(load_blob(f.path,
    "backup-archive/v1/#{Bytes.to_hex(f.account_id)}/#{Bytes.to_hex(ninth_id)}")))
  for id in ids do
    assert(d4_core_stored_matches(f, id, read_backup_archive(f.path, f.public_profile, id)))
  end
  d4_core_cleanup(f)
end

test("whole backup import refuses a ninth archive without eviction or index replacement") do
  assert(Result.is_ok(d4_import_ninth_archive()))
end

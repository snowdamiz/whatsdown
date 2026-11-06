from Mobile.BackupNative import (
  native_backup_create,
  native_backup_pending_state,
  native_backup_pending_resume,
  native_backup_pending_discard,
  native_backup_pending_repair
)
from Mobile.BackupArchive import D4BackupPendingCreated
from Mobile.BackupAuthority import capture_backup_authority
from Tests.BackupPendingSupport import (
  PendingFixture,
  pending_fixture,
  pending_install,
  pending_remove_row,
  pending_known_reply,
  d4_pending_known_native_refusal
)
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_fixture,
  d4_core_install_direct_history,
  d4_core_cleanup,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Tests.Support import repeated
from Mobile.Codec import (
  mobile_join,
  mobile_byte,
  mobile_vector,
  mobile_write_u32,
  mobile_write_u64,
  take_fixed,
  take_vector,
  mobile_utf8
)
from Binary.Reader import reader, finish

fn pending_native_join(parts :: List<Bytes>) -> Bytes!String do
  mobile_join(parts, 0, Bytes.empty())
end

fn pending_native_base(f :: D4CoreFixture) -> Bytes!String do
  pending_native_join([
    mobile_byte(1)?,
    mobile_vector(Bytes.from_utf8(f.path))?,
    mobile_vector(f.public_profile)?
  ])
end

fn pending_native_created(reply :: Bytes) -> D4BackupPendingCreated!String do
  let state = case reader(reply, 16801001) do
    Err(_) -> return Err("pending_native_fixture_reply")
    Ok(value) -> value
  end
  let version = take_fixed(state, 1)?
  assert(Bytes.to_hex(version.value) == "02")
  let draft = take_fixed(version.state, 32)?
  let wire = take_vector(draft.state, 16796864)?
  let code = take_vector(wire.state, 4096)?
  case finish(code.state) do
    Err(_) -> return Err("pending_native_fixture_reply")
    Ok(_) -> nil
  end
  Ok(D4BackupPendingCreated {
    draft_id: draft.value,
    wire: wire.value,
    recovery_code: mobile_utf8(code.value, "pending_native_fixture_code")?
  })
end

fn pending_native_portable(f :: PendingFixture) -> Bytes!String do
  pending_native_join([
    pending_native_base(f.base)?,
    f.draft_id,
    mobile_vector(Bytes.from_utf8(f.bundle.recovery_code))?
  ])
end

fn pending_native_create_case() -> Result<(), String> do
  let f = d4_core_fixture()?
  d4_core_install_direct_history(f)?
  let _ = capture_backup_authority(f.path, f.public_profile)?
  let before = d4_core_all_rows(f)?
  let selection = pending_native_join([
    mobile_byte(1)?,
    mobile_byte(1)?,
    mobile_vector(repeated(71, 16)?)?,
    mobile_byte(0)?,
    mobile_byte(0)?
  ])?
  let frame = pending_native_join([pending_native_base(f)?, mobile_vector(selection)?])?
  println("PENDING_NATIVE_CREATE_FIXTURE_READY")
  let raw = native_backup_create(frame)
  assert(Result.is_ok(raw))
  let created = pending_native_created(raw?)?
  assert(Bytes.length(created.draft_id) == 32)
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f)?, 2))
  let resume = pending_native_join([
    pending_native_base(f)?,
    created.draft_id,
    mobile_vector(Bytes.from_utf8(created.recovery_code))?
  ])?
  assert(Bytes.secure_equals(native_backup_pending_resume(resume)?,
    pending_native_join([mobile_byte(1)?, mobile_vector(created.wire)?])?))
  d4_core_cleanup(f)
end

test("native pending create returns version two exact id and persists before response") do
  assert(Result.is_ok(pending_native_create_case()))
end

fn pending_native_state_case() -> Result<(), String> do
  let f = pending_fixture()?
  let base = pending_native_base(f.base)?
  println("PENDING_NATIVE_STATE_FIXTURE_READY")
  let expected = pending_native_join([
    mobile_byte(1)?,
    mobile_byte(1)?,
    f.draft_id,
    mobile_write_u64(f.base.now)?,
    mobile_write_u32(Bytes.length(f.bundle.wire))?
  ])?
  assert(pending_known_reply(native_backup_pending_state(base), expected))
  assert(d4_pending_known_native_refusal(native_backup_pending_state(pending_native_join([
    base,
    mobile_byte(0)?
  ])?)))
  d4_core_cleanup(f.base)
end

test("native pending state projects only authenticated bounded descriptor") do
  assert(Result.is_ok(pending_native_state_case()))
end

fn pending_native_resume_case() -> Result<(), String> do
  let f = pending_fixture()?
  let before = d4_core_all_rows(f.base)?
  println("PENDING_NATIVE_RESUME_FIXTURE_READY")
  let raw = native_backup_pending_resume(pending_native_portable(f)?)
  assert(Result.is_ok(raw))
  assert(Bytes.secure_equals(raw?,
    pending_native_join([mobile_byte(1)?, mobile_vector(f.bundle.wire)?])?))
  assert(d4_core_rows_preserved(before, d4_core_all_rows(f.base)?, 0))
  d4_core_cleanup(f.base)
end

test("native pending resume returns original ciphertext without code or mutation") do
  assert(Result.is_ok(pending_native_resume_case()))
end

fn pending_native_discard_case() -> Result<(), String> do
  let f = pending_fixture()?
  let frame = pending_native_join([pending_native_base(f.base)?, f.draft_id])?
  println("PENDING_NATIVE_DISCARD_FIXTURE_READY")
  let raw = native_backup_pending_discard(frame)
  assert(Result.is_ok(raw))
  assert(Bytes.secure_equals(raw?,
    pending_native_join([mobile_byte(1)?, f.draft_id, mobile_byte(1)?])?))
  assert(Bytes.secure_equals(native_backup_pending_discard(frame)?,
    pending_native_join([mobile_byte(1)?, f.draft_id, mobile_byte(2)?])?))
  assert(pending_known_reply(native_backup_pending_state(pending_native_base(f.base)?),
    pending_native_join([mobile_byte(1)?, mobile_byte(0)?])?))
  d4_core_cleanup(f.base)
end

test("native pending discard validates exact echoed action id and idempotent receipt") do
  assert(Result.is_ok(pending_native_discard_case()))
end

fn pending_native_repair_case() -> Result<(), String> do
  let f = pending_fixture()?
  pending_remove_row(f, true)?
  let base = pending_native_base(f.base)?
  println("PENDING_NATIVE_REPAIR_FIXTURE_READY")
  let raw = native_backup_pending_repair(base)
  assert(Result.is_ok(raw))
  assert(Bytes.secure_equals(raw?, pending_native_join([mobile_byte(1)?, mobile_byte(1)?])?))
  assert(Bytes.secure_equals(native_backup_pending_repair(base)?,
    pending_native_join([mobile_byte(1)?, mobile_byte(2)?])?))
  let valid = pending_install(f.base)?
  assert(Result.is_err(native_backup_pending_repair(base)))
  d4_core_cleanup(valid.base)
end

test("native pending repair is distinct from discard and refuses valid replacement") do
  assert(Result.is_ok(pending_native_repair_case()))
end

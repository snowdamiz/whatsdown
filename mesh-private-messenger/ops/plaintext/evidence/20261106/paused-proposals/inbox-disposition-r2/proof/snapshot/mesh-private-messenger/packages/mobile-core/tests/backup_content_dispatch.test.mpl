from MobileCore import backup_create_export, backup_pending_resume_export
from Mobile.BackupNative import parse_backup_create_request, parse_backup_content_create_request
from Mobile.BackupArchive import (
  D4BackupPendingCreated,
  D4BackupPendingState,
  pending_backup_export_state
)
from Tests.BackupContentPublicationFixture import publication_fixture
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_cleanup,
  d4_core_all_rows,
  d4_core_rows_preserved,
  d4_core_backup_id
)
from Tests.Support import repeated
from Mobile.Codec import (
  mobile_join,
  mobile_byte,
  mobile_vector,
  take_fixed,
  take_vector,
  mobile_utf8
)
from Binary.Reader import reader, finish
from Backups.PortableV2 import PortableBackupV2Error, restore_portable_archive
from Backups.TextArchive import decode_text_archive
from Backups.ContentArchive import decode_content_archive, BackupAttachmentPolicy

fn dispatch_join(parts :: List<Bytes>) -> Bytes!String do
  mobile_join(parts, 0, Bytes.empty())
end

fn dispatch_base(f :: D4CoreFixture, version :: Int) -> Bytes!String do
  dispatch_join([
    mobile_byte(version)?,
    mobile_vector(Bytes.from_utf8(f.path))?,
    mobile_vector(f.public_profile)?
  ])
end

fn dispatch_create_request(f :: D4CoreFixture, version :: Int) -> Bytes!String do
  let selection = dispatch_join([
    mobile_byte(1)?,
    mobile_byte(1)?,
    mobile_vector(repeated(71, 16)?)?,
    mobile_byte(0)?,
    mobile_byte(0)?
  ])?
  dispatch_join([dispatch_base(f, version)?, mobile_vector(selection)?])
end

fn dispatch_created(reply :: Bytes) -> D4BackupPendingCreated!String do
  let state = case reader(reply, 16801001) do
    Err(_) -> return Err("dispatch_fixture_reply")
    Ok(value) -> value
  end
  let version = take_fixed(state, 1)?
  if Bytes.to_hex(version.value) != "02" do
    return Err("dispatch_fixture_reply_version")
  end
  let draft = take_fixed(version.state, 32)?
  let wire = take_vector(draft.state, 16796864)?
  let code = take_vector(wire.state, 4096)?
  case finish(code.state) do
    Err(_) -> return Err("dispatch_fixture_reply")
    Ok(_) -> nil
  end
  Ok(D4BackupPendingCreated {
    draft_id: draft.value,
    wire: wire.value,
    recovery_code: mobile_utf8(code.value, "dispatch_fixture_code")?
  })
end

fn dispatch_state_matches(raw :: Result<Plaintext<D4BackupPendingState>, String>,
  created :: D4BackupPendingCreated) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(value) -> value.kind == 1
      && Bytes.secure_equals(value.draft_id, created.draft_id)
      && value.wire_size == Bytes.length(created.wire)
      && U64.to_string(value.created_at) != "0"
  end
end

fn dispatch_payload_matches(raw :: Result<Plaintext<Bytes>, PortableBackupV2Error>,
  version :: Int,
  owner :: Bytes,
  id :: Bytes,
  scope_id :: Bytes) -> Plaintext<Bool> do
  let payload = case raw do
    Err(_) -> return false
    Ok(value) -> value
  end
  if version == 1 do
    let archive = case decode_text_archive(payload) do
      Err(_) -> return false
      Ok(value) -> value
    end
    if List.length(archive.scopes) != 1 do
      return false
    end
    let scope = List.head(archive.scopes)
    if List.length(scope.entries) != 1 do
      return false
    end
    let record = List.head(scope.entries)
    Bytes.secure_equals(archive.owner_account, owner)
      && Bytes.secure_equals(archive.backup_id, id)
      && archive.candidate_count == 1
      && archive.attachment_messages == 0
      && scope.kind == 1
      && Bytes.secure_equals(scope.id, scope_id)
      && !record.attachment_omitted
      && Bytes.secure_equals(record.text, Bytes.from_utf8("actual captured canonical direct text"))
  else
    let archive = case decode_content_archive(payload) do
      Err(_) -> return false
      Ok(value) -> value
    end
    let policy_matches = case (version, archive.policy) do
      (2, RequireArchiveAttachments) -> true
      (3, AllowArchiveAttachmentOmissions) -> true
      _ -> false
    end
    if List.length(archive.scopes) != 1 do
      return false
    end
    let scope = List.head(archive.scopes)
    if List.length(scope.entries) != 1 do
      return false
    end
    let record = List.head(scope.entries)
    policy_matches
      && Bytes.secure_equals(archive.owner_account, owner)
      && Bytes.secure_equals(archive.backup_id, id)
      && archive.candidate_count == 1
      && archive.attachment_messages == 0
      && scope.kind == 1
      && Bytes.secure_equals(scope.id, scope_id)
      && List.length(record.attachments) == 0
      && Bytes.secure_equals(record.text, Bytes.from_utf8("actual captured canonical direct text"))
  end
end

fn dispatch_create_with_fixture(f :: D4CoreFixture, version :: Int) -> Plaintext<Bool>!String do
  let frame = dispatch_create_request(f, version)?
  let shape_valid = if version == 1 do
    Result.is_ok(parse_backup_create_request(frame))
  else
    Result.is_ok(parse_backup_content_create_request(frame))
  end
  if !shape_valid do
    return Err("dispatch_fixture_request")
  end
  let before = d4_core_all_rows(f)?
  println("NATIVE_CONTENT_DISPATCH_READY/#{version}")
  let created = case backup_create_export(frame) do
    Err(_) -> return Ok(false)
    Ok(reply) -> dispatch_created(reply)?
  end
  let committed = d4_core_all_rows(f)?
  let state = pending_backup_export_state(f.path, f.public_profile)
  let resume_request = dispatch_join([
    dispatch_base(f, 1)?,
    created.draft_id,
    mobile_vector(Bytes.from_utf8(created.recovery_code))?
  ])?
  let resumed = backup_pending_resume_export(resume_request)
  let untouched = d4_core_all_rows(f)?
  let expected_reply = dispatch_join([mobile_byte(1)?, mobile_vector(created.wire)?])?
  let resume_matches = case resumed do
    Err(_) -> false
    Ok(reply) -> Bytes.secure_equals(reply, expected_reply)
  end
  let id = d4_core_backup_id(created.wire)?
  let selected = repeated(71, 16)?
  let restored = restore_portable_archive(created.recovery_code, created.wire)
  Ok(d4_core_rows_preserved(before, committed, 2)
    && d4_core_rows_preserved(committed, untouched, 0)
    && resume_matches
    && dispatch_state_matches(state, created)
    && dispatch_payload_matches(restored, version, f.account_id, id, selected))
end

fn dispatch_create_case(version :: Int) -> Plaintext<Bool>!String do
  let fixture = publication_fixture()?
  let raw = dispatch_create_with_fixture(fixture, version)
  let cleaned = d4_core_cleanup(fixture)
  cleaned?
  raw
end

fn dispatch_expect(raw :: Result<Plaintext<Bool>, String>) do
  let protected = case raw do
    Err(_) -> 0
    Ok(value) -> if value do
      2
    else
      1
    end
  end
  let outcome = declassify(protected,
    "TEST ONLY closed synthetic native creation fixture refusal false or exact archive policy selected text pending pair and ciphertext resume success; no real keys recovery codes content owner metadata or raw errors are released")
  assert(outcome != 0)
  assert(outcome == 2)
end

test("native creation tag one preserves legacy text archive and exact pending resume") do
  dispatch_expect(dispatch_create_case(1))
end

test("native creation tag two produces required-content archive and exact pending resume") do
  dispatch_expect(dispatch_create_case(2))
end

test("native creation tag three produces omission-policy archive and exact pending resume") do
  dispatch_expect(dispatch_create_case(3))
end

fn dispatch_empty_state(raw :: Result<Plaintext<D4BackupPendingState>, String>) -> Plaintext<Bool> do
  case raw do
    Err(_) -> false
    Ok(value) -> value.kind == 0 && Bytes.length(value.draft_id) == 0 && value.wire_size == 0
  end
end

fn dispatch_malformed_with_fixture(f :: D4CoreFixture) -> Plaintext<Bool>!String do
  let valid = dispatch_create_request(f, 2)?
  let frames = [
    Bytes.empty(),
    mobile_byte(2)?,
    dispatch_create_request(f, 0)?,
    dispatch_create_request(f, 4)?,
    dispatch_join([valid, mobile_byte(0)?])?,
    repeated(0, 42005)?
  ]
  let before = d4_core_all_rows(f)?
  println("NATIVE_CONTENT_DISPATCH_INVALID_READY")
  let refused = for frame in frames do
    Result.is_err(backup_create_export(frame))
  end
  let unchanged = d4_core_all_rows(f)?
  let state = pending_backup_export_state(f.path, f.public_profile)
  Ok(List.all(refused, fn(value) -> value end)
    && d4_core_rows_preserved(before, unchanged, 0)
    && dispatch_empty_state(state))
end

test("native creation rejects malformed and unknown versions without publishing either pending row") do
  let fixture = publication_fixture()
  let raw = case fixture do
    Err(error)
    Ok(value) -> do
      let result = dispatch_malformed_with_fixture(value)
      let cleaned = d4_core_cleanup(value)
      case cleaned do
        Err(error)
        Ok(_) -> result
      end
    end
  end
  dispatch_expect(raw)
end

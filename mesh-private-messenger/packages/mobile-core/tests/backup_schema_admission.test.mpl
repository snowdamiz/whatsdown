from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupArchiveAttachment,
  BackupContentRecord,
  BackupContentScope
)
from Backups.PortableV2 import (
  PortableBackupContentArchive,
  PortableBackupV2Created,
  PortableBackupV2Error,
  create_portable_content_backup_v2,
  restore_portable_archive
)
from Mobile.BackupArchive import (
  D4BackupArchiveReceipt,
  preview_backup_archive,
  import_backup_archive,
  read_backup_archive,
  list_backup_archives,
  remove_backup_archive,
  d4_manage_list_matches
)
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
from Transport.Packet import decode_client_profile

fn schema_observe(value :: Plaintext<Bool>) -> Bool do
  declassify(value,
    "TEST ONLY equality or refusal for authored synthetic content-backup fixtures and unchanged legacy controls; no application payload metadata content error or private caller control is disclosed")
end

fn schema_bundle(f :: D4CoreFixture, mode :: Int) -> PortableBackupV2Created!String do
  let profile = decode_client_profile(f.public_profile)?
  let foreign = repeated(61, 32)?
  let owner = if mode == 1 do
    foreign
  else
    profile.account_id
  end
  let authorization = if mode == 2 do
    foreign
  else
    profile.account.authorization_public_key
  end
  let realm = if mode == 3 do
    foreign
  else
    Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-backup-service-realm/v1\n"),
      Bytes.concat(Bytes.from_utf8("https://core.example"), f.config.service_public_key)?)?)
  end
  let content :: Plaintext<PortableBackupContentArchive> = PortableBackupContentArchive {
    policy: RequireArchiveAttachments,
    owner_account: owner,
    owner_authorization_key: authorization,
    service_realm: realm,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 1,
    scopes: [
      BackupContentScope {
        kind: 2,
        id: repeated(71, 32)?,
        peer: Bytes.empty(),
        name: "synthetic content archive",
        entries: [
          BackupContentRecord {
            ordinal: 255,
            direction: if mode == 5 do
              2
            else
              1
            end,
            message_id: Bytes.empty(),
            sender_account: if mode == 4 || mode == 5 do
              foreign
            else
              owner
            end,
            sender_device: profile.device_id,
            timestamp: f.now,
            text: Bytes.from_utf8("actual canonical archived file"),
            attachments: [
              ArchiveAttachmentIncluded(Bytes.from_utf8("fixture.txt"),
                Bytes.from_utf8("text/plain"),
                Bytes.from_utf8("authored private archive bytes"))
            ]
          }
        ]
      }
    ]
  }
  case create_portable_content_backup_v2(content, f.now) do
    Err(_) -> Err("schema_fixture_content_create")
    Ok(value) -> Ok(value)
  end
end

fn schema_same(expected :: Result<Plaintext<Bytes>, PortableBackupV2Error>,
  actual :: Result<Plaintext<Bytes>, String>) -> Plaintext<Bool> do
  case expected do
    Err(_) -> false
    Ok(want) -> case actual do
      Err(_) -> false
      Ok(got) -> Bytes.secure_equals(want, got)
    end
  end
end

fn schema_receipt(raw :: Result<D4BackupArchiveReceipt, String>,
  id :: Bytes,
  disposition :: Int) -> Bool do
  case raw do
    Err(_) -> false
    Ok(receipt) -> receipt.disposition == disposition && Bytes.secure_equals(receipt.backup_id, id)
  end
end

fn schema_roundtrip(mode :: Int) -> Result<(), String> do
  let f = d4_core_fixture()?
  let bundle = if mode == 6 do
    d4_core_import_bundle(f, false)?
  else
    schema_bundle(f, mode)?
  end
  let id = d4_core_backup_id(bundle.wire)?
  let before = d4_core_all_rows(f)?
  println("SCHEMA_ROUNDTRIP_FIXTURE_READY")
  let expected = restore_portable_archive(bundle.recovery_code, bundle.wire)
  let preview = preview_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code)
  let after_preview = d4_core_all_rows(f)?
  let first = import_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code, id)
  let stored = read_backup_archive(f.path, f.public_profile, id)
  let after_first = d4_core_all_rows(f)?
  let again = import_backup_archive(f.path, f.public_profile, bundle.wire, bundle.recovery_code, id)
  let after_again = d4_core_all_rows(f)?
  let listed = list_backup_archives(f.path, f.public_profile)
  let removed = remove_backup_archive(f.path, f.public_profile, id)
  let empty = list_backup_archives(f.path, f.public_profile)
  d4_core_cleanup(f)?
  assert(schema_observe(schema_same(expected, preview)))
  assert(schema_observe(schema_same(expected, stored)))
  assert(schema_receipt(first, id, 1))
  assert(schema_receipt(again, id, 2))
  assert(d4_core_rows_preserved(before, after_preview, 0))
  assert(d4_core_rows_preserved(after_first, after_again, 0))
  assert(d4_manage_list_matches(listed, [id], [f.now]))
  assert(Result.is_ok(removed))
  assert(d4_manage_list_matches(empty, [], []))
  Ok(nil)
end

test("legacy text preview import read and identical retry stay compatible") do
  assert(Result.is_ok(schema_roundtrip(6)))
end

test("content archive preview import read retry list and removal preserve authenticated bytes") do
  assert(Result.is_ok(schema_roundtrip(0)))
end

test("content archive preserves legacy incoming group sender semantics and sparse original ordinal") do
  assert(Result.is_ok(schema_roundtrip(5)))
end

fn schema_refusals() -> Result<(), String> do
  let f = d4_core_fixture()?
  let valid = schema_bundle(f, 0)?
  let expected = restore_portable_archive(valid.recovery_code, valid.wire)
  let accepted = preview_backup_archive(f.path, f.public_profile, valid.wire, valid.recovery_code)
  let before = d4_core_all_rows(f)?
  println("SCHEMA_OWNER_REFUSALS_FIXTURE_READY")
  for mode in 1..5 do
    let bundle = schema_bundle(f, mode)?
    let id = d4_core_backup_id(bundle.wire)?
    let authenticated = restore_portable_archive(bundle.recovery_code, bundle.wire)
    let preview = preview_backup_archive(f.path,
      f.public_profile,
      bundle.wire,
      bundle.recovery_code)
    let imported = import_backup_archive(f.path,
      f.public_profile,
      bundle.wire,
      bundle.recovery_code,
      id)
    assert(schema_observe(Result.is_ok(authenticated)))
    assert(schema_observe(Result.is_err(preview)))
    assert(Result.is_err(imported))
  end
  let after_rows = d4_core_all_rows(f)?
  d4_core_cleanup(f)?
  assert(d4_core_rows_preserved(before, after_rows, 0))
  assert(schema_observe(schema_same(expected, accepted)))
  Ok(nil)
end

test("content archive rejects foreign owner authorization realm and outgoing group sender without writes") do
  assert(Result.is_ok(schema_refusals()))
end

from Mobile.BackupArchive import pending_backup_export_state, resume_pending_backup_export
from Tests.BackupPendingSupport import pending_install_bundle, pending_known_state

fn schema_pending_wire(raw :: Result<Bytes, String>, wire :: Bytes) -> Bool do
  case raw do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, wire)
  end
end

fn schema_pending_resume(foreign :: Bool) -> Result<(), String> do
  let f = d4_core_fixture()?
  let bundle = schema_bundle(f,
    if foreign do
      1
    else
      0
    end)?
  let other = d4_core_import_bundle(f, false)?
  let pending = pending_install_bundle(f, bundle, repeated(214, 32)?)?
  let before = d4_core_all_rows(f)?
  println("SCHEMA_PENDING_FIXTURE_READY")
  let authenticated = restore_portable_archive(bundle.recovery_code, bundle.wire)
  let state = pending_backup_export_state(f.path, f.public_profile)
  let wrong_code = resume_pending_backup_export(f.path,
    f.public_profile,
    pending.draft_id,
    other.recovery_code)
  let wrong_draft = resume_pending_backup_export(f.path,
    f.public_profile,
    repeated(215, 32)?,
    bundle.recovery_code)
  let resumed = resume_pending_backup_export(f.path,
    f.public_profile,
    pending.draft_id,
    bundle.recovery_code)
  let again = resume_pending_backup_export(f.path,
    f.public_profile,
    pending.draft_id,
    bundle.recovery_code)
  let after_rows = d4_core_all_rows(f)?
  d4_core_cleanup(f)?
  assert(schema_observe(Result.is_ok(authenticated)))
  assert(pending_known_state(state, 1, pending.draft_id, f.now, Bytes.length(bundle.wire)))
  assert(Result.is_err(wrong_code))
  assert(Result.is_err(wrong_draft))
  assert(d4_core_rows_preserved(before, after_rows, 0))
  if foreign do
    assert(Result.is_err(resumed) && Result.is_err(again))
  else
    assert(schema_pending_wire(resumed, bundle.wire))
    assert(schema_pending_wire(again, bundle.wire))
  end
  Ok(nil)
end

test("content pending resume returns only the original committed wire and preserves retries") do
  assert(Result.is_ok(schema_pending_resume(false)))
end

test("content pending resume refuses authenticated foreign custody without changing the committed pair") do
  assert(Result.is_ok(schema_pending_resume(true)))
end

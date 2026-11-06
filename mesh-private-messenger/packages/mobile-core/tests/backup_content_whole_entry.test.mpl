from Tests.BackupContentPublicationFixture import publication_fixture
from Tests.BackupArchiveFixture import (
  D4CoreFixture,
  d4_core_cleanup,
  d4_core_synthetic_content,
  d4_core_all_rows,
  d4_core_rows_preserved
)
from Tests.BackupAttachmentCaptureFixture import (
  CaptureFixtureFile,
  capture_configure,
  capture_files,
  capture_install,
  capture_start_peer
)
from Mobile.BackupArchive import (
  D4BackupSelection,
  D4BackupPendingCreated,
  D4BackupPendingState,
  create_pending_content_backup_export,
  pending_backup_export_state,
  resume_pending_backup_export
)
from Mobile.BackupAuthority import capture_backup_authority
from Backups.PortableV2 import PortableBackupContentArchive, restore_portable_archive
from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupContentArchive,
  BackupContentScope,
  BackupContentRecord,
  BackupArchiveAttachment,
  encode_content_archive,
  decode_content_archive
)
from Transport.Packet import decode_client_profile
from Tests.Support import repeated

# Authored expected content is an oracle only. It never enters the production
# creation API, whose only inputs are original identity, selection and policy.
fn whole_expected_content(f :: D4CoreFixture,
  files :: List<CaptureFixtureFile>,
  scope_id :: Bytes,
  policy :: BackupAttachmentPolicy) -> PortableBackupContentArchive!String do
  let identity = d4_core_synthetic_content(f, [], 1, 0, 0, 0, 0, 1)?
  let profile = decode_client_profile(f.public_profile)?
  Ok(PortableBackupContentArchive {
    policy: policy,
    owner_account: identity.owner_account,
    owner_authorization_key: identity.owner_authorization_key,
    service_realm: identity.service_realm,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 1,
    scopes: [
      BackupContentScope {
        kind: 1,
        id: scope_id,
        peer: repeated(37, 32)?,
        name: "",
        entries: [
          BackupContentRecord {
            ordinal: 0,
            direction: 1,
            message_id: repeated(24, 16)?,
            sender_account: profile.account_id,
            sender_device: profile.device_id,
            timestamp: f.now,
            text: Bytes.from_utf8("x"),
            attachments: for file in files do
              ArchiveAttachmentIncluded(file.material.manifest.filename,
                file.material.manifest.mime_type,
                file.plaintext)
            end
          }
        ]
      }
    ]
  })
end

fn whole_success_matches(created :: Result<D4BackupPendingCreated, String>,
  state :: Result<Plaintext<D4BackupPendingState>, String>,
  resumed :: Result<Bytes, String>,
  expected :: PortableBackupContentArchive) -> Plaintext<Bool> do
  let reply = case created do
    Err(_) -> return false
    Ok(value) -> value
  end
  let pending = case state do
    Err(_) -> return false
    Ok(value) -> value
  end
  let wire = case resumed do
    Err(_) -> return false
    Ok(value) -> value
  end
  let payload = case restore_portable_archive(reply.recovery_code, wire) do
    Err(_) -> return false
    Ok(value) -> value
  end
  let decoded = case decode_content_archive(payload) do
    Err(_) -> return false
    Ok(value) -> value
  end
  let wanted = encode_content_archive(BackupContentArchive {
    policy: expected.policy,
    backup_id: decoded.backup_id,
    owner_account: expected.owner_account,
    owner_authorization_key: expected.owner_authorization_key,
    service_realm: expected.service_realm,
    created_at: pending.created_at,
    candidate_count: expected.candidate_count,
    omitted_timed: expected.omitted_timed,
    omitted_unknown: expected.omitted_unknown,
    omitted_nontext: expected.omitted_nontext,
    omitted_empty: expected.omitted_empty,
    attachment_messages: expected.attachment_messages,
    scopes: expected.scopes
  })
  pending.kind == 1
    && Bytes.length(reply.draft_id) == 32
    && Bytes.secure_equals(pending.draft_id, reply.draft_id)
    && pending.wire_size == Bytes.length(reply.wire)
    && Bytes.secure_equals(wire, reply.wire)
    && case wanted do
      Err(_) -> false
      Ok(value) -> Bytes.secure_equals(payload, value)
    end
end

fn whole_empty_matches(state :: Result<Plaintext<D4BackupPendingState>, String>) -> Plaintext<Bool> do
  case state do
    Err(_) -> false
    Ok(value) -> value.kind == 0
      && Bytes.length(value.draft_id) == 0
      && value.wire_size == 0
      && U64.to_string(value.created_at) == "0"
  end
end

fn whole_read_trace(path :: String) -> String!String do
  if File.exists(path <> ".capture-trace") do
    File.read(path <> ".capture-trace")
  else
    Ok("")
  end
end

fn whole_body(f :: D4CoreFixture,
  policy :: BackupAttachmentPolicy,
  mode :: Int,
  port :: Int) -> Plaintext<Bool>!String do
  capture_configure(f, port)?
  let files = capture_files(f, 1, mode, U64.parse("4102444800000")?)?
  let id = capture_install(f, 1, files, false)?
  let expected = whole_expected_content(f, files, id, policy)?
  let selected = [D4BackupSelection { kind: 1, scope_id: id, from_time: None, through_time: None }]
  capture_start_peer(port, f, files, mode)?
  # Complete genuine native revision setup before the strict source baseline.
  # The public creator still captures its own original authority and key.
  let _authority = capture_backup_authority(f.path, f.public_profile)?
  let before = d4_core_all_rows(f)?
  println("WHOLE_CONTENT_ENTRY_FIXTURE_READY")
  let created = create_pending_content_backup_export(f.path, f.public_profile, selected, policy)
  let state = pending_backup_export_state(f.path, f.public_profile)
  let after_create = d4_core_all_rows(f)?
  let trace = whole_read_trace(f.path)?
  if mode == 1 do
    # A genuine damaged authenticated chunk is fetched; both policies must
    # refuse and leave every captured ciphertext/index byte unchanged.
    return Ok(Result.is_err(created)
      && trace == "0:0\n"
      && d4_core_rows_preserved(before, after_create, 0)
      && whole_empty_matches(state))
  end
  let resumed = case created do
    Err(_) -> Err("whole_entry_refused")
    Ok(reply) -> resume_pending_backup_export(f.path,
      f.public_profile,
      reply.draft_id,
      reply.recovery_code)
  end
  # Occupied-slot refusal cannot replace the first pair or refetch attachments.
  let occupied = create_pending_content_backup_export(f.path, f.public_profile, selected, policy)
  let final_rows = d4_core_all_rows(f)?
  let final_trace = whole_read_trace(f.path)?
  Ok(trace == "0:0\n0:1\n1:0\n"
    && final_trace == trace
    && d4_core_rows_preserved(before, after_create, 2)
    && d4_core_rows_preserved(after_create, final_rows, 0)
    && Result.is_err(occupied)
    && whole_success_matches(created, state, resumed, expected))
end

fn whole_case(policy :: BackupAttachmentPolicy,
  mode :: Int,
  port :: Int) -> Plaintext<Bool>!String do
  let f = publication_fixture()?
  let raw = whole_body(f, policy, mode, port)
  for suffix in [".capture-trace", ".capture-action-ready"] do
    if File.exists(f.path <> suffix) do
      File.delete(f.path <> suffix)?
    end
  end
  let cleanup = d4_core_cleanup(f)
  cleanup?
  raw
end

fn whole_outcome(raw :: Result<Plaintext<Bool>, String>) -> Plaintext<Int> do
  case raw do
    Err(_) -> 0
    Ok(value) -> if value do
      2
    else
      1
    end
  end
end

fn whole_expect(raw :: Result<Plaintext<Bool>, String>) do
  let closed = whole_outcome(raw)
  let observed = declassify(closed,
    "TEST ONLY closed synthetic whole-content fixture setup refusal false or exact authored content pair resume refusal and ciphertext-preservation predicates; no real payload metadata codes keys source identities timestamps or raw errors are released")
  assert(observed != 0)
  assert(observed == 2)
end

test("whole pending content require captures genuine chunks and stores exact resumable content before occupied refusal") do
  whole_expect(whole_case(RequireArchiveAttachments, 0, 23460))
end

test("whole pending content allow captures genuine chunks and stores exact resumable content before occupied refusal") do
  whole_expect(whole_case(AllowArchiveAttachmentOmissions, 0, 23461))
end

test("whole pending content require refuses damaged authenticated bytes without pending rows or source writes") do
  whole_expect(whole_case(RequireArchiveAttachments, 1, 23462))
end

test("whole pending content allow refuses damaged authenticated bytes without pending rows or source writes") do
  whole_expect(whole_case(AllowArchiveAttachmentOmissions, 1, 23463))
end

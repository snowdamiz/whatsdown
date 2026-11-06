from Backups.ContentArchive import (
  BackupArchiveAttachment,
  BackupAttachmentOmission,
  BackupAttachmentPolicy,
  BackupContentArchive,
  BackupContentRecord,
  BackupContentScope,
  encode_content_archive
)
from Backups.PortableV2 import (
  PortableBackupContentArchive,
  PortableBackupV2Content,
  create_portable_content_backup_v2,
  create_portable_backup_v2,
  restore_portable_backup,
  restore_portable_archive
)
from Tests.BackupPortableV2Fixture import (
  portable_v2_fixture_code,
  portable_v2_fixture_payload,
  portable_v2_fixture_wire1,
  portable_v2_fixture_wire2,
  portable_v2_fixture_small_content
)

fn pc_observe(value :: Bool) -> Bool do
  declassify(value,
    "TEST ONLY authored synthetic portable content archive equality and finite refusal predicates; no real history attachment metadata code key digest or arbitrary error is disclosed")
end

fn pc_check(value :: Bool) -> ()!String do
  if value do
    Ok(nil)
  else
    Err("pc_fixture_check")
  end
end

fn pc_slice(value :: Bytes, start :: Int, size :: Int) -> Bytes!String do
  case Bytes.slice(value, start, size) do
    Err(_) -> Err("pc_fixture_slice")
    Ok(bytes) -> Ok(bytes)
  end
end

fn pc_content(old :: PortableBackupV2Content,
  policy :: BackupAttachmentPolicy,
  text :: Bytes,
  part :: Int,
  bytes :: Plaintext<Bytes>) -> PortableBackupContentArchive do
  let scope = List.head(old.scopes)
  let record = List.head(scope.entries)
  let parts = if part == 0 do
    []
  else if part == 1 do
    [ArchiveAttachmentIncluded(Bytes.empty(), Bytes.from_utf8("a"), bytes)]
  else
    [ArchiveAttachmentOmitted(ArchiveAttachmentExpired)]
  end
  PortableBackupContentArchive {
    policy: policy,
    owner_account: old.owner_account,
    owner_authorization_key: old.owner_authorization_key,
    service_realm: old.service_realm,
    candidate_count: 1,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: if part == 0 do
      0
    else
      1
    end,
    scopes: [
      BackupContentScope {
        kind: scope.kind,
        id: scope.id,
        peer: scope.peer,
        name: "",
        entries: [
          BackupContentRecord {
            ordinal: 255,
            direction: record.direction,
            message_id: Bytes.empty(),
            sender_account: record.sender_account,
            sender_device: record.sender_device,
            timestamp: record.timestamp,
            text: text,
            attachments: parts
          }
        ]
      }
    ]
  }
end

fn pc_expected(content :: Plaintext<PortableBackupContentArchive>,
  id :: Bytes,
  time :: U64) -> Plaintext<Bytes>!String do
  case encode_content_archive(BackupContentArchive {
    policy: content.policy,
    backup_id: id,
    owner_account: content.owner_account,
    owner_authorization_key: content.owner_authorization_key,
    service_realm: content.service_realm,
    created_at: time,
    candidate_count: content.candidate_count,
    omitted_timed: content.omitted_timed,
    omitted_unknown: content.omitted_unknown,
    omitted_nontext: content.omitted_nontext,
    omitted_empty: content.omitted_empty,
    attachment_messages: content.attachment_messages,
    scopes: content.scopes
  }) do
    Err(_) -> Err("pc_fixture_payload")
    Ok(value) -> Ok(value)
  end
end

fn pc_legacy_raw() -> Bool!String do
  let expected = portable_v2_fixture_payload()?
  let one = restore_portable_archive(portable_v2_fixture_code(), portable_v2_fixture_wire1()?)
  let two = restore_portable_archive(portable_v2_fixture_code(), portable_v2_fixture_wire2()?)
  case (one, two) do
    (Ok(a), Ok(b)) -> Ok(Bytes.secure_equals(a, expected) && Bytes.secure_equals(b, expected))
    _ -> Ok(false)
  end
end

pub fn portable_content_legacy_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_legacy_raw(), false))
end

fn pc_creation_raw() -> Bool!String do
  let authored_metadata = portable_v2_fixture_small_content(0)?
  let time = U64.parse("125")?
  let content :: Plaintext<PortableBackupContentArchive> = pc_content(authored_metadata,
    RequireArchiveAttachments,
    Bytes.empty(),
    1,
    Bytes.from_utf8("owned synthetic content"))
  let raw = create_portable_content_backup_v2(content, time)
  case raw do
    Err(_) -> Ok(false)
    Ok(created) -> do
      let id = pc_slice(created.wire, 38, 32)?
      let expected = pc_expected(content, id, time)
      let opened = restore_portable_archive(created.recovery_code, created.wire)
      let again = restore_portable_archive(created.recovery_code, created.wire)
      let wrong = Result.is_err(restore_portable_archive(portable_v2_fixture_code(), created.wire))
      let old = Result.is_err(restore_portable_backup(created.recovery_code, created.wire))
      case (expected, opened, again) do
        (Ok(want), Ok(actual), Ok(retry)) ->
          Ok(Bytes.secure_equals(want, actual) && Bytes.secure_equals(want, retry) && wrong && old)
        _ -> Ok(false)
      end
    end
  end
end

pub fn portable_content_creation_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_creation_raw(), false))
end

fn pc_policy_raw() -> Bool!String do
  let authored_metadata = portable_v2_fixture_small_content(0)?
  let time = U64.parse("126")?
  let allowed :: Plaintext<PortableBackupContentArchive> = pc_content(authored_metadata,
    AllowArchiveAttachmentOmissions,
    Bytes.empty(),
    2,
    Bytes.from_utf8("unused"))
  let strict :: Plaintext<PortableBackupContentArchive> = pc_content(authored_metadata,
    RequireArchiveAttachments,
    Bytes.empty(),
    2,
    Bytes.from_utf8("unused"))
  let one = create_portable_content_backup_v2(allowed, time)
  let refused = Result.is_err(create_portable_content_backup_v2(strict, time))
  case one do
    Err(_) -> Ok(false)
    Ok(created) -> do
      let expected = pc_expected(allowed, pc_slice(created.wire, 38, 32)?, time)
      let opened = restore_portable_archive(created.recovery_code, created.wire)
      case (expected, opened) do
        (Ok(want), Ok(actual)) -> Ok(refused && Bytes.secure_equals(want, actual))
        _ -> Ok(false)
      end
    end
  end
end

pub fn portable_content_policy_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_policy_raw(), false))
end

fn pc_minimum_raw() -> Bool!String do
  let authored_metadata = portable_v2_fixture_small_content(0)?
  let time = U64.parse("127")?
  let legacy = create_portable_backup_v2(portable_v2_fixture_small_content(0)?, time)
  let minimum :: Plaintext<PortableBackupContentArchive> = pc_content(authored_metadata,
    RequireArchiveAttachments,
    Bytes.from_utf8("x"),
    0,
    Bytes.from_utf8("unused"))
  let content = create_portable_content_backup_v2(minimum, time)
  case (legacy, content) do
    (Ok(old), Ok(fresh)) -> do
      let a = restore_portable_archive(old.recovery_code, old.wire)
      let b = restore_portable_archive(fresh.recovery_code, fresh.wire)
      case (a, b) do
        (Ok(text), Ok(mca)) -> Ok(Bytes.length(old.wire) == 561
          && Bytes.length(text) == 293
          && Bytes.length(fresh.wire) == 587
          && Bytes.length(mca) == 319)
        _ -> Ok(false)
      end
    end
    _ -> Ok(false)
  end
end

pub fn portable_content_minimum_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_minimum_raw(), false))
end

from Protocol.V1 import ProtocolError
from Tests.BackupPortableContentVectors import (
  portable_content_vector_code,
  portable_content_vector_valid_mca,
  portable_content_vector_minimum_mca,
  portable_content_vector_below_minimum_mca,
  portable_content_vector_mca_in_v1,
  portable_content_vector_wrong_payload_id,
  portable_content_vector_wrong_payload_time,
  portable_content_vector_wrong_snapshot_hash,
  portable_content_vector_wrong_file_digest,
  portable_content_vector_sum_preserving_counter_distribution,
  portable_content_vector_strict_with_omitted_slot,
  portable_content_vector_unknown_payload
)

# pc_independent_literal() is generated directly from the pinned immutable MCA1
# independent literal, with no candidate encoder or encryption implementation.
fn pc_independent_raw() -> Bool!ProtocolError do
  let literal = portable_content_vector_valid_mca()?
  let minimum = portable_content_vector_minimum_mca()?
  let expected = pc_independent_literal()?
  let one = restore_portable_archive(portable_content_vector_code(), literal)
  let two = restore_portable_archive(portable_content_vector_code(), minimum)
  let old = Result.is_err(restore_portable_backup(portable_content_vector_code(), literal))
  case (one, two) do
    (Ok(actual), Ok(small)) -> Ok(old
      && Bytes.secure_equals(actual, expected)
      && Bytes.length(small) == 319)
    _ -> Ok(false)
  end
end

pub fn portable_content_independent_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_independent_raw(), false))
end

fn pc_authenticated_refusal_raw() -> Bool!ProtocolError do
  let frames = [
    portable_content_vector_below_minimum_mca()?,
    portable_content_vector_mca_in_v1()?,
    portable_content_vector_wrong_payload_id()?,
    portable_content_vector_wrong_payload_time()?,
    portable_content_vector_wrong_snapshot_hash()?,
    portable_content_vector_wrong_file_digest()?,
    portable_content_vector_sum_preserving_counter_distribution()?,
    portable_content_vector_strict_with_omitted_slot()?,
    portable_content_vector_unknown_payload()?
  ]
  Ok(List.all(frames,
    fn(frame) -> Result.is_err(restore_portable_archive(portable_content_vector_code(),
      frame)) end))
end

pub fn portable_content_authenticated_refusal_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_authenticated_refusal_raw(), false))
end

fn pc_repeat(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("pc_fixture_repeat")
    Ok(bytes) -> Ok(bytes)
  end
end

fn pc_created_extent_proof(size :: Int,
  expected_payload :: Int,
  expected_file :: Int) -> Bool!String do
  let authored_metadata = portable_v2_fixture_small_content(0)?
  let time = U64.parse("128")?
  let bytes = pc_repeat(165, size)?
  let content :: Plaintext<PortableBackupContentArchive> = pc_content(authored_metadata,
    RequireArchiveAttachments,
    Bytes.empty(),
    1,
    bytes)
  let raw = create_portable_content_backup_v2(content, time)
  case raw do
    Err(_) -> Ok(false)
    Ok(created) -> do
      let expected = pc_expected(content, pc_slice(created.wire, 38, 32)?, time)
      let opened = restore_portable_archive(created.recovery_code, created.wire)
      case (expected, opened) do
        (Ok(want), Ok(actual)) -> Ok(Bytes.length(created.wire) == expected_file
          && Bytes.length(actual) == expected_payload
          && Bytes.secure_equals(want, actual))
        _ -> Ok(false)
      end
    end
  end
end

fn pc_maximum_raw() -> Bool!String do
  let authored_metadata = portable_v2_fixture_small_content(0)?
  let time = U64.parse("129")?
  let over_bytes = pc_repeat(165, 16776848)?
  let over :: Plaintext<PortableBackupContentArchive> = pc_content(authored_metadata,
    AllowArchiveAttachmentOmissions,
    Bytes.empty(),
    1,
    over_bytes)
  let refused = Result.is_err(create_portable_content_backup_v2(over, time))
  # Keep each protected proof Result as data until every public crypto call ends.
  let exact = pc_created_extent_proof(16776847, 16777216, 16796864)
  let one = pc_created_extent_proof(65167, 65536, 65804)
  let two = pc_created_extent_proof(65168, 65537, 65881)
  Ok(refused
    && Result.unwrap_or(exact, false)
    && Result.unwrap_or(one, false)
    && Result.unwrap_or(two, false))
end

pub fn portable_content_maximum_proof() -> Bool do
  pc_observe(Result.unwrap_or(pc_maximum_raw(), false))
end

fn pc_independent_literal() -> Bytes!ProtocolError do
  case Bytes.from_hex("014d434101101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304050607080003000000030000000800000002000000010000000100000001000000010000000200000001000000000000000100000000000000000000009d010000001001010101010101010101010101010101000000202020202020202020202020202020202020202020202020202020202020202020000000014100010000005900000200000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1202020202020202020202020202020202020202020202020202020202020202044444444444444444444444444444444ffffffffffffffff0000000548656c6c6f00000000a402000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000010000006c00070100000020b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b711111111111111111111111111111111111111111111111111111111111111114545454545454545454545454545454500000000000000000000000867726f757020cf8000000000d90200000020030303030303030303030303030303030303030303030303030303030303030300000000000000064c65676163790001000000a000ff020000000055555555555555555555555555555555555555555555555555555555555555554646464646464646464646464646464601020304050607080000000002000000520000000000086e6f74652e62696e000000186170706c69636174696f6e2f6f637465742d73747265616d49fd534fea14753447a1931542d9d58744a75810b88718eadc4ccded926317b50000000400ff4142000000020102") do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes) -> Ok(bytes)
  end
end

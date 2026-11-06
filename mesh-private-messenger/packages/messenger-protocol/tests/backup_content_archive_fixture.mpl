from Protocol.V1 import ProtocolError
from Backups.TextArchive import BackupArchiveRecord, BackupTextArchive, decode_text_archive
from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupAttachmentOmission,
  BackupArchiveAttachment,
  BackupContentRecord,
  BackupContentScope,
  BackupContentArchive,
  encode_content_archive,
  decode_content_archive
)
from Tests.BackupPortableV2Fixture import portable_v2_fixture_payload

fn ca_check(value :: Bool) -> Unit!ProtocolError do
  if value do
    Ok(nil)
  else
    Err(InvalidPolicy)
  end
end

fn ca_hex(value :: String) -> Bytes!ProtocolError do
  case Bytes.from_hex(value) do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

fn ca_repeat(value :: Int, size :: Int) -> Bytes!ProtocolError do
  case Bytes.repeat(value, size) do
    Err(_) -> Err(OversizedInput)
    Ok(bytes)
  end
end

fn ca_join(parts :: List<Bytes>) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, 16777217) do
    Err(_) -> Err(OversizedInput)
    Ok(bytes)
  end
end

fn ca_slice(input :: Bytes, at :: Int, size :: Int) -> Bytes!ProtocolError do
  case Bytes.slice(input, at, size) do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

fn ca_replace(input :: Bytes, at :: Int, bytes :: Bytes) -> Bytes!ProtocolError do
  ca_join([
    ca_slice(input, 0, at)?,
    bytes,
    ca_slice(input, at + Bytes.length(bytes), Bytes.length(input) - at - Bytes.length(bytes))?
  ])
end

fn ca_legacy() -> BackupTextArchive!ProtocolError do
  let bytes = case portable_v2_fixture_payload() do
    Err(_) -> return Err(MalformedEncoding)
    Ok(bytes) -> bytes
  end
  decode_text_archive(bytes)
end

fn ca_record(value :: BackupArchiveRecord,
  parts :: List<BackupArchiveAttachment>) -> BackupContentRecord do
  BackupContentRecord {
    ordinal: value.ordinal,
    direction: value.direction,
    message_id: value.message_id,
    sender_account: value.sender_account,
    sender_device: value.sender_device,
    timestamp: value.timestamp,
    text: value.text,
    attachments: parts
  }
end

fn ca_copy(value :: BackupTextArchive,
  scopes :: List<BackupContentScope>,
  policy :: BackupAttachmentPolicy) -> BackupContentArchive do
  BackupContentArchive {
    policy: policy,
    backup_id: value.backup_id,
    owner_account: value.owner_account,
    owner_authorization_key: value.owner_authorization_key,
    service_realm: value.service_realm,
    created_at: value.created_at,
    candidate_count: value.candidate_count,
    omitted_timed: value.omitted_timed,
    omitted_unknown: value.omitted_unknown,
    omitted_nontext: value.omitted_nontext,
    omitted_empty: value.omitted_empty,
    attachment_messages: value.attachment_messages,
    scopes: scopes
  }
end

fn ca_with_parts(parts :: List<BackupArchiveAttachment>,
  policy :: BackupAttachmentPolicy) -> BackupContentArchive!ProtocolError do
  let old = ca_legacy()?
  let scopes = for index in 0..List.length(old.scopes) do
    let scope = List.get(old.scopes, index)
    BackupContentScope {
      kind: scope.kind,
      id: scope.id,
      peer: scope.peer,
      name: scope.name,
      entries: for row in scope.entries do
        ca_record(row,
          if index == 2 do
            parts
          else
            []
          end)
      end
    }
  end
  Ok(ca_copy(old, scopes, policy))
end

fn ca_source() -> BackupContentArchive!ProtocolError do
  ca_with_parts([
      ArchiveAttachmentIncluded(Bytes.from_utf8("note.bin"),
        Bytes.from_utf8("application/octet-stream"),
        ca_hex("00ff4142")?),
      ArchiveAttachmentOmitted(ArchiveAttachmentExpired)
    ],
    AllowArchiveAttachmentOmissions)
end

fn ca_included(name :: Bytes,
  mime :: Bytes,
  content :: Bytes) -> BackupContentArchive!ProtocolError do
  ca_with_parts([ArchiveAttachmentIncluded(name, mime, content)], RequireArchiveAttachments)
end

fn ca_refused(input :: Bytes) -> Bool do
  Result.is_err(decode_content_archive(input))
end

pub fn content_archive_literal_proof() -> Bool!ProtocolError do
  let literal = ca_literal()?
  let encoded = encode_content_archive(ca_source()?)?
  let decoded = decode_content_archive(literal)?
  ca_check(Bytes.secure_equals(encoded, literal))?
  ca_check(Bytes.secure_equals(encode_content_archive(decoded)?, literal))?
  let legacy = List.head(List.get(decoded.scopes, 2).entries)
  ca_check(legacy.ordinal == 255 && Bytes.length(legacy.message_id) == 0)?
  ca_check(decoded.attachment_messages == 1 && List.length(legacy.attachments) == 2)?
  ca_check(case List.head(legacy.attachments) do
    ArchiveAttachmentIncluded(name, mime, content) -> Bytes.secure_equals(name,
      Bytes.from_utf8("note.bin"))
      && Bytes.secure_equals(mime, Bytes.from_utf8("application/octet-stream"))
      && Bytes.secure_equals(content, ca_hex("00ff4142")?)
    _ -> false
  end)?
  ca_check(case List.get(legacy.attachments, 1) do
    ArchiveAttachmentOmitted(ArchiveAttachmentExpired) -> true
    _ -> false
  end)?
  Ok(true)
end

pub fn content_archive_policy_proof() -> Bool!ProtocolError do
  ca_check(Bytes.secure_equals(encode_content_archive(ca_source()?)?, ca_literal()?))?
  let wire = ca_literal()?
  let source = ca_source()?
  ca_check(Result.is_err(encode_content_archive(%{source | policy: RequireArchiveAttachments})))?
  for (at, replacement) in [
    (4, "00"),
    (4, "02"),
    (171, "00000003"),
    (175, "00000002"),
    (183, "00000000"),
    (744, "05")
  ] do
    ca_check(ca_refused(ca_replace(wire, at, ca_hex(replacement)?)?))?
  end
  # Preserve the header sum while lying about the nested slot reason distribution.
  let redistributed = ca_replace(ca_replace(wire, 175, ca_hex("00000000")?)?,
    179,
    ca_hex("00000001")?)?
  ca_check(ca_refused(redistributed))?
  for reason in [
    ArchiveAttachmentUnavailable,
    ArchiveAttachmentExpired,
    ArchiveAttachmentUnsupported,
    ArchiveAttachmentAboveProfile
  ] do
    let value = ca_with_parts([ArchiveAttachmentOmitted(reason)], AllowArchiveAttachmentOmissions)?
    ca_check(!ca_refused(encode_content_archive(value)?))?
  end
  Ok(true)
end

pub fn content_archive_association_proof() -> Bool!ProtocolError do
  ca_check(!ca_refused(ca_literal()?))?
  let wire = ca_literal()?
  # Part positions are owned by their exact enclosing record; no ID fallback.
  for (at, replacement) in [(585, "0100"), (652, "00"), (657, "01"), (743, "00")] do
    ca_check(ca_refused(ca_replace(wire, at, ca_hex(replacement)?)?))?
  end
  ca_check(ca_refused(ca_slice(wire, 0, Bytes.length(wire) - 1)?))?
  ca_check(ca_refused(ca_join([wire, ca_hex("000000020002")?])?))?
  let source = ca_source()?
  let scope = List.get(source.scopes, 2)
  let row = List.head(scope.entries)
  let duplicate = %{scope | entries: [row, row]}
  ca_check(Result.is_err(encode_content_archive(%{source | scopes: [duplicate]})))?
  let balanced_duplicate = %{source |
    scopes: [duplicate],
    candidate_count: 2,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 2
  }
  ca_check(Result.is_err(encode_content_archive(balanced_duplicate)))?
  ca_check(Result.is_err(encode_content_archive(ca_with_parts([], RequireArchiveAttachments)?)))?
  Ok(true)
end

pub fn content_archive_metadata_proof() -> Bool!ProtocolError do
  ca_check(!ca_refused(ca_literal()?))?
  let wire = ca_literal()?
  for (at, replacement) in [(663, "ff"), (699, "ff"), (735, "01"), (744, "00")] do
    ca_check(ca_refused(ca_replace(wire, at, ca_hex(replacement)?)?))?
  end
  let content = Bytes.from_utf8("x")
  ca_check(!ca_refused(encode_content_archive(ca_included(ca_repeat(110, 255)?,
    ca_repeat(109, 127)?,
    content)?)?))?
  # A filename remains metadata, including separators; it never names an import path.
  ca_check(!ca_refused(encode_content_archive(ca_included(Bytes.from_utf8("../metadata.bin"),
    Bytes.from_utf8("a/b"),
    content)?)?))?
  for (name, mime, data) in [
    (ca_repeat(110, 256)?, Bytes.from_utf8("a"), content),
    (Bytes.from_utf8("x"), ca_repeat(109, 128)?, content),
    (Bytes.from_utf8("x"), Bytes.empty(), content),
    (Bytes.from_utf8("x"), Bytes.from_utf8("a"), Bytes.empty())
  ] do
    ca_check(Result.is_err(encode_content_archive(ca_included(name, mime, data)?)))?
  end
  Ok(true)
end

fn ca_many(extra :: Bool) -> BackupContentArchive!ProtocolError do
  let old = ca_legacy()?
  let scopes = for selected in 1..3 do
    let scope = List.get(old.scopes, selected)
    let original = List.head(scope.entries)
    BackupContentScope {
      kind: scope.kind,
      id: scope.id,
      peer: scope.peer,
      name: scope.name,
      entries: for index in 0..256 do
        let count = if extra && selected == 1 && index == 0 do
          9
        else
          8
        end
        let parts = for part in 0..count do
          ArchiveAttachmentIncluded(Bytes.from_utf8("x"),
            Bytes.from_utf8("a"),
            Bytes.from_utf8("z"))
        end
        let row = ca_record(original, parts)
        let updated = %{row | ordinal: index, message_id: Bytes.empty(), text: Bytes.from_utf8("t")}
        updated
      end
    }
  end
  let value = ca_copy(old, scopes, RequireArchiveAttachments)
  Ok(%{value |
    candidate_count: 512,
    omitted_timed: 0,
    omitted_unknown: 0,
    omitted_nontext: 0,
    omitted_empty: 0,
    attachment_messages: 512
  })
end

pub fn content_archive_count_proof() -> Bool!ProtocolError do
  let exact = encode_content_archive(ca_many(false)?)?
  ca_check(!ca_refused(exact))?
  ca_check(Result.is_err(encode_content_archive(ca_many(true)?)))?
  for count in [10, 11] do
    let parts = for index in 0..count do
      ArchiveAttachmentIncluded(Bytes.from_utf8("x"), Bytes.from_utf8("a"), Bytes.from_utf8("z"))
    end
    ca_check(Result.is_err(encode_content_archive(ca_with_parts(parts,
      RequireArchiveAttachments)?)) == (count == 11))?
  end
  ca_check(ca_refused(ca_replace(ca_literal()?, 171, ca_hex("ffffffff")?)?))?
  Ok(true)
end

pub fn content_archive_maximum_proof() -> Bool!ProtocolError do
  let exact = ca_included(Bytes.from_utf8("x"),
    Bytes.from_utf8("a"),
    ca_repeat(165, ca_maximum_content())?)?
  let wire = encode_content_archive(exact)?
  ca_check(Bytes.length(wire) == 16777216
    && Bytes.secure_equals(Crypto.sha256(wire), ca_maximum_hash()?))?
  ca_check(Bytes.secure_equals(encode_content_archive(decode_content_archive(wire)?)?, wire))?
  ca_check(Result.is_err(encode_content_archive(ca_included(Bytes.from_utf8("x"),
    Bytes.from_utf8("a"),
    ca_repeat(165, ca_maximum_content() + 1)?)?)))?
  let half = ca_repeat(165, 8388608)?
  ca_check(!ca_refused(encode_content_archive(ca_included(Bytes.from_utf8("x"),
    Bytes.from_utf8("a"),
    half)?)?))?
  let aggregate = ca_with_parts([
      ArchiveAttachmentIncluded(Bytes.from_utf8("x"), Bytes.from_utf8("a"), half),
      ArchiveAttachmentIncluded(Bytes.from_utf8("y"), Bytes.from_utf8("b"), half)
    ],
    AllowArchiveAttachmentOmissions)?
  ca_check(Result.is_err(encode_content_archive(aggregate)))?
  Ok(true)
end

pub fn content_archive_legacy_proof() -> Bool!ProtocolError do
  let old = case portable_v2_fixture_payload() do
    Err(_) -> return Err(MalformedEncoding)
    Ok(bytes) -> bytes
  end
  ca_check(!Result.is_err(decode_text_archive(old)))?
  ca_check(ca_refused(old))?
  ca_check(Result.is_err(decode_text_archive(ca_literal()?)))?
  Ok(true)
end

fn ca_literal() -> Bytes!ProtocolError do
  ca_hex("014d434101101010101010101010101010101010101010101010101010101010101010101011111111111111111111111111111111111111111111111111111111111111112222222222222222222222222222222222222222222222222222222222222222333333333333333333333333333333333333333333333333333333333333333301020304050607080003000000030000000800000002000000010000000100000001000000010000000200000001000000000000000100000000000000000000009d010000001001010101010101010101010101010101000000202020202020202020202020202020202020202020202020202020202020202020000000014100010000005900000200000010a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1202020202020202020202020202020202020202020202020202020202020202044444444444444444444444444444444ffffffffffffffff0000000548656c6c6f00000000a402000000200202020202020202020202020202020202020202020202020202020202020202000000000000000547726f757000010000006c00070100000020b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b7b711111111111111111111111111111111111111111111111111111111111111114545454545454545454545454545454500000000000000000000000867726f757020cf8000000000d90200000020030303030303030303030303030303030303030303030303030303030303030300000000000000064c65676163790001000000a000ff020000000055555555555555555555555555555555555555555555555555555555555555554646464646464646464646464646464601020304050607080000000002000000520000000000086e6f74652e62696e000000186170706c69636174696f6e2f6f637465742d73747265616d49fd534fea14753447a1931542d9d58744a75810b88718eadc4ccded926317b50000000400ff4142000000020102")
end

fn ca_maximum_content() -> Int do
  16776511
end

fn ca_maximum_hash() -> Bytes!ProtocolError do
  ca_hex("0be0d552d080df5d5707d118fd2f3fa3700bbd139ae487297cf16d1c12a938af")
end

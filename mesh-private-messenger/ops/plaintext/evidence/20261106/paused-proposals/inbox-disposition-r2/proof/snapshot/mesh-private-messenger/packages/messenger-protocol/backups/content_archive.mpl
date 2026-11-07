##! Proposed MCA1 syntax only. No history, account, object or expiry authority.
from Protocol.V1 import ProtocolError

pub type BackupAttachmentPolicy do
  RequireArchiveAttachments
  AllowArchiveAttachmentOmissions
end

pub type BackupAttachmentOmission do
  ArchiveAttachmentUnavailable
  ArchiveAttachmentExpired
  ArchiveAttachmentUnsupported
  ArchiveAttachmentAboveProfile
end

pub type BackupArchiveAttachment do
  ArchiveAttachmentIncluded(filename :: Plaintext<Bytes>, mime_type :: Plaintext<Bytes>, content :: Plaintext<Bytes>)
  ArchiveAttachmentOmitted(reason :: BackupAttachmentOmission)
end

pub struct BackupContentRecord do
  ordinal :: Int
  direction :: Int
  message_id :: Bytes
  sender_account :: Bytes
  sender_device :: Bytes
  timestamp :: U64
  text :: Bytes
  attachments :: List<BackupArchiveAttachment>
end

pub struct BackupContentScope do
  kind :: Int
  id :: Bytes
  peer :: Bytes
  name :: String
  entries :: List<BackupContentRecord>
end

pub struct BackupContentArchive do
  policy :: BackupAttachmentPolicy
  backup_id :: Bytes
  owner_account :: Bytes
  owner_authorization_key :: Bytes
  service_realm :: Bytes
  created_at :: U64
  candidate_count :: Int
  omitted_timed :: Int
  omitted_unknown :: Int
  omitted_nontext :: Int
  omitted_empty :: Int
  attachment_messages :: Int
  scopes :: List<BackupContentScope>
end

from Binary.Reader import BinaryReader
from Backups.TextArchive import (
  BackupArchiveRecord,
  BackupArchiveScope,
  BackupTextArchive,
  encode_text_archive
)
from Protocol.WirePrimitives import (
  protocol_as_int,
  protocol_byte,
  protocol_open,
  protocol_require_end,
  protocol_take_fixed,
  protocol_take_u8,
  protocol_take_u16,
  protocol_take_u32,
  protocol_take_u64,
  protocol_take_vector,
  protocol_write_length,
  protocol_write_u16,
  protocol_write_u64
)

struct ContentCounts do
  size :: Int
  records :: Int
  files :: Int
  included :: Int
  unavailable :: Int
  expired :: Int
  unsupported :: Int
  above_profile :: Int
end

fn content_magic() -> Bytes!ProtocolError do
  case Bytes.from_hex("014d4341") do
    Err(_) -> Err(MalformedEncoding)
    Ok(bytes)
  end
end

fn content_join(parts :: List<Bytes>) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, 16777216) do
    Err(_) -> Err(OversizedInput)
    Ok(bytes)
  end
end

fn content_vector(value :: Bytes) -> Bytes!ProtocolError do
  content_join([protocol_write_length(Bytes.length(value))?, value])
end

fn content_policy(value :: BackupAttachmentPolicy) -> Int do
  case value do
    RequireArchiveAttachments -> 0
    AllowArchiveAttachmentOmissions -> 1
  end
end

fn content_reason(value :: BackupAttachmentOmission) -> Int do
  case value do
    ArchiveAttachmentUnavailable -> 1
    ArchiveAttachmentExpired -> 2
    ArchiveAttachmentUnsupported -> 3
    ArchiveAttachmentAboveProfile -> 4
  end
end

fn content_add(before :: ContentCounts, size :: Int) -> ContentCounts!ProtocolError do
  if size < 0 || size > 16777216 - before.size do
    return Err(OversizedInput)
  end
  Ok(%{before | size: before.size + size})
end

fn content_parts_size(parts :: List<BackupArchiveAttachment>,
  policy :: BackupAttachmentPolicy,
  index :: Int,
  before :: ContentCounts) -> ContentCounts!ProtocolError do
  if index >= List.length(parts) do
    return Ok(before)
  end
  if before.files >= 4096 do
    return Err(OversizedInput)
  end
  let next = case List.get(parts, index) do
    ArchiveAttachmentIncluded(name, mime, bytes) ->
      if Bytes.length(name) > 255
        || Bytes.length(mime) < 1
        || Bytes.length(mime) > 127
        || Bytes.length(bytes) < 1
        || Bytes.length(bytes) > 16777216 do
        return Err(OversizedInput)
      end
      case Bytes.to_utf8(name) do
        Err(_) -> return Err(MalformedEncoding)
        Ok(_) -> nil
      end
      case Bytes.to_utf8(mime) do
        Err(_) -> return Err(MalformedEncoding)
        Ok(_) -> nil
      end
      let added = content_add(before,
        50 + Bytes.length(name) + Bytes.length(mime) + Bytes.length(bytes))?
      let updated = %{added | files: added.files + 1, included: added.included + 1}
      updated
    ArchiveAttachmentOmitted(reason) ->
      if content_policy(policy) == 0 do
        return Err(InvalidPolicy)
      end
      let added = content_add(before, 6)?
      let updated = %{added |
        files: added.files + 1,
        unavailable: added.unavailable
          + if content_reason(reason) == 1 do
            1
          else
            0
          end,
        expired: added.expired
          + if content_reason(reason) == 2 do
            1
          else
            0
          end,
        unsupported: added.unsupported
          + if content_reason(reason) == 3 do
            1
          else
            0
          end,
        above_profile: added.above_profile
          + if content_reason(reason) == 4 do
            1
          else
            0
          end
      }
      updated
  end
  content_parts_size(parts, policy, index + 1, next)
end

fn content_records_size(scope :: BackupContentScope,
  policy :: BackupAttachmentPolicy,
  index :: Int,
  before :: ContentCounts) -> ContentCounts!ProtocolError do
  if index >= List.length(scope.entries) do
    return Ok(before)
  end
  if before.records >= 4096 do
    return Err(OversizedInput)
  end
  let value = List.get(scope.entries, index)
  if List.length(value.attachments) > 10 do
    return Err(OversizedInput)
  end
  let added = content_add(before, 72 + Bytes.length(value.message_id) + Bytes.length(value.text))?
  let next = content_parts_size(value.attachments,
    policy,
    0,
    %{added | records: added.records + 1})?
  content_records_size(scope, policy, index + 1, next)
end

fn content_scopes_size(value :: BackupContentArchive,
  index :: Int,
  before :: ContentCounts) -> ContentCounts!ProtocolError do
  if index >= List.length(value.scopes) do
    return Ok(before)
  end
  let scope = List.get(value.scopes, index)
  if List.length(scope.entries) < 1
    || List.length(scope.entries) > 256
    || String.length(scope.name) > 96 do
    return Err(OversizedInput)
  end
  let added = content_add(before,
    19
      + Bytes.length(scope.id)
      + Bytes.length(scope.peer)
      + Bytes.length(Bytes.from_utf8(scope.name)))?
  let next = content_records_size(scope, value.policy, 0, added)?
  content_scopes_size(value, index + 1, next)
end

# Reuse existing canonical text/identity/ordinal rules without serializing its
# omitted flag into MCA1. The computed flag describes this private projection.
fn content_text_projection(value :: BackupContentArchive) -> BackupTextArchive do
  BackupTextArchive {
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
    scopes: for scope in value.scopes do
      BackupArchiveScope {
        kind: scope.kind,
        id: scope.id,
        peer: scope.peer,
        name: scope.name,
        entries: for entry in scope.entries do
          BackupArchiveRecord {
            ordinal: entry.ordinal,
            direction: entry.direction,
            message_id: entry.message_id,
            sender_account: entry.sender_account,
            sender_device: entry.sender_device,
            timestamp: entry.timestamp,
            attachment_omitted: List.length(entry.attachments) > 0,
            text: entry.text
          }
        end
      }
    end
  }
end

fn content_validate(value :: BackupContentArchive) -> ContentCounts!ProtocolError do
  if List.length(value.scopes) < 1 || List.length(value.scopes) > 32 do
    return Err(OversizedInput)
  end
  let counts = content_scopes_size(value,
    0,
    ContentCounts {
      size: 195,
      records: 0,
      files: 0,
      included: 0,
      unavailable: 0,
      expired: 0,
      unsupported: 0,
      above_profile: 0
    })?
  let checked = encode_text_archive(content_text_projection(value))?
  Ok(counts)
end

fn content_encode_part(value :: BackupArchiveAttachment, index :: Int) -> Bytes!ProtocolError do
  let encoded = case value do
    ArchiveAttachmentIncluded(name, mime, bytes) -> content_join([
      protocol_byte(index)?,
      protocol_byte(0)?,
      content_vector(name)?,
      content_vector(mime)?,
      Crypto.sha256(bytes),
      content_vector(bytes)?
    ])?
    ArchiveAttachmentOmitted(reason) -> content_join([
      protocol_byte(index)?,
      protocol_byte(content_reason(reason))?
    ])?
  end
  content_vector(encoded)
end

fn content_encode_record(value :: BackupContentRecord) -> Bytes!ProtocolError do
  let parts = for index in 0..List.length(value.attachments) do
    content_encode_part(List.get(value.attachments, index), index)?
  end
  content_vector(content_join([
    protocol_write_u16(value.ordinal)?,
    protocol_byte(value.direction)?,
    content_vector(value.message_id)?,
    value.sender_account,
    value.sender_device,
    protocol_write_u64(value.timestamp)?,
    content_vector(value.text)?,
    protocol_byte(List.length(value.attachments))?
  ]
    ++ parts)?)
end

fn content_encode_scope(value :: BackupContentScope) -> Bytes!ProtocolError do
  let records = for entry in value.entries do
    content_encode_record(entry)?
  end
  content_vector(content_join([
    protocol_byte(value.kind)?,
    content_vector(value.id)?,
    content_vector(value.peer)?,
    content_vector(Bytes.from_utf8(value.name))?,
    protocol_write_u16(List.length(value.entries))?
  ]
    ++ records)?)
end

pub fn encode_content_archive(value :: BackupContentArchive) -> Plaintext<Bytes>!ProtocolError do
  let counts = content_validate(value)?
  let scopes = for scope in value.scopes do
    content_encode_scope(scope)?
  end
  content_join([
    content_magic()?,
    protocol_byte(content_policy(value.policy))?,
    value.backup_id,
    value.owner_account,
    value.owner_authorization_key,
    value.service_realm,
    protocol_write_u64(value.created_at)?,
    protocol_write_u16(List.length(value.scopes))?,
    protocol_write_length(counts.records)?,
    protocol_write_length(value.candidate_count)?,
    protocol_write_length(value.omitted_timed)?,
    protocol_write_length(value.omitted_unknown)?,
    protocol_write_length(value.omitted_nontext)?,
    protocol_write_length(value.omitted_empty)?,
    protocol_write_length(value.attachment_messages)?,
    protocol_write_length(counts.files)?,
    protocol_write_length(counts.included)?,
    protocol_write_length(counts.unavailable)?,
    protocol_write_length(counts.expired)?,
    protocol_write_length(counts.unsupported)?,
    protocol_write_length(counts.above_profile)?
  ]
    ++ scopes)
end

fn content_decode_part(input :: Bytes, index :: Int) -> BackupArchiveAttachment!ProtocolError do
  let ordinal = protocol_take_u8(protocol_open(input, 16777216)?)?
  let status = protocol_take_u8(ordinal.state)?
  if ordinal.value != index || status.value > 4 do
    return Err(MalformedEncoding)
  end
  if status.value == 0 do
    let name = protocol_take_vector(status.state, 255)?
    let mime = protocol_take_vector(name.state, 127)?
    let digest = protocol_take_fixed(mime.state, 32)?
    let content = protocol_take_vector(digest.state, 16777216)?
    protocol_require_end(content.state)?
    if !Bytes.secure_equals(digest.value, Crypto.sha256(content.value)) do
      return Err(MalformedEncoding)
    end
    Ok(ArchiveAttachmentIncluded(name.value, mime.value, content.value))
  else
    protocol_require_end(status.state)?
    let reason = case status.value do
      1 -> ArchiveAttachmentUnavailable
      2 -> ArchiveAttachmentExpired
      3 -> ArchiveAttachmentUnsupported
      _ -> ArchiveAttachmentAboveProfile
    end
    Ok(ArchiveAttachmentOmitted(reason))
  end
end

fn content_decode_parts(state :: BinaryReader,
  index :: Int,
  count :: Int,
  output :: List<BackupArchiveAttachment>) -> (BinaryReader, List<BackupArchiveAttachment>)!ProtocolError do
  if index == count do
    return Ok((state, List.reverse(output)))
  end
  let part = protocol_take_vector(state, 16777216)?
  content_decode_parts(part.state,
    index + 1,
    count,
    [content_decode_part(part.value, index)?] ++ output)
end

fn content_decode_record(input :: Bytes,
  kind :: Int,
  file_budget :: Int) -> (BackupContentRecord, Int)!ProtocolError do
  let ordinal = protocol_take_u16(protocol_open(input, 16777216)?)?
  let direction = protocol_take_u8(ordinal.state)?
  let id = protocol_take_vector(direction.state, 32)?
  let account = protocol_take_fixed(id.state, 32)?
  let device = protocol_take_fixed(account.state, 16)?
  let timestamp = protocol_take_u64(device.state)?
  let text = protocol_take_vector(timestamp.state,
    if kind == 1 do
      32768
    else
      65346
    end)?
  let count = protocol_take_u8(text.state)?
  if count.value > 10 || count.value > file_budget do
    return Err(OversizedInput)
  end
  let (finished, parts) = content_decode_parts(count.state, 0, count.value, [])?
  protocol_require_end(finished)?
  Ok((BackupContentRecord {
      ordinal: ordinal.value,
      direction: direction.value,
      message_id: id.value,
      sender_account: account.value,
      sender_device: device.value,
      timestamp: timestamp.value,
      text: text.value,
      attachments: parts
    },
    count.value))
end

fn content_decode_records(state :: BinaryReader,
  kind :: Int,
  remaining :: Int,
  files :: Int,
  output :: List<BackupContentRecord>) -> (BinaryReader, List<BackupContentRecord>, Int)!ProtocolError do
  if remaining == 0 do
    return Ok((state, List.reverse(output), files))
  end
  let wire = protocol_take_vector(state, 16777216)?
  let (value, used) = content_decode_record(wire.value, kind, files)?
  content_decode_records(wire.state, kind, remaining - 1, files - used, [value] ++ output)
end

fn content_decode_scope(input :: Bytes,
  records :: Int,
  files :: Int) -> (BackupContentScope, Int)!ProtocolError do
  let kind = protocol_take_u8(protocol_open(input, 16777216)?)?
  if kind.value != 1 && kind.value != 2 do
    return Err(MalformedEncoding)
  end
  let id = protocol_take_vector(kind.state, 32)?
  let peer = protocol_take_vector(id.state, 32)?
  let name = protocol_take_vector(peer.state, 96)?
  let count = protocol_take_u16(name.state)?
  if count.value < 1 || count.value > 256 || count.value > records do
    return Err(OversizedInput)
  end
  let (finished, entries, remaining_files) = content_decode_records(count.state,
    kind.value,
    count.value,
    files,
    [])?
  protocol_require_end(finished)?
  let title = case Bytes.to_utf8(name.value) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(value) -> value
  end
  Ok((BackupContentScope {
      kind: kind.value,
      id: id.value,
      peer: peer.value,
      name: title,
      entries: entries
    },
    remaining_files))
end

fn content_decode_scopes(state :: BinaryReader,
  remaining :: Int,
  records :: Int,
  files :: Int,
  output :: List<BackupContentScope>) -> (BinaryReader, List<BackupContentScope>, Int, Int)!ProtocolError do
  if remaining == 0 do
    return Ok((state, List.reverse(output), records, files))
  end
  let wire = protocol_take_vector(state, 16777216)?
  let (scope, remaining_files) = content_decode_scope(wire.value, records, files)?
  content_decode_scopes(wire.state,
    remaining - 1,
    records - List.length(scope.entries),
    remaining_files,
    [scope] ++ output)
end

pub fn decode_content_archive(input :: Bytes) -> BackupContentArchive!ProtocolError do
  let magic = protocol_take_fixed(protocol_open(input, 16777216)?, 4)?
  if !Bytes.secure_equals(magic.value, content_magic()?) do
    return Err(MalformedEncoding)
  end
  let policy = protocol_take_u8(magic.state)?
  if policy.value > 1 do
    return Err(MalformedEncoding)
  end
  let id = protocol_take_fixed(policy.state, 32)?
  let account = protocol_take_fixed(id.state, 32)?
  let key = protocol_take_fixed(account.state, 32)?
  let realm = protocol_take_fixed(key.state, 32)?
  let time = protocol_take_u64(realm.state)?
  let scopes = protocol_take_u16(time.state)?
  let records = protocol_take_u32(scopes.state)?
  let candidates = protocol_take_u32(records.state)?
  let timed = protocol_take_u32(candidates.state)?
  let unknown = protocol_take_u32(timed.state)?
  let nontext = protocol_take_u32(unknown.state)?
  let empty = protocol_take_u32(nontext.state)?
  let attachment_messages = protocol_take_u32(empty.state)?
  let files = protocol_take_u32(attachment_messages.state)?
  let included = protocol_take_u32(files.state)?
  let unavailable = protocol_take_u32(included.state)?
  let expired = protocol_take_u32(unavailable.state)?
  let unsupported = protocol_take_u32(expired.state)?
  let above = protocol_take_u32(unsupported.state)?
  let record_count = protocol_as_int(records.value)?
  let file_count = protocol_as_int(files.value)?
  let expected = [
    protocol_as_int(included.value)?,
    protocol_as_int(unavailable.value)?,
    protocol_as_int(expired.value)?,
    protocol_as_int(unsupported.value)?,
    protocol_as_int(above.value)?
  ]
  if scopes.value < 1
    || scopes.value > 32
    || record_count < 1
    || record_count > 4096
    || file_count > 4096
    || List.any(expected, fn(value) -> value > 4096 end)
    || List.reduce(expected, 0, fn(total, value) -> total + value end) != file_count do
    return Err(OversizedInput)
  end
  if policy.value == 0 && file_count != protocol_as_int(included.value)? do
    return Err(InvalidPolicy)
  end
  let (finished, values, remaining_records, remaining_files) = content_decode_scopes(above.state,
    scopes.value,
    record_count,
    file_count,
    [])?
  protocol_require_end(finished)?
  if remaining_records != 0 || remaining_files != 0 do
    return Err(MalformedEncoding)
  end
  let value = BackupContentArchive {
    policy: if policy.value == 0 do
      RequireArchiveAttachments
    else
      AllowArchiveAttachmentOmissions
    end,
    backup_id: id.value,
    owner_account: account.value,
    owner_authorization_key: key.value,
    service_realm: realm.value,
    created_at: time.value,
    candidate_count: protocol_as_int(candidates.value)?,
    omitted_timed: protocol_as_int(timed.value)?,
    omitted_unknown: protocol_as_int(unknown.value)?,
    omitted_nontext: protocol_as_int(nontext.value)?,
    omitted_empty: protocol_as_int(empty.value)?,
    attachment_messages: protocol_as_int(attachment_messages.value)?,
    scopes: values
  }
  let counts = content_validate(value)?
  if [
    counts.included,
    counts.unavailable,
    counts.expired,
    counts.unsupported,
    counts.above_profile
  ] != expected
    || counts.size != Bytes.length(input) do
    return Err(MalformedEncoding)
  end
  Ok(value)
end

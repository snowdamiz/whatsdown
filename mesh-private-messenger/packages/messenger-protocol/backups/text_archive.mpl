##! Portable text syntax only; no account, history or message authority.
from Protocol.V1 import ProtocolError
from Binary.Reader import BinaryReader
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

pub struct BackupArchiveRecord do
  ordinal :: Int
  direction :: Int
  message_id :: Bytes
  sender_account :: Bytes
  sender_device :: Bytes
  timestamp :: U64
  attachment_omitted :: Bool
  text :: Bytes
end

pub struct BackupArchiveScope do
  kind :: Int
  id :: Bytes
  peer :: Bytes
  name :: String
  entries :: List<BackupArchiveRecord>
end

pub struct BackupTextArchive do
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
  scopes :: List<BackupArchiveScope>
end

# These are exact current-kind bounds, including all inner field framing.
# Direct:84+32768=32852; group with32-byte ID:100+65346=65446.
fn archive_record_limit(kind :: Int) -> Int do
  if kind == 1 do
    32852
  else
    65446
  end
end

fn archive_magic() -> Bytes!ProtocolError do
  case Bytes.from_list([1, 77, 84, 65]) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end
end

fn archive_join(parts :: List<Bytes>, limit :: Int) -> Bytes!ProtocolError do
  case Bytes.concat_many(parts, limit) do
    Err(_) -> Err(OversizedInput)
    Ok(value)
  end
end

fn archive_vector(value :: Bytes) -> Bytes!ProtocolError do
  archive_join([protocol_write_length(Bytes.length(value))?, value], 16777216)
end

fn archive_octet(input :: Bytes, index :: Int) -> Int!ProtocolError do
  case Bytes.get(input, index) do
    Err(_) -> Err(MalformedEncoding)
    Ok(value)
  end
end

fn archive_id_less(left :: Bytes, right :: Bytes, index :: Int) -> Bool!ProtocolError do
  if index >= Bytes.length(left) do
    Ok(Bytes.length(left) < Bytes.length(right))
  else if index >= Bytes.length(right) do
    Ok(false)
  else
    let a = archive_octet(left, index)?
    let b = archive_octet(right, index)?
    if a == b do
      archive_id_less(left, right, index + 1)
    else
      Ok(a < b)
    end
  end
end

fn archive_record_size(value :: BackupArchiveRecord,
  scope :: BackupArchiveScope,
  owner :: Bytes) -> Int!ProtocolError do
  let id_size = Bytes.length(value.message_id)
  let text_size = Bytes.length(value.text)
  if value.ordinal < 0
    || value.ordinal > 255
    || (value.direction != 1 && value.direction != 2)
    || Bytes.length(value.sender_account) != 32
    || Bytes.length(value.sender_device) != 16
    || (scope.kind == 1 && id_size != 16)
    || (scope.kind == 2 && id_size != 0 && id_size != 32)
    || (scope.kind == 1 && text_size > 32768)
    || (scope.kind == 2 && text_size > 65346)
    || (text_size == 0 && !value.attachment_omitted) do
    return Err(MalformedEncoding)
  end
  if scope.kind == 1
    && !Bytes.secure_equals(value.sender_account,
      if value.direction == 1 do
        owner
      else
        scope.peer
      end) do
    return Err(MalformedEncoding)
  end
  case Bytes.to_utf8(value.text) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(_) -> nil
  end
  Ok(68 + id_size + text_size)
end

fn archive_scope_size(value :: BackupArchiveScope,
  owner :: Bytes) -> Result<(Int, Int), ProtocolError> do
  let count = List.length(value.entries)
  if count < 1 || count > 256 do
    return Err(OversizedInput)
  end
  if (value.kind != 1 && value.kind != 2)
    || (value.kind == 1 && (Bytes.length(value.id) != 16 || Bytes.length(value.peer) != 32))
    || (value.kind == 2 && (Bytes.length(value.id) != 32 || Bytes.length(value.peer) != 0))
    || String.length(value.name) > 96 do
    return Err(MalformedEncoding)
  end
  let name = Bytes.from_utf8(value.name)
  if Bytes.length(name) > 96 || Regex.is_match(~r/\p{Cc}/, value.name) do
    return Err(MalformedEncoding)
  end
  archive_entries_size(value,
    owner,
    0,
    15 + Bytes.length(value.id) + Bytes.length(value.peer) + Bytes.length(name),
    0)
end

fn archive_entries_size(scope :: BackupArchiveScope,
  owner :: Bytes,
  index :: Int,
  size :: Int,
  attachments :: Int) -> Result<(Int, Int), ProtocolError> do
  if index >= List.length(scope.entries) do
    return Ok((size, attachments))
  end
  let entry = List.get(scope.entries, index)
  let entry_size = archive_record_size(entry, scope, owner)?
  if index > 0 && List.get(scope.entries, index - 1).ordinal >= entry.ordinal do
    return Err(MalformedEncoding)
  end
  if Bytes.length(entry.message_id) > 0
    && List.any(List.take(scope.entries, index),
      fn(previous) -> Bytes.secure_equals(previous.message_id, entry.message_id) end) do
    return Err(MalformedEncoding)
  end
  let next = size + 4 + entry_size
  if next > 16777216 do
    return Err(OversizedInput)
  end
  archive_entries_size(scope,
    owner,
    index + 1,
    next,
    attachments
      + if entry.attachment_omitted do
        1
      else
        0
      end)
end

fn archive_scopes_size(value :: BackupTextArchive,
  index :: Int,
  size :: Int,
  records :: Int,
  attachments :: Int) -> Result<(Int, Int, Int), ProtocolError> do
  if index >= List.length(value.scopes) do
    return Ok((size, records, attachments))
  end
  let scope = List.get(value.scopes, index)
  let (scope_size, flags) = archive_scope_size(scope, value.owner_account)?
  if index > 0 do
    let previous = List.get(value.scopes, index - 1)
    if previous.kind > scope.kind
      || (previous.kind == scope.kind && !archive_id_less(previous.id, scope.id, 0)?) do
      return Err(MalformedEncoding)
    end
  end
  if scope.kind == 1
    && List.any(List.take(value.scopes, index),
      fn(previous) -> previous.kind == 1 && Bytes.secure_equals(previous.peer, scope.peer) end) do
    return Err(MalformedEncoding)
  end
  let next_size = size + 4 + scope_size
  let next_count = records + List.length(scope.entries)
  if next_size > 16777216 || next_count > 4096 do
    return Err(OversizedInput)
  end
  archive_scopes_size(value, index + 1, next_size, next_count, attachments + flags)
end

fn archive_validate(value :: BackupTextArchive) -> Int!ProtocolError do
  if Bytes.length(value.backup_id) != 32
    || Bytes.length(value.owner_account) != 32
    || Bytes.length(value.owner_authorization_key) != 32
    || Bytes.length(value.service_realm) != 32 do
    return Err(MalformedEncoding)
  end
  if List.length(value.scopes) < 1 || List.length(value.scopes) > 32 do
    return Err(OversizedInput)
  end
  let counts = [
    value.candidate_count,
    value.omitted_timed,
    value.omitted_unknown,
    value.omitted_nontext,
    value.omitted_empty,
    value.attachment_messages
  ]
  if List.any(counts, fn(count) -> count < 0 || count > 8192 end) do
    return Err(MalformedEncoding)
  end
  let (size, records, flags) = archive_scopes_size(value, 0, 170, 0, 0)?
  if value.candidate_count != records
      + value.omitted_timed
      + value.omitted_unknown
      + value.omitted_nontext
      + value.omitted_empty
    || value.attachment_messages > value.candidate_count
    || value.attachment_messages < flags do
    return Err(MalformedEncoding)
  end
  Ok(size)
end

fn archive_encode_record(value :: BackupArchiveRecord) -> Bytes!ProtocolError do
  archive_join([
      protocol_write_u16(value.ordinal)?,
      protocol_byte(value.direction)?,
      archive_vector(value.message_id)?,
      value.sender_account,
      value.sender_device,
      protocol_write_u64(value.timestamp)?,
      protocol_byte(if value.attachment_omitted do
        1
      else
        0
      end)?,
      archive_vector(value.text)?
    ],
    65446)
end

fn archive_encode_scope(value :: BackupArchiveScope) -> Bytes!ProtocolError do
  let entries = for entry in value.entries do
    archive_vector(archive_encode_record(entry)?)?
  end
  archive_join([
      protocol_byte(value.kind)?,
      archive_vector(value.id)?,
      archive_vector(value.peer)?,
      archive_vector(Bytes.from_utf8(value.name))?,
      protocol_write_u16(List.length(value.entries))?
    ]
      ++ entries,
    16777216)
end

pub fn encode_text_archive(value :: BackupTextArchive) -> Bytes!ProtocolError do
  let size = archive_validate(value)?
  let scopes = for scope in value.scopes do
    archive_vector(archive_encode_scope(scope)?)?
  end
  let records = List.length(List.flatten(for scope in value.scopes do
    scope.entries
  end))
  archive_join([
      archive_magic()?,
      value.backup_id,
      value.owner_account,
      value.owner_authorization_key,
      value.service_realm,
      protocol_write_u64(value.created_at)?,
      protocol_write_u16(List.length(value.scopes))?,
      protocol_write_length(records)?,
      protocol_write_length(value.candidate_count)?,
      protocol_write_length(value.omitted_timed)?,
      protocol_write_length(value.omitted_unknown)?,
      protocol_write_length(value.omitted_nontext)?,
      protocol_write_length(value.omitted_empty)?,
      protocol_write_length(value.attachment_messages)?
    ]
      ++ scopes,
    size)
end

fn archive_decode_record(input :: Bytes, kind :: Int) -> BackupArchiveRecord!ProtocolError do
  let ordinal = protocol_take_u16(protocol_open(input, archive_record_limit(kind))?)?
  let direction = protocol_take_u8(ordinal.state)?
  let id = protocol_take_vector(direction.state, 32)?
  let account = protocol_take_fixed(id.state, 32)?
  let device = protocol_take_fixed(account.state, 16)?
  let timestamp = protocol_take_u64(device.state)?
  let flag = protocol_take_u8(timestamp.state)?
  if flag.value > 1 do
    return Err(MalformedEncoding)
  end
  let text = protocol_take_vector(flag.state,
    if kind == 1 do
      32768
    else
      65346
    end)?
  protocol_require_end(text.state)?
  Ok(BackupArchiveRecord {
    ordinal: ordinal.value,
    direction: direction.value,
    message_id: id.value,
    sender_account: account.value,
    sender_device: device.value,
    timestamp: timestamp.value,
    attachment_omitted: flag.value == 1,
    text: text.value
  })
end

fn archive_decode_records(state :: BinaryReader,
  kind :: Int,
  remaining :: Int,
  output :: List<BackupArchiveRecord>) -> Result<(BinaryReader, List<BackupArchiveRecord>), ProtocolError> do
  if remaining == 0 do
    Ok((state, List.reverse(output)))
  else
    let bytes = protocol_take_vector(state, archive_record_limit(kind))?
    archive_decode_records(bytes.state,
      kind,
      remaining - 1,
      [archive_decode_record(bytes.value, kind)?] ++ output)
  end
end

fn archive_decode_scope(input :: Bytes, record_budget :: Int) -> BackupArchiveScope!ProtocolError do
  let kind = protocol_take_u8(protocol_open(input, 16777216)?)?
  if kind.value != 1 && kind.value != 2 do
    return Err(MalformedEncoding)
  end
  let id = protocol_take_vector(kind.state, 32)?
  let peer = protocol_take_vector(id.state, 32)?
  let name = protocol_take_vector(peer.state, 96)?
  let count = protocol_take_u16(name.state)?
  if count.value < 1 || count.value > 256 || count.value > record_budget do
    return Err(OversizedInput)
  end
  let (finished, entries) = archive_decode_records(count.state, kind.value, count.value, [])?
  protocol_require_end(finished)?
  let text = case Bytes.to_utf8(name.value) do
    Err(_) -> return Err(MalformedEncoding)
    Ok(value) -> value
  end
  Ok(BackupArchiveScope {
    kind: kind.value,
    id: id.value,
    peer: peer.value,
    name: text,
    entries: entries
  })
end

fn archive_decode_scopes(state :: BinaryReader,
  remaining :: Int,
  record_budget :: Int,
  output :: List<BackupArchiveScope>) -> Result<(BinaryReader, List<BackupArchiveScope>), ProtocolError> do
  if remaining == 0 do
    Ok((state, List.reverse(output)))
  else
    let bytes = protocol_take_vector(state, 16777216)?
    let scope = archive_decode_scope(bytes.value, record_budget)?
    archive_decode_scopes(bytes.state,
      remaining - 1,
      record_budget - List.length(scope.entries),
      [scope] ++ output)
  end
end

pub fn decode_text_archive(input :: Bytes) -> BackupTextArchive!ProtocolError do
  let magic = protocol_take_fixed(protocol_open(input, 16777216)?, 4)?
  if !Bytes.secure_equals(magic.value, archive_magic()?) do
    return Err(MalformedEncoding)
  end
  let backup = protocol_take_fixed(magic.state, 32)?
  let owner = protocol_take_fixed(backup.state, 32)?
  let authorization = protocol_take_fixed(owner.state, 32)?
  let realm = protocol_take_fixed(authorization.state, 32)?
  let created = protocol_take_u64(realm.state)?
  let count = protocol_take_u16(created.state)?
  if count.value < 1 || count.value > 32 do
    return Err(OversizedInput)
  end
  let records = protocol_take_u32(count.state)?
  let expected_records = protocol_as_int(records.value)?
  if expected_records < count.value || expected_records > 4096 do
    return Err(OversizedInput)
  end
  let candidates = protocol_take_u32(records.state)?
  let timed = protocol_take_u32(candidates.state)?
  let unknown = protocol_take_u32(timed.state)?
  let nontext = protocol_take_u32(unknown.state)?
  let empty = protocol_take_u32(nontext.state)?
  let attachments = protocol_take_u32(empty.state)?
  # Public counts are admitted before count-dependent scope allocation.
  let numbers = [
    candidates.value,
    timed.value,
    unknown.value,
    nontext.value,
    empty.value,
    attachments.value
  ]
  let bound = case U64.parse("8192") do
    Err(_) -> return Err(MalformedEncoding)
    Ok(v) -> v
  end
  if List.any(numbers, fn(number) -> U64.compare(number, bound) > 0 end) do
    return Err(MalformedEncoding)
  end
  let (finished, scopes) = archive_decode_scopes(attachments.state,
    count.value,
    expected_records,
    [])?
  protocol_require_end(finished)?
  let value = BackupTextArchive {
    backup_id: backup.value,
    owner_account: owner.value,
    owner_authorization_key: authorization.value,
    service_realm: realm.value,
    created_at: created.value,
    candidate_count: protocol_as_int(candidates.value)?,
    omitted_timed: protocol_as_int(timed.value)?,
    omitted_unknown: protocol_as_int(unknown.value)?,
    omitted_nontext: protocol_as_int(nontext.value)?,
    omitted_empty: protocol_as_int(empty.value)?,
    attachment_messages: protocol_as_int(attachments.value)?,
    scopes: scopes
  }
  let _ = archive_validate(value)?
  let actual = List.length(List.flatten(for scope in scopes do
    scope.entries
  end))
  if actual != expected_records do
    return Err(MalformedEncoding)
  end
  Ok(value)
end

##! Versioned native backup framing. No authority, clock or storage plans cross it.
from Mobile.BackupArchiveView import (
  BackupArchiveConversation,
  BackupArchiveOverview,
  BackupArchivePage,
  BackupArchivePageRequest
)

pub struct BackupNativeAction do
  database_path :: String
  expected_profile :: Bytes
end

pub struct BackupNativeSelection do
  kind :: Int
  scope_id :: Bytes
  from_time :: Option<U64>
  through_time :: Option<U64>
end

pub struct BackupNativeCreateRequest do
  action :: BackupNativeAction
  selection :: List<BackupNativeSelection>
end

pub struct BackupNativePortableRequest do
  action :: BackupNativeAction
  wire :: Bytes
  recovery_code :: String
end

pub struct BackupNativeImportRequest do
  action :: BackupNativeAction
  wire :: Bytes
  recovery_code :: String
  confirmed_backup_id :: Bytes
end

pub struct BackupNativeArchiveRequest do
  action :: BackupNativeAction
  backup_id :: Bytes
end

pub struct BackupNativePageRequest do
  action :: BackupNativeAction
  backup_id :: Bytes
  page :: BackupArchivePageRequest
end

pub struct BackupNativeSummary do
  backup_id :: Bytes
  created_at :: U64
end

from Binary.Reader import BinaryReader, reader, finish, read_fixed, read_vector
from Backups.TextArchive import BackupArchiveRecord

struct BackupNativeRead do
  state :: BinaryReader
  value :: Bytes
end

struct BackupNativeBase do
  state :: BinaryReader
  action :: BackupNativeAction
end

struct BackupNativeTime do
  state :: BinaryReader
  value :: Option<U64>
end

struct BackupNativeSelectionRead do
  state :: BinaryReader
  selection :: BackupNativeSelection
end

struct BackupNativePortableRead do
  state :: BinaryReader
  request :: BackupNativePortableRequest
end

fn native_fixed(state :: BinaryReader, size :: Int) -> BackupNativeRead!String do
  case read_fixed(state, size) do
    Err(_) -> Err("invalid_backup_native_request")
    Ok((next, value)) -> Ok(BackupNativeRead { state: next, value: value })
  end
end

fn native_vector(state :: BinaryReader, maximum :: Int) -> BackupNativeRead!String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_backup_native_request")
    Ok((next, value)) -> Ok(BackupNativeRead { state: next, value: value })
  end
end

fn native_byte(value :: Bytes) -> Int!String do
  if Bytes.length(value) != 1 do
    Err("invalid_backup_native_request")
  else
    Ok(List.head(Bytes.to_list(value)))
  end
end

fn native_u32(value :: Bytes) -> Int!String do
  case Bytes.read_u32_be(value, 0) do
    Err(_) -> Err("invalid_backup_native_request")
    Ok(wide) -> case U64.to_int(wide) do
      Err(_) -> Err("invalid_backup_native_request")
      Ok(number)
    end
  end
end

fn native_u64(value :: Bytes) -> U64!String do
  case Bytes.read_u64_be(value, 0) do
    Err(_) -> Err("invalid_backup_native_request")
    Ok(number)
  end
end

fn native_utf8(value :: Bytes) -> String!String do
  case Bytes.to_utf8(value) do
    Err(_) -> Err("invalid_backup_native_request")
    Ok(text)
  end
end

fn native_finish(state :: BinaryReader) -> Result<(), String> do
  case finish(state) do
    Err(_) -> Err("invalid_backup_native_request")
    Ok(_) -> Ok(nil)
  end
end

fn native_base(input :: Bytes, maximum :: Int) -> BackupNativeBase!String do
  let state = case reader(input, maximum) do
    Err(_) -> return Err("invalid_backup_native_request")
    Ok(value) -> value
  end
  let version = native_fixed(state, 1)?
  if native_byte(version.value)? != 1 do
    return Err("invalid_backup_native_request")
  end
  let path = native_vector(version.state, 4096)?
  let profile = native_vector(path.state, 36134)?
  let text = native_utf8(path.value)?
  if Bytes.length(path.value) == 0
    || String.contains(text, "\0")
    || Bytes.length(profile.value) == 0 do
    return Err("invalid_backup_native_request")
  end
  Ok(BackupNativeBase {
    state: profile.state,
    action: BackupNativeAction { database_path: text, expected_profile: profile.value }
  })
end

pub fn parse_backup_list_request(input :: Bytes) -> BackupNativeAction!String do
  let base = native_base(input, 40239)?
  native_finish(base.state)?
  Ok(base.action)
end

fn native_time(state :: BinaryReader) -> BackupNativeTime!String do
  let tag = native_fixed(state, 1)?
  let kind = native_byte(tag.value)?
  if kind == 0 do
    Ok(BackupNativeTime { state: tag.state, value: None })
  else if kind == 1 do
    let time = native_fixed(tag.state, 8)?
    Ok(BackupNativeTime { state: time.state, value: Some(native_u64(time.value)?) })
  else
    Err("invalid_backup_native_request")
  end
end

fn native_selection(state :: BinaryReader) -> BackupNativeSelectionRead!String do
  let kind = native_fixed(state, 1)?
  let value = native_byte(kind.value)?
  let id = native_vector(kind.state, 32)?
  if (value != 1 && value != 2)
    || (value == 1 && Bytes.length(id.value) != 16)
    || (value == 2 && Bytes.length(id.value) != 32) do
    return Err("invalid_backup_native_request")
  end
  let first = native_time(id.state)?
  let last = native_time(first.state)?
  case (first.value, last.value) do
    (Some(start), Some(end_time)) -> if U64.compare(start, end_time) > 0 do
      return Err("invalid_backup_native_request")
    end
    _ -> nil
  end
  Ok(BackupNativeSelectionRead {
    state: last.state,
    selection: BackupNativeSelection {
      kind: value,
      scope_id: id.value,
      from_time: first.value,
      through_time: last.value
    }
  })
end

fn native_selections(state :: BinaryReader,
  count :: Int,
  values :: List<BackupNativeSelection>) -> Result<List<BackupNativeSelection>, String> do
  if count == 0 do
    native_finish(state)?
    return Ok(values)
  end
  let row = native_selection(state)?
  if List.any(values,
    fn(old) -> old.kind == row.selection.kind
      && Bytes.secure_equals(old.scope_id, row.selection.scope_id) end) do
    return Err("invalid_backup_native_request")
  end
  native_selections(row.state, count - 1, List.append(values, row.selection))
end

pub fn parse_backup_create_request(input :: Bytes) -> BackupNativeCreateRequest!String do
  let base = native_base(input, 42004)?
  let selection = native_vector(base.state, 1761)?
  native_finish(selection.state)?
  let state = case reader(selection.value, 1761) do
    Err(_) -> return Err("invalid_backup_native_request")
    Ok(value) -> value
  end
  let count = native_fixed(state, 1)?
  let length = native_byte(count.value)?
  if length < 1 || length > 32 do
    return Err("invalid_backup_native_request")
  end
  Ok(BackupNativeCreateRequest {
    action: base.action,
    selection: native_selections(count.state, length, [])?
  })
end

fn native_portable(input :: Bytes, maximum :: Int) -> BackupNativePortableRead!String do
  let base = native_base(input, maximum)?
  let wire = native_vector(base.state, 16796864)?
  let code = native_vector(wire.state, 4096)?
  let text = native_utf8(code.value)?
  if Bytes.length(wire.value) == 0 || String.length(text) == 0 || String.length(text) > 1024 do
    return Err("invalid_backup_native_request")
  end
  Ok(BackupNativePortableRead {
    state: code.state,
    request: BackupNativePortableRequest {
      action: base.action,
      wire: wire.value,
      recovery_code: text
    }
  })
end

pub fn parse_backup_preview_request(input :: Bytes) -> BackupNativePortableRequest!String do
  let ready = native_portable(input, 16841207)?
  native_finish(ready.state)?
  Ok(ready.request)
end

pub fn parse_backup_import_request(input :: Bytes) -> BackupNativeImportRequest!String do
  let ready = native_portable(input, 16841239)?
  let id = native_fixed(ready.state, 32)?
  native_finish(id.state)?
  Ok(BackupNativeImportRequest {
    action: ready.request.action,
    wire: ready.request.wire,
    recovery_code: ready.request.recovery_code,
    confirmed_backup_id: id.value
  })
end

fn native_archive(input :: Bytes) -> BackupNativeArchiveRequest!String do
  let base = native_base(input, 40271)?
  let id = native_fixed(base.state, 32)?
  native_finish(id.state)?
  Ok(BackupNativeArchiveRequest { action: base.action, backup_id: id.value })
end

pub fn parse_backup_remove_request(input :: Bytes) -> BackupNativeArchiveRequest!String do
  native_archive(input)
end

pub fn parse_backup_overview_request(input :: Bytes) -> BackupNativeArchiveRequest!String do
  native_archive(input)
end

pub fn parse_backup_page_request(input :: Bytes) -> BackupNativePageRequest!String do
  let base = native_base(input, 40313)?
  let id = native_fixed(base.state, 32)?
  let kind = native_fixed(id.state, 1)?
  let value = native_byte(kind.value)?
  let scope = native_vector(kind.state, 32)?
  let offset = native_fixed(scope.state, 4)?
  let position = native_u32(offset.value)?
  let limit = native_fixed(offset.state, 1)?
  let count = native_byte(limit.value)?
  native_finish(limit.state)?
  if (value != 1 && value != 2)
    || (value == 1 && Bytes.length(scope.value) != 16)
    || (value == 2 && Bytes.length(scope.value) != 32)
    || position > 256
    || count < 1
    || count > 16 do
    return Err("invalid_backup_native_request")
  end
  Ok(BackupNativePageRequest {
    action: base.action,
    backup_id: id.value,
    page: BackupArchivePageRequest {
      kind: value,
      scope_id: scope.value,
      offset: position,
      limit: count
    }
  })
end

fn reply_join(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  case Bytes.concat_many(parts, maximum) do
    Err(_) -> Err("invalid_backup_native_reply")
    Ok(value)
  end
end

fn reply_byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_backup_native_reply")
    Ok(bytes)
  end
end

fn reply_u16(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("invalid_backup_native_reply")
    Ok(bytes)
  end
end

fn reply_u32(value :: Int) -> Bytes!String do
  let wide = case U64.parse(Int.to_string(value)) do
    Err(_) -> return Err("invalid_backup_native_reply")
    Ok(number) -> number
  end
  case Bytes.write_u32_be(wide) do
    Err(_) -> Err("invalid_backup_native_reply")
    Ok(bytes)
  end
end

fn reply_u64(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_backup_native_reply")
    Ok(bytes)
  end
end

fn reply_vector(value :: Bytes) -> Bytes!String do
  reply_join([reply_u32(Bytes.length(value))?, value], 16841239)
end

fn reply_list(parts :: List<Bytes>) -> Bytes!String do
  reply_join([reply_vector(reply_u32(List.length(parts))?)?]
      ++ for part in parts do
        reply_vector(part)?
      end,
    16841239)
end

pub fn encode_backup_create_reply(wire :: Bytes, code :: String) -> Bytes!String do
  if Bytes.length(wire) == 0
    || Bytes.length(wire) > 16796864
    || String.length(code) == 0
    || String.length(code) > 1024 do
    return Err("invalid_backup_native_reply")
  end
  let encoded_code = Bytes.from_utf8(code)
  if Bytes.length(encoded_code) > 4096 do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(1)?, reply_vector(wire)?, reply_vector(encoded_code)?], 16800969)
end

pub fn encode_backup_import_reply(id :: Bytes, disposition :: Int) -> Bytes!String do
  if Bytes.length(id) != 32 || (disposition != 1 && disposition != 2) do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(1)?, id, reply_byte(disposition)?], 4096)
end

pub fn encode_backup_remove_reply(id :: Bytes) -> Bytes!String do
  if Bytes.length(id) != 32 do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(1)?, id, reply_byte(1)?], 4096)
end

pub fn encode_backup_list_reply(values :: Plaintext<List<BackupNativeSummary>>) -> Result<Plaintext<Bytes>, String> do
  if List.length(values) > 8 do
    return Err("invalid_backup_native_reply")
  end
  let rows = for value in values do
    if Bytes.length(value.backup_id) != 32 do
      return Err("invalid_backup_native_reply")
    end
    reply_list([value.backup_id, reply_u64(value.created_at)?])?
  end
  reply_join([reply_byte(1)?, reply_list(rows)?], 4096)
end

fn reply_conversation(value :: BackupArchiveConversation) -> Bytes!String do
  if (value.kind != 1 && value.kind != 2)
    || (value.kind == 1 && (Bytes.length(value.id) != 16 || Bytes.length(value.peer) != 32))
    || (value.kind == 2 && (Bytes.length(value.id) != 32 || Bytes.length(value.peer) != 0))
    || String.length(value.name) > 96
    || value.message_count < 1
    || value.message_count > 256 do
    return Err("invalid_backup_native_reply")
  end
  let name = Bytes.from_utf8(value.name)
  if Bytes.length(name) > 96 || Regex.is_match(~r/\p{Cc}/, value.name) do
    return Err("invalid_backup_native_reply")
  end
  reply_list([reply_byte(value.kind)?, value.id, value.peer, name, reply_u32(value.message_count)?])
end

pub fn encode_backup_overview_reply(value :: Plaintext<BackupArchiveOverview>) -> Result<Plaintext<Bytes>, String> do
  if Bytes.length(value.backup_id) != 32
    || List.length(value.conversations) < 1
    || List.length(value.conversations) > 32
    || value.included_count < 1
    || value.included_count > 4096 do
    return Err("invalid_backup_native_reply")
  end
  let counts = [
    value.included_count,
    value.candidate_count,
    value.omitted_timed,
    value.omitted_unknown,
    value.omitted_nontext,
    value.omitted_empty,
    value.attachment_messages
  ]
  if List.any(counts, fn(count) -> count < 0 || count > 8192 end)
    || value.candidate_count != value.included_count
        + value.omitted_timed
        + value.omitted_unknown
        + value.omitted_nontext
        + value.omitted_empty
    || value.attachment_messages > value.candidate_count
    || List.reduce(value.conversations,
      0,
      fn(count, scope) -> count + scope.message_count end) != value.included_count do
    return Err("invalid_backup_native_reply")
  end
  let scopes = for scope in value.conversations do
    reply_conversation(scope)?
  end
  reply_join([
      reply_byte(1)?,
      reply_list([value.backup_id, reply_u64(value.created_at)?]
        ++ for count in counts do
          reply_u32(count)?
        end
        ++ [reply_list(scopes)?])?
    ],
    8192)
end

fn valid_reply_record(kind :: Int, value :: BackupArchiveRecord) -> Bool do
  value.ordinal >= 0
    && value.ordinal <= 255
    && (value.direction == 1 || value.direction == 2)
    && Bytes.length(value.sender_account) == 32
    && Bytes.length(value.sender_device) == 16
    && ((kind == 1 && Bytes.length(value.message_id) == 16 && Bytes.length(value.text) <= 32768)
      || (kind == 2
        && (Bytes.length(value.message_id) == 0 || Bytes.length(value.message_id) == 32)
        && Bytes.length(value.text) <= 65346))
    && (Bytes.length(value.text) > 0 || value.attachment_omitted)
end

fn reply_record(value :: BackupArchiveRecord) -> Bytes!String do
  case Bytes.to_utf8(value.text) do
    Err(_) -> return Err("invalid_backup_native_reply")
    Ok(_) -> nil
  end
  reply_list([
    reply_u16(value.ordinal)?,
    reply_byte(value.direction)?,
    value.message_id,
    value.sender_account,
    value.sender_device,
    reply_u64(value.timestamp)?,
    reply_byte(if value.attachment_omitted do
      1
    else
      0
    end)?,
    value.text
  ])
end

pub fn encode_backup_page_reply(value :: Plaintext<BackupArchivePage>) -> Result<Plaintext<Bytes>, String> do
  if Bytes.length(value.backup_id) != 32
    || (value.kind != 1 && value.kind != 2)
    || (value.kind == 1 && Bytes.length(value.scope_id) != 16)
    || (value.kind == 2 && Bytes.length(value.scope_id) != 32)
    || value.offset < 0
    || value.offset > 256
    || List.length(value.entries) > 16
    || value.offset + List.length(value.entries) > 256 do
    return Err("invalid_backup_native_reply")
  end
  let next = case value.next_offset do
    None -> reply_byte(0)?
    Some(position) -> do
      if position <= value.offset
        || position > 255
        || position != value.offset + List.length(value.entries) do
        return Err("invalid_backup_native_reply")
      end
      reply_join([reply_byte(1)?, reply_u32(position)?], 5)?
    end
  end
  let text_bytes = List.reduce(value.entries,
    0,
    fn(count, row) -> count + Bytes.length(row.text) end)
  if text_bytes > 131072 do
    return Err("invalid_backup_native_reply")
  end
  for index in 0..List.length(value.entries) do
    let row = List.get(value.entries, index)
    if !valid_reply_record(value.kind, row)
      || (index > 0 && List.get(value.entries, index - 1).ordinal >= row.ordinal)
      || (Bytes.length(row.message_id) > 0
        && List.any(List.take(value.entries, index),
          fn(old) -> Bytes.secure_equals(old.message_id, row.message_id) end)) do
      return Err("invalid_backup_native_reply")
    end
  end
  let rows = for row in value.entries do
    reply_record(row)?
  end
  reply_join([
      reply_byte(1)?,
      reply_list([
        value.backup_id,
        reply_byte(value.kind)?,
        value.scope_id,
        reply_u32(value.offset)?,
        next,
        reply_list(rows)?
      ])?
    ],
    135168)
end

pub struct BackupNativePendingState do
  kind :: Int
  draft_id :: Bytes
  created_at :: U64
  wire_size :: Int
end

pub struct BackupNativePendingRequest do
  action :: BackupNativeAction
  draft_id :: Bytes
end

pub struct BackupNativePendingResumeRequest do
  action :: BackupNativeAction
  draft_id :: Bytes
  recovery_code :: String
end

pub fn parse_backup_pending_state_request(input :: Bytes) -> BackupNativeAction!String do
  let base = native_base(input, 40239)?
  native_finish(base.state)?
  Ok(base.action)
end

pub fn parse_backup_pending_repair_request(input :: Bytes) -> BackupNativeAction!String do
  parse_backup_pending_state_request(input)
end

pub fn parse_backup_pending_discard_request(input :: Bytes) -> BackupNativePendingRequest!String do
  let base = native_base(input, 40271)?
  let draft = native_fixed(base.state, 32)?
  native_finish(draft.state)?
  Ok(BackupNativePendingRequest { action: base.action, draft_id: draft.value })
end

pub fn parse_backup_pending_resume_request(input :: Bytes) -> BackupNativePendingResumeRequest!String do
  let base = native_base(input, 44371)?
  let draft = native_fixed(base.state, 32)?
  let raw_code = native_vector(draft.state, 4096)?
  let code = native_utf8(raw_code.value)?
  if String.length(code) < 1 || String.length(code) > 1024 do
    return Err("invalid_backup_native_request")
  end
  native_finish(raw_code.state)?
  Ok(BackupNativePendingResumeRequest {
    action: base.action,
    draft_id: draft.value,
    recovery_code: code
  })
end

pub fn encode_backup_pending_create_reply(draft :: Bytes,
  wire :: Bytes,
  code :: String) -> Bytes!String do
  if Bytes.length(draft) != 32
    || Bytes.length(wire) < 1
    || Bytes.length(wire) > 16796864
    || String.length(code) < 1
    || String.length(code) > 1024 do
    return Err("invalid_backup_native_reply")
  end
  let encoded = Bytes.from_utf8(code)
  if Bytes.length(encoded) > 4096 do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(2)?, draft, reply_vector(wire)?, reply_vector(encoded)?], 16801001)
end

pub fn encode_backup_pending_state_reply(value :: Plaintext<BackupNativePendingState>) -> Result<Plaintext<Bytes>, String> do
  if value.kind == 0 || value.kind == 2 do
    if Bytes.length(value.draft_id) != 0
      || U64.to_string(value.created_at) != "0"
      || value.wire_size != 0 do
      return Err("invalid_backup_native_reply")
    end
    return reply_join([reply_byte(1)?, reply_byte(value.kind)?], 46)
  end
  if value.kind != 1
    || Bytes.length(value.draft_id) != 32
    || value.wire_size < 1
    || value.wire_size > 16796864 do
    return Err("invalid_backup_native_reply")
  end
  reply_join([
      reply_byte(1)?,
      reply_byte(1)?,
      value.draft_id,
      reply_u64(value.created_at)?,
      reply_u32(value.wire_size)?
    ],
    46)
end

pub fn encode_backup_pending_resume_reply(wire :: Bytes) -> Bytes!String do
  if Bytes.length(wire) < 1 || Bytes.length(wire) > 16796864 do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(1)?, reply_vector(wire)?], 16796869)
end

pub fn encode_backup_pending_discard_reply(draft :: Bytes, disposition :: Int) -> Bytes!String do
  if Bytes.length(draft) != 32 || (disposition != 1 && disposition != 2) do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(1)?, draft, reply_byte(disposition)?], 34)
end

pub fn encode_backup_pending_repair_reply(disposition :: Int) -> Bytes!String do
  if disposition != 1 && disposition != 2 do
    return Err("invalid_backup_native_reply")
  end
  reply_join([reply_byte(1)?, reply_byte(disposition)?], 2)
end

## The native shell supplies no authority beyond the expected public profile.
## Every guarded operation internally captures custody, original rows and time.
from Mobile.BackupArchive import (
  D4BackupSelection,
  create_pending_backup_export,
  create_pending_content_backup_export,
  pending_backup_export_state,
  resume_pending_backup_export,
  discard_pending_backup_export,
  repair_pending_backup_export,
  import_backup_archive,
  list_backup_archives,
  remove_backup_archive
)
from Mobile.BackupArchiveReader import (
  preview_backup_archive_overview,
  read_backup_archive_overview,
  read_backup_archive_page
)

fn native_public_reply(raw :: Bytes!String) -> Bytes!String do
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(value)
  end
end

fn native_protected_reply(raw :: Result<Plaintext<Bytes>, String>) -> Result<Plaintext<Bytes>, String> do
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(value)
  end
end

fn native_backup_create_content(request :: BackupNativeContentCreateRequest) -> Bytes!String do
  let selection = for item in request.selection do
    D4BackupSelection {
      kind: item.kind,
      scope_id: item.scope_id,
      from_time: item.from_time,
      through_time: item.through_time
    }
  end
  let raw = create_pending_content_backup_export(request.action.database_path,
    request.action.expected_profile,
    selection,
    request.policy)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(created) -> native_public_reply(encode_backup_pending_create_reply(created.draft_id,
      created.wire,
      created.recovery_code))
  end
end

pub fn native_backup_create(input :: Bytes) -> Bytes!String do
  case parse_backup_content_create_request(input) do
    Ok(request) -> return native_backup_create_content(request)
    Err(_) -> nil
  end
  let request = parse_backup_create_request(input)?
  let selection = for item in request.selection do
    D4BackupSelection {
      kind: item.kind,
      scope_id: item.scope_id,
      from_time: item.from_time,
      through_time: item.through_time
    }
  end
  let raw = create_pending_backup_export(request.action.database_path,
    request.action.expected_profile,
    selection)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(created) -> native_public_reply(encode_backup_pending_create_reply(created.draft_id,
      created.wire,
      created.recovery_code))
  end
end

pub fn native_backup_import(input :: Bytes) -> Bytes!String do
  let request = parse_backup_import_request(input)?
  let raw = import_backup_archive(request.action.database_path,
    request.action.expected_profile,
    request.wire,
    request.recovery_code,
    request.confirmed_backup_id)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(receipt) -> native_public_reply(encode_backup_import_reply(receipt.backup_id,
      receipt.disposition))
  end
end

pub fn native_backup_remove(input :: Bytes) -> Bytes!String do
  let request = parse_backup_remove_request(input)?
  let raw = remove_backup_archive(request.action.database_path,
    request.action.expected_profile,
    request.backup_id)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(_) -> native_public_reply(encode_backup_remove_reply(request.backup_id))
  end
end

pub fn native_backup_preview(input :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let request = parse_backup_preview_request(input)?
  let raw = preview_backup_archive_native_overview(request.action.database_path,
    request.action.expected_profile,
    request.wire,
    request.recovery_code)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(value) -> native_protected_reply(encode_backup_readonly_overview(value))
  end
end

pub fn native_backup_list(input :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let request = parse_backup_list_request(input)?
  let raw = list_backup_archives(request.database_path, request.expected_profile)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(items) -> do
      let summaries = for item in items do
        BackupNativeSummary { backup_id: item.backup_id, created_at: item.created_at }
      end
      native_protected_reply(encode_backup_list_reply(summaries))
    end
  end
end

pub fn native_backup_overview(input :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let request = parse_backup_overview_request(input)?
  let raw = read_backup_archive_native_overview(request.action.database_path,
    request.action.expected_profile,
    request.backup_id)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(value) -> native_protected_reply(encode_backup_readonly_overview(value))
  end
end

pub fn native_backup_page(input :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let request = parse_backup_view_request(input)?
  let raw = read_backup_archive_native_page(request.action.database_path,
    request.action.expected_profile,
    request.backup_id,
    request.selection)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(value) -> native_protected_reply(encode_backup_readonly_page(value))
  end
end

pub fn native_backup_pending_state(input :: Bytes) -> Result<Plaintext<Bytes>, String> do
  let request = parse_backup_pending_state_request(input)?
  let raw = pending_backup_export_state(request.database_path, request.expected_profile)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(state) -> do
      let projection :: Plaintext<BackupNativePendingState> = BackupNativePendingState {
        kind: state.kind,
        draft_id: state.draft_id,
        created_at: state.created_at,
        wire_size: state.wire_size
      }
      native_protected_reply(encode_backup_pending_state_reply(projection))
    end
  end
end

pub fn native_backup_pending_resume(input :: Bytes) -> Bytes!String do
  let request = parse_backup_pending_resume_request(input)?
  let raw = resume_pending_backup_export(request.action.database_path,
    request.action.expected_profile,
    request.draft_id,
    request.recovery_code)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(wire) -> native_public_reply(encode_backup_pending_resume_reply(wire))
  end
end

pub fn native_backup_pending_discard(input :: Bytes) -> Bytes!String do
  let request = parse_backup_pending_discard_request(input)?
  let raw = discard_pending_backup_export(request.action.database_path,
    request.action.expected_profile,
    request.draft_id)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(disposition) -> native_public_reply(encode_backup_pending_discard_reply(request.draft_id,
      disposition))
  end
end

pub fn native_backup_pending_repair(input :: Bytes) -> Bytes!String do
  let request = parse_backup_pending_repair_request(input)?
  let raw = repair_pending_backup_export(request.database_path, request.expected_profile)
  case raw do
    Err(_) -> Err("backup_operation_refused")
    Ok(disposition) -> native_public_reply(encode_backup_pending_repair_reply(disposition))
  end
end

# BEGIN BACKUP_VIEW_CODEC_ADDITION_V1
from Mobile.BackupArchiveViewDispatch import (
  BackupReadonlyPageRequest,
  BackupReadonlyOverview,
  BackupReadonlyPage
)
from Mobile.BackupArchiveContentView import (
  BackupContentOverview,
  BackupContentPage,
  BackupContentChunk,
  BackupContentChunkRequest,
  BackupContentRecordView,
  BackupContentAttachmentView
)
from Backups.ContentArchive import BackupAttachmentPolicy, BackupAttachmentOmission
from Mobile.BackupArchiveReader import (
  read_backup_archive_native_overview,
  read_backup_archive_native_page,
  preview_backup_archive_native_overview
)

pub struct BackupNativeViewRequest do
  action :: BackupNativeAction
  backup_id :: Bytes
  selection :: BackupReadonlyPageRequest
end

pub fn parse_backup_view_request(input :: Bytes) -> BackupNativeViewRequest!String do
  let base = native_base(input, 40313)?
  let id = native_fixed(base.state, 32)?
  let tag = native_fixed(id.state, 1)?
  let kind = native_byte(tag.value)?
  if kind == 1 || kind == 2 do
    let old = parse_backup_page_request(input)?
    return Ok(BackupNativeViewRequest {
      action: old.action,
      backup_id: old.backup_id,
      selection: ReadonlyMessagePage(old.page)
    })
  end
  if kind != 3 && kind != 4 do
    return Err("invalid_backup_native_request")
  end
  let token = native_vector(tag.state, 32)?
  let ordinal = native_fixed(token.state, 1)?
  let slot = native_fixed(ordinal.state, 1)?
  let chunk = native_fixed(slot.state, 1)?
  native_finish(chunk.state)?
  let slot_value = native_byte(slot.value)?
  if Bytes.length(token.value) != 32 || slot_value > 9 do
    return Err("invalid_backup_native_request")
  end
  Ok(BackupNativeViewRequest {
    action: base.action,
    backup_id: id.value,
    selection: ReadonlyFileChunk(BackupContentChunkRequest {
      kind: kind - 2,
      token: token.value,
      ordinal: native_byte(ordinal.value)?,
      slot_index: slot_value,
      chunk_index: native_byte(chunk.value)?
    })
  })
end

fn content_reply_policy(value :: BackupAttachmentPolicy) -> Int do
  case value do
    RequireArchiveAttachments -> 0
    AllowArchiveAttachmentOmissions -> 1
  end
end

fn content_reply_reason(value :: BackupAttachmentOmission) -> Int do
  case value do
    ArchiveAttachmentUnavailable -> 1
    ArchiveAttachmentExpired -> 2
    ArchiveAttachmentUnsupported -> 3
    ArchiveAttachmentAboveProfile -> 4
  end
end

pub fn encode_backup_content_overview_reply(value :: Plaintext<BackupContentOverview>) -> Result<Plaintext<Bytes>, String> do
  if Bytes.length(value.backup_id) != 32
    || List.length(value.conversations) < 1
    || List.length(value.conversations) > 32
    || value.included_count < 1
    || value.included_count > 4096 do
    return Err("invalid_backup_native_reply")
  end
  let counts = [
    value.included_count,
    value.candidate_count,
    value.omitted_timed,
    value.omitted_unknown,
    value.omitted_nontext,
    value.omitted_empty,
    value.attachment_messages
  ]
  if List.any(counts, fn(count) -> count < 0 || count > 8192 end)
    || value.candidate_count != value.included_count
        + value.omitted_timed
        + value.omitted_unknown
        + value.omitted_nontext
        + value.omitted_empty
    || value.attachment_messages > value.candidate_count
    || List.reduce(value.conversations,
      0,
      fn(total, scope) -> total + scope.message_count end) != value.included_count do
    return Err("invalid_backup_native_reply")
  end
  let files = [
    value.files.total,
    value.files.included,
    value.files.unavailable,
    value.files.expired,
    value.files.unsupported,
    value.files.above_profile
  ]
  let omitted = value.files.unavailable
    + value.files.expired
    + value.files.unsupported
    + value.files.above_profile
  if List.any(files, fn(count) -> count < 0 || count > 4096 end)
    || value.files.total != value.files.included + omitted
    || value.files.total > value.included_count * 10
    || value.files.total > value.attachment_messages * 10
    || (content_reply_policy(value.policy) == 0 && omitted != 0) do
    return Err("invalid_backup_native_reply")
  end
  for index in 0..List.length(value.conversations) do
    let scope = List.get(value.conversations, index)
    if List.any(List.take(value.conversations, index),
      fn(old) -> old.kind == scope.kind && Bytes.secure_equals(old.id, scope.id) end) do
      return Err("invalid_backup_native_reply")
    end
  end
  let scopes = for scope in value.conversations do
    reply_conversation(scope)?
  end
  reply_join([
      reply_byte(2)?,
      reply_list([value.backup_id, reply_u64(value.created_at)?]
        ++ for count in counts do
          reply_u32(count)?
        end
        ++ [
          reply_byte(content_reply_policy(value.policy))?,
          reply_list(for count in files do
            reply_u32(count)?
          end)?,
          reply_list(scopes)?
        ])?
    ],
    8192)
end

fn content_reply_slot(part :: BackupContentAttachmentView, expected :: Int) -> Bytes!String do
  case part do
    ContentAttachmentIncluded(slot, name, mime, size, token) -> do
      if slot != expected
        || slot < 0
        || slot > 9
        || Bytes.length(name) > 255
        || Bytes.length(mime) < 1
        || Bytes.length(mime) > 127
        || size < 1
        || size > 16777216
        || Bytes.length(token) != 32 do
        return Err("invalid_backup_native_reply")
      end
      case Bytes.to_utf8(name) do
        Err(_) -> return Err("invalid_backup_native_reply")
        Ok(_) -> nil
      end
      case Bytes.to_utf8(mime) do
        Err(_) -> return Err("invalid_backup_native_reply")
        Ok(_) -> nil
      end
      reply_list([reply_byte(slot)?, reply_byte(0)?, name, mime, reply_u32(size)?, token])
    end
    ContentAttachmentOmitted(slot, reason) -> do
      if slot != expected || slot < 0 || slot > 9 do
        return Err("invalid_backup_native_reply")
      end
      reply_list([reply_byte(slot)?, reply_byte(content_reply_reason(reason))?])
    end
  end
end

fn content_reply_record(kind :: Int, value :: BackupContentRecordView) -> Bytes!String do
  if value.ordinal < 0
    || value.ordinal > 255
    || (value.direction != 1 && value.direction != 2)
    || Bytes.length(value.sender_account) != 32
    || Bytes.length(value.sender_device) != 16
    || List.length(value.attachments) > 10
    || ((kind == 1) && (Bytes.length(value.message_id) != 16 || Bytes.length(value.text) > 32768))
    || ((kind == 2)
      && ((Bytes.length(value.message_id) != 0 && Bytes.length(value.message_id) != 32)
        || Bytes.length(value.text) > 65346))
    || (Bytes.length(value.text) == 0 && List.length(value.attachments) == 0) do
    return Err("invalid_backup_native_reply")
  end
  case Bytes.to_utf8(value.text) do
    Err(_) -> return Err("invalid_backup_native_reply")
    Ok(_) -> nil
  end
  let slots = for index in 0..List.length(value.attachments) do
    content_reply_slot(List.get(value.attachments, index), index)?
  end
  reply_list([
    reply_u16(value.ordinal)?,
    reply_byte(value.direction)?,
    value.message_id,
    value.sender_account,
    value.sender_device,
    reply_u64(value.timestamp)?,
    value.text,
    reply_list(slots)?
  ])
end

pub fn encode_backup_content_page_reply(value :: Plaintext<BackupContentPage>) -> Result<Plaintext<Bytes>, String> do
  if Bytes.length(value.backup_id) != 32
    || (value.kind != 1 && value.kind != 2)
    || (value.kind == 1 && Bytes.length(value.scope_id) != 16)
    || (value.kind == 2 && Bytes.length(value.scope_id) != 32)
    || value.offset < 0
    || value.offset > 256
    || List.length(value.entries) > 16
    || value.offset + List.length(value.entries) > 256 do
    return Err("invalid_backup_native_reply")
  end
  let next = case value.next_offset do
    None -> reply_byte(0)?
    Some(position) -> do
      if position <= value.offset
        || position > 255
        || position != value.offset + List.length(value.entries) do
        return Err("invalid_backup_native_reply")
      end
      reply_join([reply_byte(1)?, reply_u32(position)?], 5)?
    end
  end
  let text_size = List.reduce(value.entries,
    0,
    fn(total, row) -> total + Bytes.length(row.text) end)
  if text_size > 131072 do
    return Err("invalid_backup_native_reply")
  end
  for index in 0..List.length(value.entries) do
    let row = List.get(value.entries, index)
    if (index > 0 && List.get(value.entries, index - 1).ordinal >= row.ordinal)
      || (Bytes.length(row.message_id) > 0
        && List.any(List.take(value.entries, index),
          fn(old) -> Bytes.secure_equals(old.message_id, row.message_id) end)) do
      return Err("invalid_backup_native_reply")
    end
  end
  let rows = for row in value.entries do
    content_reply_record(value.kind, row)?
  end
  let frame = reply_join([
      reply_byte(2)?,
      reply_byte(0)?,
      reply_list([
        value.backup_id,
        reply_byte(value.kind)?,
        value.scope_id,
        reply_u32(value.offset)?,
        next,
        reply_list(rows)?
      ])?
    ],
    135168)?
  if Bytes.length(frame) != value.encoded_size do
    return Err("invalid_backup_native_reply")
  end
  Ok(frame)
end

pub fn encode_backup_content_chunk_reply(value :: Plaintext<BackupContentChunk>) -> Result<Plaintext<Bytes>, String> do
  if Bytes.length(value.backup_id) != 32
    || (value.kind != 1 && value.kind != 2)
    || (value.kind == 1 && Bytes.length(value.scope_id) != 16)
    || (value.kind == 2 && Bytes.length(value.scope_id) != 32)
    || value.ordinal < 0
    || value.ordinal > 255
    || value.slot_index < 0
    || value.slot_index > 9
    || value.chunk_index < 0
    || value.chunk_index > 255
    || value.total_size < 1
    || value.total_size > 16777216
    || Bytes.length(value.token) != 32 do
    return Err("invalid_backup_native_reply")
  end
  let offset = value.chunk_index * 65536
  if offset >= value.total_size do
    return Err("invalid_backup_native_reply")
  end
  let count = if value.total_size - offset > 65536 do
    65536
  else
    value.total_size - offset
  end
  if Bytes.length(value.bytes) != count do
    return Err("invalid_backup_native_reply")
  end
  reply_join([
      reply_byte(2)?,
      reply_byte(1)?,
      reply_list([
        value.backup_id,
        reply_byte(value.kind)?,
        value.scope_id,
        reply_u16(value.ordinal)?,
        reply_byte(value.slot_index)?,
        reply_byte(value.chunk_index)?,
        reply_u32(value.total_size)?,
        value.token,
        value.bytes
      ])?
    ],
    135168)
end

fn encode_backup_readonly_overview(value :: Plaintext<BackupReadonlyOverview>) -> Result<Plaintext<Bytes>, String> do
  case value do
    ReadonlyTextOverview(legacy) -> encode_backup_overview_reply(legacy)
    ReadonlyContentOverview(content) -> encode_backup_content_overview_reply(content)
  end
end

fn encode_backup_readonly_page(value :: Plaintext<BackupReadonlyPage>) -> Result<Plaintext<Bytes>, String> do
  case value do
    ReadonlyTextPage(legacy) -> encode_backup_page_reply(legacy)
    ReadonlyContentPage(content) -> encode_backup_content_page_reply(content)
    ReadonlyContentChunk(chunk) -> encode_backup_content_chunk_reply(chunk)
  end
end

# END BACKUP_VIEW_CODEC_ADDITION_V1

pub struct BackupNativeContentCreateRequest do
  action :: BackupNativeAction
  selection :: List<BackupNativeSelection>
  policy :: BackupAttachmentPolicy
end

pub fn parse_backup_content_create_request(input :: Bytes) -> BackupNativeContentCreateRequest!String do
  let state = case reader(input, 42004) do
    Err(_) -> return Err("invalid_backup_native_request")
    Ok(value) -> value
  end
  let version = native_fixed(state, 1)?
  let policy = case native_byte(version.value)? do
    2 -> RequireArchiveAttachments
    3 -> AllowArchiveAttachmentOmissions
    _ -> return Err("invalid_backup_native_request")
  end
  let suffix = native_fixed(version.state, Bytes.length(input) - 1)?
  native_finish(suffix.state)?
  let legacy_version = case Bytes.from_list([1]) do
    Err(_) -> return Err("invalid_backup_native_request")
    Ok(value) -> value
  end
  let normalized = case Bytes.concat_many([legacy_version, suffix.value], 42004) do
    Err(_) -> return Err("invalid_backup_native_request")
    Ok(value) -> value
  end
  let parsed = parse_backup_create_request(normalized)?
  Ok(BackupNativeContentCreateRequest {
    action: parsed.action,
    selection: parsed.selection,
    policy: policy
  })
end

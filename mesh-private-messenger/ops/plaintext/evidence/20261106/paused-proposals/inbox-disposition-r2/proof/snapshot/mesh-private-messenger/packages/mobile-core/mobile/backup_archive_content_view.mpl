##! Pure protected MCA1 projections. No account/source/transport authority or display release.
from Backups.ContentArchive import (
  BackupAttachmentPolicy,
  BackupAttachmentOmission,
  BackupArchiveAttachment,
  BackupContentArchive,
  BackupContentScope,
  BackupContentRecord,
  decode_content_archive
)
from Mobile.BackupArchiveView import BackupArchiveConversation, BackupArchivePageRequest
from Protocol.WirePrimitives import protocol_write_length, protocol_write_u16

pub struct BackupContentFileCounts do
  total :: Int
  included :: Int
  unavailable :: Int
  expired :: Int
  unsupported :: Int
  above_profile :: Int
end

pub struct BackupContentOverview do
  backup_id :: Bytes
  created_at :: U64
  policy :: BackupAttachmentPolicy
  included_count :: Int
  candidate_count :: Int
  omitted_timed :: Int
  omitted_unknown :: Int
  omitted_nontext :: Int
  omitted_empty :: Int
  attachment_messages :: Int
  files :: BackupContentFileCounts
  conversations :: List<BackupArchiveConversation>
end

pub type BackupContentAttachmentView do
  ContentAttachmentIncluded(slot :: Int, filename :: Plaintext<Bytes>, mime_type :: Plaintext<Bytes>, size :: Int, token :: Plaintext<Bytes>)
  ContentAttachmentOmitted(slot :: Int, reason :: BackupAttachmentOmission)
end

pub struct BackupContentRecordView do
  ordinal :: Int
  direction :: Int
  message_id :: Bytes
  sender_account :: Bytes
  sender_device :: Bytes
  timestamp :: U64
  text :: Plaintext<Bytes>
  attachments :: List<BackupContentAttachmentView>
end

pub struct BackupContentPage do
  backup_id :: Bytes
  kind :: Int
  scope_id :: Bytes
  offset :: Int
  next_offset :: Option<Int>
  entries :: List<BackupContentRecordView>
  # Internal exact extent for the proposed v2 message frame; not a serialized field.
  encoded_size :: Int
end

pub struct BackupContentChunkRequest do
  kind :: Int
  token :: Bytes
  ordinal :: Int
  slot_index :: Int
  chunk_index :: Int
end

pub struct BackupContentChunk do
  backup_id :: Bytes
  kind :: Int
  scope_id :: Bytes
  ordinal :: Int
  slot_index :: Int
  chunk_index :: Int
  total_size :: Int
  token :: Plaintext<Bytes>
  bytes :: Plaintext<Bytes>
end

struct ContentSelectedFile do
  kind :: Int
  scope_id :: Bytes
  ordinal :: Int
  slot_index :: Int
  token :: Plaintext<Bytes>
  bytes :: Plaintext<Bytes>
end

fn content_decoded(payload :: Plaintext<Bytes>) -> Result<Plaintext<BackupContentArchive>, String> do
  case decode_content_archive(payload) do
    Err(_) -> Err("invalid_backup_content_view")
    Ok(value)
  end
end

fn content_count_part(count :: BackupContentFileCounts,
  part :: BackupArchiveAttachment) -> BackupContentFileCounts do
  case part do
    ArchiveAttachmentIncluded(_, _, _) ->
      %{count | total: count.total + 1, included: count.included + 1}
    ArchiveAttachmentOmitted(reason) -> case reason do
      ArchiveAttachmentUnavailable ->
        %{count | total: count.total + 1, unavailable: count.unavailable + 1}
      ArchiveAttachmentExpired ->
        %{count | total: count.total + 1, expired: count.expired + 1}
      ArchiveAttachmentUnsupported ->
        %{count | total: count.total + 1, unsupported: count.unsupported + 1}
      ArchiveAttachmentAboveProfile ->
        %{count | total: count.total + 1, above_profile: count.above_profile + 1}
    end
  end
end

fn content_file_counts(archive :: BackupContentArchive) -> BackupContentFileCounts do
  List.reduce(archive.scopes,
    BackupContentFileCounts {
      total: 0,
      included: 0,
      unavailable: 0,
      expired: 0,
      unsupported: 0,
      above_profile: 0
    },
    fn(total, scope) -> List.reduce(scope.entries,
      total,
      fn(subtotal, record) -> List.reduce(record.attachments,
        subtotal,
        content_count_part) end) end)
end

pub fn content_archive_overview(payload :: Plaintext<Bytes>) -> Result<Plaintext<BackupContentOverview>, String> do
  let archive = content_decoded(payload)?
  let conversations = for scope in archive.scopes do
    BackupArchiveConversation {
      kind: scope.kind,
      id: scope.id,
      peer: scope.peer,
      name: scope.name,
      message_count: List.length(scope.entries)
    }
  end
  Ok(BackupContentOverview {
    backup_id: archive.backup_id,
    created_at: archive.created_at,
    policy: archive.policy,
    included_count: List.reduce(conversations,
      0,
      fn(count, scope) -> count + scope.message_count end),
    candidate_count: archive.candidate_count,
    omitted_timed: archive.omitted_timed,
    omitted_unknown: archive.omitted_unknown,
    omitted_nontext: archive.omitted_nontext,
    omitted_empty: archive.omitted_empty,
    attachment_messages: archive.attachment_messages,
    files: content_file_counts(archive),
    conversations: conversations
  })
end

fn content_join(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  case Bytes.concat_many(parts, maximum) do
    Err(_) -> Err("invalid_backup_content_view")
    Ok(value)
  end
end

fn content_byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_backup_content_view")
    Ok(bytes)
  end
end

fn content_vector(value :: Bytes) -> Bytes!String do
  let length = case protocol_write_length(Bytes.length(value)) do
    Err(_) -> return Err("invalid_backup_content_view")
    Ok(bytes) -> bytes
  end
  content_join([length, value], 36)
end

fn content_ordinal(value :: Int) -> Bytes!String do
  case protocol_write_u16(value) do
    Err(_) -> Err("invalid_backup_content_view")
    Ok(bytes)
  end
end

# Pure equality/binding only. Actual Core must derive revision_tag once from
# public captured inputs with StorageKey.index_tag before private traversal.
# This function performs no storage-key effect or authority decision.
fn content_slot_token(revision_tag :: Bytes,
  digest :: Plaintext<Bytes>,
  kind :: Int,
  scope_id :: Bytes,
  ordinal :: Int,
  slot :: Int) -> Result<Plaintext<Bytes>, String> do
  let frame = content_join([
      Bytes.from_utf8("morse/backup-view-slot/v1"),
      content_byte(1)?,
      revision_tag,
      digest,
      content_byte(kind)?,
      content_vector(scope_id)?,
      content_ordinal(ordinal)?,
      content_byte(slot)?
    ],
    130)?
  Ok(Crypto.sha256(frame))
end

fn content_selected_scope(scopes :: List<BackupContentScope>,
  request :: BackupArchivePageRequest,
  index :: Int) -> BackupContentScope!String do
  if index >= List.length(scopes) do
    return Err("invalid_backup_content_view")
  end
  let scope = List.get(scopes, index)
  if scope.kind == request.kind && Bytes.secure_equals(scope.id, request.scope_id) do
    Ok(scope)
  else
    content_selected_scope(scopes, request, index + 1)
  end
end

fn content_record_view(scope :: BackupContentScope,
  record :: BackupContentRecord,
  revision_tag :: Bytes,
  digest :: Plaintext<Bytes>) -> BackupContentRecordView!String do
  let parts = for slot in 0..List.length(record.attachments) do
    case List.get(record.attachments, slot) do
      ArchiveAttachmentIncluded(name, mime, bytes) ->
        ContentAttachmentIncluded(slot,
          name,
          mime,
          Bytes.length(bytes),
          content_slot_token(revision_tag, digest, scope.kind, scope.id, record.ordinal, slot)?)
      ArchiveAttachmentOmitted(reason) -> ContentAttachmentOmitted(slot, reason)
    end
  end
  Ok(BackupContentRecordView {
    ordinal: record.ordinal,
    direction: record.direction,
    message_id: record.message_id,
    sender_account: record.sender_account,
    sender_device: record.sender_device,
    timestamp: record.timestamp,
    text: record.text,
    attachments: parts
  })
end

# Exact proposed v2 list framing: L(fields)=8+4*n+sum(field lengths).
# Slot/data byte lengths are UTF8 byte lengths already validated by MCA1.
fn content_slot_extent(part :: BackupContentAttachmentView) -> Int do
  case part do
    ContentAttachmentIncluded(_, name, mime, _, _) -> 70 + Bytes.length(name) + Bytes.length(mime)
    ContentAttachmentOmitted(_, _) -> 18
  end
end

fn content_record_extent(record :: BackupContentRecordView) -> Int do
  99
    + Bytes.length(record.message_id)
    + Bytes.length(record.text)
    + 8
    + 4 * List.length(record.attachments)
    + List.reduce(record.attachments, 0, fn(size, part) -> size + content_slot_extent(part) end)
end

fn content_page_extent(kind :: Int, more :: Bool, count :: Int, records_size :: Int) -> Int do
  (if kind == 1 do
    95
  else
    111
  end)
    + (if more do
      5
    else
      1
    end)
    + 4 * count
    + records_size
end

fn content_finished_page(id :: Bytes,
  scope :: BackupContentScope,
  request :: BackupArchivePageRequest,
  position :: Int,
  entries :: List<BackupContentRecordView>,
  records_size :: Int) -> BackupContentPage!String do
  let more = position < List.length(scope.entries)
  if List.length(entries) == 0 && more do
    return Err("invalid_backup_content_view")
  end
  let size = content_page_extent(scope.kind, more, List.length(entries), records_size)
  if size > 135168 do
    return Err("invalid_backup_content_view")
  end
  Ok(BackupContentPage {
    backup_id: id,
    kind: scope.kind,
    scope_id: scope.id,
    offset: request.offset,
    next_offset: if more do
      Some(position)
    else
      None
    end,
    entries: entries,
    encoded_size: size
  })
end

fn content_collect_page(id :: Bytes,
  scope :: BackupContentScope,
  revision_tag :: Bytes,
  digest :: Plaintext<Bytes>,
  request :: BackupArchivePageRequest,
  position :: Int,
  text_size :: Int,
  records_size :: Int,
  entries :: List<BackupContentRecordView>) -> BackupContentPage!String do
  if position >= List.length(scope.entries) || List.length(entries) >= request.limit do
    return content_finished_page(id, scope, request, position, entries, records_size)
  end
  let original = List.get(scope.entries, position)
  let next_text = text_size + Bytes.length(original.text)
  if next_text > 131072 do
    return content_finished_page(id, scope, request, position, entries, records_size)
  end
  let record = content_record_view(scope, original, revision_tag, digest)?
  let next_records = records_size + content_record_extent(record)
  let next_size = content_page_extent(scope.kind,
    position + 1 < List.length(scope.entries),
    List.length(entries) + 1,
    next_records)
  if next_size > 135168 do
    return content_finished_page(id, scope, request, position, entries, records_size)
  end
  content_collect_page(id,
    scope,
    revision_tag,
    digest,
    request,
    position + 1,
    next_text,
    next_records,
    List.append(entries, record))
end

pub fn content_archive_page(payload :: Plaintext<Bytes>,
  revision_tag :: Bytes,
  request :: BackupArchivePageRequest) -> Result<Plaintext<BackupContentPage>, String> do
  if Bytes.length(revision_tag) != 32
    || (request.kind != 1 && request.kind != 2)
    || (request.kind == 1 && Bytes.length(request.scope_id) != 16)
    || (request.kind == 2 && Bytes.length(request.scope_id) != 32)
    || request.offset < 0
    || request.offset > 256
    || request.limit < 1
    || request.limit > 16 do
    return Err("invalid_backup_content_view")
  end
  let archive = content_decoded(payload)?
  let scope = content_selected_scope(archive.scopes, request, 0)?
  if request.offset > List.length(scope.entries) do
    return Err("invalid_backup_content_view")
  end
  content_collect_page(archive.backup_id,
    scope,
    revision_tag,
    Crypto.sha256(payload),
    request,
    request.offset,
    0,
    0,
    [])
end

fn content_source_record(entries :: List<BackupContentRecord>,
  ordinal :: Int,
  index :: Int) -> Option<BackupContentRecord> do
  if index >= List.length(entries) do
    return None
  end
  let record = List.get(entries, index)
  if record.ordinal == ordinal do
    Some(record)
  else
    content_source_record(entries, ordinal, index + 1)
  end
end

fn content_file_candidate(scope :: BackupContentScope,
  revision_tag :: Bytes,
  digest :: Plaintext<Bytes>,
  request :: BackupContentChunkRequest) -> Result<Option<ContentSelectedFile>, String> do
  if scope.kind != request.kind do
    return Ok(None)
  end
  let record = case content_source_record(scope.entries, request.ordinal, 0) do
    None -> return Ok(None)
    Some(value) -> value
  end
  if request.slot_index >= List.length(record.attachments) do
    return Ok(None)
  end
  case List.get(record.attachments, request.slot_index) do
    ArchiveAttachmentOmitted(_) -> Ok(None)
    ArchiveAttachmentIncluded(_, _, bytes) -> do
      let token = content_slot_token(revision_tag,
        digest,
        scope.kind,
        scope.id,
        record.ordinal,
        request.slot_index)?
      if Bytes.secure_equals(token, request.token) do
        Ok(Some(ContentSelectedFile {
          kind: scope.kind,
          scope_id: scope.id,
          ordinal: record.ordinal,
          slot_index: request.slot_index,
          token: token,
          bytes: bytes
        }))
      else
        Ok(None)
      end
    end
  end
end

fn content_unique_file(scopes :: List<BackupContentScope>,
  revision_tag :: Bytes,
  digest :: Plaintext<Bytes>,
  request :: BackupContentChunkRequest,
  index :: Int,
  found :: Option<ContentSelectedFile>) -> ContentSelectedFile!String do
  if index >= List.length(scopes) do
    return case found do
      None -> Err("invalid_backup_content_view")
      Some(value) -> Ok(value)
    end
  end
  let candidate = content_file_candidate(List.get(scopes, index), revision_tag, digest, request)?
  case candidate do
    None -> content_unique_file(scopes, revision_tag, digest, request, index + 1, found)
    Some(value) -> case found do
      Some(_) -> Err("invalid_backup_content_view")
      None -> content_unique_file(scopes, revision_tag, digest, request, index + 1, Some(value))
    end
  end
end

pub fn content_archive_chunk(payload :: Plaintext<Bytes>,
  revision_tag :: Bytes,
  request :: BackupContentChunkRequest) -> Result<Plaintext<BackupContentChunk>, String> do
  if Bytes.length(revision_tag) != 32
    || Bytes.length(request.token) != 32
    || (request.kind != 1 && request.kind != 2)
    || request.ordinal < 0
    || request.ordinal > 255
    || request.slot_index < 0
    || request.slot_index > 9
    || request.chunk_index < 0
    || request.chunk_index > 255 do
    return Err("invalid_backup_content_view")
  end
  let archive = content_decoded(payload)?
  let selected = content_unique_file(archive.scopes,
    revision_tag,
    Crypto.sha256(payload),
    request,
    0,
    None)?
  let size = Bytes.length(selected.bytes)
  let offset = request.chunk_index * 65536
  if offset >= size do
    return Err("invalid_backup_content_view")
  end
  let count = if size - offset > 65536 do
    65536
  else
    size - offset
  end
  let bytes = case Bytes.slice(selected.bytes, offset, count) do
    Err(_) -> return Err("invalid_backup_content_view")
    Ok(value) -> value
  end
  Ok(BackupContentChunk {
    backup_id: archive.backup_id,
    kind: selected.kind,
    scope_id: selected.scope_id,
    ordinal: selected.ordinal,
    slot_index: selected.slot_index,
    chunk_index: request.chunk_index,
    total_size: size,
    token: selected.token,
    bytes: bytes
  })
end

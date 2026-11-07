##! Protected projections for an already authenticated read-only archive.
from Backups.TextArchive import (
  BackupArchiveRecord,
  BackupArchiveScope,
  BackupTextArchive,
  decode_text_archive
)

pub struct BackupArchiveConversation do
  kind :: Int
  id :: Bytes
  peer :: Bytes
  name :: String
  message_count :: Int
end

pub struct BackupArchiveOverview do
  backup_id :: Bytes
  created_at :: U64
  included_count :: Int
  candidate_count :: Int
  omitted_timed :: Int
  omitted_unknown :: Int
  omitted_nontext :: Int
  omitted_empty :: Int
  attachment_messages :: Int
  conversations :: List<BackupArchiveConversation>
end

pub struct BackupArchivePageRequest do
  kind :: Int
  scope_id :: Bytes
  offset :: Int
  limit :: Int
end

pub struct BackupArchivePage do
  backup_id :: Bytes
  kind :: Int
  scope_id :: Bytes
  offset :: Int
  next_offset :: Option<Int>
  entries :: List<BackupArchiveRecord>
end

pub fn backup_archive_overview(payload :: Plaintext<Bytes>) -> Result<Plaintext<BackupArchiveOverview>, String> do
  let archive = decoded_archive(payload)?
  let conversations = for scope in archive.scopes do
    BackupArchiveConversation {
      kind: scope.kind,
      id: scope.id,
      peer: scope.peer,
      name: scope.name,
      message_count: List.length(scope.entries)
    }
  end
  Ok(BackupArchiveOverview {
    backup_id: archive.backup_id,
    created_at: archive.created_at,
    included_count: List.reduce(conversations,
      0,
      fn(count, item) -> count + item.message_count end),
    candidate_count: archive.candidate_count,
    omitted_timed: archive.omitted_timed,
    omitted_unknown: archive.omitted_unknown,
    omitted_nontext: archive.omitted_nontext,
    omitted_empty: archive.omitted_empty,
    attachment_messages: archive.attachment_messages,
    conversations: conversations
  })
end

pub fn backup_archive_page(payload :: Plaintext<Bytes>,
  request :: BackupArchivePageRequest) -> Result<Plaintext<BackupArchivePage>, String> do
  if (request.kind != 1 && request.kind != 2)
    || (request.kind == 1 && Bytes.length(request.scope_id) != 16)
    || (request.kind == 2 && Bytes.length(request.scope_id) != 32)
    || request.offset < 0
    || request.offset > 256
    || request.limit < 1
    || request.limit > 16 do
    return Err("invalid_backup_page")
  end
  let archive = decoded_archive(payload)?
  let scope = selected_scope(archive.scopes, request, 0)?
  if request.offset > List.length(scope.entries) do
    return Err("invalid_backup_page")
  end
  Ok(collect_page(archive.backup_id, scope, request, request.offset, 0, []))
end

fn decoded_archive(payload :: Plaintext<Bytes>) -> Result<Plaintext<BackupTextArchive>, String> do
  case decode_text_archive(payload) do
    Err(_) -> Err("invalid_backup_archive")
    Ok(archive)
  end
end

fn selected_scope(scopes :: List<BackupArchiveScope>,
  request :: BackupArchivePageRequest,
  index :: Int) -> BackupArchiveScope!String do
  if index >= List.length(scopes) do
    return Err("backup_scope_not_found")
  end
  let scope = List.get(scopes, index)
  if scope.kind == request.kind && Bytes.secure_equals(scope.id, request.scope_id) do
    Ok(scope)
  else
    selected_scope(scopes, request, index + 1)
  end
end

fn finished_page(id :: Bytes,
  scope :: BackupArchiveScope,
  request :: BackupArchivePageRequest,
  position :: Int,
  entries :: List<BackupArchiveRecord>) -> BackupArchivePage do
  BackupArchivePage {
    backup_id: id,
    kind: scope.kind,
    scope_id: scope.id,
    offset: request.offset,
    next_offset: if position < List.length(scope.entries) do
      Some(position)
    else
      None
    end,
    entries: entries
  }
end

fn collect_page(id :: Bytes,
  scope :: BackupArchiveScope,
  request :: BackupArchivePageRequest,
  position :: Int,
  text_bytes :: Int,
  entries :: List<BackupArchiveRecord>) -> BackupArchivePage do
  if position >= List.length(scope.entries) || List.length(entries) >= request.limit do
    return finished_page(id, scope, request, position, entries)
  end
  let record = List.get(scope.entries, position)
  let next_bytes = text_bytes + Bytes.length(record.text)
  if next_bytes > 131072 do
    return finished_page(id, scope, request, position, entries)
  end
  collect_page(id, scope, request, position + 1, next_bytes, List.append(entries, record))
end

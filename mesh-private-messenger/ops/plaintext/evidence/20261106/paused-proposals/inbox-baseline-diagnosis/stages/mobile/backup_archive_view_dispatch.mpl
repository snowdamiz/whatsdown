##! Finite protected archive-view schema dispatch; no authority or release.
from Mobile.BackupArchiveView import (
  BackupArchiveOverview,
  BackupArchivePage,
  BackupArchivePageRequest,
  backup_archive_overview,
  backup_archive_page
)
from Mobile.BackupArchiveContentView import (
  BackupContentOverview,
  BackupContentPage,
  BackupContentChunk,
  BackupContentChunkRequest,
  content_archive_overview,
  content_archive_page,
  content_archive_chunk
)

pub type BackupReadonlyOverview do
  ReadonlyTextOverview(value :: BackupArchiveOverview)
  ReadonlyContentOverview(value :: BackupContentOverview)
end

pub type BackupReadonlyPageRequest do
  ReadonlyMessagePage(value :: BackupArchivePageRequest)
  ReadonlyFileChunk(value :: BackupContentChunkRequest)
end

pub type BackupReadonlyPage do
  ReadonlyTextPage(value :: BackupArchivePage)
  ReadonlyContentPage(value :: BackupContentPage)
  ReadonlyContentChunk(value :: BackupContentChunk)
end

fn readonly_schema(payload :: Plaintext<Bytes>) -> Int!String do
  if Bytes.length(payload) < 4 || Bytes.length(payload) > 16777216 do
    return Err("invalid_backup_view")
  end
  let magic = case Bytes.slice(payload, 0, 4) do
    Err(_) -> return Err("invalid_backup_view")
    Ok(value) -> Bytes.to_hex(value)
  end
  if magic == "014d5441" do
    Ok(1)
  else if magic == "014d4341" do
    Ok(2)
  else
    Err("invalid_backup_view")
  end
end

pub fn backup_readonly_overview(payload :: Plaintext<Bytes>) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  let schema = readonly_schema(payload)?
  if schema == 1 do
    case backup_archive_overview(payload) do
      Err(_) -> Err("invalid_backup_view")
      Ok(value) -> Ok(ReadonlyTextOverview(value))
    end
  else
    case content_archive_overview(payload) do
      Err(_) -> Err("invalid_backup_view")
      Ok(value) -> Ok(ReadonlyContentOverview(value))
    end
  end
end

pub fn backup_readonly_page(payload :: Plaintext<Bytes>,
  revision_tag :: Bytes,
  request :: BackupReadonlyPageRequest) -> Result<Plaintext<BackupReadonlyPage>, String> do
  let schema = readonly_schema(payload)?
  case request do
    ReadonlyMessagePage(selected) -> if schema == 1 do
      case backup_archive_page(payload, selected) do
        Err(_) -> Err("invalid_backup_view")
        Ok(value) -> Ok(ReadonlyTextPage(value))
      end
    else
      case content_archive_page(payload, revision_tag, selected) do
        Err(_) -> Err("invalid_backup_view")
        Ok(value) -> Ok(ReadonlyContentPage(value))
      end
    end
    ReadonlyFileChunk(selected) -> if schema != 2 do
      Err("invalid_backup_view")
    else
      case content_archive_chunk(payload, revision_tag, selected) do
        Err(_) -> Err("invalid_backup_view")
        Ok(value) -> Ok(ReadonlyContentChunk(value))
      end
    end
  end
end

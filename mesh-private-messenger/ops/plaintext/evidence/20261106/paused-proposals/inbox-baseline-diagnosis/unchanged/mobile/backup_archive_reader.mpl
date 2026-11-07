##! Account-guarded reads for the protected archive viewer.
from Mobile.BackupArchive import read_backup_archive, preview_backup_archive
from Mobile.BackupArchiveView import (
  BackupArchiveOverview,
  BackupArchivePage,
  BackupArchivePageRequest,
  backup_archive_overview,
  backup_archive_page
)

pub fn read_backup_archive_overview(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes) -> Result<Plaintext<BackupArchiveOverview>, String> do
  let payload = read_backup_archive(path, expected_profile, backup_id)?
  backup_archive_overview(payload)
end

pub fn read_backup_archive_page(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes,
  request :: BackupArchivePageRequest) -> Result<Plaintext<BackupArchivePage>, String> do
  let payload = read_backup_archive(path, expected_profile, backup_id)?
  backup_archive_page(payload, request)
end

pub fn preview_backup_archive_overview(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  recovery_code :: String) -> Result<Plaintext<BackupArchiveOverview>, String> do
  let payload = preview_backup_archive(path, expected_profile, wire, recovery_code)?
  backup_archive_overview(payload)
end

from Mobile.BackupArchive import (
  read_backup_archive_view_overview,
  read_backup_archive_view_page,
  preview_backup_archive_view_overview
)
from Mobile.BackupArchiveViewDispatch import (
  BackupReadonlyOverview,
  BackupReadonlyPage,
  BackupReadonlyPageRequest
)

pub fn read_backup_archive_native_overview(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  read_backup_archive_view_overview(path, expected_profile, backup_id)
end

pub fn read_backup_archive_native_page(path :: String,
  expected_profile :: Bytes,
  backup_id :: Bytes,
  request :: BackupReadonlyPageRequest) -> Result<Plaintext<BackupReadonlyPage>, String> do
  read_backup_archive_view_page(path, expected_profile, backup_id, request)
end

pub fn preview_backup_archive_native_overview(path :: String,
  expected_profile :: Bytes,
  wire :: Bytes,
  recovery_code :: String) -> Result<Plaintext<BackupReadonlyOverview>, String> do
  preview_backup_archive_view_overview(path, expected_profile, wire, recovery_code)
end

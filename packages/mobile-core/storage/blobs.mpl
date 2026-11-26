from Storage.Keys import platform_key
from Storage.Rows import (
  StorageRowKey,
  storage_insert,
  storage_load,
  storage_open_key,
  storage_prepare,
  storage_put
)

##! Storage.Blobs: the records every module keeps, by label. How and where they
##! are kept is Storage.Rows (local record format 2).

pub fn ensure_schema(database_path :: String) -> Result<(), String> do
  storage_prepare(database_path)
end

# ponytail: each call reads the platform key again, a secure-store read on a
# phone. A caller that holds it and loads in a loop uses Storage.Rows'
# storage_load; cache the label key per process once Mesh can hold one.

pub fn blob_row_key(database :: SqliteConn) -> StorageRowKey!String do
  let wrapping_key = platform_key()?
  storage_open_key(database, wrapping_key)
end

pub fn insert_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result<(), String> do
  storage_insert(database, blob_row_key(database)?, label, blob)
end

pub fn put_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result<(), String> do
  storage_put(database, blob_row_key(database)?, label, blob)
end

pub fn load_blob(database_path :: String, label :: String) -> Bytes!String do
  let wrapping_key = platform_key()?
  storage_load(database_path, label, wrapping_key)
end

##! PostgreSQL metadata and typed row decoding.

from Store.Files import (
  maximum_part_bytes,
  maximum_part_index,
  object_bytes_limit,
  validate_paths
)

pub struct ObjectRecord do
  object_id :: Bytes
  upload_hash :: Bytes
  download_hash :: Bytes
  part_count :: Int
  total_bytes :: Int
  expires_at :: Int
  completed :: Int
end

pub struct PartRecord do
  part_index :: Int
  size :: Int
  content_hash :: Bytes
end

pub fn lock_writer(database :: borrow PgConn) -> Result<(), String> do
  ## ponytail: one object-store writer; use per-object locks when contention matters.
  Pg.query(database, "SELECT pg_advisory_xact_lock(1835365486)", [])?
  Ok(nil)
end

pub fn begin_immediate(database :: borrow PgConn) -> Result<(), String> do
  Pg.begin(database)?
  lock_writer(database)
end

fn schema(database :: borrow PgConn) -> Result<(), String> do
  lock_writer(database)?
  Pg.execute(database,
    "CREATE TABLE IF NOT EXISTS objects (object_id BYTEA PRIMARY KEY CHECK(octet_length(object_id) = 32), grant_hash BYTEA NOT NULL UNIQUE CHECK(octet_length(grant_hash) = 32), upload_hash BYTEA NOT NULL CHECK(octet_length(upload_hash) = 32), download_hash BYTEA NOT NULL CHECK(octet_length(download_hash) = 32), part_count INTEGER NOT NULL CHECK(part_count BETWEEN 1 AND 8193), total_bytes INTEGER NOT NULL DEFAULT 0 CHECK(total_bytes BETWEEN 0 AND 537199106), expires_at BIGINT NOT NULL CHECK(expires_at >= 0), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1)))",
    [])?
  Pg.execute(database,
    "CREATE TABLE IF NOT EXISTS object_parts (object_id BYTEA NOT NULL REFERENCES objects(object_id) ON DELETE CASCADE CHECK(octet_length(object_id) = 32), part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 8192), size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 65608), content_hash BYTEA NOT NULL CHECK(octet_length(content_hash) = 32), PRIMARY KEY (object_id, part_index))",
    [])?
  Pg.execute(database,
    "CREATE INDEX IF NOT EXISTS objects_expiry ON objects (expires_at, object_id)",
    [])?
  # Tables made before large objects carry the 16 MiB bounds; widen them to
  # 512 MiB attachments (8,193 parts, 537,199,106 bytes).
  Pg.execute(database,
    "ALTER TABLE objects DROP CONSTRAINT IF EXISTS objects_part_count_check, DROP CONSTRAINT IF EXISTS objects_total_bytes_check, ADD CONSTRAINT objects_part_count_check CHECK(part_count BETWEEN 1 AND 8193), ADD CONSTRAINT objects_total_bytes_check CHECK(total_bytes BETWEEN 0 AND 537199106)",
    [])?
  Pg.execute(database,
    "ALTER TABLE object_parts DROP CONSTRAINT IF EXISTS object_parts_part_index_check, ADD CONSTRAINT object_parts_part_index_check CHECK(part_index BETWEEN 0 AND 8192)",
    [])?
  Ok(nil)
end

pub fn open_database(url :: String) -> PgConn!String do
  Pg.connect(url)
end

pub fn initialize_database(database_url :: String, root :: String) -> Result<(), String> do
  validate_paths(database_url, root)?
  let database = open_database(database_url)?
  let result = Pg.transaction(database, schema)
  Pg.close(database)
  result
end

pub fn binary_value(row :: Map<String, DbValue>, key :: String) -> Bytes!String do
  case Map.get(row, key) do
    Binary(value) -> Ok(value)
    Text(_) -> Err("invalid object metadata")
    Null -> Err("invalid object metadata")
  end
end

fn integer_value(row :: Map<String, DbValue>, key :: String) -> Int!String do
  case Map.get(row, key) do
    Text(value) -> case String.to_int(value) do
      None -> Err("invalid object metadata")
      Some(parsed) -> Ok(parsed)
    end
    Binary(_) -> Err("invalid object metadata")
    Null -> Err("invalid object metadata")
  end
end

pub fn decode_object(row :: Map<String, DbValue>) -> ObjectRecord!String do
  let value = ObjectRecord {
    object_id: binary_value(row, "object_id")?,
    upload_hash: binary_value(row, "upload_hash")?,
    download_hash: binary_value(row, "download_hash")?,
    part_count: integer_value(row, "part_count")?,
    total_bytes: integer_value(row, "total_bytes")?,
    expires_at: integer_value(row, "expires_at")?,
    completed: integer_value(row, "completed")?
  }
  if Bytes.length(value.object_id) != 32
    || Bytes.length(value.upload_hash) != 32
    || Bytes.length(value.download_hash) != 32
    || value.part_count < 1
    || value.part_count > maximum_part_index() + 1
    || value.total_bytes < 0
    || value.total_bytes > object_bytes_limit(value.part_count)
    || value.expires_at < 0
    || (value.completed != 0 && value.completed != 1) do
    Err("invalid object metadata")
  else
    Ok(value)
  end
end

pub fn decode_part(row :: Map<String, DbValue>) -> PartRecord!String do
  let value = PartRecord {
    part_index: integer_value(row, "part_index")?,
    size: integer_value(row, "size")?,
    content_hash: binary_value(row, "content_hash")?
  }
  if value.part_index < 0
    || value.part_index > maximum_part_index()
    || value.size < 1
    || value.size > maximum_part_bytes()
    || Bytes.length(value.content_hash) != 32 do
    Err("invalid object metadata")
  else
    Ok(value)
  end
end

pub fn find_object(database :: borrow PgConn, object_id :: Bytes) -> Option<ObjectRecord>!String do
  if Bytes.length(object_id) != 32 do
    Ok(None)
  else
    let rows = Pg.query_values(database,
      "SELECT object_id, upload_hash, download_hash, part_count, total_bytes, expires_at, completed FROM objects WHERE object_id = $1",
      [Binary(object_id)])?
    case rows do
      [] -> Ok(None)
      [row] -> Ok(Some(decode_object(row)?))
      _ -> Err("invalid object metadata")
    end
  end
end

pub fn find_part(database :: borrow PgConn,
  object_id :: Bytes,
  part_index :: Int) -> Option<PartRecord>!String do
  let rows = Pg.query_values(database,
    "SELECT part_index, size, content_hash FROM object_parts WHERE object_id = $1 AND part_index = $2",
    [Binary(object_id), Text(Int.to_string(part_index))])?
  case rows do
    [] -> Ok(None)
    [row] -> Ok(Some(decode_part(row)?))
    _ -> Err("invalid object metadata")
  end
end

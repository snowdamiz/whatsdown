import File
from Objects.Grant import ObjectGrantRequest, ObjectGrantResponse, decode_complete, decode_delete, decode_grant, encode_grant_response, verify_grant

pub struct ObjectResult do
  status :: Int
  body :: Bytes
end

struct ObjectRecord do
  object_id :: Bytes
  upload_hash :: Bytes
  download_hash :: Bytes
  part_count :: Int
  total_bytes :: Int
  expires_at :: Int
  completed :: Int
end

struct PartRecord do
  part_index :: Int
  size :: Int
  content_hash :: Bytes
end

fn maximum_part_bytes() -> Int do
  65608
end

fn maximum_object_bytes() -> Int do
  16795830
end

fn response(status :: Int, body :: Bytes) -> ObjectResult do
  ObjectResult {
    status : status,
    body : body
  }
end

fn empty(status :: Int) -> ObjectResult do
  response(status, Bytes.empty())
end

fn valid_root(root :: String) -> Bool do
  String.length(root) > 1 && String.length(root) <= 4096 && String.starts_with(root, "/") && !String.ends_with(root,
  "/") && !String.contains(root, "/../") && !String.ends_with(root, "/..") && !String.contains(root,
  "/./") && !String.ends_with(root, "/.")
end

fn validate_paths(database_path :: String, root :: String) -> Result <(), String > do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 || database_path == ":memory:" || !valid_root(root) || !File.exists(root) do
    Err("invalid object storage configuration")
  else
    case File.size(root) do
      Ok( _) -> Err("object storage root is not a directory")
      Err( _) -> Ok(nil)
    end
  end
end

fn configure(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database, "PRAGMA busy_timeout = 5000", []) ?
  let _ = Sqlite.execute(database, "PRAGMA foreign_keys = ON", []) ?
  let _ = Sqlite.execute(database, "PRAGMA synchronous = FULL", []) ?
  Ok(nil)
end

fn begin_immediate(database :: SqliteConn) -> Result <(), String > do
  case Sqlite.execute(database, "BEGIN IMMEDIATE", []) do
    Err( _) -> Err("object metadata unavailable")
    Ok( _) -> Ok(nil)
  end
end

fn create_current_tables(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database,
  "CREATE TABLE IF NOT EXISTS objects (object_id BLOB PRIMARY KEY CHECK(typeof(object_id) = 'blob' AND length(object_id) = 32), grant_hash BLOB NOT NULL UNIQUE CHECK(typeof(grant_hash) = 'blob' AND length(grant_hash) = 32), upload_hash BLOB NOT NULL CHECK(typeof(upload_hash) = 'blob' AND length(upload_hash) = 32), download_hash BLOB NOT NULL CHECK(typeof(download_hash) = 'blob' AND length(download_hash) = 32), part_count INTEGER NOT NULL CHECK(part_count BETWEEN 1 AND 257), total_bytes INTEGER NOT NULL DEFAULT 0 CHECK(total_bytes BETWEEN 0 AND 16795830), expires_at INTEGER NOT NULL CHECK(expires_at >= 0), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1))) STRICT",
  []) ?
  let _ = Sqlite.execute(database,
  "CREATE TABLE IF NOT EXISTS object_parts (object_id BLOB NOT NULL CHECK(typeof(object_id) = 'blob' AND length(object_id) = 32), part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 256), size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 65608), content_hash BLOB NOT NULL CHECK(typeof(content_hash) = 'blob' AND length(content_hash) = 32), PRIMARY KEY (object_id, part_index), FOREIGN KEY (object_id) REFERENCES objects(object_id) ON DELETE CASCADE) STRICT",
  []) ?
  Ok(nil)
end

fn table_sql(database :: SqliteConn, table_name :: String) -> String ! String do
  let rows = Sqlite.query_values(database,
  "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = ?",
  [Text(table_name)]) ?
  if List.length(rows) != 1 do
    Err("invalid object metadata schema")
  else
    case Map.get(List.head(rows), "sql") do
      Binary( _) -> Err("invalid object metadata schema")
      Null -> Err("invalid object metadata schema")
      Text( value) -> Ok(value)
    end
  end
end

fn ceiling_schema_version(database :: SqliteConn) -> Int ! String do
  let objects = table_sql(database, "objects") ?
  let parts = table_sql(database, "object_parts") ?
  if String.contains(objects, "total_bytes BETWEEN 0 AND 16795830") && String.contains(parts,
  "size BETWEEN 1 AND 65608") do
    Ok(1)
  else if String.contains(objects, "total_bytes BETWEEN 0 AND 16777216") && String.contains(parts,
  "size BETWEEN 1 AND 65576") do
    Ok(0)
  else
    Err("invalid object metadata schema")
  end
end

fn migrate_legacy_ceiling_schema(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database,
  "CREATE TABLE objects_ceiling_migration (object_id BLOB PRIMARY KEY CHECK(typeof(object_id) = 'blob' AND length(object_id) = 32), grant_hash BLOB NOT NULL UNIQUE CHECK(typeof(grant_hash) = 'blob' AND length(grant_hash) = 32), upload_hash BLOB NOT NULL CHECK(typeof(upload_hash) = 'blob' AND length(upload_hash) = 32), download_hash BLOB NOT NULL CHECK(typeof(download_hash) = 'blob' AND length(download_hash) = 32), part_count INTEGER NOT NULL CHECK(part_count BETWEEN 1 AND 257), total_bytes INTEGER NOT NULL DEFAULT 0 CHECK(total_bytes BETWEEN 0 AND 16795830), expires_at INTEGER NOT NULL CHECK(expires_at >= 0), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1))) STRICT",
  []) ?
  let _ = Sqlite.execute(database,
  "CREATE TABLE object_parts_ceiling_migration (object_id BLOB NOT NULL CHECK(typeof(object_id) = 'blob' AND length(object_id) = 32), part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 256), size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 65608), content_hash BLOB NOT NULL CHECK(typeof(content_hash) = 'blob' AND length(content_hash) = 32), PRIMARY KEY (object_id, part_index), FOREIGN KEY (object_id) REFERENCES objects_ceiling_migration(object_id) ON DELETE CASCADE) STRICT",
  []) ?
  let _ = Sqlite.execute(database,
  "INSERT INTO objects_ceiling_migration (object_id, grant_hash, upload_hash, download_hash, part_count, total_bytes, expires_at, completed) SELECT object_id, grant_hash, upload_hash, download_hash, part_count, total_bytes, expires_at, completed FROM objects",
  []) ?
  let _ = Sqlite.execute(database,
  "INSERT INTO object_parts_ceiling_migration (object_id, part_index, size, content_hash) SELECT object_id, part_index, size, content_hash FROM object_parts",
  []) ?
  let _ = Sqlite.execute(database,
  "ALTER TABLE object_parts RENAME TO object_parts_legacy_ceiling",
  []) ?
  let _ = Sqlite.execute(database, "ALTER TABLE objects RENAME TO objects_legacy_ceiling", []) ?
  let _ = Sqlite.execute(database, "ALTER TABLE objects_ceiling_migration RENAME TO objects", []) ?
  let _ = Sqlite.execute(database,
  "ALTER TABLE object_parts_ceiling_migration RENAME TO object_parts",
  []) ?
  let _ = Sqlite.execute(database, "DROP TABLE object_parts_legacy_ceiling", []) ?
  let _ = Sqlite.execute(database, "DROP TABLE objects_legacy_ceiling", []) ?
  Ok(nil)
end

fn ensure_schema_in_transaction(database :: SqliteConn) -> Result <(), String > do
  create_current_tables(database) ?
  let version = ceiling_schema_version(database) ?
  if version == 0 do
    migrate_legacy_ceiling_schema(database) ?
  else if version != 1 do
    Err("invalid object metadata schema") ?
  else
    nil
  end
  let _ = Sqlite.execute(database,
  "CREATE INDEX IF NOT EXISTS objects_expiry ON objects (expires_at, object_id)",
  []) ?
  Ok(nil)
end

fn schema(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database, "PRAGMA journal_mode = WAL", []) ?
  begin_immediate(database) ?
  case ensure_schema_in_transaction(database) do
    Err( error) -> do
      let _ = Sqlite.rollback(database)
      Err(error)
    end
    Ok( _) -> case Sqlite.commit(database) do
      Err( error) -> do
        let _ = Sqlite.rollback(database)
        Err(error)
      end
      Ok( _) -> Ok(nil)
    end
  end
end

fn open_database(path :: String) -> SqliteConn ! String do
  let database = Sqlite.open(path) ?
  case configure(database) do
    Err( _) -> do
      Sqlite.close(database)
      Err("object metadata unavailable")
    end
    Ok( _) -> Ok(database)
  end
end

pub fn initialize(database_path :: String, root :: String) -> Result <(), String > do
  validate_paths(database_path, root) ?
  let database = Sqlite.open(database_path) ?
  let result = case configure(database) do
    Err( error) -> Err(error)
    Ok( _) -> schema(database)
  end
  Sqlite.close(database)
  case result do
    Err( _) -> Err("object metadata unavailable")
    Ok( _) -> Ok(nil)
  end
end

fn binary_value(row :: Map < String, DbValue >, key :: String) -> Bytes ! String do
  case Map.get(row, key) do
    Binary( value) -> Ok(value)
    Text( _) -> Err("invalid object metadata")
    Null -> Err("invalid object metadata")
  end
end

fn integer_value(row :: Map < String, DbValue >, key :: String) -> Int ! String do
  case Map.get(row, key) do
    Text( value) -> case String.to_int(value) do
      None -> Err("invalid object metadata")
      Some( parsed) -> Ok(parsed)
    end
    Binary( _) -> Err("invalid object metadata")
    Null -> Err("invalid object metadata")
  end
end

fn decode_object(row :: Map < String, DbValue >) -> ObjectRecord ! String do
  let value = ObjectRecord {
    object_id : binary_value(row, "object_id") ?,
    upload_hash : binary_value(row, "upload_hash") ?,
    download_hash : binary_value(row, "download_hash") ?,
    part_count : integer_value(row, "part_count") ?,
    total_bytes : integer_value(row, "total_bytes") ?,
    expires_at : integer_value(row, "expires_at") ?,
    completed : integer_value(row, "completed") ?
  }
  if Bytes.length(value.object_id) != 32 || Bytes.length(value.upload_hash) != 32 || Bytes.length(value.download_hash) != 32 || value.part_count < 1 || value.part_count > 257 || value.total_bytes < 0 || value.total_bytes > maximum_object_bytes() || value.expires_at < 0 || (value.completed != 0 && value.completed != 1) do
    Err("invalid object metadata")
  else
    Ok(value)
  end
end

fn decode_part(row :: Map < String, DbValue >) -> PartRecord ! String do
  let value = PartRecord {
    part_index : integer_value(row, "part_index") ?,
    size : integer_value(row, "size") ?,
    content_hash : binary_value(row, "content_hash") ?
  }
  if value.part_index < 0 || value.part_index > 256 || value.size < 1 || value.size > maximum_part_bytes() || Bytes.length(value.content_hash) != 32 do
    Err("invalid object metadata")
  else
    Ok(value)
  end
end

fn find_object(database :: SqliteConn, object_id :: Bytes) -> Option < ObjectRecord > ! String do
  if Bytes.length(object_id) != 32 do
    Ok(None)
  else
    let rows = Sqlite.query_values(database,
    "SELECT object_id, upload_hash, download_hash, part_count, total_bytes, expires_at, completed FROM objects WHERE object_id = ?",
    [Binary(object_id)]) ?
    if List.length(rows) == 0 do
      Ok(None)
    else if List.length(rows) == 1 do
      Ok(Some(decode_object(List.head(rows)) ?))
    else
      Err("invalid object metadata")
    end
  end
end

fn find_part(database :: SqliteConn, object_id :: Bytes, part_index :: Int) -> Option < PartRecord > ! String do
  let rows = Sqlite.query_values(database,
  "SELECT part_index, size, content_hash FROM object_parts WHERE object_id = ? AND part_index = ?",
  [Binary(object_id), Text(Int.to_string(part_index))]) ?
  if List.length(rows) == 0 do
    Ok(None)
  else if List.length(rows) == 1 do
    Ok(Some(decode_part(List.head(rows)) ?))
  else
    Err("invalid object metadata")
  end
end

fn part_path(root :: String, object_id :: Bytes, part_index :: Int) -> String ! String do
  if !valid_root(root) || Bytes.length(object_id) != 32 || part_index < 0 || part_index > 256 do
    Err("invalid object part path")
  else
    Ok(root <> "/" <> Bytes.to_hex(object_id) <> "." <> Int.to_string(part_index))
  end
end

fn remove_file(path :: String) -> Result <(), String > do
  if File.exists(path) do
    File.delete(path)
  else
    Ok(nil)
  end
end

fn write_part_file(path :: String, body :: Bytes) -> Result <(), String > do
  let length = Bytes.length(body)
  if length <= 0 || length > maximum_part_bytes() do
    Err("invalid object part size")
  else if length <= 65536 do
    File.write_bytes(path, 0, body, true)
  else
    File.write_bytes(path, 0, Bytes.slice(body, 0, 65536) ?, true) ?
    File.write_bytes(path, 65536, Bytes.slice(body, 65536, length - 65536) ?, false)
  end
end

fn append_part_tail(head :: Bytes, path :: String, expected_size :: Int) -> Option < Bytes > do
  case File.read_bytes(path, 65536, expected_size - 65536) do
    Err( _) -> None
    Ok( tail) -> if Bytes.length(head) != 65536 || Bytes.length(tail) != expected_size - 65536 do
      None
    else
      case Bytes.concat(head, tail) do
        Err( _) -> None
        Ok( body) -> Some(body)
      end
    end
  end
end

fn read_part_file(path :: String, expected_size :: Int) -> Option < Bytes > do
  if expected_size > 0 && expected_size <= maximum_part_bytes() do
    if expected_size <= 65536 do
      case File.read_bytes(path, 0, expected_size) do
        Err( _) -> None
        Ok( body) -> if Bytes.length(body) == expected_size do
          Some(body)
        else
          None
        end
      end
    else
      case File.read_bytes(path, 0, 65536) do
        Err( _) -> None
        Ok( head) -> append_part_tail(head, path, expected_size)
      end
    end
  else
    None
  end
end

fn upload_authorized(value :: ObjectRecord, capability :: Bytes) -> Bool do
  Bytes.length(capability) == 32 && Bytes.secure_equals(Crypto.sha256(capability),
  value.upload_hash)
end

fn download_authorized(value :: ObjectRecord, capability :: Bytes) -> Bool do
  Bytes.length(capability) == 32 && Bytes.secure_equals(Crypto.sha256(capability),
  value.download_hash)
end

fn grant_open(database :: SqliteConn, body :: Bytes, grant_value :: ObjectGrantRequest) -> ObjectResult ! String do
  let grant_hash = Crypto.sha256(body)
  let existing = Sqlite.query_values(database,
  "SELECT grant_hash FROM objects WHERE object_id = ?",
  [Binary(grant_value.object_id)]) ?
  if List.length(existing) == 1 do
    if Bytes.secure_equals(binary_value(List.head(existing), "grant_hash") ?, grant_hash) do
      Ok(response(200,
      encode_grant_response(ObjectGrantResponse { object_id : grant_value.object_id }) ?))
    else
      Ok(empty(409))
    end
  else if List.length(existing) > 1 do
    Err("invalid object metadata")
  else
    let expires_at = U64.to_int(grant_value.expires_at) ?
    let changed = Sqlite.execute_values(database,
    "INSERT INTO objects (object_id, grant_hash, upload_hash, download_hash, part_count, total_bytes, expires_at, completed) VALUES (?, ?, ?, ?, ?, 0, ?, 0)",
    [Binary(grant_value.object_id), Binary(grant_hash), Binary(Crypto.sha256(grant_value.upload_capability)), Binary(Crypto.sha256(grant_value.download_capability)), Text(Int.to_string(grant_value.part_count)), Text(Int.to_string(expires_at))]) ?
    if changed == 1 do
      Ok(response(201,
      encode_grant_response(ObjectGrantResponse { object_id : grant_value.object_id }) ?))
    else
      Err("object grant collision")
    end
  end
end

pub fn grant(database_path :: String,
root :: String,
body :: Bytes,
now :: U64,
maximum_work_future :: U64,
difficulty :: Int) -> ObjectResult do
  case validate_paths(database_path, root) do
    Err( _) -> empty(500)
    Ok( _) -> case U64.parse("604800000") do
      Err( _) -> empty(500)
      Ok( maximum_object_future) -> case verify_grant(body,
      now,
      maximum_work_future,
      maximum_object_future,
      difficulty) do
        Err( _) -> empty(400)
        Ok( false) -> empty(429)
        Ok( true) -> case decode_grant(body) do
          Err( _) -> empty(400)
          Ok( grant_value) -> case open_database(database_path) do
            Err( _) -> empty(500)
            Ok( database) -> do
              let output = case begin_immediate(database) do
                Err( _) -> empty(500)
                Ok( _) -> case grant_open(database, body, grant_value) do
                  Err( _) -> do
                    let _ = Sqlite.rollback(database)
                    empty(500)
                  end
                  Ok( value) -> case Sqlite.commit(database) do
                    Err( _) -> empty(500)
                    Ok( _) -> value
                  end
                end
              end
              Sqlite.close(database)
              output
            end
          end
        end
      end
    end
  end
end

fn put_open(database :: SqliteConn,
root :: String,
object_id :: Bytes,
part_index :: Int,
capability :: Bytes,
body :: Bytes,
now :: Int) -> ObjectResult ! String do
  case find_object(database, object_id) ? do
    None -> Ok(empty(404))
    Some( object) -> if !upload_authorized(object, capability) do
      Ok(empty(403))
    else if now >= object.expires_at do
      Ok(empty(410))
    else if part_index < 0 || part_index >= object.part_count do
      Ok(empty(404))
    else if object.completed == 1 do
      Ok(empty(409))
    else
      let content_hash = Crypto.sha256(body)
      let path = part_path(root, object_id, part_index) ?
      case find_part(database, object_id, part_index) ? do
        Some( existing) -> if existing.size != Bytes.length(body) || !Bytes.secure_equals(existing.content_hash,
        content_hash) do
          Ok(empty(409))
        else
          case read_part_file(path, existing.size) do
            None -> Err("object part integrity failure")
            Some( stored) -> if Bytes.secure_equals(stored, body) do
              Ok(empty(200))
            else
              Err("object part integrity failure")
            end
          end
        end
        None -> if object.total_bytes + Bytes.length(body) > maximum_object_bytes() do
          Ok(empty(413))
        else
          case write_part_file(path, body) do
            Err( _) -> do
              let _ = remove_file(path)
              Err("object part write failed")
            end
            Ok( _) -> do
              let inserted = Sqlite.execute_values(database,
              "INSERT INTO object_parts (object_id, part_index, size, content_hash) VALUES (?, ?, ?, ?)",
              [Binary(object_id), Text(Int.to_string(part_index)), Text(Int.to_string(Bytes.length(body))), Binary(content_hash)])
              let updated = case inserted do
                Err( error) -> Err(error)
                Ok( _) -> Sqlite.execute_values(database,
                "UPDATE objects SET total_bytes = total_bytes + ? WHERE object_id = ? AND completed = 0 AND total_bytes + ? <= 16795830",
                [Text(Int.to_string(Bytes.length(body))), Binary(object_id), Text(Int.to_string(Bytes.length(body)))])
              end
              case updated do
                Err( _) -> do
                  let _ = remove_file(path)
                  Err("object metadata unavailable")
                end
                Ok( changed) -> if changed != 1 do
                  let _ = remove_file(path)
                  Err("object metadata unavailable")
                else
                  Ok(empty(201))
                end
              end
            end
          end
        end
      end
    end
  end
end

pub fn put_part(database_path :: String,
root :: String,
object_id :: Bytes,
part_index :: Int,
capability :: Bytes,
body :: Bytes,
now :: U64) -> ObjectResult do
  if Bytes.length(body) <= 0 || Bytes.length(body) > maximum_part_bytes() do
    empty(413)
  else
    case validate_paths(database_path, root) do
      Err( _) -> empty(500)
      Ok( _) -> case U64.to_int(now) do
        Err( _) -> empty(400)
        Ok( now_value) -> case open_database(database_path) do
          Err( _) -> empty(500)
          Ok( database) -> do
            let output = case begin_immediate(database) do
              Err( _) -> empty(500)
              Ok( _) -> case put_open(database,
              root,
              object_id,
              part_index,
              capability,
              body,
              now_value) do
                Err( _) -> do
                  let _ = Sqlite.rollback(database)
                  empty(500)
                end
                Ok( value) -> case Sqlite.commit(database) do
                  Err( _) -> do
                    if value.status == 201 do
                      case part_path(root, object_id, part_index) do
                        Err( _) -> nil
                        Ok( path) -> do
                          let _ = remove_file(path)
                          nil
                        end
                      end
                    else
                      nil
                    end
                    empty(500)
                  end
                  Ok( _) -> value
                end
              end
            end
            Sqlite.close(database)
            output
          end
        end
      end
    end
  end
end

fn get_open(database :: SqliteConn,
root :: String,
object_id :: Bytes,
part_index :: Int,
capability :: Bytes,
now :: Int) -> ObjectResult ! String do
  case find_object(database, object_id) ? do
    None -> Ok(empty(404))
    Some( object) -> if !download_authorized(object, capability) do
      Ok(empty(403))
    else if now >= object.expires_at do
      Ok(empty(410))
    else if object.completed != 1 || part_index < 0 || part_index >= object.part_count do
      Ok(empty(409))
    else
      case find_part(database, object_id, part_index) ? do
        None -> Ok(empty(404))
        Some( part) -> case part_path(root, object_id, part_index) do
          Err( _) -> Err("object part integrity failure")
          Ok( path) -> case read_part_file(path, part.size) do
            None -> Err("object part integrity failure")
            Some( body) -> if Bytes.secure_equals(Crypto.sha256(body), part.content_hash) do
              Ok(response(200, body))
            else
              Err("object part integrity failure")
            end
          end
        end
      end
    end
  end
end

pub fn get_part(database_path :: String,
root :: String,
object_id :: Bytes,
part_index :: Int,
capability :: Bytes,
now :: U64) -> ObjectResult do
  case validate_paths(database_path, root) do
    Err( _) -> empty(500)
    Ok( _) -> case U64.to_int(now) do
      Err( _) -> empty(400)
      Ok( now_value) -> case open_database(database_path) do
        Err( _) -> empty(500)
        Ok( database) -> do
          let output = case get_open(database, root, object_id, part_index, capability, now_value) do
            Err( _) -> empty(500)
            Ok( value) -> value
          end
          Sqlite.close(database)
          output
        end
      end
    end
  end
end

fn files_present(rows :: List < Map < String, DbValue > >,
root :: String,
object_id :: Bytes,
part_count :: Int,
index :: Int) -> Bool ! String do
  if index >= part_count do
    Ok(true)
  else if index >= List.length(rows) do
    Ok(false)
  else
    let part = decode_part(List.get(rows, index)) ?
    if part.part_index != index do
      Ok(false)
    else
      let path = part_path(root, object_id, index) ?
      if !File.exists(path) do
        Ok(false)
      else
        case File.size(path) do
          Err( _) -> Ok(false)
          Ok( size) -> if size != part.size do
            Ok(false)
          else
            files_present(rows, root, object_id, part_count, index + 1)
          end
        end
      end
    end
  end
end

fn complete_open(database :: SqliteConn, root :: String, body :: Bytes, now :: Int) -> ObjectResult ! String do
  let control = decode_complete(body) ?
  case find_object(database, control.object_id) ? do
    None -> Ok(empty(404))
    Some( object) -> if !upload_authorized(object, control.capability) do
      Ok(empty(403))
    else if now >= object.expires_at do
      Ok(empty(410))
    else if object.completed == 1 do
      Ok(empty(200))
    else
      let rows = Sqlite.query_values(database,
      "SELECT part_index, size, content_hash FROM object_parts WHERE object_id = ? ORDER BY part_index",
      [Binary(control.object_id)]) ?
      if List.length(rows) != object.part_count || !files_present(rows,
      root,
      control.object_id,
      object.part_count,
      0) ? do
        Ok(empty(409))
      else
        let changed = Sqlite.execute_values(database,
        "UPDATE objects SET completed = 1 WHERE object_id = ? AND completed = 0",
        [Binary(control.object_id)]) ?
        if changed == 1 do
          Ok(empty(200))
        else
          Err("object completion conflict")
        end
      end
    end
  end
end

pub fn complete(database_path :: String, root :: String, body :: Bytes, now :: U64) -> ObjectResult do
  case validate_paths(database_path, root) do
    Err( _) -> empty(500)
    Ok( _) -> case U64.to_int(now) do
      Err( _) -> empty(400)
      Ok( now_value) -> case open_database(database_path) do
        Err( _) -> empty(500)
        Ok( database) -> do
          let output = case begin_immediate(database) do
            Err( _) -> empty(500)
            Ok( _) -> case complete_open(database, root, body, now_value) do
              Err( error) -> do
                let _ = Sqlite.rollback(database)
                if String.contains(error, "object wire") || String.contains(error, "object control") do
                  empty(400)
                else
                  empty(500)
                end
              end
              Ok( value) -> case Sqlite.commit(database) do
                Err( _) -> empty(500)
                Ok( _) -> value
              end
            end
          end
          Sqlite.close(database)
          output
        end
      end
    end
  end
end

fn remove_parts(root :: String, object_id :: Bytes, part_count :: Int, index :: Int) -> Result <(), String > do
  if index >= part_count do
    Ok(nil)
  else
    remove_file(part_path(root, object_id, index) ?) ?
    remove_parts(root, object_id, part_count, index + 1)
  end
end

fn delete_open(database :: SqliteConn, root :: String, body :: Bytes) -> ObjectResult ! String do
  let control = decode_delete(body) ?
  case find_object(database, control.object_id) ? do
    None -> Ok(empty(404))
    Some( object) -> if !upload_authorized(object, control.capability) do
      Ok(empty(403))
    else
      remove_parts(root, control.object_id, object.part_count, 0) ?
      let changed = Sqlite.execute_values(database,
      "DELETE FROM objects WHERE object_id = ?",
      [Binary(control.object_id)]) ?
      if changed == 1 do
        Ok(empty(204))
      else
        Err("object deletion conflict")
      end
    end
  end
end

pub fn delete_object(database_path :: String, root :: String, body :: Bytes, _now :: U64) -> ObjectResult do
  case validate_paths(database_path, root) do
    Err( _) -> empty(500)
    Ok( _) -> case open_database(database_path) do
      Err( _) -> empty(500)
      Ok( database) -> do
        let output = case begin_immediate(database) do
          Err( _) -> empty(500)
          Ok( _) -> case delete_open(database, root, body) do
            Err( error) -> do
              let _ = Sqlite.rollback(database)
              if String.contains(error, "object wire") || String.contains(error, "object control") do
                empty(400)
              else
                empty(500)
              end
            end
            Ok( value) -> case Sqlite.commit(database) do
              Err( _) -> empty(500)
              Ok( _) -> value
            end
          end
        end
        Sqlite.close(database)
        output
      end
    end
  end
end

fn purge_rows(database :: SqliteConn,
root :: String,
rows :: List < Map < String, DbValue > >,
now :: Int,
index :: Int) -> Int ! String do
  if index >= List.length(rows) do
    Ok(index)
  else
    let object = decode_object(List.get(rows, index)) ?
    remove_parts(root, object.object_id, object.part_count, 0) ?
    let changed = Sqlite.execute_values(database,
    "DELETE FROM objects WHERE object_id = ? AND expires_at <= ?",
    [Binary(object.object_id), Text(Int.to_string(now))]) ?
    if changed != 1 do
      Err("object purge conflict")
    else
      purge_rows(database, root, rows, now, index + 1)
    end
  end
end

pub fn purge_expired(database_path :: String, root :: String, now :: U64, limit :: Int) -> Int ! String do
  validate_paths(database_path, root) ?
  if limit <= 0 || limit > 32 do
    Err("invalid object purge limit")
  else
    let now_value = U64.to_int(now) ?
    let database = open_database(database_path) ?
    let result = case begin_immediate(database) do
      Err( error) -> Err(error)
      Ok( _) -> case Sqlite.query_values(database,
      "SELECT object_id, upload_hash, download_hash, part_count, total_bytes, expires_at, completed FROM objects WHERE expires_at <= ? ORDER BY expires_at, object_id LIMIT ?",
      [Text(Int.to_string(now_value)), Text(Int.to_string(limit))]) do
        Err( error) -> do
          let _ = Sqlite.rollback(database)
          Err(error)
        end
        Ok( rows) -> case purge_rows(database, root, rows, now_value, 0) do
          Err( error) -> do
            let _ = Sqlite.rollback(database)
            Err(error)
          end
          Ok( count) -> case Sqlite.commit(database) do
            Err( _) -> Err("object purge commit failed")
            Ok( _) -> Ok(count)
          end
        end
      end
    end
    Sqlite.close(database)
    case result do
      Err( _) -> Err("object purge failed")
      Ok( count) -> Ok(count)
    end
  end
end

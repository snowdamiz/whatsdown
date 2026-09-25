import Store.Database
import RuntimeJobs
from Store.Database import ObjectRecord, PartRecord, begin_immediate, binary_value, decode_object, decode_part, find_object, find_part, open_database
from Store.Files import maximum_object_bytes, maximum_part_bytes, part_path, read_part_file, remove_file, remove_parts, validate_paths, write_part_file
from Objects.Grant import ObjectGrantRequest, ObjectGrantResponse, decode_complete, decode_delete, decode_grant, encode_grant_response, verify_grant

pub struct ObjectResult do
  status :: Int
  body :: Bytes
end

fn response(status :: Int, body :: Bytes) -> ObjectResult do
  ObjectResult { status: status, body: body }
end

fn empty(status :: Int) -> ObjectResult do
  response(status, Bytes.empty())
end

fn upload_authorized(value :: ObjectRecord, capability :: Bytes) -> Bool do
  Bytes.length(capability) == 32 && Bytes.secure_equals(Crypto.sha256(capability),
    value.upload_hash)
end

fn download_authorized(value :: ObjectRecord, capability :: Bytes) -> Bool do
  Bytes.length(capability) == 32 && Bytes.secure_equals(Crypto.sha256(capability),
    value.download_hash)
end

fn grant_open(database :: borrow PgConn, body :: Bytes, grant_value :: ObjectGrantRequest) -> ObjectResult!String do
  let grant_hash = Crypto.sha256(body)
  let existing = Pg.query_values(database,
    "SELECT grant_hash FROM objects WHERE object_id = $1",
    [Binary(grant_value.object_id)])?
  if List.length(existing) == 1 do
    if Bytes.secure_equals(binary_value(List.head(existing), "grant_hash")?, grant_hash) do
      Ok(response(200,
        encode_grant_response(ObjectGrantResponse { object_id: grant_value.object_id })?))
    else
      Ok(empty(409))
    end
  else if List.length(existing) > 1 do
    Err("invalid object metadata")
  else
    let expires_at = U64.to_int(grant_value.expires_at)?
    let changed = Pg.execute_values(database,
      "INSERT INTO objects (object_id, grant_hash, upload_hash, download_hash, part_count, total_bytes, expires_at, completed) VALUES ($1, $2, $3, $4, $5, 0, $6, 0)",
      [
        Binary(grant_value.object_id),
        Binary(grant_hash),
        Binary(Crypto.sha256(grant_value.upload_capability)),
        Binary(Crypto.sha256(grant_value.download_capability)),
        Text(Int.to_string(grant_value.part_count)),
        Text(Int.to_string(expires_at))
      ])?
    if changed == 1 do
      RuntimeJobs.notify(database, "objects")?
      Ok(response(201,
        encode_grant_response(ObjectGrantResponse { object_id: grant_value.object_id })?))
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
    Err(_) -> empty(500)
    Ok(_) -> case verified_grant(body, now, maximum_work_future, difficulty) do
      Err(status) -> empty(status)
      Ok(value) -> case open_transaction(database_path) do
        Err(_) -> empty(500)
        Ok(database) -> do
          let result = grant_open(database, body, value)
          operation_response(finish_database(database, result))
        end
      end
    end
  end
end

fn replay_part(path :: String, size :: Int, body :: Bytes) -> ObjectResult!String do
  case read_part_file(path, size) do
    None -> Err("object part integrity failure")
    Some(stored) -> if Bytes.secure_equals(stored, body) do
      Ok(empty(200))
    else
      Err("object part integrity failure")
    end
  end
end

fn store_part(database :: borrow PgConn,
  path :: String,
  object_id :: Bytes,
  part_index :: Int,
  body :: Bytes,
  content_hash :: Bytes) -> ObjectResult!String do
  case write_part_file(path, body) do
    ## Failed or uncertain transactions leave parts for exact replay;
    ## the R2 lifecycle eventually removes unreferenced parts.
    Err(_) -> do
      Err("object part write failed")
    end
    Ok(_) -> do
      let inserted = Pg.execute_values(database,
        "INSERT INTO object_parts (object_id, part_index, size, content_hash) VALUES ($1, $2, $3, $4)",
        [
          Binary(object_id),
          Text(Int.to_string(part_index)),
          Text(Int.to_string(Bytes.length(body))),
          Binary(content_hash)
        ])
      let updated = case inserted do
        Err(error)
        Ok(_) -> Pg.execute_values(database,
          "UPDATE objects SET total_bytes = total_bytes + $1 WHERE object_id = $2 AND completed = 0 AND total_bytes + $3 <= 16795830",
          [
            Text(Int.to_string(Bytes.length(body))),
            Binary(object_id),
            Text(Int.to_string(Bytes.length(body)))
          ])
      end
      case updated do
        Err(_) -> do
          Err("object metadata unavailable")
        end
        Ok(changed) -> if changed != 1 do
          Err("object metadata unavailable")
        else
          Ok(empty(201))
        end
      end
    end
  end
end

fn put_open(database :: borrow PgConn,
  root :: String,
  object_id :: Bytes,
  part_index :: Int,
  capability :: Bytes,
  body :: Bytes,
  now :: Int) -> ObjectResult!String do
  case find_object(database, object_id)? do
    None -> Ok(empty(404))
    Some(object) -> if !upload_authorized(object, capability) do
      Ok(empty(403))
    else if now >= object.expires_at do
      Ok(empty(410))
    else if part_index < 0 || part_index >= object.part_count do
      Ok(empty(404))
    else if object.completed == 1 do
      Ok(empty(409))
    else
      let content_hash = Crypto.sha256(body)
      let path = part_path(root, object_id, part_index)?
      case find_part(database, object_id, part_index)? do
        Some(existing) -> if existing.size != Bytes.length(body) || !Bytes.secure_equals(existing.content_hash,
          content_hash) do
          Ok(empty(409))
        else
          replay_part(path, existing.size, body)
        end
        None -> if object.total_bytes + Bytes.length(body) > maximum_object_bytes() do
          Ok(empty(413))
        else
          store_part(database, path, object_id, part_index, body, content_hash)
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
    return empty(413)
  end
  case validate_paths(database_path, root) do
    Err(_) -> empty(500)
    Ok(_) -> case U64.to_int(now) do
      Err(_) -> empty(400)
      Ok(timestamp) -> case open_transaction(database_path) do
        Err(_) -> empty(500)
        Ok(database) -> do
          let result = put_open(database, root, object_id, part_index, capability, body, timestamp)
          operation_response(finish_database(database, result))
        end
      end
    end
  end
end

fn read_part(root :: String, object_id :: Bytes, part_index :: Int, part :: PartRecord) -> ObjectResult!String do
  case part_path(root, object_id, part_index) do
    Err(_) -> Err("object part integrity failure")
    Ok(path) -> case read_part_file(path, part.size) do
      None -> Err("object part integrity failure")
      Some(body) -> if Bytes.secure_equals(Crypto.sha256(body), part.content_hash) do
        Ok(response(200, body))
      else
        Err("object part integrity failure")
      end
    end
  end
end

fn get_open(database :: borrow PgConn,
  root :: String,
  object_id :: Bytes,
  part_index :: Int,
  capability :: Bytes,
  now :: Int) -> ObjectResult!String do
  case find_object(database, object_id)? do
    None -> Ok(empty(404))
    Some(object) -> if !download_authorized(object, capability) do
      Ok(empty(403))
    else if now >= object.expires_at do
      Ok(empty(410))
    else if object.completed != 1 || part_index < 0 || part_index >= object.part_count do
      Ok(empty(409))
    else
      case find_part(database, object_id, part_index)? do
        None -> Ok(empty(404))
        Some(part) -> read_part(root, object_id, part_index, part)
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
    Err(_) -> empty(500)
    Ok(_) -> case U64.to_int(now) do
      Err(_) -> empty(400)
      Ok(timestamp) -> case open_transaction(database_path) do
        Err(_) -> empty(500)
        Ok(database) -> do
          let result = get_open(database, root, object_id, part_index, capability, timestamp)
          operation_response(finish_database(database, result))
        end
      end
    end
  end
end

fn files_present(rows :: List<Map<String, DbValue>>,
  root :: String,
  object_id :: Bytes,
  part_count :: Int,
  index :: Int) -> Bool!String do
  if index >= part_count do
    Ok(true)
  else if index >= List.length(rows) do
    Ok(false)
  else
    let part = decode_part(List.get(rows, index))?
    if part.part_index != index do
      Ok(false)
    else
      let path = part_path(root, object_id, index)?
      case read_part_file(path, part.size) do
        None -> Ok(false)
        Some(body) -> if !Bytes.secure_equals(Crypto.sha256(body), part.content_hash) do
          Ok(false)
        else
          files_present(rows, root, object_id, part_count, index + 1)
        end
      end
    end
  end
end

fn complete_open(database :: borrow PgConn, root :: String, body :: Bytes, now :: Int) -> ObjectResult!String do
  let control = decode_complete(body)?
  case find_object(database, control.object_id)? do
    None -> Ok(empty(404))
    Some(object) -> if !upload_authorized(object, control.capability) do
      Ok(empty(403))
    else if now >= object.expires_at do
      Ok(empty(410))
    else if object.completed == 1 do
      Ok(empty(200))
    else
      let rows = Pg.query_values(database,
        "SELECT part_index, size, content_hash FROM object_parts WHERE object_id = $1 ORDER BY part_index",
        [Binary(control.object_id)])?
      if List.length(rows) != object.part_count || !files_present(rows,
        root,
        control.object_id,
        object.part_count,
        0)? do
        Ok(empty(409))
      else
        let changed = Pg.execute_values(database,
          "UPDATE objects SET completed = 1 WHERE object_id = $1 AND completed = 0",
          [Binary(control.object_id)])?
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
    Err(_) -> empty(500)
    Ok(_) -> case U64.to_int(now) do
      Err(_) -> empty(400)
      Ok(timestamp) -> case open_transaction(database_path) do
        Err(_) -> empty(500)
        Ok(database) -> do
          let result = complete_open(database, root, body, timestamp)
          control_response(finish_database(database, result))
        end
      end
    end
  end
end

fn delete_open(database :: borrow PgConn, root :: String, body :: Bytes) -> ObjectResult!String do
  let control = decode_delete(body)?
  case find_object(database, control.object_id)? do
    None -> Ok(empty(404))
    Some(object) -> if !upload_authorized(object, control.capability) do
      Ok(empty(403))
    else
      remove_parts(root, control.object_id, object.part_count, 0)?
      let changed = Pg.execute_values(database,
        "DELETE FROM objects WHERE object_id = $1",
        [Binary(control.object_id)])?
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
    Err(_) -> empty(500)
    Ok(_) -> case open_transaction(database_path) do
      Err(_) -> empty(500)
      Ok(database) -> do
        let result = delete_open(database, root, body)
        control_response(finish_database(database, result))
      end
    end
  end
end

fn purge_rows(database :: borrow PgConn,
  root :: String,
  rows :: List<Map<String, DbValue>>,
  now :: Int,
  index :: Int) -> Int!String do
  if index >= List.length(rows) do
    Ok(index)
  else
    let object = decode_object(List.get(rows, index))?
    remove_parts(root, object.object_id, object.part_count, 0)?
    let changed = Pg.execute_values(database,
      "DELETE FROM objects WHERE object_id = $1 AND expires_at <= $2",
      [Binary(object.object_id), Text(Int.to_string(now))])?
    if changed != 1 do
      Err("object purge conflict")
    else
      purge_rows(database, root, rows, now, index + 1)
    end
  end
end

pub fn purge_expired(database_path :: String, root :: String, now :: U64, limit :: Int) -> Int!String do
  validate_paths(database_path, root)?
  if limit <= 0 || limit > 32 do
    return Err("invalid object purge limit")
  end
  let now_value = U64.to_int(now)?
  let database = open_database(database_path)?
  let result = case begin_immediate(database) do
    Err(error)
    Ok(_) -> case Pg.query_values(database,
      "SELECT object_id, upload_hash, download_hash, part_count, total_bytes, expires_at, completed FROM objects WHERE expires_at <= $1 ORDER BY expires_at, object_id LIMIT $2",
      [Text(Int.to_string(now_value)), Text(Int.to_string(limit))]) do
      Err(error) -> do
        Pg.rollback(database)
        Err(error)
      end
      Ok(rows) -> case purge_rows(database, root, rows, now_value, 0) do
        Err(error) -> do
          Pg.rollback(database)
          Err(error)
        end
        Ok(count) -> case Pg.commit(database) do
          Err(_) -> Err("object purge commit failed")
          Ok(_) -> Ok(count)
        end
      end
    end
  end
  Pg.close(database)
  case result do
    Err(_) -> Err("object purge failed")
    Ok(count)
  end
end

pub fn initialize(database_path :: String, root :: String) -> Result<(), String> do
  Database.initialize_database(database_path, root)
end

pub fn transaction_in_progress(path :: String, id :: String) -> Bool!String do
  let database = open_database(path)?
  let result = RuntimeJobs.in_progress(database, id)
  Pg.close(database)
  result
end

pub fn next_expiry(path :: String) -> Int!String do
  let database = open_database(path)?
  let rows = Pg.query(database, "SELECT COALESCE(min(expires_at), 0)::text AS due FROM objects", [])
  Pg.close(database)
  RuntimeJobs.due_time(rows?)
end

fn operation_response(result :: Result<ObjectResult, String>) -> ObjectResult do
  case result do
    Err(_) -> empty(500)
    Ok(value) -> value
  end
end

fn control_response(result :: Result<ObjectResult, String>) -> ObjectResult do
  case result do
    Err(error) -> if String.contains(error, "object wire") || String.contains(error,
      "object control") do
      empty(400)
    else
      empty(500)
    end
    Ok(value) -> value
  end
end

fn verified_grant(body :: Bytes, now :: U64, maximum_work_future :: U64, difficulty :: Int) -> ObjectGrantRequest!Int do
  let maximum_object_future = case U64.parse("604800000") do
    Err(_) -> Err(500)
    Ok(value)
  end?
  case verify_grant(body, now, maximum_work_future, maximum_object_future, difficulty) do
    Err(_) -> Err(400)
    Ok(false) -> Err(429)
    Ok(true) -> Ok(nil)
  end?
  case decode_grant(body) do
    Err(_) -> Err(400)
    Ok(value)
  end
end

fn open_transaction(path :: String) -> PgConn!String do
  let database = open_database(path)?
  case begin_immediate(database) do
    Err(error) -> do
      Pg.close(database)
      Err(error)
    end
    Ok(_) -> Ok(database)
  end
end

fn finish_database(database :: PgConn, result :: Result<ObjectResult, String>) -> ObjectResult!String do
  let committed = case result do
    Err(error) -> do
      Pg.rollback(database)
      Err(error)
    end
    Ok(value) -> case Pg.commit(database) do
      Err(_) -> Err("object metadata commit unavailable")
      Ok(_) -> Ok(value)
    end
  end
  Pg.close(database)
  committed
end

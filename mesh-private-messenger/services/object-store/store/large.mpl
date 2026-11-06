from Store.Database import open_database, begin_immediate, binary_value
from Store.Files import (
  validate_paths,
  read_part_file,
  write_part_file,
  remove_file
)
from Attachments.Layout import (
  large_attachment_chunks,
  large_attachment_total_bytes,
  bucketed_large_attachment_chunks,
  bucketed_large_attachment_total_bytes
)
from Attachments.Protocol import validate_large_attachment_part, validate_bucketed_attachment_part
from Credits.ActionWire import decode_credit_action_submission, decode_credit_action_receipt
from Credits.Attachment import (
  decode_credit_attachment_grant,
  decode_credit_attachment_result,
  credit_attachment_result,
  verify_credit_attachment_receipt
)
from Objects.Grant import decode_complete, decode_delete
from Store.Service import ObjectResult
import RuntimeJobs

struct LargeObjectRecord do
  layout_version :: Int
  object_id :: Bytes
  request_hash :: Bytes
  upload_hash :: Bytes
  download_hash :: Bytes
  size_bytes :: Int
  manifest_size :: Int
  manifest_hash :: Bytes
  part_count :: Int
  total_bytes :: Int
  expires_at :: Int
  completed :: Int
  verify_index :: Int
  purge_index :: Int
  deleting :: Int
  receipt :: Bytes
end

fn reply(status :: Int, body :: Bytes) -> ObjectResult do
  ObjectResult { status: status, body: body }
end

fn empty(status :: Int) -> ObjectResult do
  reply(status, Bytes.empty())
end

fn integer(row :: Map<String, DbValue>, key :: String) -> Int!String do
  case Map.get(row, key) do
    Text(value) -> case String.to_int(value) do
      Some(output) -> Ok(output)
      None -> Err("invalid large object metadata")
    end
    _ -> Err("invalid large object metadata")
  end
end

fn decode(row :: Map<String, DbValue>) -> LargeObjectRecord!String do
  let value = LargeObjectRecord {
    layout_version: integer(row, "layout_version")?,
    object_id: binary_value(row, "object_id")?,
    request_hash: binary_value(row, "request_hash")?,
    upload_hash: binary_value(row, "upload_hash")?,
    download_hash: binary_value(row, "download_hash")?,
    size_bytes: integer(row, "plaintext_size")?,
    manifest_size: integer(row, "manifest_size")?,
    manifest_hash: binary_value(row, "manifest_hash")?,
    part_count: integer(row, "part_count")?,
    total_bytes: integer(row, "total_bytes")?,
    expires_at: integer(row, "expires_at")?,
    completed: integer(row, "completed")?,
    verify_index: integer(row, "verify_index")?,
    purge_index: integer(row, "purge_index")?,
    deleting: integer(row, "deleting")?,
    receipt: binary_value(row, "receipt")?
  }
  if value.part_count != record_chunks(value)? + 1
    || value.total_bytes < 0
    || value.total_bytes > record_total(value)?
    || Bytes.length(value.manifest_hash) != 32
    || Bytes.length(value.receipt) != 290
    || value.verify_index < 0
    || value.verify_index > value.part_count
    || (value.completed == 1 && value.verify_index != value.part_count)
    || value.purge_index < 0
    || value.purge_index > value.part_count do
    return Err("invalid large object metadata")
  end
  # The stored grant version is bound to the exact core receipt retained on
  # admission. These are structural checks; initial signature verification is
  # still performed against pinned_core before inserting any object row.
  let receipt = decode_credit_action_receipt(value.receipt)?
  let result = decode_credit_attachment_result(receipt.result)?
  if result.layout_version != value.layout_version
    || !Bytes.secure_equals(result.object_id, value.object_id)
    || result.part_count != value.part_count
    || result.total_bytes != record_total(value)?
    || result.expires_at_ms != U64.parse(Int.to_string(value.expires_at))? do
    return Err("invalid large object metadata")
  end
  Ok(value)
end

fn record_chunks(value :: LargeObjectRecord) -> Int!String do
  if value.layout_version == 1 do
    large_attachment_chunks(value.size_bytes)
  else if value.layout_version == 2 do
    bucketed_large_attachment_chunks(value.size_bytes)
  else
    Err("invalid large object metadata")
  end
end

fn record_total(value :: LargeObjectRecord) -> Int!String do
  if value.layout_version == 1 do
    large_attachment_total_bytes(value.size_bytes, value.manifest_size)
  else if value.layout_version == 2 do
    bucketed_large_attachment_total_bytes(value.size_bytes, value.manifest_size)
  else
    Err("invalid large object metadata")
  end
end

fn find(conn :: borrow PgConn, object_id :: Bytes) -> Option<LargeObjectRecord>!String do
  let rows = Pg.query_values(conn,
    "SELECT * FROM large_objects WHERE object_id = $1",
    [Binary(object_id)])?
  if List.length(rows) == 0 do
    Ok(None)
  else if List.length(rows) == 1 do
    Ok(Some(decode(List.head(rows))?))
  else
    Err("invalid large object metadata")
  end
end

pub fn large_part_path(root :: String, object_id :: Bytes, index :: Int) -> String!String do
  if Bytes.length(object_id) != 32 || index < 0 || index > 8192 do
    return Err("invalid large object path")
  end
  Ok(root <> "/large-" <> Bytes.to_hex(object_id) <> "." <> Int.to_string(index))
end

fn schema(conn :: borrow PgConn) -> Result<(), String> do
  Pg.execute(conn,
    "CREATE TABLE IF NOT EXISTS large_objects (object_id BYTEA PRIMARY KEY CHECK(octet_length(object_id)=32), request_hash BYTEA NOT NULL CHECK(octet_length(request_hash)=32), upload_hash BYTEA NOT NULL CHECK(octet_length(upload_hash)=32), download_hash BYTEA NOT NULL CHECK(octet_length(download_hash)=32), plaintext_size INTEGER NOT NULL CHECK(plaintext_size BETWEEN 16777217 AND 536870912), manifest_size INTEGER NOT NULL CHECK(manifest_size BETWEEN 68 AND 514), manifest_hash BYTEA NOT NULL CHECK(octet_length(manifest_hash)=32), part_count INTEGER NOT NULL CHECK(part_count BETWEEN 258 AND 8193), total_bytes INTEGER NOT NULL DEFAULT 0 CHECK(total_bytes BETWEEN 0 AND 537199106), expires_at BIGINT NOT NULL CHECK(expires_at>0), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0,1)), verify_index INTEGER NOT NULL DEFAULT 0 CHECK(verify_index BETWEEN 0 AND 8193), purge_index INTEGER NOT NULL DEFAULT 0 CHECK(purge_index BETWEEN 0 AND 8193), deleting INTEGER NOT NULL DEFAULT 0 CHECK(deleting IN (0,1)), receipt BYTEA NOT NULL CHECK(octet_length(receipt)=290))",
    [])?
  # Existing rows are exact-size v1. Never rewrite their grants/receipts or
  # reinterpret their values as capacities during this additive schema step.
  Pg.execute(conn,
    "ALTER TABLE large_objects ADD COLUMN IF NOT EXISTS layout_version INTEGER NOT NULL DEFAULT 1 CHECK(layout_version IN (1,2))",
    [])?
  Pg.execute(conn,
    "CREATE TABLE IF NOT EXISTS large_object_parts (object_id BYTEA NOT NULL REFERENCES large_objects(object_id) ON DELETE CASCADE, part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 8192), size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 65576), content_hash BYTEA NOT NULL CHECK(octet_length(content_hash)=32), PRIMARY KEY(object_id,part_index))",
    [])?
  Pg.execute(conn,
    "CREATE INDEX IF NOT EXISTS large_objects_expiry ON large_objects(expires_at,object_id)",
    [])?
  Ok(nil)
end

fn finish(conn :: PgConn, result :: ObjectResult!String) -> ObjectResult do
  let output = case result do
    Err(_) -> do
      Pg.rollback(conn)
      empty(503)
    end
    Ok(value) -> case Pg.commit(conn) do
      Err(_) -> empty(503)
      Ok(_) -> value
    end
  end
  Pg.close(conn)
  output
end

fn transaction(url :: String, root :: String) -> PgConn!String do
  validate_paths(url, root)?
  let conn = open_database(url)?
  case begin_immediate(conn) do
    Err(error) -> do
      Pg.close(conn)
      Err(error)
    end
    Ok(_) -> Ok(conn)
  end
end

pub fn initialize_large(url :: String, root :: String) -> Result<(), String> do
  let conn = transaction(url, root)?
  let result = schema(conn)
  case result do
    Err(error) -> do
      Pg.rollback(conn)
      Pg.close(conn)
      Err(error)
    end
    Ok(_) -> do
      let committed = Pg.commit(conn)
      Pg.close(conn)
      committed
    end
  end
end

fn pinned_core() -> SigningPublicKey!String do
  let encoded = Env.get("MESSENGER_OBJECT_CREDIT_SERVICE_PUBLIC_KEY_HEX", "")
  let key = Bytes.from_hex(encoded)?
  if String.length(encoded) != 64
    || Bytes.to_hex(key) != encoded
    || Bytes.length(key) != 32
    || encoded == String.repeat("00", 32) do
    return Err("large object core pin unavailable")
  end
  Ok(SigningPublicKey { bytes: key })
end

pub fn valid_large_credit_origin(origin :: String) -> Bool do
  if origin == "http://credit-core.internal" do
    return true
  end
  if String.length(origin) > 2048
    || String.contains(origin, "@")
    || String.contains(origin, "?")
    || String.contains(origin, "#")
    || String.contains(origin, "\\")
    || String.contains(origin, "\n")
    || String.contains(origin, "\r") do
    return false
  end
  if String.starts_with(origin, "https://") do
    let host = String.slice(origin, 8, String.length(origin))
    return String.length(host) > 0 && !String.contains(host, "/")
  end
  if !String.starts_with(origin, "http://127.0.0.1:") do
    return false
  end
  let port = String.slice(origin, 17, String.length(origin))
  case String.to_int(port) do
    None -> false
    Some(value) -> value > 0 && value <= 65535 && Int.to_string(value) == port
  end
end

fn core_receipt(body :: Bytes) -> ObjectResult!String do
  let origin = Env.get("MESSENGER_OBJECT_CREDIT_CORE_URL", "")
  let token = Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")
  if !valid_large_credit_origin(origin)
    || (String.length(token) < 32 || String.length(token) > 256) do
    return Err("large object core unavailable")
  end
  let result = Http.build(:post, origin <> "/internal/credits/attachments/grant")
    |> Http.header("Authorization", "Bearer " <> token)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Accept-Encoding", "identity")
    |> Http.body_bytes(body)
    |> Http.timeout(15000)
    |> Http.max_response_bytes(462)
    |> Http.send()
  let response = result?
  Ok(reply(response.status, response.body_bytes))
end

fn grant_open(conn :: borrow PgConn, body :: Bytes, now :: Int) -> ObjectResult!String do
  let submission = decode_credit_action_submission(body)?
  let grant = decode_credit_attachment_grant(submission.request_body)?
  let request_hash = Crypto.sha256(body)
  case find(conn, grant.object_id)? do
    Some(existing) -> if Bytes.secure_equals(existing.request_hash, request_hash) do
      return Ok(reply(200, existing.receipt))
    else
      return Ok(empty(409))
    end
    None -> nil
  end
  let result = core_receipt(body)?
  if result.status != 200 && result.status != 201 do
    return Ok(empty(if result.status == 400 || result.status == 409 do
      result.status
    else
      503
    end))
  end
  verify_credit_attachment_receipt(submission, pinned_core()?, result.body)?
  let expires = U64.to_int(grant.expires_at_ms)?
  if expires <= now do
    return Ok(empty(410))
  end
  Pg.execute_values(conn,
    "INSERT INTO large_objects (object_id,request_hash,upload_hash,download_hash,plaintext_size,manifest_size,manifest_hash,part_count,expires_at,receipt,layout_version) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
    [
      Binary(grant.object_id),
      Binary(request_hash),
      Binary(Crypto.sha256(grant.upload_capability)),
      Binary(Crypto.sha256(grant.download_capability)),
      Text(Int.to_string(grant.size_bytes)),
      Text(Int.to_string(grant.manifest_size)),
      Binary(grant.manifest_sha256),
      Text(Int.to_string(credit_attachment_result(grant)?.part_count)),
      Text(Int.to_string(expires)),
      Binary(result.body),
      Text(Int.to_string(grant.layout_version))
    ])?
  RuntimeJobs.notify(conn, "objects")?
  Ok(reply(201, result.body))
end

pub fn grant_large(url :: String, root :: String, body :: Bytes, now :: U64) -> ObjectResult do
  let timestamp = case U64.to_int(now) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  if Env.get("MORSE_PAID_LARGE_ATTACHMENTS", "off") != "on" do
    return empty(503)
  end
  # Validate before opening a transaction or reaching the privileged core.
  case decode_credit_action_submission(body) do
    Err(_) -> return empty(400)
    Ok(value) -> case decode_credit_attachment_grant(value.request_body) do
      Err(_) -> return empty(400)
      Ok(_) -> nil
    end
  end
  case transaction(url, root) do
    Err(_) -> empty(503)
    Ok(conn) -> do
      let result = grant_open(conn, body, timestamp)
      finish(conn, result)
    end
  end
end

fn authorized(value :: LargeObjectRecord, capability :: Bytes, upload :: Bool) -> Bool do
  Bytes.length(capability) == 32
    && Bytes.secure_equals(Crypto.sha256(capability),
      if upload do
        value.upload_hash
      else
        value.download_hash
      end)
end

fn put_open(conn :: borrow PgConn,
  root :: String,
  id :: Bytes,
  index :: Int,
  capability :: Bytes,
  body :: Bytes,
  now :: Int) -> ObjectResult!String do
  let object = case find(conn, id)? do
    None -> return Ok(empty(404))
    Some(value) -> value
  end
  if !authorized(object, capability, true) do
    return Ok(empty(403))
  end
  if object.deleting == 1 || object.expires_at <= now do
    return Ok(empty(410))
  end
  if index < 0 || index >= object.part_count do
    return Ok(empty(404))
  end
  if object.completed == 1 do
    return Ok(empty(409))
  end
  let valid_result = if object.layout_version == 1 do
    validate_large_attachment_part(id,
      object.size_bytes,
      object.manifest_size,
      object.manifest_hash,
      index,
      body)
  else
    validate_bucketed_attachment_part(id, object.size_bytes, object.manifest_hash, index, body)
  end
  let valid = case valid_result do
    Err(_) -> false
    Ok(value) -> value
  end
  if !valid do
    return Ok(empty(400))
  end
  let path = large_part_path(root, id, index)?
  let rows = Pg.query_values(conn,
    "SELECT size,content_hash FROM large_object_parts WHERE object_id=$1 AND part_index=$2",
    [Binary(id), Text(Int.to_string(index))])?
  let hash = Crypto.sha256(body)
  if List.length(rows) == 1 do
    let previous = List.head(rows)
    if integer(previous, "size")? != Bytes.length(body)
      || !Bytes.secure_equals(binary_value(previous, "content_hash")?, hash) do
      return Ok(empty(409))
    end
    case read_part_file(path, Bytes.length(body)) do
      None -> return Err("large object integrity failure")
      Some(value) -> if !Bytes.secure_equals(value, body) do
        return Err("large object integrity failure")
      end
    end
    return Ok(empty(200))
  end
  if object.total_bytes + Bytes.length(body) > record_total(object)? do
    return Ok(empty(413))
  end
  write_part_file(path, body)?
  Pg.execute_values(conn,
    "INSERT INTO large_object_parts(object_id,part_index,size,content_hash) VALUES($1,$2,$3,$4)",
    [
      Binary(id),
      Text(Int.to_string(index)),
      Text(Int.to_string(Bytes.length(body))),
      Binary(hash)
    ])?
  Pg.execute_values(conn,
    "UPDATE large_objects SET total_bytes=total_bytes+$2 WHERE object_id=$1",
    [Binary(id), Text(Int.to_string(Bytes.length(body)))])?
  Ok(empty(201))
end

pub fn put_large_part(url :: String,
  root :: String,
  id :: Bytes,
  index :: Int,
  capability :: Bytes,
  body :: Bytes,
  now :: U64) -> ObjectResult do
  let timestamp = case U64.to_int(now) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  if Bytes.length(body) < 1 || Bytes.length(body) > 65576 do
    return empty(413)
  end
  case transaction(url, root) do
    Err(_) -> empty(503)
    Ok(conn) -> do
      let result = put_open(conn, root, id, index, capability, body, timestamp)
      finish(conn, result)
    end
  end
end

fn get_open(conn :: borrow PgConn,
  root :: String,
  id :: Bytes,
  index :: Int,
  capability :: Bytes,
  now :: Int) -> ObjectResult!String do
  let object = case find(conn, id)? do
    None -> return Ok(empty(404))
    Some(value) -> value
  end
  if !authorized(object, capability, false) do
    return Ok(empty(403))
  end
  if object.deleting == 1 || object.expires_at <= now do
    return Ok(empty(410))
  end
  if object.completed != 1 || index < 0 || index >= object.part_count do
    return Ok(empty(409))
  end
  let rows = Pg.query_values(conn,
    "SELECT size,content_hash FROM large_object_parts WHERE object_id=$1 AND part_index=$2",
    [Binary(id), Text(Int.to_string(index))])?
  if List.length(rows) != 1 do
    return Ok(empty(404))
  end
  let part = List.head(rows)
  case read_part_file(large_part_path(root, id, index)?, integer(part, "size")?) do
    None -> Err("large object integrity failure")
    Some(value) -> if Bytes.secure_equals(Crypto.sha256(value),
      binary_value(part, "content_hash")?) do
      Ok(reply(200, value))
    else
      Err("large object integrity failure")
    end
  end
end

pub fn get_large_part(url :: String,
  root :: String,
  id :: Bytes,
  index :: Int,
  capability :: Bytes,
  now :: U64) -> ObjectResult do
  let timestamp = case U64.to_int(now) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case transaction(url, root) do
    Err(_) -> empty(503)
    Ok(conn) -> do
      let result = get_open(conn, root, id, index, capability, timestamp)
      finish(conn, result)
    end
  end
end

fn complete_open(conn :: borrow PgConn,
  root :: String,
  body :: Bytes,
  now :: Int) -> ObjectResult!String do
  let control = decode_complete(body)?
  let object = case find(conn, control.object_id)? do
    None -> return Ok(empty(404))
    Some(value) -> value
  end
  if !authorized(object, control.capability, true) do
    return Ok(empty(403))
  end
  if object.deleting == 1 || object.expires_at <= now do
    return Ok(empty(410))
  end
  if object.completed == 1 do
    return Ok(empty(200))
  end
  if object.total_bytes != record_total(object)? do
    return Ok(empty(409))
  end
  let counts = Pg.query_values(conn,
    "SELECT count(*)::text AS count FROM large_object_parts WHERE object_id=$1",
    [Binary(control.object_id)])?
  if List.length(counts) != 1 || integer(List.head(counts), "count")? != object.part_count do
    return Ok(empty(409))
  end
  let stop = if object.verify_index + 128 < object.part_count do
    object.verify_index + 128
  else
    object.part_count
  end
  let rows = Pg.query_values(conn,
    "SELECT part_index,size,content_hash FROM large_object_parts WHERE object_id=$1 AND part_index >= $2 AND part_index < $3 ORDER BY part_index LIMIT 128",
    [
      Binary(control.object_id),
      Text(Int.to_string(object.verify_index)),
      Text(Int.to_string(stop))
    ])?
  if List.length(rows) != stop - object.verify_index do
    return Ok(empty(409))
  end
  for offset in 0..List.length(rows) do
    let index = object.verify_index + offset
    let part = List.get(rows, offset)
    if integer(part, "part_index")? != index do
      return Ok(empty(409))
    end
    let bytes = case read_part_file(large_part_path(root, object.object_id, index)?,
      integer(part, "size")?) do
      None -> return Ok(empty(409))
      Some(value) -> value
    end
    if !Bytes.secure_equals(Crypto.sha256(bytes), binary_value(part, "content_hash")?) do
      return Ok(empty(409))
    end
  end
  Pg.execute_values(conn,
    "UPDATE large_objects SET verify_index=$2,completed=$3 WHERE object_id=$1",
    [
      Binary(object.object_id),
      Text(Int.to_string(stop)),
      Text(if stop == object.part_count do
        "1"
      else
        "0"
      end)
    ])?
  Ok(empty(if stop == object.part_count do
    200
  else
    202
  end))
end

pub fn complete_large(url :: String, root :: String, body :: Bytes, now :: U64) -> ObjectResult do
  let timestamp = case U64.to_int(now) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case decode_complete(body) do
    Err(_) -> return empty(400)
    Ok(_) -> nil
  end
  case transaction(url, root) do
    Err(_) -> empty(503)
    Ok(conn) -> do
      let result = complete_open(conn, root, body, timestamp)
      finish(conn, result)
    end
  end
end

# At most128 part deletions per transaction, including explicit deletion. A
# durable cursor makes interrupted cleanup/retries idempotent and bounded.
fn purge_object(conn :: borrow PgConn,
  root :: String,
  object :: LargeObjectRecord) -> ObjectResult!String do
  let stop = if object.purge_index + 128 < object.part_count do
    object.purge_index + 128
  else
    object.part_count
  end
  for index in object.purge_index..stop do
    remove_file(large_part_path(root, object.object_id, index)?)?
  end
  if stop == object.part_count do
    Pg.execute_values(conn,
      "DELETE FROM large_objects WHERE object_id=$1",
      [Binary(object.object_id)])?
    Ok(empty(204))
  else
    Pg.execute_values(conn,
      "UPDATE large_objects SET deleting=1,purge_index=$2 WHERE object_id=$1",
      [Binary(object.object_id), Text(Int.to_string(stop))])?
    RuntimeJobs.notify(conn, "objects")?
    Ok(empty(202))
  end
end

fn delete_open(conn :: borrow PgConn, root :: String, body :: Bytes) -> ObjectResult!String do
  let control = decode_delete(body)?
  let object = case find(conn, control.object_id)? do
    None -> return Ok(empty(404))
    Some(value) -> value
  end
  if !authorized(object, control.capability, true) do
    return Ok(empty(403))
  end
  purge_object(conn, root, object)
end

pub fn delete_large(url :: String, root :: String, body :: Bytes) -> ObjectResult do
  case decode_delete(body) do
    Err(_) -> return empty(400)
    Ok(_) -> nil
  end
  case transaction(url, root) do
    Err(_) -> empty(503)
    Ok(conn) -> do
      let result = delete_open(conn, root, body)
      finish(conn, result)
    end
  end
end

pub fn purge_large(url :: String, root :: String, now :: U64) -> ObjectResult do
  let timestamp = case U64.to_int(now) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case transaction(url, root) do
    Err(_) -> empty(503)
    Ok(conn) -> do
      let result = purge_due(conn, root, timestamp)
      finish(conn, result)
    end
  end
end

fn purge_due(conn :: borrow PgConn, root :: String, now :: Int) -> ObjectResult!String do
  let rows = Pg.query_values(conn,
    "SELECT * FROM large_objects WHERE deleting=1 OR expires_at<=$1 ORDER BY expires_at,object_id LIMIT 1",
    [Text(Int.to_string(now))])?
  if List.length(rows) == 0 do
    Ok(empty(204))
  else
    purge_object(conn, root, decode(List.head(rows))?)
  end
end

pub fn next_large_expiry(url :: String) -> Int!String do
  let conn = open_database(url)?
  let rows = Pg.query(conn,
    "SELECT CASE WHEN count(*) FILTER (WHERE deleting=1)>0 THEN 1 ELSE COALESCE(min(expires_at),0) END::text AS due FROM large_objects",
    [])
  Pg.close(conn)
  RuntimeJobs.due_time(rows?)
end

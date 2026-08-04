import File
from Objects.Grant import ObjectControl, decode_grant_response, encode_complete, encode_delete, encode_grant, mint_grant
from Store.Service import complete, delete_object, get_part, grant, initialize, purge_expired, put_part

fn bytes(value :: Int, length :: Int) -> Bytes ! String do
  case Bytes.repeat(value, length) do
    Err( _) -> Err("test byte allocation failed")
    Ok( output) -> Ok(output)
  end
end

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

fn binary(row :: Map < String, DbValue >, key :: String) -> Bytes ! String do
  case Map.get(row, key) do
    Binary( value) -> Ok(value)
    Text( _) -> Err("metadata value was text")
    Null -> Err("metadata value was null")
  end
end

fn text(row :: Map < String, DbValue >, key :: String) -> String ! String do
  case Map.get(row, key) do
    Binary( _) -> Err("metadata value was binary")
    Text( value) -> Ok(value)
    Null -> Err("metadata value was null")
  end
end

fn create_legacy_store(database_path :: String,
root :: String,
object_id :: Bytes,
upload :: Bytes,
download :: Bytes,
body :: Bytes) -> Result <(), String > do
  let database = Sqlite.open(database_path) ?
  let result = case Sqlite.execute(database, "PRAGMA foreign_keys = ON", []) do
    Err( error) -> Err(error)
    Ok( _) -> case Sqlite.execute(database,
    "CREATE TABLE objects (object_id BLOB PRIMARY KEY CHECK(typeof(object_id) = 'blob' AND length(object_id) = 32), grant_hash BLOB NOT NULL UNIQUE CHECK(typeof(grant_hash) = 'blob' AND length(grant_hash) = 32), upload_hash BLOB NOT NULL CHECK(typeof(upload_hash) = 'blob' AND length(upload_hash) = 32), download_hash BLOB NOT NULL CHECK(typeof(download_hash) = 'blob' AND length(download_hash) = 32), part_count INTEGER NOT NULL CHECK(part_count BETWEEN 1 AND 257), total_bytes INTEGER NOT NULL DEFAULT 0 CHECK(total_bytes BETWEEN 0 AND 16777216), expires_at INTEGER NOT NULL CHECK(expires_at >= 0), completed INTEGER NOT NULL DEFAULT 0 CHECK(completed IN (0, 1))) STRICT",
    []) do
      Err( error) -> Err(error)
      Ok( _) -> case Sqlite.execute(database,
      "CREATE TABLE object_parts (object_id BLOB NOT NULL CHECK(typeof(object_id) = 'blob' AND length(object_id) = 32), part_index INTEGER NOT NULL CHECK(part_index BETWEEN 0 AND 256), size INTEGER NOT NULL CHECK(size BETWEEN 1 AND 65576), content_hash BLOB NOT NULL CHECK(typeof(content_hash) = 'blob' AND length(content_hash) = 32), PRIMARY KEY (object_id, part_index), FOREIGN KEY (object_id) REFERENCES objects(object_id) ON DELETE CASCADE) STRICT",
      []) do
        Err( error) -> Err(error)
        Ok( _) -> case Sqlite.execute(database,
        "CREATE INDEX objects_expiry ON objects (expires_at, object_id)",
        []) do
          Err( error) -> Err(error)
          Ok( _) -> case Sqlite.execute_values(database,
          "INSERT INTO objects (object_id, grant_hash, upload_hash, download_hash, part_count, total_bytes, expires_at, completed) VALUES (?, ?, ?, ?, 2, ?, 700000, 0)",
          [Binary(object_id), Binary(Crypto.sha256(Bytes.from_utf8("legacy-object-grant"))), Binary(Crypto.sha256(upload)), Binary(Crypto.sha256(download)), Text(Int.to_string(Bytes.length(body)))]) do
            Err( error) -> Err(error)
            Ok( _) -> case Sqlite.execute_values(database,
            "INSERT INTO object_parts (object_id, part_index, size, content_hash) VALUES (?, 0, ?, ?)",
            [Binary(object_id), Text(Int.to_string(Bytes.length(body))), Binary(Crypto.sha256(body))]) do
              Err( error) -> Err(error)
              Ok( _) -> Ok(nil)
            end
          end
        end
      end
    end
  end
  Sqlite.close(database)
  result ?
  File.write_bytes(root <> "/" <> Bytes.to_hex(object_id) <> ".0", 0, body, true)
end

fn upload_range(database_path :: String,
root :: String,
object_id :: Bytes,
capability :: Bytes,
body :: Bytes,
part_index :: Int,
last_part_index :: Int,
now :: U64) -> Result <(), String > do
  if part_index > last_part_index do
    Ok(nil)
  else if put_part(database_path, root, object_id, part_index, capability, body, now).status != 201 do
    Err("test object part upload failed")
  else
    upload_range(database_path,
    root,
    object_id,
    capability,
    body,
    part_index + 1,
    last_part_index,
    now)
  end
end

fn random_32() -> Bytes ! String do
  case Crypto.random_bytes(32) do
    Err( _) -> Err("test random value generation failed")
    Ok( value) -> Ok(value)
  end
end

fn aggregate_boundaries(database_path :: String, root :: String) -> Result <(), String > do
  let exact_upload = random_32() ?
  let exact_download = random_32() ?
  let exact_id = random_32() ?
  let exact_control = ObjectControl {
    object_id : exact_id,
    capability : exact_upload
  }
  assert(grant(database_path,
  root,
  encode_grant(mint_grant(exact_id,
  257,
  wide("700000") ?,
  wide("200000") ?,
  exact_upload,
  exact_download,
  4) ?) ?,
  wide("100000") ?,
  wide("300000") ?,
  4).status == 201)
  let maximum_chunk = bytes(3, 65608) ?
  assert(put_part(database_path, root, exact_id, 0, exact_upload, bytes(4, 182) ?, wide("100009") ?).status == 201)
  upload_range(database_path, root, exact_id, exact_upload, maximum_chunk, 1, 256, wide("100009") ?) ?
  assert(complete(database_path, root, encode_complete(exact_control) ?, wide("100010") ?).status == 200)
  assert(delete_object(database_path, root, encode_delete(exact_control) ?, wide("100011") ?).status == 204)
  let over_upload = random_32() ?
  let over_download = random_32() ?
  let over_id = random_32() ?
  let over_control = ObjectControl {
    object_id : over_id,
    capability : over_upload
  }
  assert(grant(database_path,
  root,
  encode_grant(mint_grant(over_id,
  257,
  wide("700000") ?,
  wide("200000") ?,
  over_upload,
  over_download,
  4) ?) ?,
  wide("100000") ?,
  wide("300000") ?,
  4).status == 201)
  assert(put_part(database_path, root, over_id, 0, over_upload, bytes(5, 183) ?, wide("100012") ?).status == 201)
  upload_range(database_path, root, over_id, over_upload, maximum_chunk, 1, 255, wide("100012") ?) ?
  assert(put_part(database_path, root, over_id, 256, over_upload, maximum_chunk, wide("100012") ?).status == 413)
  assert(delete_object(database_path, root, encode_delete(over_control) ?, wide("100013") ?).status == 204)
  Ok(nil)
end

fn await_status(job :: Pid < Int >, normal_exits :: Int) -> Int ! String do
  case Job.await(job) do
    Ok( status) -> Ok(status)
    Err( error) -> if error == "normal" && normal_exits < 2 do
      await_status(job, normal_exits + 1)
    else
      Err("concurrent object upload failed")
    end
  end
end

fn migration_proof() -> Bool ! String do
  let random = case Crypto.random_bytes(8) do
    Err( _) -> Err("test path generation failed")
    Ok( value) -> Ok(value)
  end ?
  let database_path = "/tmp/mesh_object_store_migration_" <> Bytes.to_hex(random) <> ".db"
  let root = "/tmp"
  let object_id = case Crypto.random_bytes(32) do
    Err( _) -> Err("test object identifier generation failed")
    Ok( value) -> Ok(value)
  end ?
  let upload = bytes(9, 32) ?
  let download = bytes(10, 32) ?
  let legacy_body = Bytes.from_hex("00ff8001") ?
  create_legacy_store(database_path, root, object_id, upload, download, legacy_body) ?
  initialize(database_path, root) ?
  let database = Sqlite.open(database_path) ?
  let object_schema = Sqlite.query_values(database,
  "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'objects'",
  []) ?
  let part_schema = Sqlite.query_values(database,
  "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'object_parts'",
  []) ?
  assert(List.length(object_schema) == 1)
  assert(List.length(part_schema) == 1)
  assert(String.contains(text(List.head(object_schema), "sql") ?,
  "total_bytes BETWEEN 0 AND 16795830"))
  assert(String.contains(text(List.head(part_schema), "sql") ?, "size BETWEEN 1 AND 65608"))
  let object_rows = Sqlite.query_values(database,
  "SELECT object_id, grant_hash, upload_hash, download_hash, part_count, total_bytes, expires_at, completed FROM objects WHERE object_id = ?",
  [Binary(object_id)]) ?
  assert(List.length(object_rows) == 1)
  let object_row = List.head(object_rows)
  assert(Bytes.secure_equals(binary(object_row, "object_id") ?, object_id))
  assert(Bytes.secure_equals(binary(object_row, "grant_hash") ?,
  Crypto.sha256(Bytes.from_utf8("legacy-object-grant"))))
  assert(Bytes.secure_equals(binary(object_row, "upload_hash") ?, Crypto.sha256(upload)))
  assert(Bytes.secure_equals(binary(object_row, "download_hash") ?, Crypto.sha256(download)))
  assert(text(object_row, "part_count") ? == "2")
  assert(text(object_row, "total_bytes") ? == Int.to_string(Bytes.length(legacy_body)))
  assert(text(object_row, "expires_at") ? == "700000")
  assert(text(object_row, "completed") ? == "0")
  let part_rows = Sqlite.query_values(database,
  "SELECT part_index, size, content_hash FROM object_parts WHERE object_id = ? AND part_index = 0",
  [Binary(object_id)]) ?
  assert(List.length(part_rows) == 1)
  let part_row = List.head(part_rows)
  assert(text(part_row, "part_index") ? == "0")
  assert(text(part_row, "size") ? == Int.to_string(Bytes.length(legacy_body)))
  assert(Bytes.secure_equals(binary(part_row, "content_hash") ?, Crypto.sha256(legacy_body)))
  assert(List.length(Sqlite.query_values(database,
  "SELECT name FROM sqlite_master WHERE type = 'index' AND name = 'objects_expiry' AND tbl_name = 'objects'",
  []) ?) == 1)
  assert(List.length(Sqlite.query_values(database, "PRAGMA foreign_key_check", []) ?) == 0)
  Sqlite.close(database)
  assert(put_part(database_path, root, object_id, 0, upload, legacy_body, wide("100000") ?).status == 200)
  assert(put_part(database_path, root, object_id, 1, upload, bytes(11, 65609) ?, wide("100001") ?).status == 413)
  let maximum_part = bytes(12, 65608) ?
  assert(put_part(database_path, root, object_id, 1, upload, maximum_part, wide("100001") ?).status == 201)
  initialize(database_path, root) ?
  assert(put_part(database_path, root, object_id, 0, upload, legacy_body, wide("100002") ?).status == 200)
  assert(put_part(database_path, root, object_id, 1, upload, maximum_part, wide("100002") ?).status == 200)
  let control = ObjectControl {
    object_id : object_id,
    capability : upload
  }
  assert(complete(database_path, root, encode_complete(control) ?, wide("100003") ?).status == 200)
  let downloaded = get_part(database_path, root, object_id, 0, download, wide("100004") ?)
  assert(downloaded.status == 200)
  assert(Bytes.secure_equals(downloaded.body, legacy_body))
  assert(delete_object(database_path, root, encode_delete(control) ?, wide("100005") ?).status == 204)
  aggregate_boundaries(database_path, root) ?
  if File.exists(database_path) do
    File.delete(database_path) ?
  else
    nil
  end
  Ok(true)
end

fn proof() -> Bool ! String do
  let random = case Crypto.random_bytes(8) do
    Err( _) -> Err("test path generation failed")
    Ok( value) -> Ok(value)
  end ?
  let suffix = Bytes.to_hex(random)
  let database_path = "/tmp/mesh_object_store_" <> suffix <> ".db"
  let root = "/tmp"
  initialize(database_path, root) ?
  let upload = bytes(17, 32) ?
  let download = bytes(34, 32) ?
  let wrong = bytes(51, 32) ?
  let object_id = bytes(102, 32) ?
  let request = encode_grant(mint_grant(object_id,
  2,
  wide("700000") ?,
  wide("200000") ?,
  upload,
  download,
  4) ?) ?
  let granted = grant(database_path, root, request, wide("100000") ?, wide("300000") ?, 4)
  assert(granted.status == 201)
  assert(Bytes.secure_equals(decode_grant_response(granted.body) ?.object_id, object_id))
  let replayed = grant(database_path, root, request, wide("100000") ?, wide("300000") ?, 4)
  assert(replayed.status == 200)
  assert(Bytes.secure_equals(decode_grant_response(replayed.body) ?.object_id, object_id))
  let changed_grant = encode_grant(mint_grant(object_id,
  1,
  wide("700000") ?,
  wide("200000") ?,
  upload,
  download,
  4) ?) ?
  assert(grant(database_path, root, changed_grant, wide("100000") ?, wide("300000") ?, 4).status == 409)
  let first = Bytes.from_hex("00ff8001") ?
  assert(put_part(database_path, root, object_id, 0, wrong, first, wide("100001") ?).status == 403)
  assert(put_part(database_path, root, object_id, 0, upload, bytes(1, 65609) ?, wide("100001") ?).status == 413)
  let upload_now = wide("100001") ?
  let first_job = Job.async(fn () -> put_part(database_path,
  root,
  object_id,
  0,
  upload,
  first,
  upload_now).status end)
  let second_job = Job.async(fn () -> put_part(database_path,
  root,
  object_id,
  0,
  upload,
  first,
  upload_now).status end)
  let first_status = await_status(first_job, 0) ?
  let second_status = await_status(second_job, 0) ?
  assert((first_status == 201 && second_status == 200) || (first_status == 200 && second_status == 201))
  assert(put_part(database_path, root, object_id, 0, upload, first, wide("100002") ?).status == 200)
  assert(put_part(database_path,
  root,
  object_id,
  0,
  upload,
  Bytes.from_hex("00ff8002") ?,
  wide("100002") ?).status == 409)
  let control = ObjectControl {
    object_id : object_id,
    capability : upload
  }
  assert(complete(database_path, root, encode_complete(control) ?, wide("100003") ?).status == 409)
  let second = bytes(2, 65608) ?
  assert(put_part(database_path, root, object_id, 1, upload, second, wide("100004") ?).status == 201)
  assert(complete(database_path, root, encode_complete(control) ?, wide("100005") ?).status == 200)
  assert(get_part(database_path, root, object_id, 1, wrong, wide("100006") ?).status == 403)
  let downloaded = get_part(database_path, root, object_id, 1, download, wide("100006") ?)
  assert(downloaded.status == 200)
  assert(Bytes.secure_equals(downloaded.body, second))
  let database = Sqlite.open(database_path) ?
  let rows = Sqlite.query_values(database,
  "SELECT object_id, upload_hash, download_hash FROM objects WHERE object_id = ?",
  [Binary(object_id)]) ?
  assert(List.length(rows) == 1)
  let metadata = List.head(rows)
  assert(Bytes.secure_equals(binary(metadata, "object_id") ?, object_id))
  assert(Bytes.secure_equals(binary(metadata, "upload_hash") ?, Crypto.sha256(upload)))
  assert(Bytes.secure_equals(binary(metadata, "download_hash") ?, Crypto.sha256(download)))
  assert(!Bytes.secure_equals(binary(metadata, "upload_hash") ?, upload))
  let schema = Map.get(List.head(Sqlite.query(database,
  "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'objects'",
  []) ?),
  "sql")
  assert(!String.contains(schema, "filename"))
  assert(!String.contains(schema, "mime"))
  assert(!String.contains(schema, "identity"))
  assert(!String.contains(schema, "conversation"))
  Sqlite.close(database)
  assert(delete_object(database_path,
  root,
  encode_delete(ObjectControl {
    object_id : object_id,
    capability : wrong
  }) ?,
  wide("100007") ?).status == 403)
  assert(delete_object(database_path, root, encode_delete(control) ?, wide("100007") ?).status == 204)
  assert(get_part(database_path, root, object_id, 1, download, wide("100008") ?).status == 404)
  aggregate_boundaries(database_path, root) ?
  let expiring_upload = bytes(68, 32) ?
  let expiring_download = bytes(85, 32) ?
  let expiring_id = bytes(119, 32) ?
  let expiring = grant(database_path,
  root,
  encode_grant(mint_grant(expiring_id,
  1,
  wide("101000") ?,
  wide("100500") ?,
  expiring_upload,
  expiring_download,
  4) ?) ?,
  wide("100000") ?,
  wide("300000") ?,
  4)
  assert(expiring.status == 201)
  assert(Bytes.secure_equals(decode_grant_response(expiring.body) ?.object_id, expiring_id))
  assert(put_part(database_path,
  root,
  expiring_id,
  0,
  expiring_upload,
  Bytes.from_utf8("expiring"),
  wide("100100") ?).status == 201)
  assert(complete(database_path,
  root,
  encode_complete(ObjectControl {
    object_id : expiring_id,
    capability : expiring_upload
  }) ?,
  wide("100200") ?).status == 200)
  assert(get_part(database_path, root, expiring_id, 0, expiring_download, wide("101000") ?).status == 410)
  assert(purge_expired(database_path, root, wide("101001") ?, 1) ? == 1)
  assert(get_part(database_path, root, expiring_id, 0, expiring_download, wide("101001") ?).status == 404)
  case mint_grant(bytes(136, 32) ?, 258, wide("700000") ?, wide("200000") ?, upload, download, 4) do
    Err( _) -> nil
    Ok( _) -> assert(false)
  end
  if File.exists(database_path) do
    File.delete(database_path) ?
  else
    nil
  end
  Ok(true)
end

test("opaque objects enforce capabilities, replay, completion, deletion, expiry, and bounds") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

test("legacy opaque object limits migrate without losing rows and reopening is idempotent") do
  case migration_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

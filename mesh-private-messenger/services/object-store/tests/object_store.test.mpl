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
  assert(put_part(database_path, root, object_id, 0, upload, bytes(1, 65577) ?, wide("100001") ?).status == 413)
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
  let second = bytes(2, 65576) ?
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

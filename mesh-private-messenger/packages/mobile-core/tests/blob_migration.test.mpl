import File
from Storage.Blobs import ensure_schema, insert_blob, load_blob, put_blob

fn text(row :: Map < String, DbValue >, key :: String) -> String ! String do
  case Map.get(row, key) do
    Text( value) -> Ok(value)
    Binary( _) -> Err("expected text")
    Null -> Err("expected text")
  end
end

fn binary(row :: Map < String, DbValue >, key :: String) -> Bytes ! String do
  case Map.get(row, key) do
    Binary( value) -> Ok(value)
    Text( _) -> Err("expected binary")
    Null -> Err("expected binary")
  end
end

fn create_legacy(path :: String) -> Result <(), String > do
  case Sqlite.open(path) do
    Err( error) -> Err(error)
    Ok( database) -> do
      let result = case Sqlite.execute(database,
      "CREATE TABLE encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext TEXT NOT NULL CHECK(length(ciphertext) > 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT",
      []) do
        Err( error) -> Err(error)
        Ok( _) -> case Sqlite.execute(database,
        "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES ('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'AP+A', '2026-01-02 03:04:05')",
        []) do
          Err( error) -> Err(error)
          Ok( _) -> Ok(nil)
        end
      end
      Sqlite.close(database)
      result
    end
  end
end

fn proof() -> Bool ! String do
  let random = case Crypto.random_bytes(8) do
    Err( _) -> Err("test path generation failed")
    Ok( value) -> Ok(value)
  end ?
  let suffix = Bytes.to_hex(random)
  let valid_path = "/tmp/mesh_mobile_blob_" <> suffix <> ".db"
  let invalid_path = valid_path <> ".invalid"
  let valid_created = case create_legacy(valid_path) do
    Err( _) -> false
    Ok( _) -> true
  end
  let invalid_created = case create_legacy(invalid_path) do
    Err( _) -> false
    Ok( _) -> true
  end
  assert(valid_created && invalid_created)
  let valid_legacy = Sqlite.open(valid_path) ?
  let _ = Sqlite.execute(valid_legacy,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'AQ==', '2026-01-03 04:05:06')",
  []) ?
  Sqlite.close(valid_legacy)
  let invalid_legacy = Sqlite.open(invalid_path) ?
  let _ = Sqlite.execute(invalid_legacy,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES ('bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb', 'not-base64', '2026-01-03 04:05:06')",
  []) ?
  Sqlite.close(invalid_legacy)
  ensure_schema(valid_path) ?
  ensure_schema(valid_path) ?
  let database = Sqlite.open(valid_path) ?
  let rows = Sqlite.query_values(database,
  "SELECT ciphertext, updated_at, typeof(ciphertext) AS storage_type FROM encrypted_blobs WHERE record_hash = ?",
  [Text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")]) ?
  assert(List.length(rows) == 1)
  let row = List.head(rows)
  assert(Bytes.secure_equals(binary(row, "ciphertext") ?, Bytes.from_hex("00ff80") ?))
  assert(text(row, "updated_at") ? == "2026-01-02 03:04:05")
  assert(text(row, "storage_type") ? == "blob")
  let columns = Sqlite.query_values(database,
  "SELECT type FROM pragma_table_info('encrypted_blobs') WHERE name = 'ciphertext'",
  []) ?
  assert(List.length(columns) == 1)
  assert(text(List.head(columns), "type") ? == "BLOB")
  insert_blob(database, "typed-round-trip", Bytes.from_hex("0102") ?) ?
  put_blob(database, "typed-round-trip", Bytes.from_hex("00ff8003") ?) ?
  Sqlite.close(database)
  assert(Bytes.secure_equals(load_blob(valid_path, "typed-round-trip") ?,
  Bytes.from_hex("00ff8003") ?))
  case ensure_schema(invalid_path) do
    Ok( _) -> assert(false)
    Err( _) -> assert(true)
  end
  let invalid_database = Sqlite.open(invalid_path) ?
  let invalid_rows = Sqlite.query_values(invalid_database,
  "SELECT ciphertext, typeof(ciphertext) AS storage_type FROM encrypted_blobs ORDER BY record_hash",
  []) ?
  assert(List.length(invalid_rows) == 2)
  assert(text(List.get(invalid_rows, 0), "ciphertext") ? == "AP+A")
  assert(text(List.get(invalid_rows, 1), "ciphertext") ? == "not-base64")
  assert(text(List.get(invalid_rows, 0), "storage_type") ? == "text")
  let invalid_columns = Sqlite.query_values(invalid_database,
  "SELECT type FROM pragma_table_info('encrypted_blobs') WHERE name = 'ciphertext'",
  []) ?
  assert(text(List.head(invalid_columns), "type") ? == "TEXT")
  Sqlite.close(invalid_database)
  File.delete(valid_path) ?
  File.delete(invalid_path) ?
  Ok(true)
end

test("legacy encrypted blobs migrate atomically to typed binary storage") do
  case proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

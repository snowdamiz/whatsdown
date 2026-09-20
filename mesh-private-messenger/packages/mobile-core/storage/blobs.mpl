fn migrate_rows(database :: SqliteConn, rows :: List < Map < String, DbValue > >, index :: Int) -> Result <(), String > do
  if index >= List.length(rows) do
    Ok(nil)
  else
    let row = List.get(rows, index)
    case Map.get(row, "record_hash") do
      Binary( _) -> Err("invalid_legacy_blob")
      Null -> Err("invalid_legacy_blob")
      Text( record_hash) -> case Map.get(row, "ciphertext") do
        Binary( _) -> Err("invalid_legacy_blob")
        Null -> Err("invalid_legacy_blob")
        Text( encoded) -> case Map.get(row, "updated_at") do
          Binary( _) -> Err("invalid_legacy_blob")
          Null -> Err("invalid_legacy_blob")
          Text( updated_at) -> case Bytes.from_base64(encoded) do
            Err( _) -> Err("invalid_legacy_blob")
            Ok( blob) -> if Bytes.length(blob) == 0 || Bytes.to_base64(blob) != encoded do
              Err("invalid_legacy_blob")
            else
              let _ = Sqlite.execute_values(database,
              "INSERT INTO encrypted_blobs_blob_migration (record_hash, ciphertext, updated_at) VALUES (?, ?, ?)",
              [Text(record_hash), Binary(blob), Text(updated_at)]) ?
              migrate_rows(database, rows, index + 1)
            end
          end
        end
      end
    end
  end
end

fn ensure_schema_in_transaction(database :: SqliteConn) -> Result <(), String > do
  let _ = Sqlite.execute(database,
  "CREATE TABLE IF NOT EXISTS encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT",
  []) ?
  let columns = Sqlite.query_values(database,
  "SELECT upper(type) AS ciphertext_type FROM pragma_table_info('encrypted_blobs') WHERE name = 'ciphertext'",
  []) ?
  if List.length(columns) != 1 do
    Err("invalid_blob_schema")
  else
    case Map.get(List.head(columns), "ciphertext_type") do
      Binary( _) -> Err("invalid_blob_schema")
      Null -> Err("invalid_blob_schema")
      Text( ciphertext_type) -> if ciphertext_type == "BLOB" do
        Ok(nil)
      else if ciphertext_type != "TEXT" do
        Err("invalid_blob_schema")
      else
        let _ = Sqlite.execute(database,
        "CREATE TABLE encrypted_blobs_blob_migration (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext BLOB NOT NULL CHECK(length(ciphertext) > 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT",
        []) ?
        let rows = Sqlite.query_values(database,
        "SELECT record_hash, ciphertext, updated_at FROM encrypted_blobs ORDER BY record_hash",
        []) ?
        migrate_rows(database, rows, 0) ?
        let _ = Sqlite.execute(database,
        "ALTER TABLE encrypted_blobs RENAME TO encrypted_blobs_legacy_text",
        []) ?
        let _ = Sqlite.execute(database,
        "ALTER TABLE encrypted_blobs_blob_migration RENAME TO encrypted_blobs",
        []) ?
        let _ = Sqlite.execute(database, "DROP TABLE encrypted_blobs_legacy_text", []) ?
        Ok(nil)
      end
    end
  end
end

pub fn ensure_schema(database_path :: String) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( error) -> Err(error)
        Ok( _) -> case ensure_schema_in_transaction(database) do
          Err( error) -> Err(error)
          Ok( _) -> Sqlite.commit(database)
        end
      end
      case result do
        Err( _) -> do
          let _ = Sqlite.rollback(database)
          Sqlite.close(database)
          Err("database_schema_failed")
        end
        Ok( _) -> do
          Sqlite.close(database)
          Ok(nil)
        end
      end
    end
  end
end

pub fn insert_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result <(), String > do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.execute_values(database,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
  [Text(record_hash), Binary(blob)]) do
    Err( _) -> Err("database_write_failed")
    Ok( _) -> Ok(nil)
  end
end

pub fn put_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result <(), String > do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.execute_values(database,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP",
  [Text(record_hash), Binary(blob)]) do
    Err( _) -> Err("database_write_failed")
    Ok( _) -> Ok(nil)
  end
end

pub fn load_blob(database_path :: String, label :: String) -> Bytes ! String do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> case Sqlite.query_values(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [Text(record_hash)]) do
      Err( _) -> do
        Sqlite.close(database)
        Err("database_read_failed")
      end
      Ok( rows) -> do
        Sqlite.close(database)
        if List.length(rows) != 1 do
          Err("local_state_not_found")
        else
          case Map.get(List.head(rows), "ciphertext") do
            Binary( blob) -> Ok(blob)
            Text( _) -> Err("invalid_local_state")
            Null -> Err("invalid_local_state")
          end
        end
      end
    end
  end
end

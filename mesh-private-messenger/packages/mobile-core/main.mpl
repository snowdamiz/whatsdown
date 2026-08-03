from Binary.Reader import BinaryReader, finish, read_vector, reader
from Protocol.V1 import OuterEnvelope, decode_outer_envelope, encode_outer_envelope

struct MobileReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct MobileStoreRequest do
  database_path :: String
  record_key :: Bytes
  envelope :: Bytes
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> MobileReadBytes ! String do
  case read_vector(state, maximum) do
    Err(_) -> Err("invalid_store_request")
    Ok((next, value)) -> Ok(MobileReadBytes { state: next, value: value })
    Ok(_) -> Err("invalid_store_request")
  end
end

fn parse_store_request(input :: Bytes) -> MobileStoreRequest ! String do
  if Bytes.length(input) > 69854 do
    Err("store_request_too_large")
  else
    case reader(input, 69854) do
      Err(_) -> Err("invalid_store_request")
      Ok(state) -> do
        let path = take_vector(state, 4096)?
        let record_key = take_vector(path.state, 128)?
        let envelope = take_vector(record_key.state, 65606)?
        case finish(envelope.state) do
          Err(_) -> Err("invalid_store_request")
          Ok(_) -> case Bytes.to_utf8(path.value) do
              Err(_) -> Err("invalid_database_path")
              Ok(database_path) -> if String.length(database_path) == 0 || Bytes.length(record_key.value) == 0 do
                  Err("invalid_store_request")
                else
                  Ok(MobileStoreRequest {
                    database_path: database_path,
                    record_key: record_key.value,
                    envelope: envelope.value
                  })
                end
            end
        end
      end
    end
  end
end

fn canonical_outer(input :: Bytes) -> OuterEnvelope ! String do
  case decode_outer_envelope(input) do
    Err(_) -> Err("invalid_outer_envelope")
    Ok(value) -> case encode_outer_envelope(value) do
        Err(_) -> Err("invalid_outer_envelope")
        Ok(encoded) -> if Bytes.secure_equals(encoded, input) do
            Ok(value)
          else
            Err("noncanonical_outer_envelope")
          end
      end
  end
end

fn ensure_schema(database_path :: String) -> Result<(), String> do
  case Sqlite.open(database_path) do
    Err(_) -> Err("database_open_failed")
    Ok(database) -> case Sqlite.execute(database,
        "CREATE TABLE IF NOT EXISTS encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext TEXT NOT NULL CHECK(length(ciphertext) > 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT",
        []) do
        Err(_) -> do
          Sqlite.close(database)
          Err("database_schema_failed")
        end
        Ok(_) -> do
          Sqlite.close(database)
          Ok(nil)
        end
      end
  end
end

fn store_envelope(request :: MobileStoreRequest) -> Bytes ! String do
  let envelope = canonical_outer(request.envelope)?
  if Bytes.length(envelope.ciphertext) < 16 do
    Err("ciphertext_too_short")
  else
    ensure_schema(request.database_path)?
    let record_hash = Bytes.to_hex(Crypto.sha256(request.record_key))
    let ciphertext = Bytes.to_base64(envelope.ciphertext)
    case Sqlite.open(request.database_path) do
      Err(_) -> Err("database_open_failed")
      Ok(database) -> case Sqlite.execute(database,
          "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP",
          [record_hash, ciphertext]) do
          Err(_) -> do
            Sqlite.close(database)
            Err("database_write_failed")
          end
          Ok(_) -> do
            Sqlite.close(database)
            Ok(Bytes.from_utf8(record_hash))
          end
        end
    end
  end
end

@export("mesh_messenger_initialize")
pub fn initialize(request :: Bytes) -> Bytes ! String do
  case Bytes.to_utf8(request) do
    Err(_) -> Err("invalid_database_path")
    Ok(database_path) -> if String.length(database_path) == 0 || String.length(database_path) > 4096 do
        Err("invalid_database_path")
      else
        ensure_schema(database_path)?
        Ok(Bytes.from_utf8("mesh-messenger-mobile-v1"))
      end
  end
end

@export("mesh_messenger_validate_outer")
pub fn validate_outer(request :: Bytes) -> Bytes ! String do
  let value = canonical_outer(request)?
  case encode_outer_envelope(value) do
    Err(_) -> Err("invalid_outer_envelope")
    Ok(encoded) -> Ok(encoded)
  end
end

@export("mesh_messenger_store_envelope")
pub fn persist_envelope(request :: Bytes) -> Bytes ! String do
  store_envelope(parse_store_request(request)?)
end

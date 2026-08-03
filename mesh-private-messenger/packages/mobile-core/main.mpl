from Binary.Reader import BinaryReader, finish, read_vector, reader
from Identity.Device import AccountKeys, DeviceKeys, generate_account, generate_device, issue_device_credential
from Prekeys.Bundle import OneTimePrekeySecrets, SignedPrekeySecrets, build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey
from Protocol.V1 import AccountIdentity, DirectoryEntry, OuterEnvelope, decode_outer_envelope, encode_account_identity, encode_directory_entry, encode_outer_envelope, encode_prekey_bundle

struct MobileReadBytes do
  state :: BinaryReader
  value :: Bytes
end

struct MobileStoreRequest do
  database_path :: String
  record_key :: Bytes
  envelope :: Bytes
end

struct MobileAccountRequest do
  database_path :: Bytes
  username :: Bytes
end

fn take_vector(state :: BinaryReader, maximum :: Int) -> MobileReadBytes ! String do
  case read_vector(state, maximum) do
    Err( _) -> Err("invalid_store_request")
    Ok( ( next, value)) -> Ok(MobileReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid_store_request")
  end
end

fn parse_store_request(input :: Bytes) -> MobileStoreRequest ! String do
  if Bytes.length(input) > 69854 do
    Err("store_request_too_large")
  else
    case reader(input, 69854) do
      Err( _) -> Err("invalid_store_request")
      Ok( state) -> do
        let path = take_vector(state, 4096) ?
        let record_key = take_vector(path.state, 128) ?
        let envelope = take_vector(record_key.state, 65606) ?
        case finish(envelope.state) do
          Err( _) -> Err("invalid_store_request")
          Ok( _) -> case Bytes.to_utf8(path.value) do
            Err( _) -> Err("invalid_database_path")
            Ok( database_path) -> if String.length(database_path) == 0 || Bytes.length(record_key.value) == 0 do
              Err("invalid_store_request")
            else
              Ok(MobileStoreRequest {
                database_path : database_path,
                record_key : record_key.value,
                envelope : envelope.value
              })
            end
          end
        end
      end
    end
  end
end

fn mobile_wide(value :: String) -> U64 ! String do
  case U64.parse(value) do
    Err( _) -> Err("invalid_wide_integer")
    Ok( parsed) -> Ok(parsed)
  end
end

fn mobile_append(left :: Bytes, right :: Bytes) -> Bytes ! String do
  case Bytes.concat(left, right) do
    Err( _) -> Err("byte_concatenation_failed")
    Ok( value) -> Ok(value)
  end
end

fn mobile_join(parts :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(parts) do
    Ok(output)
  else
    mobile_join(parts, index + 1, mobile_append(output, List.get(parts, index)) ?)
  end
end

fn mobile_write_u16(value :: Int) -> Bytes ! String do
  case Bytes.write_u16_be(value) do
    Err( _) -> Err("integer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn mobile_byte(value :: Int) -> Bytes ! String do
  case Bytes.from_list([value]) do
    Err( _) -> Err("integer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn mobile_zeroes(length :: Int) -> Bytes ! String do
  case Bytes.repeat(0, length) do
    Err( _) -> Err("storage_context_failed")
    Ok( value) -> Ok(value)
  end
end

fn mobile_write_u32(value :: Int) -> Bytes ! String do
  case Bytes.write_u32_be(mobile_wide(Int.to_string(value)) ?) do
    Err( _) -> Err("integer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn mobile_write_u64(value :: U64) -> Bytes ! String do
  case Bytes.write_u64_be(value) do
    Err( _) -> Err("integer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn mobile_vector(value :: Bytes) -> Bytes ! String do
  mobile_append(mobile_write_u32(Bytes.length(value)) ?, value)
end

fn mobile_utf8(value :: Bytes, error :: String) -> String ! String do
  case Bytes.to_utf8(value) do
    Err( _) -> Err(error)
    Ok( text) -> Ok(text)
  end
end

fn parse_account_request(input :: Bytes) -> MobileAccountRequest ! String do
  if Bytes.length(input) > 4168 do
    Err("account_request_too_large")
  else
    case reader(input, 4168) do
      Err( _) -> Err("invalid_account_request")
      Ok( state) -> do
        let path = take_vector(state, 4096) ?
        let username = take_vector(path.state, 64) ?
        case finish(username.state) do
          Err( _) -> Err("invalid_account_request")
          Ok( _) -> Ok(MobileAccountRequest {
            database_path : path.value,
            username : username.value
          })
        end
      end
    end
  end
end

fn context(account_id :: Bytes, device_id :: Bytes, label :: String, purpose :: Int) -> Bytes ! String do
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 do
    Err("invalid_storage_identity")
  else
    let session_id = if purpose >= 5 && purpose <= 10 do
      mobile_zeroes(32) ?
    else
      Crypto.sha256(Bytes.from_utf8("mesh-msg/mobile/storage-session/v1"))
    end
    mobile_join([mobile_byte(1) ?, account_id, device_id, session_id, Crypto.sha256(Bytes.from_utf8(label)), mobile_write_u16(purpose) ?, mobile_write_u64(mobile_wide("1") ?) ?],
    0,
    Bytes.empty())
  end
end

fn profile_context() -> Bytes ! String do
  case Bytes.repeat(0, 32) do
    Err( _) -> Err("storage_context_failed")
    Ok( account_id) -> case Bytes.repeat(0, 16) do
      Err( _) -> Err("storage_context_failed")
      Ok( device_id) -> context(account_id, device_id, "profile/v1", 14)
    end
  end
end

fn platform_key() -> StorageKey ! String do
  case StorageKey.platform() do
    Err( _) -> Err("secure_storage_unavailable")
    Ok( key) -> Ok(key)
  end
end

fn seal_signing(key :: borrow SigningPrivateKey,
wrapping_key :: borrow StorageKey,
value_context :: Bytes) -> Bytes ! String do
  case SigningPrivateKey.seal_for_storage(key, wrapping_key, value_context) do
    Err( _) -> Err("identity_seal_failed")
    Ok( blob) -> Ok(blob)
  end
end

fn seal_x25519(key :: borrow X25519PrivateKey,
wrapping_key :: borrow StorageKey,
value_context :: Bytes) -> Bytes ! String do
  case X25519PrivateKey.seal_for_storage(key, wrapping_key, value_context) do
    Err( _) -> Err("identity_seal_failed")
    Ok( blob) -> Ok(blob)
  end
end

fn seal_local(value :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> Bytes ! String do
  case StorageKey.seal_bytes(value, wrapping_key, value_context) do
    Err( _) -> Err("local_state_seal_failed")
    Ok( blob) -> Ok(blob)
  end
end

fn open_local(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> Bytes ! String do
  case StorageKey.unseal_bytes(blob, wrapping_key, value_context) do
    Err( _) -> Err("local_state_open_failed")
    Ok( value) -> Ok(value)
  end
end

fn insert_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result <(), String > do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.execute(database,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)",
  [record_hash, Bytes.to_base64(blob)]) do
    Err( _) -> Err("database_write_failed")
    Ok( _) -> Ok(nil)
  end
end

fn insert_blobs(database :: SqliteConn,
labels :: List < String >,
blobs :: List < Bytes >,
index :: Int) -> Result <(), String > do
  if List.length(labels) != List.length(blobs) do
    Err("invalid_local_state")
  else
    if index >= List.length(labels) do
      Ok(nil)
    else
      insert_blob(database, List.get(labels, index), List.get(blobs, index)) ?
      insert_blobs(database, labels, blobs, index + 1)
    end
  end
end

fn store_blobs(database_path :: String, labels :: List < String >, blobs :: List < Bytes >) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blobs(database, labels, blobs, 0) do
          Err( error) -> Err(error)
          Ok( _) -> case Sqlite.commit(database) do
            Err( _) -> Err("database_write_failed")
            Ok( _) -> Ok(nil)
          end
        end
      end
      case result do
        Err( error) -> do
          let _ = Sqlite.rollback(database)
          Sqlite.close(database)
          Err(error)
        end
        Ok( _) -> do
          Sqlite.close(database)
          Ok(nil)
        end
      end
    end
  end
end

fn load_blob(database_path :: String, label :: String) -> Bytes ! String do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> case Sqlite.query(database,
    "SELECT ciphertext FROM encrypted_blobs WHERE record_hash = ?",
    [record_hash]) do
      Err( _) -> do
        Sqlite.close(database)
        Err("database_read_failed")
      end
      Ok( rows) -> do
        Sqlite.close(database)
        if List.length(rows) != 1 do
          Err("local_state_not_found")
        else
          case Bytes.from_base64(Map.get(List.head(rows), "ciphertext")) do
            Err( _) -> Err("invalid_local_state")
            Ok( blob) -> Ok(blob)
          end
        end
      end
    end
  end
end

fn ensure_account_missing(database_path :: String) -> Result <(), String > do
  case load_blob(database_path, "profile/v1") do
    Ok( _) -> Err("account_already_exists")
    Err( error) -> if error == "local_state_not_found" do
      Ok(nil)
    else
      Err(error)
    end
  end
end

fn account_keys(created_at :: U64) -> Result <( AccountKeys, AccountIdentity), String > do
  case generate_account(created_at, mobile_wide("1") ?) do
    Err( _) -> Err("account_generation_failed")
    Ok( value) -> Ok(value)
  end
end

fn device_keys() -> DeviceKeys ! String do
  case generate_device() do
    Err( _) -> Err("device_generation_failed")
    Ok( value) -> Ok(value)
  end
end

fn directory_bytes(value :: DirectoryEntry) -> Bytes ! String do
  case encode_directory_entry(value) do
    Err( _) -> Err("directory_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn profile_bytes(value :: DirectoryEntry, account_id :: Bytes, device_id :: Bytes) -> Bytes ! String do
  mobile_join([mobile_vector(Bytes.from_utf8(value.username)) ?, mobile_vector(account_id) ?, mobile_vector(device_id) ?, mobile_vector(directory_bytes(value) ?) ?],
  0,
  Bytes.empty())
end

fn create_account(request :: MobileAccountRequest) -> Bytes ! String do
  let database_path = mobile_utf8(request.database_path, "invalid_database_path") ?
  let username = mobile_utf8(request.username, "invalid_username") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_account_request")
  else
    let created_at = mobile_wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()))) ?
    let expires_at = U64.add(created_at, mobile_wide("31536000000") ?) ?
    ensure_schema(database_path) ?
    ensure_account_missing(database_path) ?
    let ( account, identity) = account_keys(created_at) ?
    let device = device_keys() ?
    let credential = case issue_device_credential(account,
    device,
    mobile_wide("1") ?,
    created_at,
    expires_at,
    mobile_wide("1") ?) do
      Err( _) -> Err("credential_generation_failed")
      Ok( value) -> Ok(value)
    end ?
    let signed = case generate_signed_prekey(device, credential, mobile_wide("1") ?, expires_at) do
      Err( _) -> Err("prekey_generation_failed")
      Ok( value) -> Ok(value)
    end ?
    let one_time = case generate_one_time_prekey(mobile_wide("2") ?) do
      Err( _) -> Err("prekey_generation_failed")
      Ok( value) -> Ok(value)
    end ?
    let bundle = case build_prekey_bundle(credential, signed, one_time) do
      Err( _) -> Err("prekey_bundle_failed")
      Ok( value) -> Ok(value)
    end ?
    let account_wire = case encode_account_identity(identity) do
      Err( _) -> Err("account_encoding_failed")
      Ok( value) -> Ok(value)
    end ?
    let bundle_wire = case encode_prekey_bundle(bundle) do
      Err( _) -> Err("prekey_encoding_failed")
      Ok( value) -> Ok(value)
    end ?
    let mailbox_token = case Crypto.random_bytes(32) do
      Err( _) -> Err("mailbox_generation_failed")
      Ok( value) -> Ok(value)
    end ?
    let entry = DirectoryEntry {
      version : 1,
      username : username,
      account_identity : account_wire,
      prekey_bundle : bundle_wire,
      mailbox_token : mailbox_token
    }
    let profile = profile_bytes(entry, identity.account_id, credential.device_id) ?
    let wrapping_key = platform_key() ?
    let account_blob = case seal_signing(account.private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, "account-signing-key/v1", 6) ?) do
      Err( _) -> Err("account_key_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let device_signing_blob = case seal_signing(device.signing_private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, "device-signing-key/v1", 7) ?) do
      Err( _) -> Err("device_signing_key_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let device_identity_blob = case seal_x25519(device.identity_private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, "device-identity-key/v1", 8) ?) do
      Err( _) -> Err("device_identity_key_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let signed_prekey_blob = case seal_x25519(signed.private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, "signed-prekey/v1", 9) ?) do
      Err( _) -> Err("signed_prekey_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let one_time_prekey_blob = case seal_x25519(one_time.private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, "one-time-prekey/v1", 10) ?) do
      Err( _) -> Err("one_time_prekey_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let profile_blob = seal_local(profile, wrapping_key, profile_context() ?) ?
    store_blobs(database_path,
    ["account-signing-key/v1", "device-signing-key/v1", "device-identity-key/v1", "signed-prekey/v1", "one-time-prekey/v1", "profile/v1"],
    [account_blob, device_signing_blob, device_identity_blob, signed_prekey_blob, one_time_prekey_blob, profile_blob]) ?
    Ok(profile)
  end
end

fn load_profile(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    let wrapping_key = platform_key() ?
    open_local(load_blob(database_path, "profile/v1") ?, wrapping_key, profile_context() ?)
  end
end

fn canonical_outer(input :: Bytes) -> OuterEnvelope ! String do
  case decode_outer_envelope(input) do
    Err( _) -> Err("invalid_outer_envelope")
    Ok( value) -> case encode_outer_envelope(value) do
      Err( _) -> Err("invalid_outer_envelope")
      Ok( encoded) -> if Bytes.secure_equals(encoded, input) do
        Ok(value)
      else
        Err("noncanonical_outer_envelope")
      end
    end
  end
end

fn ensure_schema(database_path :: String) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> case Sqlite.execute(database,
    "CREATE TABLE IF NOT EXISTS encrypted_blobs (record_hash TEXT PRIMARY KEY CHECK(length(record_hash) = 64), ciphertext TEXT NOT NULL CHECK(length(ciphertext) > 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP) STRICT",
    []) do
      Err( _) -> do
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

fn store_envelope(request :: MobileStoreRequest) -> Bytes ! String do
  let envelope = canonical_outer(request.envelope) ?
  if Bytes.length(envelope.ciphertext) < 16 do
    Err("ciphertext_too_short")
  else
    ensure_schema(request.database_path) ?
    let record_hash = Bytes.to_hex(Crypto.sha256(request.record_key))
    let ciphertext = Bytes.to_base64(envelope.ciphertext)
    case Sqlite.open(request.database_path) do
      Err( _) -> Err("database_open_failed")
      Ok( database) -> case Sqlite.execute(database,
      "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP",
      [record_hash, ciphertext]) do
        Err( _) -> do
          Sqlite.close(database)
          Err("database_write_failed")
        end
        Ok( _) -> do
          Sqlite.close(database)
          Ok(Bytes.from_utf8(record_hash))
        end
      end
    end
  end
end

@ export("mesh_messenger_initialize")pub fn initialize(request :: Bytes) -> Bytes ! String do
  case Bytes.to_utf8(request) do
    Err( _) -> Err("invalid_database_path")
    Ok( database_path) -> if String.length(database_path) == 0 || String.length(database_path) > 4096 do
      Err("invalid_database_path")
    else
      ensure_schema(database_path) ?
      Ok(Bytes.from_utf8("mesh-messenger-mobile-v1"))
    end
  end
end

@ export("mesh_messenger_validate_outer")pub fn validate_outer(request :: Bytes) -> Bytes ! String do
  let value = canonical_outer(request) ?
  case encode_outer_envelope(value) do
    Err( _) -> Err("invalid_outer_envelope")
    Ok( encoded) -> Ok(encoded)
  end
end

@ export("mesh_messenger_store_envelope")pub fn persist_envelope(request :: Bytes) -> Bytes ! String do
  store_envelope(parse_store_request(request) ?)
end

@ export("mesh_messenger_create_account")pub fn create_account_export(request :: Bytes) -> Bytes ! String do
  case parse_account_request(request) do
    Err( error) -> Err(error)
    Ok( parsed) -> create_account(parsed)
  end
end

@ export("mesh_messenger_load_profile")pub fn load_profile_export(request :: Bytes) -> Bytes ! String do
  load_profile(mobile_utf8(request, "invalid_database_path") ?)
end

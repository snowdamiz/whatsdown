from Binary.Reader import BinaryReader, finish, read_vector, reader
from Identity.Device import AccountKeys, DeviceKeys, VerificationPolicy, authorize_device_link, generate_account, generate_device, issue_device_credential, issue_device_revocation, verify_device_link_authorization
from Prekeys.Bundle import OneTimePrekeySecrets, SignedPrekeySecrets, build_prekey_bundle, generate_one_time_prekey, generate_signed_prekey, verify_prekey_bundle
from Protocol.V1 import AccountIdentity, DeliveredEnvelope, DeviceCredential, DeviceLinkAuthorization, DeviceLinkRequest, DeviceSet, DirectoryEntry, InitialMessage, InnerEnvelope, MailboxAck, MailboxFetch, OuterEnvelope, PrekeyBundle, decode_account_identity, decode_delivery_batch, decode_device_credential, decode_device_link_authorization, decode_device_link_request, decode_device_set, decode_directory_entry, decode_inner_envelope, decode_outer_envelope, decode_prekey_bundle, encode_account_identity, encode_device_credential, encode_device_link_authorization, encode_device_link_request, encode_device_revocation, encode_device_set, encode_directory_entry, encode_directory_lookup, encode_initial_message, encode_inner_envelope, encode_mailbox_ack, encode_mailbox_fetch, encode_outer_envelope, encode_prekey_bundle
from Session.Handshake import RatchetState, initiate, receive_initial
from Session.Ratchet import DecryptOutcome, RatchetMessage, decode_ratchet_message, decrypt, encode_ratchet_message, encrypt
from Session.Snapshot import SnapshotOutcome, restore, snapshot

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

struct MobileProfile do
  encoded :: Bytes
  username :: String
  account_id :: Bytes
  device_id :: Bytes
  entry :: DirectoryEntry
  account :: AccountIdentity
  bundle :: PrekeyBundle
  credential :: DeviceCredential
end

struct MobileStartRequest do
  database_path :: String
  peer_profile :: Bytes
  body :: Bytes
end

struct MobileReceiveRequest do
  database_path :: String
  outer :: Bytes
end

struct MobileInitialPacket do
  account_identity :: Bytes
  message :: Bytes
end

struct MobileInitialPlaintext do
  profile :: Bytes
  inner :: Bytes
end

struct MobileSessionRecord do
  snapshot :: Bytes
  local_account_id :: Bytes
  local_device_id :: Bytes
  peer_account_id :: Bytes
  peer_device_id :: Bytes
  peer_username :: String
  peer_mailbox :: Bytes
  conversation_id :: Bytes
  request_state :: Int
  blocked :: Bool
  verified :: Bool
  key_changed :: Bool
  disappearing_seconds :: Int
end

struct MobileLoadedSession do
  session_id :: Bytes
  label :: String
  record :: MobileSessionRecord
end

struct MobileRatchetPacket do
  message :: Bytes
end

struct MobileHistoryEntry do
  direction :: Int
  inner :: InnerEnvelope
end

struct MobilePolicyRequest do
  database_path :: String
  peer_profile :: Bytes
  action :: Int
  value :: Int
end

struct MobilePeerRequest do
  database_path :: String
  peer_profile :: Bytes
end

struct MobileBatchRequest do
  database_path :: String
  batch :: Bytes
end

struct MobilePayloadRequest do
  database_path :: String
  payload :: Bytes
end

struct MobileTriplePayloadRequest do
  database_path :: String
  first :: Bytes
  second :: Bytes
end

struct MobileVerifiedDeviceSet do
  wire :: Bytes
  value :: DeviceSet
  account :: AccountIdentity
  profiles :: List < MobileProfile >
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

fn mobile_read_byte(value :: Bytes) -> Int ! String do
  if Bytes.length(value) != 1 do
    Err("invalid_integer")
  else
    Ok(List.head(Bytes.to_list(value)))
  end
end

fn mobile_read_u32(value :: Bytes) -> Int ! String do
  if Bytes.length(value) != 4 do
    Err("invalid_integer")
  else
    case Bytes.read_u32_be(value, 0) do
      Err( _) -> Err("invalid_integer")
      Ok( wide) -> case U64.to_int(wide) do
        Err( _) -> Err("invalid_integer")
        Ok( number) -> Ok(number)
      end
    end
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

fn local_context(label :: String) -> Bytes ! String do
  case Bytes.repeat(0, 32) do
    Err( _) -> Err("storage_context_failed")
    Ok( account_id) -> case Bytes.repeat(0, 16) do
      Err( _) -> Err("storage_context_failed")
      Ok( device_id) -> context(account_id, device_id, label, 14)
    end
  end
end

fn pending_context(label :: String, purpose :: Int) -> Bytes ! String do
  case Bytes.repeat(0, 32) do
    Err( _) -> Err("storage_context_failed")
    Ok( account_id) -> case Bytes.repeat(0, 16) do
      Err( _) -> Err("storage_context_failed")
      Ok( device_id) -> context(account_id, device_id, label, purpose)
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

fn open_signing(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> SigningPrivateKey ! String do
  case SigningPrivateKey.unseal_from_storage(blob, wrapping_key, value_context) do
    Err( _) -> Err("identity_open_failed")
    Ok( key) -> Ok(key)
  end
end

fn open_x25519(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> X25519PrivateKey ! String do
  case X25519PrivateKey.unseal_from_storage(blob, wrapping_key, value_context) do
    Err( _) -> Err("identity_open_failed")
    Ok( key) -> Ok(key)
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

fn put_blob(database :: SqliteConn, label :: String, blob :: Bytes) -> Result <(), String > do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.execute(database,
  "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP",
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

fn delete_blob(database :: SqliteConn, label :: String) -> Result <(), String > do
  let record_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(label)))
  case Sqlite.execute(database, "DELETE FROM encrypted_blobs WHERE record_hash = ?", [record_hash]) do
    Err( _) -> Err("database_write_failed")
    Ok( _) -> Ok(nil)
  end
end

fn delete_blobs(database :: SqliteConn, labels :: List < String >, index :: Int) -> Result <(), String > do
  if index >= List.length(labels) do
    Ok(nil)
  else
    delete_blob(database, List.get(labels, index)) ?
    delete_blobs(database, labels, index + 1)
  end
end

fn store_linked_blobs(database_path :: String, labels :: List < String >, blobs :: List < Bytes >) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blobs(database, labels, blobs, 0) do
          Err( error) -> Err(error)
          Ok( _) -> case delete_blobs(database,
          ["pending-link-request/v1", "pending-device-signing-key/v1", "pending-device-identity-key/v1"],
          0) do
            Err( error) -> Err(error)
            Ok( _) -> case Sqlite.commit(database) do
              Err( _) -> Err("database_write_failed")
              Ok( _) -> Ok(nil)
            end
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
    let profile_blob = seal_local(profile, wrapping_key, local_context("profile/v1") ?) ?
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
    open_local(load_blob(database_path, "profile/v1") ?,
    wrapping_key,
    local_context("profile/v1") ?)
  end
end

fn parse_profile(encoded :: Bytes) -> MobileProfile ! String do
  case reader(encoded, 16384) do
    Err( _) -> Err("invalid_profile")
    Ok( state) -> do
      let username_bytes = take_vector(state, 64) ?
      let account_id = take_vector(username_bytes.state, 32) ?
      let device_id = take_vector(account_id.state, 16) ?
      let entry_bytes = take_vector(device_id.state, 15000) ?
      case finish(entry_bytes.state) do
        Err( _) -> Err("invalid_profile")
        Ok( _) -> do
          let username = mobile_utf8(username_bytes.value, "invalid_profile") ?
          let entry = case decode_directory_entry(entry_bytes.value) do
            Err( _) -> Err("invalid_profile")
            Ok( value) -> Ok(value)
          end ?
          let account = case decode_account_identity(entry.account_identity) do
            Err( _) -> Err("invalid_profile")
            Ok( value) -> Ok(value)
          end ?
          let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
            Err( _) -> Err("invalid_profile")
            Ok( value) -> Ok(value)
          end ?
          let credential = case decode_device_credential(bundle.device_credential) do
            Err( _) -> Err("invalid_profile")
            Ok( value) -> Ok(value)
          end ?
          let mismatch = entry.username != username || !Bytes.secure_equals(account_id.value,
          account.account_id) || !Bytes.secure_equals(device_id.value, credential.device_id) || !Bytes.secure_equals(account.account_id,
          credential.account_id)
          if mismatch do
            Err("invalid_profile")
          else
            Ok(MobileProfile {
              encoded : encoded,
              username : username,
              account_id : account_id.value,
              device_id : device_id.value,
              entry : entry,
              account : account,
              bundle : bundle,
              credential : credential
            })
          end
        end
      end
    end
  end
end

fn peer_account_id(reference :: Bytes) -> Bytes ! String do
  if Bytes.length(reference) == 32 do
    Ok(reference)
  else
    Ok(parse_profile(reference) ?.account_id)
  end
end

fn parse_start_request(input :: Bytes) -> MobileStartRequest ! String do
  case reader(input, 53260) do
    Err( _) -> Err("invalid_start_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_profile = take_vector(path.state, 16384) ?
      let body = take_vector(peer_profile.state, 32768) ?
      case finish(body.state) do
        Err( _) -> Err("invalid_start_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(body.value) == 0 do
            Err("invalid_start_request")
          else
            Ok(MobileStartRequest {
              database_path : database_path,
              peer_profile : peer_profile.value,
              body : body.value
            })
          end
        end
      end
    end
  end
end

fn parse_receive_request(input :: Bytes) -> MobileReceiveRequest ! String do
  case reader(input, 69710) do
    Err( _) -> Err("invalid_receive_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let outer = take_vector(path.state, 65606) ?
      case finish(outer.state) do
        Err( _) -> Err("invalid_receive_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 do
            Err("invalid_receive_request")
          else
            Ok(MobileReceiveRequest {
              database_path : database_path,
              outer : outer.value
            })
          end
        end
      end
    end
  end
end

fn parse_policy_request(input :: Bytes) -> MobilePolicyRequest ! String do
  case reader(input, 20532) do
    Err( _) -> Err("invalid_policy_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_profile = take_vector(path.state, 16384) ?
      let action = take_vector(peer_profile.state, 1) ?
      let value = take_vector(action.state, 4) ?
      case finish(value.state) do
        Err( _) -> Err("invalid_policy_request")
        Ok( _) -> Ok(MobilePolicyRequest {
          database_path : mobile_utf8(path.value, "invalid_database_path") ?,
          peer_profile : peer_profile.value,
          action : mobile_read_byte(action.value) ?,
          value : mobile_read_u32(value.value) ?
        })
      end
    end
  end
end

fn parse_peer_request(input :: Bytes) -> MobilePeerRequest ! String do
  case reader(input, 20488) do
    Err( _) -> Err("invalid_peer_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_profile = take_vector(path.state, 16384) ?
      case finish(peer_profile.state) do
        Err( _) -> Err("invalid_peer_request")
        Ok( _) -> Ok(MobilePeerRequest {
          database_path : mobile_utf8(path.value, "invalid_database_path") ?,
          peer_profile : peer_profile.value
        })
      end
    end
  end
end

fn parse_batch_request(input :: Bytes) -> MobileBatchRequest ! String do
  case reader(input, 604104) do
    Err( _) -> Err("invalid_batch_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let batch = take_vector(path.state, 600000) ?
      case finish(batch.state) do
        Err( _) -> Err("invalid_batch_request")
        Ok( _) -> Ok(MobileBatchRequest {
          database_path : mobile_utf8(path.value, "invalid_database_path") ?,
          batch : batch.value
        })
      end
    end
  end
end

fn parse_payload_request(input :: Bytes) -> MobilePayloadRequest ! String do
  case reader(input, 290504) do
    Err( _) -> Err("invalid_payload_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let payload = take_vector(path.state, 286400) ?
      case finish(payload.state) do
        Err( _) -> Err("invalid_payload_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(payload.value) == 0 do
            Err("invalid_payload_request")
          else
            Ok(MobilePayloadRequest {
              database_path : database_path,
              payload : payload.value
            })
          end
        end
      end
    end
  end
end

fn parse_triple_payload_request(input :: Bytes) -> MobileTriplePayloadRequest ! String do
  case reader(input, 577000) do
    Err( _) -> Err("invalid_payload_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let first = take_vector(path.state, 286400) ?
      let second = take_vector(first.state, 286400) ?
      case finish(second.state) do
        Err( _) -> Err("invalid_payload_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(first.value) == 0 || Bytes.length(second.value) == 0 do
            Err("invalid_payload_request")
          else
            Ok(MobileTriplePayloadRequest {
              database_path : database_path,
              first : first.value,
              second : second.value
            })
          end
        end
      end
    end
  end
end

fn current_time() -> U64 ! String do
  mobile_wide(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))
end

fn random_bytes(length :: Int) -> Bytes ! String do
  case Crypto.random_bytes(length) do
    Err( _) -> Err("random_generation_failed")
    Ok( value) -> Ok(value)
  end
end

fn policy(profile :: MobileProfile, now :: U64) -> VerificationPolicy do
  VerificationPolicy {
    current_time : now,
    minimum_directory_sequence : profile.account.directory_sequence
  }
end

fn reject_device_open(signing :: consume SigningPrivateKey, error :: String) -> DeviceKeys ! String do
  Err(error)
end

fn open_account(profile :: MobileProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> AccountKeys ! String do
  let account_blob = load_blob(database_path, "account-signing-key/v1") ?
  case open_signing(account_blob,
  wrapping_key,
  context(profile.account_id, profile.device_id, "account-signing-key/v1", 6) ?) do
    Err( error) -> Err(error)
    Ok( private_key) -> Ok(AccountKeys {
      account_id : profile.account_id,
      private_key : private_key,
      public_key : SigningPublicKey { bytes : profile.account.authorization_public_key }
    })
  end
end

fn reject_prekey_open(signed_private :: consume X25519PrivateKey, error :: String) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets), String > do
  Err(error)
end

fn open_device(profile :: MobileProfile, wrapping_key :: borrow StorageKey, database_path :: String) -> DeviceKeys ! String do
  let signing_blob = load_blob(database_path, "device-signing-key/v1") ?
  let identity_blob = load_blob(database_path, "device-identity-key/v1") ?
  let signing_context = context(profile.account_id, profile.device_id, "device-signing-key/v1", 7) ?
  let identity_context = context(profile.account_id, profile.device_id, "device-identity-key/v1", 8) ?
  case open_signing(signing_blob, wrapping_key, signing_context) do
    Err( error) -> Err(error)
    Ok( signing) -> case open_x25519(identity_blob, wrapping_key, identity_context) do
      Err( error) -> reject_device_open(signing, error)
      Ok( identity) -> Ok(DeviceKeys {
        device_id : profile.device_id,
        signing_private_key : signing,
        signing_public_key : SigningPublicKey { bytes : profile.credential.signing_public_key },
        identity_private_key : identity,
        identity_public_key : X25519PublicKey { bytes : profile.credential.dh_public_key }
      })
    end
  end
end

fn open_pending_device(request :: DeviceLinkRequest,
wrapping_key :: borrow StorageKey,
database_path :: String) -> DeviceKeys ! String do
  let signing_blob = load_blob(database_path, "pending-device-signing-key/v1") ?
  let identity_blob = load_blob(database_path, "pending-device-identity-key/v1") ?
  case open_signing(signing_blob,
  wrapping_key,
  pending_context("pending-device-signing-key/v1", 7) ?) do
    Err( error) -> Err(error)
    Ok( signing) -> case open_x25519(identity_blob,
    wrapping_key,
    pending_context("pending-device-identity-key/v1", 8) ?) do
      Err( error) -> reject_device_open(signing, error)
      Ok( identity) -> Ok(DeviceKeys {
        device_id : request.device_id,
        signing_private_key : signing,
        signing_public_key : SigningPublicKey { bytes : request.signing_public_key },
        identity_private_key : identity,
        identity_public_key : X25519PublicKey { bytes : request.dh_public_key }
      })
    end
  end
end

fn open_prekeys(profile :: MobileProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets), String > do
  let signed_blob = load_blob(database_path, "signed-prekey/v1") ?
  let one_time_blob = load_blob(database_path, "one-time-prekey/v1") ?
  let signed_context = context(profile.account_id, profile.device_id, "signed-prekey/v1", 9) ?
  let one_time_context = context(profile.account_id, profile.device_id, "one-time-prekey/v1", 10) ?
  case open_x25519(signed_blob, wrapping_key, signed_context) do
    Err( error) -> Err(error)
    Ok( signed_private) -> case open_x25519(one_time_blob, wrapping_key, one_time_context) do
      Err( error) -> reject_prekey_open(signed_private, error)
      Ok( one_time_private) -> Ok((SignedPrekeySecrets {
        id : profile.bundle.signed_prekey_id,
        private_key : signed_private,
        public_key : X25519PublicKey { bytes : profile.bundle.signed_prekey },
        signature : Signature { bytes : profile.bundle.signed_prekey_signature },
        expires_at : profile.bundle.expires_at
      },
      OneTimePrekeySecrets {
        id : profile.bundle.one_time_prekey_id,
        private_key : one_time_private,
        public_key : X25519PublicKey { bytes : profile.bundle.one_time_prekey }
      }))
    end
  end
end

fn link_request_bytes(value :: DeviceLinkRequest) -> Bytes ! String do
  case encode_device_link_request(value) do
    Err( _) -> Err("link_request_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn parse_link_request(input :: Bytes) -> DeviceLinkRequest ! String do
  case decode_device_link_request(input) do
    Err( _) -> Err("invalid_link_request")
    Ok( value) -> if Bytes.secure_equals(link_request_bytes(value) ?, input) do
      Ok(value)
    else
      Err("noncanonical_link_request")
    end
  end
end

fn link_authorization_bytes(value :: DeviceLinkAuthorization) -> Bytes ! String do
  case encode_device_link_authorization(value) do
    Err( _) -> Err("link_authorization_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn parse_link_authorization(input :: Bytes) -> DeviceLinkAuthorization ! String do
  case decode_device_link_authorization(input) do
    Err( _) -> Err("invalid_link_authorization")
    Ok( value) -> if Bytes.secure_equals(link_authorization_bytes(value) ?, input) do
      Ok(value)
    else
      Err("noncanonical_link_authorization")
    end
  end
end

fn load_pending_link_request(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  open_local(load_blob(database_path, "pending-link-request/v1") ?,
  wrapping_key,
  local_context("pending-link-request/v1") ?)
end

fn create_device_link_request(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    ensure_account_missing(database_path) ?
    let wrapping_key = platform_key() ?
    case load_pending_link_request(database_path, wrapping_key) do
      Ok( existing) -> do
        let pending = parse_link_request(existing) ?
        if U64.compare(pending.expires_at, current_time() ?) >= 0 do
          Ok(existing)
        else
          store_linked_blobs(database_path, List.new(), List.new()) ?
          create_device_link_request(database_path)
        end
      end
      Err( error) -> if error != "local_state_not_found" do
        Err(error)
      else
        let now = current_time() ?
        let device = device_keys() ?
        let request = DeviceLinkRequest {
          version : 1,
          nonce : random_bytes(32) ?,
          device_id : device.device_id,
          signing_public_key : device.signing_public_key.bytes,
          dh_public_key : device.identity_public_key.bytes,
          capabilities : mobile_wide("1") ?,
          created_at : now,
          expires_at : U64.add(now, mobile_wide("600000") ?) ?
        }
        let request_wire = link_request_bytes(request) ?
        let request_blob = seal_local(request_wire,
        wrapping_key,
        local_context("pending-link-request/v1") ?) ?
        let signing_blob = seal_signing(device.signing_private_key,
        wrapping_key,
        pending_context("pending-device-signing-key/v1", 7) ?) ?
        let identity_blob = seal_x25519(device.identity_private_key,
        wrapping_key,
        pending_context("pending-device-identity-key/v1", 8) ?) ?
        store_blobs(database_path,
        ["pending-link-request/v1", "pending-device-signing-key/v1", "pending-device-identity-key/v1"],
        [request_blob, signing_blob, identity_blob]) ?
        Ok(request_wire)
      end
    end
  end
end

fn authorize_link(request :: MobilePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = parse_profile(load_profile(request.database_path) ?) ?
  let requested_device = parse_link_request(request.payload) ?
  let now = current_time() ?
  if U64.compare(requested_device.created_at, now) > 0 || U64.compare(requested_device.expires_at,
  now) < 0 do
    Err("link_request_expired")
  else
    let wrapping_key = platform_key() ?
    let account = open_account(local, wrapping_key, request.database_path) ?
    let authorization = case authorize_device_link(account,
    local.account,
    requested_device,
    local.username,
    U64.add(now, mobile_wide("31536000000") ?) ?,
    U64.add(local.account.directory_sequence, mobile_wide("1") ?) ?) do
      Err( _) -> Err("link_authorization_failed")
      Ok( value) -> Ok(value)
    end ?
    link_authorization_bytes(authorization)
  end
end

fn complete_link(request :: MobilePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  ensure_account_missing(request.database_path) ?
  let authorization = parse_link_authorization(request.payload) ?
  let wrapping_key = platform_key() ?
  let pending_wire = load_pending_link_request(request.database_path, wrapping_key) ?
  let pending = parse_link_request(pending_wire) ?
  let now = current_time() ?
  let valid = case verify_device_link_authorization(pending, authorization, now, mobile_wide("1") ?) do
    Err( _) -> Err("link_authorization_failed")
    Ok( value) -> Ok(value)
  end ?
  if !valid do
    Err("link_authorization_failed")
  else
    let account = case decode_account_identity(authorization.account_identity) do
      Err( _) -> Err("invalid_link_authorization")
      Ok( value) -> Ok(value)
    end ?
    let credential = case decode_device_credential(authorization.device_credential) do
      Err( _) -> Err("invalid_link_authorization")
      Ok( value) -> Ok(value)
    end ?
    let device = open_pending_device(pending, wrapping_key, request.database_path) ?
    let signed = case generate_signed_prekey(device,
    credential,
    mobile_wide("1") ?,
    credential.expires_at) do
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
    let entry = DirectoryEntry {
      version : 1,
      username : authorization.username,
      account_identity : authorization.account_identity,
      prekey_bundle : case encode_prekey_bundle(bundle) do
        Err( _) -> Err("prekey_encoding_failed")
        Ok( value) -> Ok(value)
      end ?,
      mailbox_token : random_bytes(32) ?
    }
    let profile = profile_bytes(entry, account.account_id, credential.device_id) ?
    let signing_blob = seal_signing(device.signing_private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "device-signing-key/v1", 7) ?) ?
    let identity_blob = seal_x25519(device.identity_private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "device-identity-key/v1", 8) ?) ?
    let signed_prekey_blob = seal_x25519(signed.private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "signed-prekey/v1", 9) ?) ?
    let one_time_prekey_blob = seal_x25519(one_time.private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "one-time-prekey/v1", 10) ?) ?
    let profile_blob = seal_local(profile, wrapping_key, local_context("profile/v1") ?) ?
    store_linked_blobs(request.database_path,
    ["device-signing-key/v1", "device-identity-key/v1", "signed-prekey/v1", "one-time-prekey/v1", "profile/v1"],
    [signing_blob, identity_blob, signed_prekey_blob, one_time_prekey_blob, profile_blob]) ?
    Ok(profile)
  end
end

fn device_link_sas(input :: Bytes) -> Bytes ! String do
  let request = parse_link_request(input) ?
  let digest = Crypto.sha256(link_request_bytes(request) ?)
  case Bytes.slice(digest, 0, 6) do
    Err( _) -> Err("link_sas_failed")
    Ok( value) -> Ok(Bytes.from_utf8(Bytes.to_hex(value)))
  end
end

fn device_set_bytes(value :: DeviceSet) -> Bytes ! String do
  case encode_device_set(value) do
    Err( _) -> Err("device_set_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn canonical_device_set(input :: Bytes) -> DeviceSet ! String do
  case decode_device_set(input) do
    Err( _) -> Err("invalid_device_set")
    Ok( value) -> if Bytes.secure_equals(device_set_bytes(value) ?, input) do
      Ok(value)
    else
      Err("noncanonical_device_set")
    end
  end
end

fn contains_device_id(profiles :: List < MobileProfile >, device_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(profiles) do
    false
  else if Bytes.secure_equals(List.get(profiles, index).device_id, device_id) do
    true
  else
    contains_device_id(profiles, device_id, index + 1)
  end
end

fn contains_revoked_id(values :: List < Bytes >, device_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), device_id) do
    true
  else
    contains_revoked_id(values, device_id, index + 1)
  end
end

fn verified_device_profiles(value :: DeviceSet,
account :: AccountIdentity,
now :: U64,
index :: Int,
profiles :: List < MobileProfile >) -> List < MobileProfile > ! String do
  if index >= List.length(value.devices) do
    Ok(profiles)
  else
    let entry = List.get(value.devices, index)
    let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
      Err( _) -> Err("invalid_device_set")
      Ok( decoded) -> Ok(decoded)
    end ?
    let credential = case decode_device_credential(bundle.device_credential) do
      Err( _) -> Err("invalid_device_set")
      Ok( decoded) -> Ok(decoded)
    end ?
    let verified = case verify_prekey_bundle(account, bundle, 1, now, account.directory_sequence) do
      Err( _) -> false
      Ok( result) -> result
    end
    let profile = parse_profile(profile_bytes(entry, account.account_id, credential.device_id) ?) ?
    let invalid = !verified || contains_device_id(profiles, profile.device_id, 0) || contains_revoked_id(value.revoked_device_ids,
    profile.device_id,
    0)
    if invalid do
      Err("invalid_device_set")
    else
      verified_device_profiles(value, account, now, index + 1, List.append(profiles, profile))
    end
  end
end

fn verified_device_set(input :: Bytes) -> MobileVerifiedDeviceSet ! String do
  let value = canonical_device_set(input) ?
  let account = case decode_account_identity(value.account_identity) do
    Err( _) -> Err("invalid_device_set")
    Ok( decoded) -> Ok(decoded)
  end ?
  if U64.compare(value.sequence, account.directory_sequence) < 0 do
    Err("device_set_rollback")
  else
    Ok(MobileVerifiedDeviceSet {
      wire : input,
      value : value,
      account : account,
      profiles : verified_device_profiles(value, account, current_time() ?, 0, List.new()) ?
    })
  end
end

fn device_set_label(account_id :: Bytes) -> String do
  "device-set/v1/#{Bytes.to_hex(account_id)}"
end

fn cached_device_set_changed(database_path :: String,
wrapping_key :: borrow StorageKey,
next :: MobileVerifiedDeviceSet,
label :: String) -> Bool ! String do
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok( blob) -> do
      let previous_wire = open_local(blob, wrapping_key, local_context(label) ?) ?
      let previous = canonical_device_set(previous_wire) ?
      let same_identity = previous.username == next.value.username && Bytes.secure_equals(previous.account_identity,
      next.value.account_identity)
      let sequence = U64.compare(next.value.sequence, previous.sequence)
      if !same_identity || sequence < 0 do
        Err("device_set_rollback")
      else if sequence == 0 && !Bytes.secure_equals(previous_wire, next.wire) do
        Err("device_set_equivocation")
      else
        Ok(sequence > 0)
      end
    end
  end
end

fn active_device_rows(profiles :: List < MobileProfile >,
local_device_id :: Bytes,
index :: Int,
rows :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(profiles) do
    Ok(rows)
  else
    let profile = List.get(profiles, index)
    let row = mobile_join([mobile_vector(profile.device_id) ?, mobile_vector(mobile_byte(1) ?) ?, mobile_vector(mobile_byte(if Bytes.secure_equals(profile.device_id,
    local_device_id) do
      1
    else
      0
    end) ?) ?],
    0,
    Bytes.empty()) ?
    active_device_rows(profiles, local_device_id, index + 1, List.append(rows, row))
  end
end

fn revoked_device_rows(values :: List < Bytes >, index :: Int, rows :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(values) do
    Ok(rows)
  else
    let row = mobile_join([mobile_vector(List.get(values, index)) ?, mobile_vector(mobile_byte(0) ?) ?, mobile_vector(mobile_byte(0) ?) ?],
    0,
    Bytes.empty()) ?
    revoked_device_rows(values, index + 1, List.append(rows, row))
  end
end

fn inspect_device_set(request :: MobilePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = parse_profile(load_profile(request.database_path) ?) ?
  let verified = verified_device_set(request.payload) ?
  let wrapping_key = platform_key() ?
  let label = device_set_label(verified.account.account_id)
  let changed = cached_device_set_changed(request.database_path, wrapping_key, verified, label) ?
  let sealed = seal_local(verified.wire, wrapping_key, local_context(label) ?) ?
  store_updated_session(request.database_path, label, sealed) ?
  let can_manage = case load_blob(request.database_path, "account-signing-key/v1") do
    Err( error) -> if error == "local_state_not_found" do
      Ok(false)
    else
      Err(error)
    end
    Ok( _) -> Ok(true)
  end ?
  let active = active_device_rows(verified.profiles, local.device_id, 0, List.new()) ?
  let rows = revoked_device_rows(verified.value.revoked_device_ids, 0, active) ?
  mobile_join([mobile_vector(Bytes.from_utf8(verified.value.username)) ?, mobile_vector(verified.account.account_id) ?, mobile_vector(mobile_write_u64(verified.value.sequence) ?) ?, mobile_vector(mobile_byte(if changed do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if can_manage do
    1
  else
    0
  end) ?) ?, mobile_vector(encode_output_list(rows) ?) ?],
  0,
  Bytes.empty())
end

fn local_device_set(local :: MobileProfile, value :: MobileVerifiedDeviceSet) -> Bool do
  local.username == value.value.username && Bytes.secure_equals(local.account_id,
  value.account.account_id) && Bytes.secure_equals(local.entry.account_identity,
  value.value.account_identity) && contains_device_id(value.profiles, local.device_id, 0)
end

fn authorize_link_for_set(request :: MobileTriplePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = parse_profile(load_profile(request.database_path) ?) ?
  let devices = verified_device_set(request.first) ?
  let requested_device = parse_link_request(request.second) ?
  let now = current_time() ?
  if !local_device_set(local, devices) || U64.compare(requested_device.created_at, now) > 0 || U64.compare(requested_device.expires_at,
  now) < 0 do
    Err("link_authorization_failed")
  else
    let wrapping_key = platform_key() ?
    let account = open_account(local, wrapping_key, request.database_path) ?
    let authorization = case authorize_device_link(account,
    local.account,
    requested_device,
    local.username,
    U64.add(now, mobile_wide("31536000000") ?) ?,
    U64.add(devices.value.sequence, mobile_wide("1") ?) ?) do
      Err( _) -> Err("link_authorization_failed")
      Ok( value) -> Ok(value)
    end ?
    link_authorization_bytes(authorization)
  end
end

fn create_device_revocation(request :: MobileTriplePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = parse_profile(load_profile(request.database_path) ?) ?
  let devices = verified_device_set(request.first) ?
  let target = request.second
  let allowed = Bytes.length(target) == 16 && local_device_set(local, devices) && List.length(devices.profiles) > 1 && contains_device_id(devices.profiles,
  target,
  0) && !Bytes.secure_equals(local.device_id, target)
  if !allowed do
    Err("invalid_device_revocation")
  else
    let wrapping_key = platform_key() ?
    let account = open_account(local, wrapping_key, request.database_path) ?
    let revocation = case issue_device_revocation(account,
    target,
    U64.add(devices.value.sequence, mobile_wide("1") ?) ?) do
      Err( _) -> Err("invalid_device_revocation")
      Ok( value) -> Ok(value)
    end ?
    case encode_device_revocation(revocation) do
      Err( _) -> Err("invalid_device_revocation")
      Ok( encoded) -> Ok(encoded)
    end
  end
end

fn inner_bytes(value :: InnerEnvelope) -> Bytes ! String do
  case encode_inner_envelope(value) do
    Err( _) -> Err("inner_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn initial_bytes(value :: InitialMessage) -> Bytes ! String do
  case encode_initial_message(value) do
    Err( _) -> Err("initial_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn encode_initial_packet(account_identity :: Bytes, message :: Bytes) -> Bytes ! String do
  mobile_join([mobile_vector(mobile_byte(1) ?) ?, mobile_vector(account_identity) ?, mobile_vector(message) ?],
  0,
  Bytes.empty())
end

fn parse_initial_packet(input :: Bytes) -> MobileInitialPacket ! String do
  case reader(input, 65536) do
    Err( _) -> Err("invalid_initial_packet")
    Ok( state) -> do
      let kind = take_vector(state, 1) ?
      let account_identity = take_vector(kind.state, 4096) ?
      let message = take_vector(account_identity.state, 60000) ?
      case finish(message.state) do
        Err( _) -> Err("invalid_initial_packet")
        Ok( _) -> if !Bytes.secure_equals(kind.value, mobile_byte(1) ?) do
          Err("invalid_initial_packet")
        else
          Ok(MobileInitialPacket {
            account_identity : account_identity.value,
            message : message.value
          })
        end
      end
    end
  end
end

fn encode_initial_plaintext(profile :: Bytes, inner :: Bytes) -> Bytes ! String do
  mobile_join([mobile_vector(profile) ?, mobile_vector(inner) ?], 0, Bytes.empty())
end

fn parse_initial_plaintext(input :: Bytes) -> MobileInitialPlaintext ! String do
  case reader(input, 65536) do
    Err( _) -> Err("invalid_initial_plaintext")
    Ok( state) -> do
      let profile = take_vector(state, 16384) ?
      let inner = take_vector(profile.state, 49144) ?
      case finish(inner.state) do
        Err( _) -> Err("invalid_initial_plaintext")
        Ok( _) -> Ok(MobileInitialPlaintext {
          profile : profile.value,
          inner : inner.value
        })
      end
    end
  end
end

fn session_label(session_id :: Bytes) -> String do
  "session/v1/#{Bytes.to_hex(session_id)}"
end

fn encode_session_record(snapshot_blob :: Bytes,
local :: MobileProfile,
peer :: MobileProfile,
conversation_id :: Bytes,
request_state :: Int,
key_changed :: Bool) -> Bytes ! String do
  mobile_join([mobile_vector(snapshot_blob) ?, mobile_vector(local.account_id) ?, mobile_vector(local.device_id) ?, mobile_vector(peer.account_id) ?, mobile_vector(peer.device_id) ?, mobile_vector(Bytes.from_utf8(peer.username)) ?, mobile_vector(peer.entry.mailbox_token) ?, mobile_vector(conversation_id) ?, mobile_vector(mobile_byte(request_state) ?) ?, mobile_vector(mobile_byte(0) ?) ?, mobile_vector(mobile_byte(0) ?) ?, mobile_vector(mobile_byte(if key_changed do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_write_u32(0) ?) ?],
  0,
  Bytes.empty())
end

fn parse_session_record(input :: Bytes) -> MobileSessionRecord ! String do
  case reader(input, 68000) do
    Err( _) -> Err("invalid_session_record")
    Ok( state) -> do
      let snapshot_blob = take_vector(state, 66300) ?
      let local_account_id = take_vector(snapshot_blob.state, 32) ?
      let local_device_id = take_vector(local_account_id.state, 16) ?
      let peer_account_id = take_vector(local_device_id.state, 32) ?
      let peer_device_id = take_vector(peer_account_id.state, 16) ?
      let peer_username = take_vector(peer_device_id.state, 64) ?
      let peer_mailbox = take_vector(peer_username.state, 32) ?
      let conversation_id = take_vector(peer_mailbox.state, 16) ?
      let request_state = take_vector(conversation_id.state, 1) ?
      let blocked = take_vector(request_state.state, 1) ?
      let verified = take_vector(blocked.state, 1) ?
      let key_changed = take_vector(verified.state, 1) ?
      let disappearing_seconds = take_vector(key_changed.state, 4) ?
      case finish(disappearing_seconds.state) do
        Err( _) -> Err("invalid_session_record")
        Ok( _) -> do
          let username = mobile_utf8(peer_username.value, "invalid_session_record") ?
          let request_value = mobile_read_byte(request_state.value) ?
          let blocked_value = mobile_read_byte(blocked.value) ?
          let verified_value = mobile_read_byte(verified.value) ?
          let changed_value = mobile_read_byte(key_changed.value) ?
          let disappearing_value = mobile_read_u32(disappearing_seconds.value) ?
          let valid = Bytes.length(local_account_id.value) == 32 && Bytes.length(local_device_id.value) == 16 && Bytes.length(peer_account_id.value) == 32 && Bytes.length(peer_device_id.value) == 16 && String.length(username) > 0 && Bytes.length(peer_mailbox.value) == 32 && Bytes.length(conversation_id.value) == 16 && (request_value == 0 || request_value == 1) && blocked_value <= 1 && verified_value <= 1 && changed_value <= 1
          if !valid do
            Err("invalid_session_record")
          else
            Ok(MobileSessionRecord {
              snapshot : snapshot_blob.value,
              local_account_id : local_account_id.value,
              local_device_id : local_device_id.value,
              peer_account_id : peer_account_id.value,
              peer_device_id : peer_device_id.value,
              peer_username : username,
              peer_mailbox : peer_mailbox.value,
              conversation_id : conversation_id.value,
              request_state : request_value,
              blocked : blocked_value == 1,
              verified : verified_value == 1,
              key_changed : changed_value == 1,
              disappearing_seconds : disappearing_value
            })
          end
        end
      end
    end
  end
end

fn read_session_ids(encoded :: Bytes, offset :: Int, values :: List < Bytes >) -> List < Bytes > ! String do
  if offset >= Bytes.length(encoded) do
    Ok(values)
  else
    case Bytes.slice(encoded, offset, 32) do
      Err( _) -> Err("invalid_session_index")
      Ok( value) -> read_session_ids(encoded, offset + 32, List.append(values, value))
    end
  end
end

fn decode_session_ids(encoded :: Bytes) -> List < Bytes > ! String do
  if Bytes.length(encoded) % 32 != 0 do
    Err("invalid_session_index")
  else
    read_session_ids(encoded, 0, List.new())
  end
end

fn contains_session_id(values :: List < Bytes >, session_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), session_id) do
    true
  else
    contains_session_id(values, session_id, index + 1)
  end
end

fn load_session_ids(database_path :: String, wrapping_key :: borrow StorageKey) -> List < Bytes > ! String do
  case load_blob(database_path, "sessions/v1") do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> decode_session_ids(open_local(blob, wrapping_key, local_context("sessions/v1") ?) ?)
  end
end

fn updated_session_index(database_path :: String,
wrapping_key :: borrow StorageKey,
session_id :: Bytes) -> Bytes ! String do
  let existing = load_session_ids(database_path, wrapping_key) ?
  let encoded = if contains_session_id(existing, session_id, 0) do
    mobile_join(existing, 0, Bytes.empty()) ?
  else
    mobile_join(List.append(existing, session_id), 0, Bytes.empty()) ?
  end
  seal_local(encoded, wrapping_key, local_context("sessions/v1") ?)
end

fn load_session_record(database_path :: String,
wrapping_key :: borrow StorageKey,
session_id :: Bytes) -> MobileLoadedSession ! String do
  let label = session_label(session_id)
  let record = open_local(load_blob(database_path, label) ?, wrapping_key, local_context(label) ?) ?
  Ok(MobileLoadedSession {
    session_id : session_id,
    label : label,
    record : parse_session_record(record) ?
  })
end

# ponytail: the MVP scans encrypted session IDs; add an encrypted peer index if measured conversation counts make this slow.

fn find_peer_session(database_path :: String,
wrapping_key :: borrow StorageKey,
peer_account_id :: Bytes,
session_ids :: List < Bytes >,
index :: Int) -> MobileLoadedSession ! String do
  if index >= List.length(session_ids) do
    Err("session_not_found")
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) do
      Ok(loaded)
    else
      find_peer_session(database_path, wrapping_key, peer_account_id, session_ids, index + 1)
    end
  end
end

fn history_label(conversation_id :: Bytes) -> String do
  "history/v1/#{Bytes.to_hex(conversation_id)}"
end

fn encode_history_entry(value :: MobileHistoryEntry) -> Bytes ! String do
  mobile_join([mobile_vector(mobile_byte(value.direction) ?) ?, mobile_vector(inner_bytes(value.inner) ?) ?],
  0,
  Bytes.empty())
end

fn encode_history_parts(values :: List < MobileHistoryEntry >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_history_parts(values,
    index + 1,
    mobile_append(output, mobile_vector(encode_history_entry(List.get(values, index)) ?) ?) ?)
  end
end

fn encode_history(values :: List < MobileHistoryEntry >) -> Bytes ! String do
  let bounded = if List.length(values) > 256 do
    List.drop(values, List.length(values) - 256)
  else
    values
  end
  encode_history_parts(bounded, 0, mobile_vector(mobile_write_u32(List.length(bounded)) ?) ?)
end

fn parse_history_entry(input :: Bytes) -> MobileHistoryEntry ! String do
  case reader(input, 65600) do
    Err( _) -> Err("invalid_history")
    Ok( state) -> do
      let direction = take_vector(state, 1) ?
      let inner = take_vector(direction.state, 65536) ?
      case finish(inner.state) do
        Err( _) -> Err("invalid_history")
        Ok( _) -> do
          let direction_value = mobile_read_byte(direction.value) ?
          if direction_value != 1 && direction_value != 2 do
            Err("invalid_history")
          else
            case decode_inner_envelope(inner.value) do
              Err( _) -> Err("invalid_history")
              Ok( value) -> Ok(MobileHistoryEntry {
                direction : direction_value,
                inner : value
              })
            end
          end
        end
      end
    end
  end
end

fn parse_history_parts(state :: BinaryReader,
count :: Int,
index :: Int,
values :: List < MobileHistoryEntry >) -> List < MobileHistoryEntry > ! String do
  if index >= count do
    case finish(state) do
      Err( _) -> Err("invalid_history")
      Ok( _) -> Ok(values)
    end
  else
    let entry = take_vector(state, 65600) ?
    parse_history_parts(entry.state,
    count,
    index + 1,
    List.append(values, parse_history_entry(entry.value) ?))
  end
end

fn decode_history(input :: Bytes) -> List < MobileHistoryEntry > ! String do
  case reader(input, 8388608) do
    Err( _) -> Err("invalid_history")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let count_value = mobile_read_u32(count.value) ?
      if count_value > 256 do
        Err("invalid_history")
      else
        parse_history_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn load_history(database_path :: String,
wrapping_key :: borrow StorageKey,
conversation_id :: Bytes) -> List < MobileHistoryEntry > ! String do
  let label = history_label(conversation_id)
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> decode_history(open_local(blob, wrapping_key, local_context(label) ?) ?)
  end
end

fn updated_history(database_path :: String,
wrapping_key :: borrow StorageKey,
inner :: InnerEnvelope,
direction :: Int) -> Result <( String, Bytes), String > do
  let label = history_label(inner.conversation_id)
  let entries = load_history(database_path, wrapping_key, inner.conversation_id) ?
  let updated = List.append(entries,
  MobileHistoryEntry {
    direction : direction,
    inner : inner
  })
  Ok((label, seal_local(encode_history(updated) ?, wrapping_key, local_context(label) ?) ?))
end

fn encode_output_parts(values :: List < Bytes >, index :: Int, output :: Bytes) -> Bytes ! String do
  if index >= List.length(values) do
    Ok(output)
  else
    encode_output_parts(values,
    index + 1,
    mobile_append(output, mobile_vector(List.get(values, index)) ?) ?)
  end
end

fn encode_output_list(values :: List < Bytes >) -> Bytes ! String do
  encode_output_parts(values, 0, mobile_vector(mobile_write_u32(List.length(values)) ?) ?)
end

fn safety_number(session_id :: Bytes) -> Bytes ! String do
  Ok(Bytes.from_utf8(Bytes.to_hex(Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/safety/v1"),
  session_id) ?))))
end

fn conversation_summary(loaded :: MobileLoadedSession) -> Bytes ! String do
  mobile_join([mobile_vector(loaded.record.conversation_id) ?, mobile_vector(Bytes.from_utf8(loaded.record.peer_username)) ?, mobile_vector(loaded.record.peer_account_id) ?, mobile_vector(loaded.record.peer_device_id) ?, mobile_vector(safety_number(loaded.session_id) ?) ?, mobile_vector(mobile_byte(loaded.record.request_state) ?) ?, mobile_vector(mobile_byte(if loaded.record.blocked do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if loaded.record.verified do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if loaded.record.key_changed do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_write_u32(loaded.record.disappearing_seconds) ?) ?],
  0,
  Bytes.empty())
end

fn collect_conversations(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
index :: Int,
values :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(session_ids) do
    Ok(values)
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    collect_conversations(database_path,
    wrapping_key,
    session_ids,
    index + 1,
    List.append(values, conversation_summary(loaded) ?))
  end
end

fn list_conversations(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let wrapping_key = platform_key() ?
  let session_ids = load_session_ids(database_path, wrapping_key) ?
  encode_output_list(collect_conversations(database_path, wrapping_key, session_ids, 0, List.new()) ?)
end

fn message_visible(value :: MobileHistoryEntry, now :: U64) -> Bool ! String do
  if value.inner.disappearing_seconds == 0 do
    Ok(true)
  else
    let lifetime = mobile_wide(Int.to_string(value.inner.disappearing_seconds * 1000)) ?
    let expires_at = U64.add(value.inner.client_timestamp, lifetime) ?
    Ok(U64.compare(now, expires_at) < 0)
  end
end

fn visible_history(values :: List < MobileHistoryEntry >,
now :: U64,
index :: Int,
visible :: List < MobileHistoryEntry >) -> List < MobileHistoryEntry > ! String do
  if index >= List.length(values) do
    Ok(visible)
  else
    let value = List.get(values, index)
    let next = if message_visible(value, now) ? do
      List.append(visible, value)
    else
      visible
    end
    visible_history(values, now, index + 1, next)
  end
end

fn history_summary(value :: MobileHistoryEntry) -> Bytes ! String do
  mobile_join([mobile_vector(mobile_byte(value.direction) ?) ?, mobile_vector(value.inner.client_message_id) ?, mobile_vector(mobile_write_u64(value.inner.client_timestamp) ?) ?, mobile_vector(value.inner.body) ?, mobile_vector(mobile_write_u32(value.inner.disappearing_seconds) ?) ?],
  0,
  Bytes.empty())
end

fn history_summaries(values :: List < MobileHistoryEntry >,
index :: Int,
summaries :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(values) do
    Ok(summaries)
  else
    history_summaries(values,
    index + 1,
    List.append(summaries, history_summary(List.get(values, index)) ?))
  end
end

fn load_visible_history(request :: MobilePeerRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  peer_id,
  load_session_ids(request.database_path, wrapping_key) ?,
  0) ?
  let entries = load_history(request.database_path, wrapping_key, loaded.record.conversation_id) ?
  let visible = visible_history(entries, current_time() ?, 0, List.new()) ?
  if List.length(visible) != List.length(entries) do
    let label = history_label(loaded.record.conversation_id)
    let blob = seal_local(encode_history(visible) ?, wrapping_key, local_context(label) ?) ?
    store_updated_session(request.database_path, label, blob) ?
  else
    nil
  end
  encode_output_list(history_summaries(visible, 0, List.new()) ?)
end

fn conversation_safety(request :: MobilePeerRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  peer_id,
  load_session_ids(request.database_path, wrapping_key) ?,
  0) ?
  safety_number(loaded.session_id)
end

fn reject_session_snapshot(state :: consume RatchetState) -> Result <( Bytes, String, Bytes), String > do
  Err("session_snapshot_failed")
end

fn finish_session_snapshot(state :: consume RatchetState,
snapshot_blob :: Bytes,
wrapping_key :: borrow StorageKey,
local :: MobileProfile,
peer :: MobileProfile,
conversation_id :: Bytes,
request_state :: Int,
key_changed :: Bool,
session_id :: Bytes,
label :: String) -> Result <( Bytes, String, Bytes), String > do
  let record = encode_session_record(snapshot_blob,
  local,
  peer,
  conversation_id,
  request_state,
  key_changed) ?
  Ok((session_id, label, seal_local(record, wrapping_key, local_context(label) ?) ?))
end

fn seal_session(state :: consume RatchetState,
wrapping_key :: borrow StorageKey,
local :: MobileProfile,
peer :: MobileProfile,
conversation_id :: Bytes,
request_state :: Int,
key_changed :: Bool) -> Result <( Bytes, String, Bytes), String > do
  let session_id = state.session_id
  let label = session_label(session_id)
  case snapshot(state, wrapping_key, local.account_id, local.device_id, mobile_wide("1") ?) do
    SnapshotRejected( rejected_state, _) -> reject_session_snapshot(rejected_state)
    SnapshotSealed( next_state, snapshot_blob) -> finish_session_snapshot(next_state,
    snapshot_blob,
    wrapping_key,
    local,
    peer,
    conversation_id,
    request_state,
    key_changed,
    session_id,
    label)
  end
end

fn store_started_session(database_path :: String,
label :: String,
blob :: Bytes,
index_blob :: Bytes,
history_key :: String,
history_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, label, blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, "sessions/v1", index_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, history_key, history_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case Sqlite.commit(database) do
                Err( _) -> Err("database_write_failed")
                Ok( _) -> Ok(nil)
              end
            end
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

fn store_received_session(database_path :: String,
label :: String,
blob :: Bytes,
index_blob :: Bytes,
history_key :: String,
history_blob :: Bytes) -> Result <(), String > do
  let one_time_hash = Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("one-time-prekey/v1")))
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, label, blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, "sessions/v1", index_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, history_key, history_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case Sqlite.execute(database,
              "DELETE FROM encrypted_blobs WHERE record_hash = ?",
              [one_time_hash]) do
                Err( _) -> Err("database_write_failed")
                Ok( _) -> case Sqlite.commit(database) do
                  Err( _) -> Err("database_write_failed")
                  Ok( _) -> Ok(nil)
                end
              end
            end
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

fn padding_bucket(length :: Int) -> Int ! String do
  if length <= 256 do
    Ok(256)
  else if length <= 512 do
    Ok(512)
  else if length <= 1024 do
    Ok(1024)
  else if length <= 2048 do
    Ok(2048)
  else if length <= 4096 do
    Ok(4096)
  else if length <= 8192 do
    Ok(8192)
  else if length <= 16384 do
    Ok(16384)
  else if length <= 32768 do
    Ok(32768)
  else if length <= 65536 do
    Ok(65536)
  else
    Err("message_too_large")
  end
end

fn outer_bytes(mailbox_token :: Bytes, packet :: Bytes, now :: U64) -> Bytes ! String do
  let expiration = U64.add(now, mobile_wide("2592000000") ?) ?
  case encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : random_bytes(16) ?,
    mailbox_token : mailbox_token,
    suite : 1,
    expiration : expiration,
    padding_bucket : padding_bucket(Bytes.length(packet)) ?,
    ciphertext : packet
  }) do
    Err( _) -> Err("outer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn start_conversation(request :: MobileStartRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_profile_bytes = load_profile(request.database_path) ?
  let local = parse_profile(local_profile_bytes) ?
  let peer = parse_profile(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let local_device = open_device(local, wrapping_key, request.database_path) ?
  let now = current_time() ?
  let conversation_id = random_bytes(16) ?
  let inner = InnerEnvelope {
    version : 1,
    sender_account_id : local.account_id,
    sender_device_id : local.device_id,
    recipient_device_id : peer.device_id,
    conversation_id : conversation_id,
    client_message_id : random_bytes(16) ?,
    client_timestamp : now,
    message_type : 1,
    body : request.body,
    reply_reference : Bytes.empty(),
    attachment_manifest : Bytes.empty(),
    receipt_policy : 0,
    disappearing_seconds : 0,
    extensions : List.new()
  }
  let plaintext = encode_initial_plaintext(local_profile_bytes, inner_bytes(inner) ?) ?
  let ( state, initial) = case initiate(local_device,
  local.credential,
  peer.account,
  peer.bundle,
  policy(peer, now),
  1,
  plaintext) do
    Err( _) -> Err("session_start_failed")
    Ok( value) -> Ok(value)
  end ?
  let packet = encode_initial_packet(local.entry.account_identity, initial_bytes(initial) ?) ?
  let outer = outer_bytes(peer.entry.mailbox_token, packet, now) ?
  let ( session_id, label, session_blob) = seal_session(state,
  wrapping_key,
  local,
  peer,
  conversation_id,
  1,
  false) ?
  let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
  let ( history_key, history_blob) = updated_history(request.database_path, wrapping_key, inner, 1) ?
  store_started_session(request.database_path,
  label,
  session_blob,
  index_blob,
  history_key,
  history_blob) ?
  Ok(outer)
end

fn receive_initial_message(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_profile_bytes = load_profile(request.database_path) ?
  let local = parse_profile(local_profile_bytes) ?
  let outer = canonical_outer(request.outer) ?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let packet = parse_initial_packet(outer.ciphertext) ?
    let initiator_account = case decode_account_identity(packet.account_identity) do
      Err( _) -> Err("invalid_initiator_account")
      Ok( value) -> Ok(value)
    end ?
    let wrapping_key = platform_key() ?
    let local_device = open_device(local, wrapping_key, request.database_path) ?
    let ( signed, one_time) = open_prekeys(local, wrapping_key, request.database_path) ?
    let now = current_time() ?
    let ( state, plaintext) = case receive_initial(local_device,
    local.account,
    local.bundle,
    signed,
    one_time,
    initiator_account,
    policy(local, now),
    VerificationPolicy {
      current_time : now,
      minimum_directory_sequence : initiator_account.directory_sequence
    },
    packet.message) do
      Err( _) -> Err("initial_receive_failed")
      Ok( value) -> Ok(value)
    end ?
    let decoded = parse_initial_plaintext(plaintext) ?
    let peer = parse_profile(decoded.profile) ?
    let inner = case decode_inner_envelope(decoded.inner) do
      Err( _) -> Err("invalid_inner_envelope")
      Ok( value) -> Ok(value)
    end ?
    let mismatch = !Bytes.secure_equals(peer.entry.account_identity, packet.account_identity) || !Bytes.secure_equals(inner.sender_account_id,
    peer.account_id) || !Bytes.secure_equals(inner.sender_device_id, peer.device_id) || !Bytes.secure_equals(inner.recipient_device_id,
    local.device_id)
    if mismatch do
      Err("initial_identity_mismatch")
    else
      let ( session_id, label, session_blob) = seal_session(state,
      wrapping_key,
      local,
      peer,
      inner.conversation_id,
      0,
      false) ?
      let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
      let ( history_key, history_blob) = updated_history(request.database_path,
      wrapping_key,
      inner,
      2) ?
      store_received_session(request.database_path,
      label,
      session_blob,
      index_blob,
      history_key,
      history_blob) ?
      Ok(inner.body)
    end
  end
end

fn ratchet_bytes(value :: RatchetMessage) -> Bytes ! String do
  case encode_ratchet_message(value) do
    Err( _) -> Err("ratchet_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn encode_ratchet_packet(message :: Bytes) -> Bytes ! String do
  mobile_join([mobile_vector(mobile_byte(2) ?) ?, mobile_vector(message) ?], 0, Bytes.empty())
end

fn parse_ratchet_packet(input :: Bytes) -> MobileRatchetPacket ! String do
  case reader(input, 65536) do
    Err( _) -> Err("invalid_ratchet_packet")
    Ok( state) -> do
      let kind = take_vector(state, 1) ?
      let message = take_vector(kind.state, 65520) ?
      case finish(message.state) do
        Err( _) -> Err("invalid_ratchet_packet")
        Ok( _) -> if !Bytes.secure_equals(kind.value, mobile_byte(2) ?) do
          Err("invalid_ratchet_packet")
        else
          Ok(MobileRatchetPacket { message : message.value })
        end
      end
    end
  end
end

fn ratchet_aad(session_id :: Bytes) -> Bytes ! String do
  Ok(Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/ratchet-aad/v1"), session_id) ?))
end

fn restore_session(loaded :: MobileLoadedSession, wrapping_key :: borrow StorageKey) -> RatchetState ! String do
  case restore(loaded.record.snapshot,
  wrapping_key,
  loaded.record.local_account_id,
  loaded.record.local_device_id,
  mobile_wide("1") ?) do
    Err( _) -> Err("session_restore_failed")
    Ok( state) -> Ok(state)
  end
end

fn updated_session_record(snapshot_blob :: Bytes, record :: MobileSessionRecord) -> Bytes ! String do
  mobile_join([mobile_vector(snapshot_blob) ?, mobile_vector(record.local_account_id) ?, mobile_vector(record.local_device_id) ?, mobile_vector(record.peer_account_id) ?, mobile_vector(record.peer_device_id) ?, mobile_vector(Bytes.from_utf8(record.peer_username)) ?, mobile_vector(record.peer_mailbox) ?, mobile_vector(record.conversation_id) ?, mobile_vector(mobile_byte(record.request_state) ?) ?, mobile_vector(mobile_byte(if record.blocked do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if record.verified do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_byte(if record.key_changed do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_write_u32(record.disappearing_seconds) ?) ?],
  0,
  Bytes.empty())
end

fn reject_updated_snapshot(state :: consume RatchetState) -> Bytes ! String do
  Err("session_snapshot_failed")
end

fn finish_updated_snapshot(state :: consume RatchetState,
snapshot_blob :: Bytes,
record :: MobileSessionRecord,
wrapping_key :: borrow StorageKey,
label :: String) -> Bytes ! String do
  seal_local(updated_session_record(snapshot_blob, record) ?, wrapping_key, local_context(label) ?)
end

fn seal_updated_session(state :: consume RatchetState,
loaded :: MobileLoadedSession,
wrapping_key :: borrow StorageKey) -> Bytes ! String do
  let next_version = U64.add(state.snapshot_version, mobile_wide("1") ?) ?
  case snapshot(state,
  wrapping_key,
  loaded.record.local_account_id,
  loaded.record.local_device_id,
  next_version) do
    SnapshotRejected( rejected_state, _) -> reject_updated_snapshot(rejected_state)
    SnapshotSealed( next_state, snapshot_blob) -> finish_updated_snapshot(next_state,
    snapshot_blob,
    loaded.record,
    wrapping_key,
    loaded.label)
  end
end

fn store_updated_session(database_path :: String, label :: String, blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> case put_blob(database, label, blob) do
      Err( error) -> do
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

fn store_updated_session_and_history(database_path :: String,
session_key :: String,
session_blob :: Bytes,
history_key :: String,
history_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, session_key, session_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, history_key, history_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case Sqlite.commit(database) do
              Err( _) -> Err("database_write_failed")
              Ok( _) -> Ok(nil)
            end
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

fn send_message(request :: MobileStartRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = parse_profile(load_profile(request.database_path) ?) ?
  let requested_peer = parse_profile(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  requested_peer.account_id,
  load_session_ids(request.database_path, wrapping_key) ?,
  0) ?
  let changed = !Bytes.secure_equals(loaded.record.peer_device_id, requested_peer.device_id) || !Bytes.secure_equals(loaded.record.peer_mailbox,
  requested_peer.entry.mailbox_token)
  if changed do
    Err("peer_keys_changed")
  else if loaded.record.blocked do
    Err("conversation_blocked")
  else if loaded.record.request_state != 1 do
    Err("message_request_pending")
  else
    let state = restore_session(loaded, wrapping_key) ?
    let now = current_time() ?
    let inner = InnerEnvelope {
      version : 1,
      sender_account_id : local.account_id,
      sender_device_id : local.device_id,
      recipient_device_id : loaded.record.peer_device_id,
      conversation_id : loaded.record.conversation_id,
      client_message_id : random_bytes(16) ?,
      client_timestamp : now,
      message_type : 1,
      body : request.body,
      reply_reference : Bytes.empty(),
      attachment_manifest : Bytes.empty(),
      receipt_policy : 0,
      disappearing_seconds : loaded.record.disappearing_seconds,
      extensions : List.new()
    }
    let ( next_state, message) = case encrypt(state,
    inner_bytes(inner) ?,
    ratchet_aad(loaded.session_id) ?) do
      Err( _) -> Err("message_encryption_failed")
      Ok( value) -> Ok(value)
    end ?
    let packet = encode_ratchet_packet(ratchet_bytes(message) ?) ?
    let outer = outer_bytes(loaded.record.peer_mailbox, packet, now) ?
    let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
    let ( history_key, history_blob) = updated_history(request.database_path,
    wrapping_key,
    inner,
    1) ?
    store_updated_session_and_history(request.database_path,
    loaded.label,
    session_blob,
    history_key,
    history_blob) ?
    Ok(outer)
  end
end

fn reject_message(state :: consume RatchetState) -> Bytes ! String do
  Err("message_rejected")
end

fn receive_message(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = parse_profile(load_profile(request.database_path) ?) ?
  let outer = canonical_outer(request.outer) ?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let packet = parse_ratchet_packet(outer.ciphertext) ?
    let message = case decode_ratchet_message(packet.message) do
      Err( _) -> Err("invalid_ratchet_message")
      Ok( value) -> Ok(value)
    end ?
    let wrapping_key = platform_key() ?
    let loaded = load_session_record(request.database_path, wrapping_key, message.session_id) ?
    let state = restore_session(loaded, wrapping_key) ?
    case decrypt(state, message, ratchet_aad(loaded.session_id) ?) do
      Rejected( rejected_state, _) -> reject_message(rejected_state)
      Opened( next_state, plaintext) -> do
        let inner = case decode_inner_envelope(plaintext) do
          Err( _) -> Err("invalid_inner_envelope")
          Ok( value) -> Ok(value)
        end ?
        let mismatch = !Bytes.secure_equals(inner.sender_account_id, loaded.record.peer_account_id) || !Bytes.secure_equals(inner.sender_device_id,
        loaded.record.peer_device_id) || !Bytes.secure_equals(inner.recipient_device_id,
        local.device_id) || !Bytes.secure_equals(inner.conversation_id,
        loaded.record.conversation_id)
        if mismatch do
          reject_message(next_state)
        else
          let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
          if loaded.record.blocked do
            store_updated_session(request.database_path, loaded.label, session_blob) ?
            Err("blocked_message")
          else
            let ( history_key, history_blob) = updated_history(request.database_path,
            wrapping_key,
            inner,
            2) ?
            store_updated_session_and_history(request.database_path,
            loaded.label,
            session_blob,
            history_key,
            history_blob) ?
            Ok(inner.body)
          end
        end
      end
    end
  end
end

fn updated_policy(record :: MobileSessionRecord, action :: Int, value :: Int) -> MobileSessionRecord ! String do
  if action == 1 do
    Ok(% { record | request_state : 1 })
  else if action == 2 do
    Ok(% { record | blocked : true })
  else if action == 3 do
    Ok(% { record | blocked : false })
  else if action == 4 do
    Ok(% { record | verified : true, key_changed : false })
  else if action == 5 && value >= 0 && value <= 2592000 do
    Ok(% { record | disappearing_seconds : value })
  else
    Err("invalid_conversation_policy")
  end
end

fn update_conversation(request :: MobilePolicyRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  peer_id,
  load_session_ids(request.database_path, wrapping_key) ?,
  0) ?
  let record = updated_policy(loaded.record, request.action, request.value) ?
  let blob = seal_local(updated_session_record(record.snapshot, record) ?,
  wrapping_key,
  local_context(loaded.label) ?) ?
  store_updated_session(request.database_path, loaded.label, blob) ?
  Ok(Bytes.from_utf8("ok"))
end

fn import_contact(input :: Bytes) -> Bytes ! String do
  let entry = case decode_directory_entry(input) do
    Err( _) -> Err("invalid_directory_entry")
    Ok( value) -> Ok(value)
  end ?
  let account = case decode_account_identity(entry.account_identity) do
    Err( _) -> Err("invalid_directory_entry")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case decode_prekey_bundle(entry.prekey_bundle) do
    Err( _) -> Err("invalid_directory_entry")
    Ok( value) -> Ok(value)
  end ?
  let credential = case decode_device_credential(bundle.device_credential) do
    Err( _) -> Err("invalid_directory_entry")
    Ok( value) -> Ok(value)
  end ?
  let profile = profile_bytes(entry, account.account_id, credential.device_id) ?
  let _ = parse_profile(profile) ?
  Ok(profile)
end

fn directory_entry_for(database_path :: String) -> Bytes ! String do
  let profile = parse_profile(load_profile(database_path) ?) ?
  directory_bytes(profile.entry)
end

fn directory_lookup(input :: Bytes) -> Bytes ! String do
  let username = mobile_utf8(input, "invalid_username") ?
  case encode_directory_lookup(username) do
    Err( _) -> Err("invalid_username")
    Ok( encoded) -> Ok(encoded)
  end
end

fn mailbox_fetch(database_path :: String) -> Bytes ! String do
  let profile = parse_profile(load_profile(database_path) ?) ?
  case encode_mailbox_fetch(MailboxFetch {
    version : 1,
    mailbox_token : profile.entry.mailbox_token,
    after_sequence : mobile_wide("0") ?
  }) do
    Err( _) -> Err("mailbox_fetch_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn process_deliveries(database_path :: String,
deliveries :: List < DeliveredEnvelope >,
index :: Int,
envelope_ids :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(deliveries) do
    envelope_ids
  else
    let delivered = List.get(deliveries, index)
    case canonical_outer(delivered.envelope) do
      Err( _) -> process_deliveries(database_path, deliveries, index + 1, envelope_ids)
      Ok( outer) -> do
        let ignored = case parse_initial_packet(outer.ciphertext) do
          Ok( _) -> receive_initial_message(MobileReceiveRequest {
            database_path : database_path,
            outer : delivered.envelope
          })
          Err( _) -> receive_message(MobileReceiveRequest {
            database_path : database_path,
            outer : delivered.envelope
          })
        end
        process_deliveries(database_path,
        deliveries,
        index + 1,
        List.append(envelope_ids, outer.envelope_id))
      end
    end
  end
end

fn process_delivery_batch(request :: MobileBatchRequest) -> Bytes ! String do
  let profile = parse_profile(load_profile(request.database_path) ?) ?
  let deliveries = case decode_delivery_batch(request.batch) do
    Err( _) -> Err("invalid_delivery_batch")
    Ok( values) -> Ok(values)
  end ?
  let envelope_ids = process_deliveries(request.database_path, deliveries, 0, List.new())
  case encode_mailbox_ack(MailboxAck {
    version : 1,
    mailbox_token : profile.entry.mailbox_token,
    envelope_ids : envelope_ids
  }) do
    Err( _) -> Err("mailbox_ack_encoding_failed")
    Ok( encoded) -> Ok(encoded)
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

@ export("mesh_messenger_create_link_request")pub fn create_link_request_export(request :: Bytes) -> Bytes ! String do
  create_device_link_request(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_device_link_sas")pub fn device_link_sas_export(request :: Bytes) -> Bytes ! String do
  device_link_sas(request)
end

@ export("mesh_messenger_authorize_device_link")pub fn authorize_device_link_export(request :: Bytes) -> Bytes ! String do
  authorize_link(parse_payload_request(request) ?)
end

@ export("mesh_messenger_authorize_device_link_for_set")pub fn authorize_device_link_for_set_export(request :: Bytes) -> Bytes ! String do
  authorize_link_for_set(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_complete_device_link")pub fn complete_device_link_export(request :: Bytes) -> Bytes ! String do
  complete_link(parse_payload_request(request) ?)
end

@ export("mesh_messenger_inspect_device_set")pub fn inspect_device_set_export(request :: Bytes) -> Bytes ! String do
  inspect_device_set(parse_payload_request(request) ?)
end

@ export("mesh_messenger_create_device_revocation")pub fn create_device_revocation_export(request :: Bytes) -> Bytes ! String do
  create_device_revocation(parse_triple_payload_request(request) ?)
end

@ export("mesh_messenger_start_conversation")pub fn start_conversation_export(request :: Bytes) -> Bytes ! String do
  start_conversation(parse_start_request(request) ?)
end

@ export("mesh_messenger_receive_initial")pub fn receive_initial_export(request :: Bytes) -> Bytes ! String do
  receive_initial_message(parse_receive_request(request) ?)
end

@ export("mesh_messenger_send_message")pub fn send_message_export(request :: Bytes) -> Bytes ! String do
  send_message(parse_start_request(request) ?)
end

@ export("mesh_messenger_receive_message")pub fn receive_message_export(request :: Bytes) -> Bytes ! String do
  receive_message(parse_receive_request(request) ?)
end

@ export("mesh_messenger_update_conversation")pub fn update_conversation_export(request :: Bytes) -> Bytes ! String do
  update_conversation(parse_policy_request(request) ?)
end

@ export("mesh_messenger_list_conversations")pub fn list_conversations_export(request :: Bytes) -> Bytes ! String do
  list_conversations(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_load_history")pub fn load_history_export(request :: Bytes) -> Bytes ! String do
  load_visible_history(parse_peer_request(request) ?)
end

@ export("mesh_messenger_safety_number")pub fn safety_number_export(request :: Bytes) -> Bytes ! String do
  conversation_safety(parse_peer_request(request) ?)
end

@ export("mesh_messenger_import_contact")pub fn import_contact_export(request :: Bytes) -> Bytes ! String do
  import_contact(request)
end

@ export("mesh_messenger_directory_entry")pub fn directory_entry_export(request :: Bytes) -> Bytes ! String do
  directory_entry_for(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_directory_lookup")pub fn directory_lookup_export(request :: Bytes) -> Bytes ! String do
  directory_lookup(request)
end

@ export("mesh_messenger_mailbox_fetch")pub fn mailbox_fetch_export(request :: Bytes) -> Bytes ! String do
  mailbox_fetch(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_process_delivery_batch")pub fn process_delivery_batch_export(request :: Bytes) -> Bytes ! String do
  process_delivery_batch(parse_batch_request(request) ?)
end

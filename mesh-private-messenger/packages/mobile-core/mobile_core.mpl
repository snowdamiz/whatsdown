from Binary.Reader import BinaryReader, finish, read_fixed, read_vector, reader
from Groups.Mls import CommitApplyOutcome, GroupAddOutcome, GroupCommit, GroupDecryptOutcome, GroupDeliveryTarget, GroupEncryptOutcome, GroupError, GroupMessage, GroupProposal, GroupRemoveOutcome, GroupSnapshotOutcome, GroupState, GroupTransparencyPolicy, GroupWelcome, apply_commit, commit_add, commit_remove, create_group, decode_group_commit, decode_group_message, decode_group_welcome, decrypt_group_message, delivery_targets, encode_group_commit, encode_group_message, encode_group_welcome, encrypt_group_message, group_snapshot, join_from_welcome, restore_group
from Groups.Tree import GroupMember, IndexedGroupMember, find_member_index, indexed_members, member_at
from Identity.Device import AccountKeys, DeviceKeys, VerificationPolicy, authorize_device_link, generate_account, generate_device, is_retryable_verification_crypto_error, issue_device_credential, issue_device_revocation, issue_hybrid_device_credential, verify_device_link_authorization
from Prekeys.Bundle import OneTimePrekeySecrets, PostQuantumPrekeySecrets, PrekeyError, SignedPrekeySecrets, build_hybrid_prekey_bundle, build_prekey_bundle, generate_one_time_prekey, generate_post_quantum_prekey, generate_signed_prekey, normalize_prekey_bundle, verify_prekey_bundle
from Prekeys.Pool import OneTimePrekeyPublic, PrekeyClaimRequest, PrekeyPublishRequest, decode_prekey_claim, decode_prekey_publish_response, encode_prekey_claim, encode_prekey_publish, prekey_publish_signing_bytes
from Privacy.Edge import encode_privacy_submission, mint_submission, seal_delivery
from Protocol.V1 import AccountIdentity, DeliveredEnvelope, DeviceCredential, DeviceLinkAuthorization, DeviceLinkRequest, DeviceSet, DirectoryEntry, InitialMessage, InnerEnvelope, MailboxAck, MailboxFetch, OuterEnvelope, PrekeyBundle, decode_account_identity, decode_delivery_batch, decode_device_credential, decode_device_link_authorization, decode_device_link_request, decode_device_set, decode_directory_entry, decode_initial_message, decode_inner_envelope, decode_outer_envelope, decode_prekey_bundle, encode_account_identity, encode_device_credential, encode_device_link_authorization, encode_device_link_request, encode_device_revocation, encode_device_set, encode_directory_entry, encode_directory_lookup, encode_initial_message, encode_inner_envelope, encode_mailbox_ack, encode_mailbox_fetch, encode_outer_envelope, encode_prekey_bundle
from Push.Binding import PushBindRequest, PushUnbindRequest, decode_push_bind, decode_push_unbind, encode_push_bind, encode_push_unbind, push_bind_signing_bytes, push_unbind_signing_bytes
from Push.Token import seal_provider_token
from Session.Handshake import RatchetState, SessionError, initiate, is_retryable_session_crypto_error, is_retryable_session_error, receive_initial
from Session.Ratchet import DecryptOutcome, RatchetError, RatchetMessage, decode_ratchet_message, decrypt, encode_ratchet_message, encrypt, is_retryable_ratchet_error, ratchet_open_error, skipped_key_error
from Session.Snapshot import SnapshotOutcome, restore, snapshot
from Storage.Blobs import ensure_schema, insert_blob, load_blob, put_blob
from Transparency.Client import verify_evidence
from Transparency.Merkle import ConsistencyProof, TransparencyCheckpoint, WitnessKey, checkpoint_hash, verify_checkpoint, verify_consistency
from Transparency.Wire import TransparencyLookup, decode_checkpoint, decode_consistency_proof, decode_transparency_evidence, encode_checkpoint, encode_consistency_proof, encode_transparency_lookup
from Transport.Packet import ClientProfile, TransportPacket, decode_client_profile, decode_initial_plaintext, decode_packet, encode_client_profile, encode_initial_plaintext, encode_packet, is_sealed_initial_packet, open_initial_packet, seal_initial_packet, session_aad

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

struct MobilePrekeyRequest do
  database_path :: String
  count :: Int
end

struct MobilePrekeyReconcileRequest do
  database_path :: String
  response :: Bytes
end

struct MobileOneTimePrekey do
  id :: U64
  public_key :: Bytes
end

struct MobileStartRequest do
  database_path :: String
  peer_profile :: Bytes
  body :: Bytes
end

struct MobileFanoutRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
  body :: Bytes
end

struct MobileFanoutTargetsRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
end

struct MobileFanoutPrepareRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
  directory_url :: String
end

struct MobileFanoutPrekeyReservationRequest do
  database_path :: String
  peer_device_set :: Bytes
  local_device_set :: Bytes
  claimed_prekey :: Bytes
end

struct MobileReceiveRequest do
  database_path :: String
  outer :: Bytes
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
  strongest_suite :: Int
  safety_number :: Bytes
end

struct MobileLoadedSession do
  session_id :: Bytes
  label :: String
  record :: MobileSessionRecord
end

struct MobilePreparedSend do
  envelope :: Bytes
  session_id :: Bytes
  session_label :: String
  session_blob :: Bytes
  new_session :: Bool
end

struct MobileHistoryEntry do
  direction :: Int
  inner :: InnerEnvelope
end

struct MobileSyncPayload do
  peer_username :: String
  peer_account_id :: Bytes
  conversation_id :: Bytes
  client_message_id :: Bytes
  client_timestamp :: U64
  body :: Bytes
  disappearing_seconds :: Int
  safety_number :: Bytes
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

pub struct ConversationSummary do
  conversation_id :: Bytes
  username :: String
  peer_account_id :: Bytes
  peer_device_id :: Bytes
  safety_number :: Bytes
  request_state :: Int
  blocked :: Bool
  verified :: Bool
  key_changed :: Bool
  disappearing_seconds :: Int
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

struct MobileTransparencyRequest do
  database_path :: String
  username :: String
  evidence :: Bytes
end

struct MobileSecurityConfig do
  transparency_service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
  delivery_public_key :: Bytes
  abuse_difficulty :: Int
end

struct MobilePushState do
  revision :: U64
  mode :: Int
  wake_token_hash :: Bytes
  provider_token_hash :: Bytes
  pending_kind :: Int
  pending_wire :: Bytes
  action_epoch :: U64
  action_kind :: Int
  target_mode :: Int
  project_id :: Bytes
  broker_public_key :: Bytes
end

struct MobilePushIntentRequest do
  database_path :: String
  intent :: Int
end

struct MobilePushBuildConfig do
  project_id :: Bytes
  broker_public_key :: Bytes
end

struct MobilePushActionCompletion do
  database_path :: String
  action :: Bytes
  outcome :: Int
end

struct MobilePushActionFrame do
  kind :: Int
  epoch :: U64
  payload :: Bytes
end

struct MobileExpoRawToken do
  platform :: Int
  development :: Bool
  app_id :: String
  device_token :: String
end

struct MobileVerifiedDeviceSet do
  wire :: Bytes
  value :: DeviceSet
  account :: AccountIdentity
  profiles :: List < ClientProfile >
end

struct MobileClaimedPrekey do
  base_bundle :: Bytes
  profile :: ClientProfile
end

struct MobileVerifiedTransparencySet do
  checkpoint :: Bytes
  device_set :: Bytes
end

struct MobileTransparencyView do
  checkpoint :: Bytes
  consistency :: Bytes
  service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
end

struct MobileTransparencyManifest do
  checkpoint :: Bytes
  consistency_length :: Int
  consistency_hash :: Bytes
  chunk_count :: Int
  service_public_key :: Bytes
  witness_a_public_key :: Bytes
  witness_b_public_key :: Bytes
end

struct MobileTransparencyStorage do
  labels :: List < String >
  blobs :: List < Bytes >
end

struct MobileGroupKeyPackage do
  account_id :: Bytes
  device_id :: Bytes
  init_public_key :: X25519PublicKey
  leaf_public_key :: X25519PublicKey
  checkpoint :: Bytes
  witness_count :: Int
  signature :: Signature
end

struct MobileGroupWelcomePacket do
  baseline_checkpoint :: Bytes
  welcome :: Bytes
end

struct MobileGroupAddRequest do
  database_path :: String
  group_id :: Bytes
  device_set :: Bytes
  key_package :: Bytes
end

struct MobileGroupRemoveRequest do
  database_path :: String
  group_id :: Bytes
  account_id :: Bytes
  device_id :: Bytes
end

struct MobileGroupSendRequest do
  database_path :: String
  group_id :: Bytes
  body :: Bytes
end

struct MobileGroupPacket do
  kind :: Int
  payload :: Bytes
end

struct MobileGroupReferenceRequest do
  database_path :: String
  group_id :: Bytes
end

struct MobileGroupHistoryEntry do
  direction :: Int
  epoch :: U64
  sender_account_id :: Bytes
  sender_device_id :: Bytes
  timestamp :: U64
  body :: Bytes
end

type MobileGroupReceiveOutcome do
  GroupReceiveApplied( output :: Bytes)

  GroupReceiveRetry( error :: String)

  GroupReceiveRejected( error :: String)
end

type MobileDirectReceiveOutcome do
  DirectReceiveApplied( output :: Bytes)

  DirectReceiveRetry( error :: String)

  DirectReceiveRejected( error :: String)
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

fn take_vector_error(state :: BinaryReader, maximum :: Int, error :: String) -> MobileReadBytes ! String do
  case read_vector(state, maximum) do
    Err( _) -> Err(error)
    Ok( ( next, value)) -> Ok(MobileReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err(error)
  end
end

fn take_fixed(state :: BinaryReader, length :: Int) -> MobileReadBytes ! String do
  case read_fixed(state, length) do
    Err( _) -> Err("invalid_fixed_value")
    Ok( ( next, value)) -> Ok(MobileReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid_fixed_value")
  end
end

fn take_group_vector(state :: BinaryReader, maximum :: Int) -> MobileReadBytes ! String do
  case read_vector(state, maximum) do
    Err( _) -> Err("invalid_group_request")
    Ok( ( next, value)) -> Ok(MobileReadBytes {
      state : next,
      value : value
    })
    Ok( _) -> Err("invalid_group_request")
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

fn mobile_read_u64(value :: Bytes) -> U64 ! String do
  if Bytes.length(value) != 8 do
    Err("invalid_integer")
  else
    case Bytes.read_u64_be(value, 0) do
      Err( _) -> Err("invalid_integer")
      Ok( wide) -> Ok(wide)
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

fn parse_prekey_request(input :: Bytes) -> MobilePrekeyRequest ! String do
  case reader(input, 4108) do
    Err( _) -> Err("invalid_prekey_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let count = take_vector(path.state, 4) ?
      case finish(count.state) do
        Err( _) -> Err("invalid_prekey_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          let count_value = mobile_read_u32(count.value) ?
          if String.length(database_path) == 0 || count_value > 64 do
            Err("invalid_prekey_request")
          else
            Ok(MobilePrekeyRequest {
              database_path : database_path,
              count : count_value
            })
          end
        end
      end
    end
  end
end

fn parse_prekey_reconcile_request(input :: Bytes) -> MobilePrekeyReconcileRequest ! String do
  case reader(input, 4669) do
    Err( _) -> Err("invalid_prekey_reconcile_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let response = take_vector(path.state, 565) ?
      case finish(response.state) do
        Err( _) -> Err("invalid_prekey_reconcile_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 do
            Err("invalid_prekey_reconcile_request")
          else
            Ok(MobilePrekeyReconcileRequest {
              database_path : database_path,
              response : response.value
            })
          end
        end
      end
    end
  end
end

fn context(account_id :: Bytes, device_id :: Bytes, label :: String, purpose :: Int) -> Bytes ! String do
  if Bytes.length(account_id) != 32 || Bytes.length(device_id) != 16 do
    Err("invalid_storage_identity")
  else
    let session_id = if (purpose >= 5 && purpose <= 10) || purpose == 15 do
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

fn one_time_prekey_label(id :: U64) -> String do
  "one-time-prekey/v1/#{U64.to_string(id)}"
end

fn one_time_prekey_context(profile :: ClientProfile, id :: U64) -> Bytes ! String do
  let label = one_time_prekey_label(id)
  context(profile.account_id, profile.device_id, label, 10)
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

fn seal_mlkem(key :: borrow MlKemPrivateKey,
wrapping_key :: borrow StorageKey,
value_context :: Bytes) -> Bytes ! String do
  case MlKemPrivateKey.seal_for_storage(key, wrapping_key, value_context) do
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

fn open_mlkem(blob :: Bytes, wrapping_key :: borrow StorageKey, value_context :: Bytes) -> MlKemPrivateKey ! String do
  case MlKemPrivateKey.unseal_from_storage(blob, wrapping_key, value_context) do
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

fn valid_prekey_id(id :: U64) -> Bool ! String do
  Ok(U64.compare(id, mobile_wide("0") ?) > 0 && U64.compare(id,
  mobile_wide("9223372036854775807") ?) <= 0)
end

fn encode_prekey_entries(entries :: List < MobileOneTimePrekey >, index :: Int, output :: Bytes) -> Bytes ! String do
  if List.length(entries) > 128 do
    Err("prekey_pool_full")
  else if index >= List.length(entries) do
    Ok(output)
  else
    let entry = List.get(entries, index)
    if !(valid_prekey_id(entry.id) ?) || Bytes.length(entry.public_key) != 32 do
      Err("invalid_prekey_pool")
    else
      encode_prekey_entries(entries,
      index + 1,
      mobile_join([output, mobile_write_u64(entry.id) ?, entry.public_key], 0, Bytes.empty()) ?)
    end
  end
end

fn decode_prekey_entries(encoded :: Bytes,
offset :: Int,
previous :: U64,
entries :: List < MobileOneTimePrekey >) -> List < MobileOneTimePrekey > ! String do
  if offset >= Bytes.length(encoded) do
    Ok(entries)
  else
    let id = mobile_read_u64(Bytes.slice(encoded, offset, 8) ?) ?
    let public_key = Bytes.slice(encoded, offset + 8, 32) ?
    if !(valid_prekey_id(id) ?) || U64.compare(id, previous) <= 0 do
      Err("invalid_prekey_pool")
    else
      decode_prekey_entries(encoded,
      offset + 40,
      id,
      List.append(entries,
      MobileOneTimePrekey {
        id : id,
        public_key : public_key
      }))
    end
  end
end

fn decode_prekey_pool(encoded :: Bytes) -> List < MobileOneTimePrekey > ! String do
  if Bytes.length(encoded) % 40 != 0 || Bytes.length(encoded) > 5120 do
    Err("invalid_prekey_pool")
  else
    decode_prekey_entries(encoded, 0, mobile_wide("0") ?, List.new())
  end
end

fn contains_prekey_id(ids :: List < U64 >, id :: U64, index :: Int) -> Bool do
  if index >= List.length(ids) do
    false
  else if U64.compare(List.get(ids, index), id) == 0 do
    true
  else
    contains_prekey_id(ids, id, index + 1)
  end
end

fn mobile_prekey_ids(entries :: List < MobileOneTimePrekey >, index :: Int, output :: List < U64 >) -> List < U64 > do
  if index >= List.length(entries) do
    output
  else
    let entry = List.get(entries, index)
    mobile_prekey_ids(entries, index + 1, List.append(output, entry.id))
  end
end

fn encode_active_prekey_ids(ids :: List < U64 >, index :: Int, previous :: U64, output :: Bytes) -> Bytes ! String do
  if List.length(ids) > 64 do
    Err("active_prekey_pool_full")
  else if index >= List.length(ids) do
    Ok(output)
  else
    let id = List.get(ids, index)
    if !(valid_prekey_id(id) ?) || U64.compare(id, previous) <= 0 do
      Err("invalid_active_prekey_pool")
    else
      encode_active_prekey_ids(ids, index + 1, id, mobile_append(output, mobile_write_u64(id) ?) ?)
    end
  end
end

fn decode_active_prekey_ids(encoded :: Bytes,
offset :: Int,
previous :: U64,
entry_ids :: List < U64 >,
output :: List < U64 >) -> List < U64 > ! String do
  if offset >= Bytes.length(encoded) do
    Ok(output)
  else
    let id = mobile_read_u64(Bytes.slice(encoded, offset, 8) ?) ?
    if !(valid_prekey_id(id) ?) || U64.compare(id, previous) <= 0 || !contains_prekey_id(entry_ids,
    id,
    0) do
      Err("invalid_active_prekey_pool")
    else
      decode_active_prekey_ids(encoded, offset + 8, id, entry_ids, List.append(output, id))
    end
  end
end

fn decode_active_prekey_pool(encoded :: Bytes, entry_ids :: List < U64 >) -> List < U64 > ! String do
  if Bytes.length(encoded) % 8 != 0 || Bytes.length(encoded) > 512 do
    Err("invalid_active_prekey_pool")
  else
    decode_active_prekey_ids(encoded, 0, mobile_wide("0") ?, entry_ids, List.new())
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

fn put_blobs(database :: SqliteConn,
labels :: List < String >,
blobs :: List < Bytes >,
index :: Int) -> Result <(), String > do
  if List.length(labels) != List.length(blobs) do
    Err("invalid_local_state")
  else if index >= List.length(labels) do
    Ok(nil)
  else
    put_blob(database, List.get(labels, index), List.get(blobs, index)) ?
    put_blobs(database, labels, blobs, index + 1)
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
          ["pending-link-request/v1", "pending-device-signing-key/v1", "pending-device-identity-key/v1", "pending-post-quantum-prekey/v1"],
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

fn store_updated_blobs(database_path :: String, labels :: List < String >, blobs :: List < Bytes >) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blobs(database, labels, blobs, 0) do
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

fn store_prekey_batch(database_path :: String,
labels :: List < String >,
blobs :: List < Bytes >,
removed_labels :: List < String >,
index_blob :: Bytes,
active_blob :: Bytes,
next_id_blob :: Bytes,
delete_legacy :: Bool) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case delete_blobs(database, removed_labels, 0) do
          Err( error) -> Err(error)
          Ok( _) -> case insert_blobs(database, labels, blobs, 0) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "one-time-prekeys/v1", index_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case put_blob(database, "one-time-prekey-active/v1", active_blob) do
                Err( error) -> Err(error)
                Ok( _) -> case put_blob(database, "one-time-prekey-next-id/v1", next_id_blob) do
                  Err( error) -> Err(error)
                  Ok( _) -> do
                    let legacy_result = if delete_legacy do
                      delete_blob(database, "one-time-prekey/v1")
                    else
                      Ok(nil)
                    end
                    case legacy_result do
                      Err( error) -> Err(error)
                      Ok( _) -> case Sqlite.commit(database) do
                        Err( _) -> Err("database_write_failed")
                        Ok( _) -> Ok(nil)
                      end
                    end
                  end
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

fn store_prekey_reconciliation(database_path :: String,
removed_labels :: List < String >,
index_blob :: Bytes,
active_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case delete_blobs(database, removed_labels, 0) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, "one-time-prekeys/v1", index_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "one-time-prekey-active/v1", active_blob) do
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

fn store_prepared_sessions(database :: SqliteConn,
prepared :: List < MobilePreparedSend >,
index :: Int) -> Result <(), String > do
  if index >= List.length(prepared) do
    Ok(nil)
  else
    let value = List.get(prepared, index)
    let stored = if value.new_session do
      insert_blob(database, value.session_label, value.session_blob)
    else
      put_blob(database, value.session_label, value.session_blob)
    end
    stored ?
    store_prepared_sessions(database, prepared, index + 1)
  end
end

fn store_outbound(database_path :: String,
prepared :: List < MobilePreparedSend >,
removed_labels :: List < String >,
session_index_blob :: Bytes,
history_key :: String,
history_blob :: Bytes,
outbox_labels :: List < String >,
outbox_blobs :: List < Bytes >,
outbox_index_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case store_prepared_sessions(database, prepared, 0) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, "sessions/v1", session_index_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, history_key, history_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case put_blobs(database, outbox_labels, outbox_blobs, 0) do
                Err( error) -> Err(error)
                Ok( _) -> case put_blob(database, "outbox/v1", outbox_index_blob) do
                  Err( error) -> Err(error)
                  Ok( _) -> case delete_blobs(database, removed_labels, 0) do
                    Err( error) -> Err(error)
                    Ok( _) -> case Sqlite.commit(database) do
                      Err( _) -> Err("database_write_failed")
                      Ok( _) -> Ok(nil)
                    end
                  end
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
    let post_quantum = case generate_post_quantum_prekey() do
      Err( _) -> Err("post_quantum_prekey_generation_failed")
      Ok( value) -> Ok(value)
    end ?
    let credential = case issue_hybrid_device_credential(account,
    device,
    post_quantum.public_key,
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
    let bundle = case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
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
    let profile = encode_client_profile(entry, identity.account_id, credential.device_id) ?
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
    let one_time_label = one_time_prekey_label(one_time.id)
    let one_time_prekey_blob = case seal_x25519(one_time.private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, one_time_label, 10) ?) do
      Err( _) -> Err("one_time_prekey_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let post_quantum_prekey_blob = case seal_mlkem(post_quantum.private_key,
    wrapping_key,
    context(identity.account_id, credential.device_id, "post-quantum-prekey/v1", 15) ?) do
      Err( _) -> Err("post_quantum_prekey_seal_failed")
      Ok( value) -> Ok(value)
    end ?
    let profile_blob = seal_local(profile, wrapping_key, local_context("profile/v1") ?) ?
    let prekey_index_blob = seal_prekey_pool([MobileOneTimePrekey {
      id : one_time.id,
      public_key : one_time.public_key.bytes
    }],
    wrapping_key) ?
    let prekey_active_blob = seal_active_prekey_pool([one_time.id], wrapping_key) ?
    let prekey_next_id_blob = seal_prekey_wide("one-time-prekey-next-id/v1",
    U64.add(one_time.id, mobile_wide("1") ?) ?,
    wrapping_key) ?
    store_blobs(database_path,
    ["account-signing-key/v1", "device-signing-key/v1", "device-identity-key/v1", "signed-prekey/v1", one_time_label, "post-quantum-prekey/v1", "profile/v1", "one-time-prekeys/v1", "one-time-prekey-active/v1", "one-time-prekey-next-id/v1"],
    [account_blob, device_signing_blob, device_identity_blob, signed_prekey_blob, one_time_prekey_blob, post_quantum_prekey_blob, profile_blob, prekey_index_blob, prekey_active_blob, prekey_next_id_blob]) ?
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

fn peer_account_id(reference :: Bytes) -> Bytes ! String do
  if Bytes.length(reference) == 32 do
    Ok(reference)
  else
    Ok(decode_client_profile(reference) ?.account_id)
  end
end

fn parse_start_request(input :: Bytes) -> MobileStartRequest ! String do
  case reader(input, 73010) do
    Err( _) -> Err("invalid_start_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_profile = take_vector(path.state, 36134) ?
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

fn parse_fanout_targets_request(input :: Bytes) -> MobileFanoutTargetsRequest ! String do
  case reader(input, 614628) do
    Err( _) -> Err("invalid_fanout_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_device_set = take_vector(path.state, 305260) ?
      let local_device_set = take_vector(peer_device_set.state, 305260) ?
      case finish(local_device_set.state) do
        Err( _) -> Err("invalid_fanout_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 do
            Err("invalid_fanout_request")
          else
            Ok(MobileFanoutTargetsRequest {
              database_path : database_path,
              peer_device_set : peer_device_set.value,
              local_device_set : local_device_set.value
            })
          end
        end
      end
    end
  end
end

fn parse_fanout_prepare_request(input :: Bytes) -> MobileFanoutPrepareRequest ! String do
  case reader(input, 616680) do
    Err( _) -> Err("invalid_fanout_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_device_set = take_vector(path.state, 305260) ?
      let local_device_set = take_vector(peer_device_set.state, 305260) ?
      let directory_url = take_vector(local_device_set.state, 2048) ?
      case finish(directory_url.state) do
        Err( _) -> Err("invalid_fanout_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          let url = mobile_utf8(directory_url.value, "invalid_fanout_request") ?
          if String.length(database_path) == 0 || String.length(url) == 0 do
            Err("invalid_fanout_request")
          else
            Ok(MobileFanoutPrepareRequest {
              database_path : database_path,
              peer_device_set : peer_device_set.value,
              local_device_set : local_device_set.value,
              directory_url : url
            })
          end
        end
      end
    end
  end
end

fn parse_fanout_prekey_reservation_request(input :: Bytes) -> MobileFanoutPrekeyReservationRequest ! String do
  case reader(input, 633944) do
    Err( _) -> Err("invalid_fanout_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_device_set = take_vector(path.state, 305260) ?
      let local_device_set = take_vector(peer_device_set.state, 305260) ?
      let claimed_prekey = take_vector(local_device_set.state, 19312) ?
      case finish(claimed_prekey.state) do
        Err( _) -> Err("invalid_fanout_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(claimed_prekey.value) == 0 do
            Err("invalid_fanout_request")
          else
            Ok(MobileFanoutPrekeyReservationRequest {
              database_path : database_path,
              peer_device_set : peer_device_set.value,
              local_device_set : local_device_set.value,
              claimed_prekey : claimed_prekey.value
            })
          end
        end
      end
    end
  end
end

fn parse_fanout_request(input :: Bytes) -> MobileFanoutRequest ! String do
  case reader(input, 646632) do
    Err( _) -> Err("invalid_fanout_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_device_set = take_vector(path.state, 305260) ?
      let local_device_set = take_vector(peer_device_set.state, 305260) ?
      let body = take_vector(local_device_set.state, 32000) ?
      case finish(body.state) do
        Err( _) -> Err("invalid_fanout_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(body.value) == 0 do
            Err("invalid_fanout_request")
          else
            Ok(MobileFanoutRequest {
              database_path : database_path,
              peer_device_set : peer_device_set.value,
              local_device_set : local_device_set.value,
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
  case reader(input, 40251) do
    Err( _) -> Err("invalid_policy_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_profile = take_vector(path.state, 36134) ?
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
  case reader(input, 40238) do
    Err( _) -> Err("invalid_peer_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let peer_profile = take_vector(path.state, 36134) ?
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
  case reader(input, 309364) do
    Err( _) -> Err("invalid_payload_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let payload = take_vector(path.state, 305260) ?
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

fn parse_push_bind_request_inner(input :: Bytes) -> MobilePayloadRequest ! String do
  let state = case reader(input, 4140) do
    Err( _) -> Err("invalid")
    Ok( value) -> Ok(value)
  end ?
  let path = take_vector(state, 4096) ?
  let project_id = take_vector(path.state, 36) ?
  let _ = case finish(project_id.state) do
    Err( _) -> Err("invalid")
    Ok( _) -> Ok(nil)
  end ?
  let database_path = mobile_utf8(path.value, "invalid") ?
  if String.length(database_path) == 0 do
    Err("invalid")
  else
    Ok(MobilePayloadRequest {
      database_path : database_path,
      payload : project_id.value
    })
  end
end

fn parse_push_bind_request(input :: Bytes) -> MobilePayloadRequest ! String do
  case parse_push_bind_request_inner(input) do
    Err( _) -> Err("invalid_payload_request")
    Ok( value) -> Ok(value)
  end
end

fn parse_push_intent_request(input :: Bytes) -> MobilePushIntentRequest ! String do
  case reader(input, 4105) do
    Err( _) -> Err("invalid_push_intent")
    Ok( state) -> do
      let path = take_vector_error(state, 4096, "invalid_push_intent") ?
      let intent = take_vector_error(path.state, 1, "invalid_push_intent") ?
      let database_path = mobile_utf8(path.value, "invalid_database_path") ?
      let intent_value = mobile_read_byte(intent.value) ?
      if String.length(database_path) == 0 || (intent_value != 0 && intent_value != 1 && intent_value != 2) do
        Err("invalid_push_intent")
      else
        case finish(intent.state) do
          Err( _) -> Err("invalid_push_intent")
          Ok( _) -> Ok(MobilePushIntentRequest {
            database_path : database_path,
            intent : intent_value
          })
        end
      end
    end
  end
end

fn parse_push_action_completion(input :: Bytes) -> MobilePushActionCompletion ! String do
  case reader(input, 4852) do
    Err( _) -> Err("invalid_push_action_completion")
    Ok( state) -> do
      let path = take_vector_error(state, 4096, "invalid_push_action_completion") ?
      let action = take_vector_error(path.state, 743, "invalid_push_action_completion") ?
      let outcome = take_vector_error(action.state, 1, "invalid_push_action_completion") ?
      case finish(outcome.state) do
        Err( _) -> Err("invalid_push_action_completion")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          let outcome_value = mobile_read_byte(outcome.value) ?
          if String.length(database_path) == 0 || Bytes.length(action.value) < 18 || (outcome_value != 0 && outcome_value != 1) do
            Err("invalid_push_action_completion")
          else
            Ok(MobilePushActionCompletion {
              database_path : database_path,
              action : action.value,
              outcome : outcome_value
            })
          end
        end
      end
    end
  end
end

fn parse_triple_payload_request(input :: Bytes) -> MobileTriplePayloadRequest ! String do
  case reader(input, 614628) do
    Err( _) -> Err("invalid_payload_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let first = take_vector(path.state, 305260) ?
      let second = take_vector(first.state, 305260) ?
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

fn parse_group_add_request(input :: Bytes) -> MobileGroupAddRequest ! String do
  case reader(input, 309773) do
    Err( _) -> Err("invalid_group_request")
    Ok( state) -> do
      let path = take_group_vector(state, 4096) ?
      let group_id = take_group_vector(path.state, 32) ?
      let device_set = take_group_vector(group_id.state, 305260) ?
      let key_package = take_group_vector(device_set.state, 369) ?
      case finish(key_package.state) do
        Err( _) -> Err("invalid_group_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 || Bytes.length(device_set.value) == 0 || Bytes.length(key_package.value) != 369 do
            Err("invalid_group_request")
          else
            Ok(MobileGroupAddRequest {
              database_path : database_path,
              group_id : group_id.value,
              device_set : device_set.value,
              key_package : key_package.value
            })
          end
        end
      end
    end
  end
end

fn parse_group_remove_request(input :: Bytes) -> MobileGroupRemoveRequest ! String do
  case reader(input, 4192) do
    Err( _) -> Err("invalid_group_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let group_id = take_vector(path.state, 32) ?
      let account_id = take_vector(group_id.state, 32) ?
      let device_id = take_vector(account_id.state, 16) ?
      case finish(device_id.state) do
        Err( _) -> Err("invalid_group_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 || Bytes.length(account_id.value) != 32 || Bytes.length(device_id.value) != 16 do
            Err("invalid_group_request")
          else
            Ok(MobileGroupRemoveRequest {
              database_path : database_path,
              group_id : group_id.value,
              account_id : account_id.value,
              device_id : device_id.value
            })
          end
        end
      end
    end
  end
end

fn parse_group_reference_request(input :: Bytes) -> MobileGroupReferenceRequest ! String do
  case reader(input, 4136) do
    Err( _) -> Err("invalid_group_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let group_id = take_vector(path.state, 32) ?
      case finish(group_id.state) do
        Err( _) -> Err("invalid_group_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 do
            Err("invalid_group_request")
          else
            Ok(MobileGroupReferenceRequest {
              database_path : database_path,
              group_id : group_id.value
            })
          end
        end
      end
    end
  end
end

fn parse_group_send_request(input :: Bytes) -> MobileGroupSendRequest ! String do
  case reader(input, 69487) do
    Err( _) -> Err("invalid_group_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let group_id = take_vector(path.state, 32) ?
      let body = take_vector(group_id.state, 65347) ?
      case finish(body.state) do
        Err( _) -> Err("invalid_group_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          if String.length(database_path) == 0 || Bytes.length(group_id.value) != 32 do
            Err("invalid_group_request")
          else
            Ok(MobileGroupSendRequest {
              database_path : database_path,
              group_id : group_id.value,
              body : body.value
            })
          end
        end
      end
    end
  end
end

fn parse_transparency_request(input :: Bytes) -> MobileTransparencyRequest ! String do
  case reader(input, 574446) do
    Err( _) -> Err("invalid_transparency_request")
    Ok( state) -> do
      let path = take_vector(state, 4096) ?
      let username = take_vector(path.state, 64) ?
      let evidence = take_vector(username.state, 570274) ?
      case finish(evidence.state) do
        Err( _) -> Err("invalid_transparency_request")
        Ok( _) -> do
          let database_path = mobile_utf8(path.value, "invalid_database_path") ?
          let expected_username = mobile_utf8(username.value, "invalid_username") ?
          if String.length(database_path) == 0 || String.length(expected_username) == 0 || Bytes.length(evidence.value) == 0 do
            Err("invalid_transparency_request")
          else
            Ok(MobileTransparencyRequest {
              database_path : database_path,
              username : expected_username,
              evidence : evidence.value
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

fn privacy_submission(outer :: Bytes) -> Bytes ! String do
  let config = native_security_config() ?
  let sealed = seal_delivery(outer, X25519PublicKey { bytes : config.delivery_public_key }) ?
  let expires_at = U64.add(current_time() ?, mobile_wide("300000") ?) ?
  encode_privacy_submission(mint_submission(sealed, expires_at, config.abuse_difficulty) ?)
end

fn random_bytes(length :: Int) -> Bytes ! String do
  case Crypto.random_bytes(length) do
    Err( _) -> Err("random_generation_failed")
    Ok( value) -> Ok(value)
  end
end

fn policy(profile :: ClientProfile, now :: U64) -> VerificationPolicy do
  VerificationPolicy {
    current_time : now,
    minimum_directory_sequence : profile.account.directory_sequence
  }
end

fn reject_device_open(signing :: consume SigningPrivateKey, error :: String) -> DeviceKeys ! String do
  Err(error)
end

fn open_account(profile :: ClientProfile,
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

fn reject_prekey_open(signed_private :: consume X25519PrivateKey, error :: String) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String > do
  Err(error)
end

fn reject_post_quantum_open(signed_private :: consume X25519PrivateKey,
one_time_private :: consume X25519PrivateKey,
error :: String) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String > do
  Err(error)
end

fn open_post_quantum_prekey(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> PostQuantumPrekeySecrets ! String do
  let label = "post-quantum-prekey/v1"
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" && profile.bundle.suite == 1 do
      case generate_post_quantum_prekey() do
        Err( _) -> Err("post_quantum_prekey_generation_failed")
        Ok( value) -> Ok(value)
      end
    else
      Err(error)
    end
    Ok( blob) -> do
      let private_key = open_mlkem(blob,
      wrapping_key,
      context(profile.account_id, profile.device_id, label, 15) ?) ?
      Ok(PostQuantumPrekeySecrets {
        private_key : private_key,
        public_key : MlKemPublicKey { bytes : profile.bundle.post_quantum_prekey }
      })
    end
  end
end

fn open_device(profile :: ClientProfile, wrapping_key :: borrow StorageKey, database_path :: String) -> DeviceKeys ! String do
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

fn seal_prekey_pool(entries :: List < MobileOneTimePrekey >, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  seal_local(encode_prekey_entries(entries, 0, Bytes.empty()) ?,
  wrapping_key,
  local_context("one-time-prekeys/v1") ?)
end

fn seal_active_prekey_pool(ids :: List < U64 >, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  seal_local(encode_active_prekey_ids(ids, 0, mobile_wide("0") ?, Bytes.empty()) ?,
  wrapping_key,
  local_context("one-time-prekey-active/v1") ?)
end

fn seal_prekey_wide(label :: String, value :: U64, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  seal_local(mobile_write_u64(value) ?, wrapping_key, local_context(label) ?)
end

fn load_prekey_wide(database_path :: String, label :: String, wrapping_key :: borrow StorageKey) -> U64 ! String do
  mobile_read_u64(open_local(load_blob(database_path, label) ?,
  wrapping_key,
  local_context(label) ?) ?)
end

fn migrate_legacy_prekey(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> List < MobileOneTimePrekey > ! String do
  let id = profile.bundle.one_time_prekey_id
  if !(valid_prekey_id(id) ?) || Bytes.length(profile.bundle.one_time_prekey) != 32 do
    Err("prekey_pool_uninitialized")
  else
    let legacy_private = open_x25519(load_blob(database_path, "one-time-prekey/v1") ?,
    wrapping_key,
    context(profile.account_id, profile.device_id, "one-time-prekey/v1", 10) ?) ?
    let label = one_time_prekey_label(id)
    let blob = seal_x25519(legacy_private, wrapping_key, one_time_prekey_context(profile, id) ?) ?
    let entries = [MobileOneTimePrekey {
      id : id,
      public_key : profile.bundle.one_time_prekey
    }]
    store_prekey_batch(database_path,
    [label],
    [blob],
    List.new(),
    seal_prekey_pool(entries, wrapping_key) ?,
    seal_active_prekey_pool([id], wrapping_key) ?,
    seal_prekey_wide("one-time-prekey-next-id/v1", U64.add(id, mobile_wide("1") ?) ?, wrapping_key) ?,
    true) ?
    Ok(entries)
  end
end

fn load_prekey_pool(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String) -> List < MobileOneTimePrekey > ! String do
  case load_blob(database_path, "one-time-prekeys/v1") do
    Err( error) -> if error == "local_state_not_found" do
      migrate_legacy_prekey(profile, wrapping_key, database_path)
    else
      Err(error)
    end
    Ok( blob) -> decode_prekey_pool(open_local(blob,
    wrapping_key,
    local_context("one-time-prekeys/v1") ?) ?)
  end
end

fn active_ids_belong(active_ids :: List < U64 >, entry_ids :: List < U64 >, index :: Int) -> Bool do
  if index >= List.length(active_ids) do
    true
  else if !contains_prekey_id(entry_ids, List.get(active_ids, index), 0) do
    false
  else
    active_ids_belong(active_ids, entry_ids, index + 1)
  end
end

fn inferred_active_prekey_pool(entries :: List < MobileOneTimePrekey >) -> List < U64 > ! String do
  let ids = mobile_prekey_ids(entries, 0, List.new())
  if List.length(ids) > 64 do
    Err("invalid_active_prekey_pool")
  else
    Ok(ids)
  end
end

fn load_active_prekey_pool(database_path :: String,
entries :: List < MobileOneTimePrekey >,
wrapping_key :: borrow StorageKey) -> List < U64 > ! String do
  case load_blob(database_path, "one-time-prekey-active/v1") do
    Err( error) -> if error == "local_state_not_found" do
      # Pools created before active acknowledgements treat all local entries as
      # active until count=0 recovery obtains the server truth.
      inferred_active_prekey_pool(entries)
    else
      Err(error)
    end
    Ok( blob) -> decode_active_prekey_pool(open_local(blob,
    wrapping_key,
    local_context("one-time-prekey-active/v1") ?) ?,
    mobile_prekey_ids(entries, 0, List.new()))
  end
end

fn generate_prekey_batch(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
next_id :: U64,
remaining :: Int,
entries :: List < MobileOneTimePrekey >,
labels :: List < String >,
blobs :: List < Bytes >) -> Result <( List < MobileOneTimePrekey >, List < String >, List < Bytes >, U64), String > do
  if remaining <= 0 do
    Ok((entries, labels, blobs, next_id))
  else if !(valid_prekey_id(next_id) ?) do
    Err("prekey_id_exhausted")
  else
    let generated = case generate_one_time_prekey(next_id) do
      Err( _) -> Err("prekey_generation_failed")
      Ok( value) -> Ok(value)
    end ?
    let label = one_time_prekey_label(next_id)
    let blob = seal_x25519(generated.private_key,
    wrapping_key,
    one_time_prekey_context(profile, next_id) ?) ?
    generate_prekey_batch(profile,
    wrapping_key,
    U64.add(next_id, mobile_wide("1") ?) ?,
    remaining - 1,
    List.append(entries,
    MobileOneTimePrekey {
      id : next_id,
      public_key : generated.public_key.bytes
    }),
    List.append(labels, label),
    List.append(blobs, blob))
  end
end

fn append_prekeys(source :: List < MobileOneTimePrekey >,
index :: Int,
output :: List < MobileOneTimePrekey >) -> List < MobileOneTimePrekey > do
  if index >= List.length(source) do
    output
  else
    append_prekeys(source, index + 1, List.append(output, List.get(source, index)))
  end
end

fn public_prekeys(entries :: List < MobileOneTimePrekey >,
index :: Int,
output :: List < OneTimePrekeyPublic >) -> List < OneTimePrekeyPublic > do
  if index >= List.length(entries) do
    output
  else
    let entry = List.get(entries, index)
    public_prekeys(entries,
    index + 1,
    List.append(output,
    OneTimePrekeyPublic {
      id : entry.id,
      public_key : entry.public_key
    }))
  end
end

fn find_prekey(entries :: List < MobileOneTimePrekey >, id :: U64, index :: Int) -> MobileOneTimePrekey ! String do
  if index >= List.length(entries) do
    Err("one_time_prekey_not_found")
  else
    let entry = List.get(entries, index)
    if U64.compare(entry.id, id) == 0 do
      Ok(entry)
    else
      find_prekey(entries, id, index + 1)
    end
  end
end

fn remove_prekey(entries :: List < MobileOneTimePrekey >,
id :: U64,
index :: Int,
remaining :: List < MobileOneTimePrekey >) -> List < MobileOneTimePrekey > do
  if index >= List.length(entries) do
    remaining
  else
    let entry = List.get(entries, index)
    if U64.compare(entry.id, id) == 0 do
      remove_prekey(entries, id, index + 1, remaining)
    else
      remove_prekey(entries, id, index + 1, List.append(remaining, entry))
    end
  end
end

fn remove_prekey_id(ids :: List < U64 >, id :: U64, index :: Int, remaining :: List < U64 >) -> List < U64 > do
  if index >= List.length(ids) do
    remaining
  else
    let value = List.get(ids, index)
    if U64.compare(value, id) == 0 do
      remove_prekey_id(ids, id, index + 1, remaining)
    else
      remove_prekey_id(ids, id, index + 1, List.append(remaining, value))
    end
  end
end

fn inactive_prekeys(entries :: List < MobileOneTimePrekey >,
active_ids :: List < U64 >,
index :: Int,
output :: List < MobileOneTimePrekey >) -> List < MobileOneTimePrekey > do
  if index >= List.length(entries) do
    output
  else
    let entry = List.get(entries, index)
    if contains_prekey_id(active_ids, entry.id, 0) do
      inactive_prekeys(entries, active_ids, index + 1, output)
    else
      inactive_prekeys(entries, active_ids, index + 1, List.append(output, entry))
    end
  end
end

fn signed_prekey_publication(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String,
entries :: List < MobileOneTimePrekey >) -> Bytes ! String do
  let unsigned = PrekeyPublishRequest {
    account_id : profile.account_id,
    device_id : profile.device_id,
    prekeys : public_prekeys(entries, 0, List.new()),
    signature : Bytes.empty()
  }
  let device = open_device(profile, wrapping_key, database_path) ?
  let signature = case Crypto.sign(device.signing_private_key,
  prekey_publish_signing_bytes(unsigned) ?) do
    Err( _) -> Err("prekey_publication_signing_failed")
    Ok( value) -> Ok(value.bytes)
  end ?
  encode_prekey_publish(% { unsigned | signature : signature })
end

fn replenish_prekeys(request :: MobilePrekeyRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let existing = load_prekey_pool(profile, wrapping_key, request.database_path) ?
  let active_ids = load_active_prekey_pool(request.database_path, existing, wrapping_key) ?
  let inactive = inactive_prekeys(existing, active_ids, 0, List.new())
  if request.count == 0 do
    signed_prekey_publication(profile, wrapping_key, request.database_path, inactive)
  else if List.length(active_ids) + request.count > 64 do
    Err("prekey_pool_full")
  else
    let next_id = load_prekey_wide(request.database_path,
    "one-time-prekey-next-id/v1",
    wrapping_key) ?
    let ( generated, labels, blobs, following_id) = generate_prekey_batch(profile,
    wrapping_key,
    next_id,
    request.count,
    List.new(),
    List.new(),
    List.new()) ?
    let publication = signed_prekey_publication(profile,
    wrapping_key,
    request.database_path,
    generated) ?
    let retired_overflow = if List.length(inactive) + request.count > 64 do
      List.length(inactive) + request.count - 64
    else
      0
    end
    let ( retained, removed_labels) = retain_reconciled_prekeys(existing,
    active_ids,
    0,
    retired_overflow,
    List.new(),
    List.new()) ?
    let updated = append_prekeys(generated, 0, retained)
    store_prekey_batch(request.database_path,
    labels,
    blobs,
    removed_labels,
    seal_prekey_pool(updated, wrapping_key) ?,
    seal_active_prekey_pool(active_ids, wrapping_key) ?,
    seal_prekey_wide("one-time-prekey-next-id/v1", following_id, wrapping_key) ?,
    false) ?
    Ok(publication)
  end
end

fn retain_reconciled_prekeys(entries :: List < MobileOneTimePrekey >,
active_ids :: List < U64 >,
index :: Int,
drop_inactive :: Int,
retained :: List < MobileOneTimePrekey >,
removed_labels :: List < String >) -> Result <( List < MobileOneTimePrekey >, List < String >), String > do
  if index >= List.length(entries) do
    if drop_inactive == 0 do
      Ok((retained, removed_labels))
    else
      Err("invalid_prekey_reconciliation")
    end
  else
    let entry = List.get(entries, index)
    if contains_prekey_id(active_ids, entry.id, 0) do
      retain_reconciled_prekeys(entries,
      active_ids,
      index + 1,
      drop_inactive,
      List.append(retained, entry),
      removed_labels)
    else if drop_inactive > 0 do
      # ponytail: retain the newest 64 retired/in-flight secrets; if more than
      # 64 claimed initial messages remain undelivered, the oldest can no longer
      # decrypt. Add an acknowledged-delivery protocol before raising this cap.
      retain_reconciled_prekeys(entries,
      active_ids,
      index + 1,
      drop_inactive - 1,
      retained,
      List.append(removed_labels, one_time_prekey_label(entry.id)))
    else
      retain_reconciled_prekeys(entries,
      active_ids,
      index + 1,
      drop_inactive,
      List.append(retained, entry),
      removed_labels)
    end
  end
end

fn reconcile_prekeys(request :: MobilePrekeyReconcileRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let response = case decode_prekey_publish_response(request.response) do
    Err( _) -> Err("invalid_prekey_reconciliation")
    Ok( value) -> Ok(value)
  end ?
  if !Bytes.secure_equals(response.account_id, profile.account_id) || !Bytes.secure_equals(response.device_id,
  profile.device_id) do
    Err("wrong_prekey_reconciliation_identity")
  else
    let wrapping_key = platform_key() ?
    let entries = load_prekey_pool(profile, wrapping_key, request.database_path) ?
    let _ = load_active_prekey_pool(request.database_path, entries, wrapping_key) ?
    let entry_ids = mobile_prekey_ids(entries, 0, List.new())
    if !active_ids_belong(response.active_ids, entry_ids, 0) do
      Err("unknown_active_prekey")
    else
      let inactive_count = List.length(entries) - List.length(response.active_ids)
      let drop_inactive = if inactive_count > 64 do
        inactive_count - 64
      else
        0
      end
      let ( retained, removed_labels) = retain_reconciled_prekeys(entries,
      response.active_ids,
      0,
      drop_inactive,
      List.new(),
      List.new()) ?
      store_prekey_reconciliation(request.database_path,
      removed_labels,
      seal_prekey_pool(retained, wrapping_key) ?,
      seal_active_prekey_pool(response.active_ids, wrapping_key) ?) ?
      mobile_write_u32(List.length(response.active_ids))
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

fn open_pending_post_quantum_prekey(request :: DeviceLinkRequest,
wrapping_key :: borrow StorageKey,
database_path :: String) -> PostQuantumPrekeySecrets ! String do
  let label = "pending-post-quantum-prekey/v1"
  let private_key = open_mlkem(load_blob(database_path, label) ?,
  wrapping_key,
  pending_context(label, 15) ?) ?
  Ok(PostQuantumPrekeySecrets {
    private_key : private_key,
    public_key : MlKemPublicKey { bytes : request.post_quantum_public_key }
  })
end

fn open_prekeys(profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
database_path :: String,
selected :: MobileOneTimePrekey) -> Result <( SignedPrekeySecrets, OneTimePrekeySecrets, PostQuantumPrekeySecrets), String > do
  let signed_blob = load_blob(database_path, "signed-prekey/v1") ?
  let one_time_label = one_time_prekey_label(selected.id)
  let one_time_blob = load_blob(database_path, one_time_label) ?
  let signed_context = context(profile.account_id, profile.device_id, "signed-prekey/v1", 9) ?
  let one_time_context = one_time_prekey_context(profile, selected.id) ?
  case open_x25519(signed_blob, wrapping_key, signed_context) do
    Err( error) -> Err(error)
    Ok( signed_private) -> case open_x25519(one_time_blob, wrapping_key, one_time_context) do
      Err( error) -> reject_prekey_open(signed_private, error)
      Ok( one_time_private) -> case open_post_quantum_prekey(profile, wrapping_key, database_path) do
        Err( error) -> reject_post_quantum_open(signed_private, one_time_private, error)
        Ok( post_quantum) -> Ok((SignedPrekeySecrets {
          id : profile.bundle.signed_prekey_id,
          private_key : signed_private,
          public_key : X25519PublicKey { bytes : profile.bundle.signed_prekey },
          signature : Signature { bytes : profile.bundle.signed_prekey_signature },
          expires_at : profile.bundle.expires_at
        },
        OneTimePrekeySecrets {
          id : selected.id,
          private_key : one_time_private,
          public_key : X25519PublicKey { bytes : selected.public_key }
        },
        post_quantum))
      end
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
        let post_quantum = case generate_post_quantum_prekey() do
          Err( _) -> Err("post_quantum_prekey_generation_failed")
          Ok( value) -> Ok(value)
        end ?
        let request = DeviceLinkRequest {
          version : 2,
          suite : 2,
          nonce : random_bytes(32) ?,
          device_id : device.device_id,
          signing_public_key : device.signing_public_key.bytes,
          dh_public_key : device.identity_public_key.bytes,
          post_quantum_public_key : post_quantum.public_key.bytes,
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
        let post_quantum_blob = seal_mlkem(post_quantum.private_key,
        wrapping_key,
        pending_context("pending-post-quantum-prekey/v1", 15) ?) ?
        store_blobs(database_path,
        ["pending-link-request/v1", "pending-device-signing-key/v1", "pending-device-identity-key/v1", "pending-post-quantum-prekey/v1"],
        [request_blob, signing_blob, identity_blob, post_quantum_blob]) ?
        Ok(request_wire)
      end
    end
  end
end

fn authorize_link(request :: MobilePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
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
    let post_quantum = open_pending_post_quantum_prekey(pending,
    wrapping_key,
    request.database_path) ?
    let bundle = case build_hybrid_prekey_bundle(credential, signed, one_time, post_quantum) do
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
    let profile = encode_client_profile(entry, account.account_id, credential.device_id) ?
    let signing_blob = seal_signing(device.signing_private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "device-signing-key/v1", 7) ?) ?
    let identity_blob = seal_x25519(device.identity_private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "device-identity-key/v1", 8) ?) ?
    let signed_prekey_blob = seal_x25519(signed.private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "signed-prekey/v1", 9) ?) ?
    let one_time_label = one_time_prekey_label(one_time.id)
    let one_time_prekey_blob = seal_x25519(one_time.private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, one_time_label, 10) ?) ?
    let post_quantum_prekey_blob = seal_mlkem(post_quantum.private_key,
    wrapping_key,
    context(account.account_id, credential.device_id, "post-quantum-prekey/v1", 15) ?) ?
    let profile_blob = seal_local(profile, wrapping_key, local_context("profile/v1") ?) ?
    let prekey_index_blob = seal_prekey_pool([MobileOneTimePrekey {
      id : one_time.id,
      public_key : one_time.public_key.bytes
    }],
    wrapping_key) ?
    let prekey_active_blob = seal_active_prekey_pool([one_time.id], wrapping_key) ?
    let prekey_next_id_blob = seal_prekey_wide("one-time-prekey-next-id/v1",
    U64.add(one_time.id, mobile_wide("1") ?) ?,
    wrapping_key) ?
    store_linked_blobs(request.database_path,
    ["device-signing-key/v1", "device-identity-key/v1", "signed-prekey/v1", one_time_label, "post-quantum-prekey/v1", "profile/v1", "one-time-prekeys/v1", "one-time-prekey-active/v1", "one-time-prekey-next-id/v1"],
    [signing_blob, identity_blob, signed_prekey_blob, one_time_prekey_blob, post_quantum_prekey_blob, profile_blob, prekey_index_blob, prekey_active_blob, prekey_next_id_blob]) ?
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

fn contains_device_id(profiles :: List < ClientProfile >, device_id :: Bytes, index :: Int) -> Bool do
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
profiles :: List < ClientProfile >) -> List < ClientProfile > ! String do
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
    let profile = decode_client_profile(encode_client_profile(entry,
    account.account_id,
    credential.device_id) ?) ?
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

fn active_device_rows(profiles :: List < ClientProfile >,
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
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let verified = verified_device_set(request.payload) ?
  let wrapping_key = platform_key() ?
  let _ = require_transparency_device_set(request.database_path, wrapping_key, verified) ?
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

fn local_device_set(local :: ClientProfile, value :: MobileVerifiedDeviceSet) -> Bool do
  local.username == value.value.username && Bytes.secure_equals(local.account_id,
  value.account.account_id) && Bytes.secure_equals(local.entry.account_identity,
  value.value.account_identity) && contains_device_id(value.profiles, local.device_id, 0)
end

fn authorize_link_for_set(request :: MobileTriplePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let devices = verified_device_set(request.first) ?
  let wrapping_key = platform_key() ?
  let _ = require_transparency_device_set(request.database_path, wrapping_key, devices) ?
  let requested_device = parse_link_request(request.second) ?
  let now = current_time() ?
  if !local_device_set(local, devices) || U64.compare(requested_device.created_at, now) > 0 || U64.compare(requested_device.expires_at,
  now) < 0 do
    Err("link_authorization_failed")
  else
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
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let devices = verified_device_set(request.first) ?
  let wrapping_key = platform_key() ?
  let _ = require_transparency_device_set(request.database_path, wrapping_key, devices) ?
  let target = request.second
  let allowed = Bytes.length(target) == 16 && local_device_set(local, devices) && List.length(devices.profiles) > 1 && contains_device_id(devices.profiles,
  target,
  0) && !Bytes.secure_equals(local.device_id, target)
  if !allowed do
    Err("invalid_device_revocation")
  else
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

fn encode_sync_payload(local :: ClientProfile, peer :: ClientProfile, inner :: InnerEnvelope) -> Bytes ! String do
  mobile_join([mobile_vector(Bytes.from_utf8(peer.username)) ?, mobile_vector(peer.account_id) ?, mobile_vector(inner.conversation_id) ?, mobile_vector(inner.client_message_id) ?, mobile_vector(mobile_write_u64(inner.client_timestamp) ?) ?, mobile_vector(inner.body) ?, mobile_vector(mobile_write_u32(inner.disappearing_seconds) ?) ?, mobile_vector(safety_number(local, peer) ?) ?],
  0,
  Bytes.empty())
end

fn parse_sync_payload(input :: Bytes) -> MobileSyncPayload ! String do
  case reader(input, 32500) do
    Err( _) -> Err("invalid_sync_payload")
    Ok( state) -> do
      let peer_username = take_vector_error(state, 64, "invalid_sync_payload") ?
      let peer_account_id = take_vector_error(peer_username.state, 32, "invalid_sync_payload") ?
      let conversation_id = take_vector_error(peer_account_id.state, 16, "invalid_sync_payload") ?
      let client_message_id = take_vector_error(conversation_id.state, 16, "invalid_sync_payload") ?
      let client_timestamp = take_vector_error(client_message_id.state, 8, "invalid_sync_payload") ?
      let body = take_vector_error(client_timestamp.state, 32000, "invalid_sync_payload") ?
      let disappearing_seconds = take_vector_error(body.state, 4, "invalid_sync_payload") ?
      let safety = optional_safety_number(disappearing_seconds.state) ?
      case finish(safety.state) do
        Err( _) -> Err("invalid_sync_payload")
        Ok( _) -> do
          let username = mobile_utf8(peer_username.value, "invalid_sync_payload") ?
          if String.length(username) == 0 || Bytes.length(peer_account_id.value) != 32 || Bytes.length(conversation_id.value) != 16 || Bytes.length(client_message_id.value) != 16 || Bytes.length(client_timestamp.value) != 8 || Bytes.length(disappearing_seconds.value) != 4 do
            Err("invalid_sync_payload")
          else
            let timestamp = case mobile_read_u64(client_timestamp.value) do
              Err( _) -> Err("invalid_sync_payload")
              Ok( value) -> Ok(value)
            end ?
            let disappearing = case mobile_read_u32(disappearing_seconds.value) do
              Err( _) -> Err("invalid_sync_payload")
              Ok( value) -> Ok(value)
            end ?
            Ok(MobileSyncPayload {
              peer_username : username,
              peer_account_id : peer_account_id.value,
              conversation_id : conversation_id.value,
              client_message_id : client_message_id.value,
              client_timestamp : timestamp,
              body : body.value,
              disappearing_seconds : disappearing,
              safety_number : safety.value
            })
          end
        end
      end
    end
  end
end

fn sync_history_inner(local :: ClientProfile, value :: MobileSyncPayload) -> InnerEnvelope ! String do
  Ok(InnerEnvelope {
    version : 1,
    sender_account_id : local.account_id,
    sender_device_id : local.device_id,
    recipient_device_id : mobile_zeroes(16) ?,
    conversation_id : value.conversation_id,
    client_message_id : value.client_message_id,
    client_timestamp : value.client_timestamp,
    message_type : 1,
    body : value.body,
    reply_reference : Bytes.empty(),
    attachment_manifest : Bytes.empty(),
    receipt_policy : 0,
    disappearing_seconds : value.disappearing_seconds,
    extensions : List.new()
  })
end

fn initial_bytes(value :: InitialMessage) -> Bytes ! String do
  case encode_initial_message(value) do
    Err( _) -> Err("initial_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn parse_initial_packet(input :: Bytes, recipient :: borrow X25519PrivateKey) -> Result <( Bytes, Bytes), String > do
  case open_initial_packet(input, recipient) do
    Err( error) -> if error == "initial_crypto_failed" do
      Err(error)
    else
      Err("invalid_initial_packet")
    end
    Ok( RatchetPacket( _)) -> Err("invalid_initial_packet")
    Ok( InitialPacket( account_identity, message)) -> Ok((account_identity, message))
  end
end

fn session_label(session_id :: Bytes) -> String do
  "session/v1/#{Bytes.to_hex(session_id)}"
end

fn encode_session_record(snapshot_blob :: Bytes,
local :: ClientProfile,
peer :: ClientProfile,
conversation_id :: Bytes,
request_state :: Int,
key_changed :: Bool,
strongest_suite :: Int) -> Bytes ! String do
  mobile_join([mobile_vector(snapshot_blob) ?, mobile_vector(local.account_id) ?, mobile_vector(local.device_id) ?, mobile_vector(peer.account_id) ?, mobile_vector(peer.device_id) ?, mobile_vector(Bytes.from_utf8(peer.username)) ?, mobile_vector(peer.entry.mailbox_token) ?, mobile_vector(conversation_id) ?, mobile_vector(mobile_byte(request_state) ?) ?, mobile_vector(mobile_byte(0) ?) ?, mobile_vector(mobile_byte(0) ?) ?, mobile_vector(mobile_byte(if key_changed do
    1
  else
    0
  end) ?) ?, mobile_vector(mobile_write_u32(0) ?) ?, mobile_vector(mobile_byte(strongest_suite) ?) ?, mobile_vector(safety_number(local, peer) ?) ?],
  0,
  Bytes.empty())
end

fn optional_safety_number(state :: BinaryReader) -> MobileReadBytes ! String do
  if state.offset == Bytes.length(state.input) do
    Ok(MobileReadBytes { state : state, value : Bytes.empty() })
  else
    let value = take_vector(state, 64) ?
    if Bytes.length(value.value) != 0 && Bytes.length(value.value) != 64 do
      Err("invalid_safety_number")
    else
      Ok(value)
    end
  end
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
      let strongest_suite = if disappearing_seconds.state.offset == Bytes.length(disappearing_seconds.state.input) do
        MobileReadBytes {
          state : disappearing_seconds.state,
          value : mobile_byte(1) ?
        }
      else
        take_vector(disappearing_seconds.state, 1) ?
      end
      let safety = optional_safety_number(strongest_suite.state) ?
      case finish(safety.state) do
        Err( _) -> Err("invalid_session_record")
        Ok( _) -> do
          let username = mobile_utf8(peer_username.value, "invalid_session_record") ?
          let request_value = mobile_read_byte(request_state.value) ?
          let blocked_value = mobile_read_byte(blocked.value) ?
          let verified_value = mobile_read_byte(verified.value) ?
          let changed_value = mobile_read_byte(key_changed.value) ?
          let disappearing_value = mobile_read_u32(disappearing_seconds.value) ?
          let strongest_value = mobile_read_byte(strongest_suite.value) ?
          let valid = Bytes.length(local_account_id.value) == 32 && Bytes.length(local_device_id.value) == 16 && Bytes.length(peer_account_id.value) == 32 && Bytes.length(peer_device_id.value) == 16 && String.length(username) > 0 && Bytes.length(peer_mailbox.value) == 32 && Bytes.length(conversation_id.value) == 16 && (request_value == 0 || request_value == 1) && blocked_value <= 1 && verified_value <= 1 && changed_value <= 1 && (strongest_value == 1 || strongest_value == 2)
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
              verified : verified_value == 1 && Bytes.length(safety.value) == 64,
              key_changed : changed_value == 1 || Bytes.length(safety.value) == 0,
              disappearing_seconds : disappearing_value,
              strongest_suite : strongest_value,
              safety_number : safety.value
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

fn prepared_session_ids(prepared :: List < MobilePreparedSend >,
index :: Int,
session_ids :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(prepared) do
    session_ids
  else
    let value = List.get(prepared, index)
    let next = if value.new_session && !contains_session_id(session_ids, value.session_id, 0) do
      List.append(session_ids, value.session_id)
    else
      session_ids
    end
    prepared_session_ids(prepared, index + 1, next)
  end
end

fn prepared_envelopes(prepared :: List < MobilePreparedSend >,
index :: Int,
envelopes :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(prepared) do
    envelopes
  else
    prepared_envelopes(prepared,
    index + 1,
    List.append(envelopes, List.get(prepared, index).envelope))
  end
end

fn seal_session_ids(session_ids :: List < Bytes >, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  seal_local(mobile_join(session_ids, 0, Bytes.empty()) ?,
  wrapping_key,
  local_context("sessions/v1") ?)
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

fn preferred_session(first :: MobileLoadedSession, second :: MobileLoadedSession) -> MobileLoadedSession do
  let first_active = Bytes.length(first.record.snapshot) > 0
  let second_active = Bytes.length(second.record.snapshot) > 0
  if second_active && !first_active do
    second
  else if first_active && !second_active do
    first
  else if second.record.strongest_suite > first.record.strongest_suite do
    second
  else if second.record.strongest_suite == first.record.strongest_suite && Bytes.length(second.record.safety_number) == 64 && !Bytes.secure_equals(first.record.safety_number, second.record.safety_number) do
    second
  else
    first
  end
end

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
      case find_peer_session(database_path, wrapping_key, peer_account_id, session_ids, index + 1) do
        Err( error) -> if error == "session_not_found" do
          Ok(loaded)
        else
          Err(error)
        end
        Ok( next) -> Ok(preferred_session(loaded, next))
      end
    else
      find_peer_session(database_path, wrapping_key, peer_account_id, session_ids, index + 1)
    end
  end
end

fn find_device_session(database_path :: String,
wrapping_key :: borrow StorageKey,
peer_account_id :: Bytes,
peer_device_id :: Bytes,
session_ids :: List < Bytes >,
index :: Int) -> MobileLoadedSession ! String do
  if index >= List.length(session_ids) do
    Err("session_not_found")
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) && Bytes.secure_equals(loaded.record.peer_device_id,
    peer_device_id) do
      case find_device_session(database_path,
      wrapping_key,
      peer_account_id,
      peer_device_id,
      session_ids,
      index + 1) do
        Err( error) -> if error == "session_not_found" do
          Ok(loaded)
        else
          Err(error)
        end
        Ok( next) -> Ok(preferred_session(loaded, next))
      end
    else
      find_device_session(database_path,
      wrapping_key,
      peer_account_id,
      peer_device_id,
      session_ids,
      index + 1)
    end
  end
end

fn strongest_device_suite(database_path :: String,
wrapping_key :: borrow StorageKey,
peer_account_id :: Bytes,
peer_device_id :: Bytes,
session_ids :: List < Bytes >,
index :: Int,
strongest :: Int) -> Int ! String do
  if index >= List.length(session_ids) do
    Ok(strongest)
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    let matches = Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) && Bytes.secure_equals(loaded.record.peer_device_id,
    peer_device_id)
    let next = if matches && loaded.record.strongest_suite > strongest do
      loaded.record.strongest_suite
    else
      strongest
    end
    strongest_device_suite(database_path,
    wrapping_key,
    peer_account_id,
    peer_device_id,
    session_ids,
    index + 1,
    next)
  end
end

fn device_needs_prekey(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
profile :: ClientProfile) -> Bool ! String do
  case find_device_session(database_path,
  wrapping_key,
  profile.account_id,
  profile.device_id,
  session_ids,
  0) do
    Err( error) -> if error == "session_not_found" do
      Ok(true)
    else
      Err(error)
    end
    Ok( loaded) -> if loaded.record.strongest_suite > profile.bundle.suite do
      Err("peer_keys_changed")
    else
      Ok(loaded.record.strongest_suite < profile.bundle.suite || Bytes.length(loaded.record.safety_number) == 0)
    end
  end
end

fn conversation_alias_id(peer_account_id :: Bytes) -> Bytes ! String do
  Ok(Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/conversation-alias/v1"),
  peer_account_id) ?))
end

fn self_sync_conversation_id(account_id :: Bytes) -> Bytes ! String do
  case Bytes.slice(Crypto.sha256(mobile_append(Bytes.from_utf8("mesh-msg/mobile/self-sync/v1"),
  account_id) ?),
  0,
  16) do
    Err( _) -> Err("self_sync_failed")
    Ok( value) -> Ok(value)
  end
end

fn ensure_conversation_alias(database_path :: String,
wrapping_key :: borrow StorageKey,
local :: ClientProfile,
sync :: MobileSyncPayload) -> Result <(), String > do
  let alias_id = conversation_alias_id(sync.peer_account_id) ?
  let label = session_label(alias_id)
  case load_blob(database_path, label) do
    Ok( _) -> do
      let existing = load_session_record(database_path, wrapping_key, alias_id) ?
      if Bytes.secure_equals(existing.record.conversation_id, sync.conversation_id) && Bytes.secure_equals(existing.record.peer_account_id,
      sync.peer_account_id) do
        Ok(nil)
      else
        Err("sync_conversation_mismatch")
      end
    end
    Err( error) -> if error != "local_state_not_found" do
      Err(error)
    else
      let record = MobileSessionRecord {
        snapshot : Bytes.empty(),
        local_account_id : local.account_id,
        local_device_id : local.device_id,
        peer_account_id : sync.peer_account_id,
        peer_device_id : mobile_zeroes(16) ?,
        peer_username : sync.peer_username,
        peer_mailbox : mobile_zeroes(32) ?,
        conversation_id : sync.conversation_id,
        request_state : 1,
        blocked : false,
        verified : false,
        key_changed : false,
        disappearing_seconds : sync.disappearing_seconds,
        strongest_suite : 1,
        safety_number : sync.safety_number
      }
      let blob = seal_local(updated_session_record(record.snapshot, record) ?,
      wrapping_key,
      local_context(label) ?) ?
      let index_blob = updated_session_index(database_path, wrapping_key, alias_id) ?
      store_new_session(database_path, label, blob, index_blob)
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

fn decode_outbox_ids_parts(state :: BinaryReader, count :: Int, index :: Int, ids :: List < Bytes >) -> List < Bytes > ! String do
  if index >= count do
    case finish(state) do
      Err( _) -> Err("invalid_outbox")
      Ok( _) -> Ok(ids)
    end
  else
    let id = take_vector(state, 16) ?
    if Bytes.length(id.value) != 16 do
      Err("invalid_outbox")
    else
      decode_outbox_ids_parts(id.state, count, index + 1, List.append(ids, id.value))
    end
  end
end

fn decode_outbox_ids(input :: Bytes) -> List < Bytes > ! String do
  case reader(input, 2048) do
    Err( _) -> Err("invalid_outbox")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let count_value = mobile_read_u32(count.value) ?
      if count_value > 64 do
        Err("invalid_outbox")
      else
        decode_outbox_ids_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn outbox_entry_label(id :: Bytes) -> String ! String do
  if Bytes.length(id) != 16 do
    Err("invalid_outbox")
  else
    Ok("outbox-envelope/v1/#{Bytes.to_hex(id)}")
  end
end

fn outbox_tail_label(id :: Bytes) -> String ! String do
  if Bytes.length(id) != 16 do
    Err("invalid_outbox")
  else
    Ok("outbox-envelope-tail/v1/#{Bytes.to_hex(id)}")
  end
end

fn load_outbox_ids(database_path :: String, wrapping_key :: borrow StorageKey) -> List < Bytes > ! String do
  case load_blob(database_path, "outbox/v1") do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> decode_outbox_ids(open_local(blob, wrapping_key, local_context("outbox/v1") ?) ?)
  end
end

fn outbox_contains(ids :: List < Bytes >, id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(ids) do
    false
  else if Bytes.secure_equals(List.get(ids, index), id) do
    true
  else
    outbox_contains(ids, id, index + 1)
  end
end

fn prepare_outbox(envelopes :: List < Bytes >,
wrapping_key :: borrow StorageKey,
index :: Int,
ids :: List < Bytes >,
labels :: List < String >,
blobs :: List < Bytes >) -> Result <( List < Bytes >, List < String >, List < Bytes >), String > do
  if index >= List.length(envelopes) do
    Ok((ids, labels, blobs))
  else
    let envelope = List.get(envelopes, index)
    let outer = canonical_outer(envelope) ?
    let label = outbox_entry_label(outer.envelope_id) ?
    let envelope_length = Bytes.length(envelope)
    if envelope_length > 65606 || outbox_contains(ids, outer.envelope_id, 0) do
      Err("invalid_outbox")
    else
      let head_length = if envelope_length > 65532 do
        65532
      else
        envelope_length
      end
      let head = mobile_append(mobile_write_u32(envelope_length) ?,
      Bytes.slice(envelope, 0, head_length) ?) ?
      let head_blob = seal_local(head, wrapping_key, local_context(label) ?) ?
      if envelope_length == head_length do
        prepare_outbox(envelopes,
        wrapping_key,
        index + 1,
        List.append(ids, outer.envelope_id),
        List.append(labels, label),
        List.append(blobs, head_blob))
      else
        let tail_label = outbox_tail_label(outer.envelope_id) ?
        let tail = Bytes.slice(envelope, head_length, envelope_length - head_length) ?
        prepare_outbox(envelopes,
        wrapping_key,
        index + 1,
        List.append(ids, outer.envelope_id),
        List.append(List.append(labels, label), tail_label),
        List.append(List.append(blobs, head_blob),
        seal_local(tail, wrapping_key, local_context(tail_label) ?) ?))
      end
    end
  end
end

fn prepare_outbox_writes(wrapping_key :: borrow StorageKey,
existing_ids :: List < Bytes >,
envelopes :: List < Bytes >) -> Result <( List < String >, List < Bytes >, Bytes), String > do
  if List.length(existing_ids) + List.length(envelopes) > 64 do
    Err("outbox_full")
  else
    let ( ids, labels, blobs) = prepare_outbox(envelopes,
    wrapping_key,
    0,
    existing_ids,
    List.new(),
    List.new()) ?
    let index_blob = seal_local(encode_output_list(ids) ?,
    wrapping_key,
    local_context("outbox/v1") ?) ?
    Ok((labels, blobs, index_blob))
  end
end

fn load_outbox_entry(database_path :: String, wrapping_key :: borrow StorageKey, id :: Bytes) -> Bytes ! String do
  let label = outbox_entry_label(id) ?
  let head = open_local(load_blob(database_path, label) ?, wrapping_key, local_context(label) ?) ?
  if Bytes.length(head) < 4 do
    Err("invalid_outbox")
  else
    let envelope_length = mobile_read_u32(Bytes.slice(head, 0, 4) ?) ?
    let head_length = Bytes.length(head) - 4
    if envelope_length > 65606 || envelope_length < head_length || head_length > 65532 do
      Err("invalid_outbox")
    else
      let head_value = Bytes.slice(head, 4, head_length) ?
      let value = if envelope_length == head_length do
        Ok(head_value)
      else if head_length != 65532 || envelope_length - head_length > 74 do
        Err("invalid_outbox")
      else
        let tail_label = outbox_tail_label(id) ?
        let tail = open_local(load_blob(database_path, tail_label) ?,
        wrapping_key,
        local_context(tail_label) ?) ?
        if Bytes.length(tail) != envelope_length - head_length do
          Err("invalid_outbox")
        else
          mobile_append(head_value, tail)
        end
      end ?
      let outer = canonical_outer(value) ?
      if Bytes.secure_equals(outer.envelope_id, id) do
        Ok(value)
      else
        Err("invalid_outbox")
      end
    end
  end
end

fn load_outbox_entries(database_path :: String,
wrapping_key :: borrow StorageKey,
ids :: List < Bytes >,
index :: Int,
entries :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(ids) || index >= 8 do
    Ok(entries)
  else
    load_outbox_entries(database_path,
    wrapping_key,
    ids,
    index + 1,
    List.append(entries, load_outbox_entry(database_path, wrapping_key, List.get(ids, index)) ?))
  end
end

fn remove_outbox_id(ids :: List < Bytes >, id :: Bytes, index :: Int, remaining :: List < Bytes >) -> List < Bytes > do
  if index >= List.length(ids) do
    remaining
  else if Bytes.secure_equals(List.get(ids, index), id) do
    remove_outbox_id(ids, id, index + 1, remaining)
  else
    remove_outbox_id(ids, id, index + 1, List.append(remaining, List.get(ids, index)))
  end
end

fn update_outbox_index(database :: SqliteConn, remaining :: List < Bytes >, index_blob :: Bytes) -> Result <(), String > do
  if List.length(remaining) == 0 do
    delete_blob(database, "outbox/v1")
  else
    put_blob(database, "outbox/v1", index_blob)
  end
end

fn store_outbox_ack(database_path :: String,
id :: Bytes,
remaining :: List < Bytes >,
index_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case delete_blob(database, outbox_entry_label(id) ?) do
          Err( error) -> Err(error)
          Ok( _) -> case delete_blob(database, outbox_tail_label(id) ?) do
            Err( error) -> Err(error)
            Ok( _) -> case update_outbox_index(database, remaining, index_blob) do
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

fn list_outbox(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let wrapping_key = platform_key() ?
  encode_output_list(load_outbox_entries(database_path,
  wrapping_key,
  load_outbox_ids(database_path, wrapping_key) ?,
  0,
  List.new()) ?)
end

fn acknowledge_outbox(request :: MobilePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let envelope = canonical_outer(request.payload) ?
  let wrapping_key = platform_key() ?
  let ids = load_outbox_ids(request.database_path, wrapping_key) ?
  if !outbox_contains(ids, envelope.envelope_id, 0) do
    Ok(Bytes.empty())
  else if !Bytes.secure_equals(load_outbox_entry(request.database_path,
  wrapping_key,
  envelope.envelope_id) ?,
  request.payload) do
    Err("outbox_ack_mismatch")
  else
    let remaining = remove_outbox_id(ids, envelope.envelope_id, 0, List.new())
    let index_blob = if List.length(remaining) == 0 do
      Bytes.empty()
    else
      seal_local(encode_output_list(remaining) ?, wrapping_key, local_context("outbox/v1") ?) ?
    end
    store_outbox_ack(request.database_path, envelope.envelope_id, remaining, index_blob) ?
    Ok(Bytes.empty())
  end
end

fn bytes_before(left :: Bytes, right :: Bytes, index :: Int) -> Bool ! String do
  if Bytes.length(left) != Bytes.length(right) do
    Err("invalid_safety_number")
  else if index >= Bytes.length(left) do
    Ok(false)
  else
    let left_byte = mobile_read_byte(Bytes.slice(left, index, 1) ?) ?
    let right_byte = mobile_read_byte(Bytes.slice(right, index, 1) ?) ?
    if left_byte == right_byte do
      bytes_before(left, right, index + 1)
    else
      Ok(left_byte < right_byte)
    end
  end
end

fn safety_number(local :: ClientProfile, peer :: ClientProfile) -> Bytes ! String do
  let local_identity = mobile_append(local.account_id, local.account.authorization_public_key) ?
  let peer_identity = mobile_append(peer.account_id, peer.account.authorization_public_key) ?
  let ordered = if bytes_before(local_identity, peer_identity, 0) ? do
    [local_identity, peer_identity]
  else
    [peer_identity, local_identity]
  end
  Ok(Bytes.from_utf8(Bytes.to_hex(Crypto.sha256(mobile_join([Bytes.from_utf8("mesh-msg/mobile/account-safety/v2"), List.get(ordered,
  0), List.get(ordered, 1)],
  0,
  Bytes.empty()) ?))))
end

fn conversation_summary(loaded :: MobileLoadedSession) -> Bytes ! String do
  mobile_join([mobile_vector(loaded.record.conversation_id) ?, mobile_vector(Bytes.from_utf8(loaded.record.peer_username)) ?, mobile_vector(loaded.record.peer_account_id) ?, mobile_vector(loaded.record.peer_device_id) ?, mobile_vector(loaded.record.safety_number) ?, mobile_vector(mobile_byte(loaded.record.request_state) ?) ?, mobile_vector(mobile_byte(if loaded.record.blocked do
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

pub fn decode_conversation_summary(input :: Bytes) -> ConversationSummary ! String do
  case reader(input, 1024) do
    Err( _) -> Err("invalid_conversation_summary")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let entry_bytes = take_vector(count.state, 512) ?
      let entry = case reader(entry_bytes.value, 512) do
        Err( _) -> Err("invalid_conversation_summary")
        Ok( value) -> Ok(value)
      end ?
      let conversation_id = take_vector(entry, 16) ?
      let username = take_vector(conversation_id.state, 32) ?
      let peer_account_id = take_vector(username.state, 32) ?
      let peer_device_id = take_vector(peer_account_id.state, 16) ?
      let safety = take_vector(peer_device_id.state, 64) ?
      let request_state = take_vector(safety.state, 1) ?
      let blocked = take_vector(request_state.state, 1) ?
      let verified = take_vector(blocked.state, 1) ?
      let key_changed = take_vector(verified.state, 1) ?
      let disappearing = take_vector(key_changed.state, 4) ?
      let request_value = mobile_read_byte(request_state.value) ?
      let blocked_value = mobile_read_byte(blocked.value) ?
      let verified_value = mobile_read_byte(verified.value) ?
      let changed_value = mobile_read_byte(key_changed.value) ?
      let username_value = mobile_utf8(username.value, "invalid_conversation_summary") ?
      let valid_safety = Bytes.length(safety.value) == 64 || (Bytes.length(safety.value) == 0 && verified_value == 0 && changed_value == 1)
      let valid = mobile_read_u32(count.value) ? == 1 && String.length(username_value) > 0 && Bytes.length(conversation_id.value) == 16 && Bytes.length(peer_account_id.value) == 32 && Bytes.length(peer_device_id.value) == 16 && valid_safety && (request_value == 0 || request_value == 1) && blocked_value <= 1 && verified_value <= 1 && changed_value <= 1
      case finish(entry_bytes.state) do
        Err( _) -> Err("invalid_conversation_summary")
        Ok( _) -> case finish(disappearing.state) do
          Err( _) -> Err("invalid_conversation_summary")
          Ok( _) -> if !valid do
            Err("invalid_conversation_summary")
          else
            Ok(ConversationSummary {
              conversation_id : conversation_id.value,
              username : username_value,
              peer_account_id : peer_account_id.value,
              peer_device_id : peer_device_id.value,
              safety_number : safety.value,
              request_state : request_value,
              blocked : blocked_value == 1,
              verified : verified_value == 1,
              key_changed : changed_value == 1,
              disappearing_seconds : mobile_read_u32(disappearing.value) ?
            })
          end
        end
      end
    end
  end
end

fn collect_conversations(database_path :: String,
wrapping_key :: borrow StorageKey,
local_account_id :: Bytes,
session_ids :: List < Bytes >,
index :: Int,
seen_accounts :: List < Bytes >,
values :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(session_ids) do
    Ok(values)
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    if Bytes.secure_equals(local_account_id, loaded.record.peer_account_id) || contains_session_id(seen_accounts,
    loaded.record.peer_account_id,
    0) do
      collect_conversations(database_path,
      wrapping_key,
      local_account_id,
      session_ids,
      index + 1,
      seen_accounts,
      values)
    else
      let preferred = find_peer_session(database_path,
      wrapping_key,
      loaded.record.peer_account_id,
      session_ids,
      0) ?
      collect_conversations(database_path,
      wrapping_key,
      local_account_id,
      session_ids,
      index + 1,
      List.append(seen_accounts, loaded.record.peer_account_id),
      List.append(values, conversation_summary(preferred) ?))
    end
  end
end

fn list_conversations(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let wrapping_key = platform_key() ?
  let local = decode_client_profile(load_profile(database_path) ?) ?
  let session_ids = load_session_ids(database_path, wrapping_key) ?
  encode_output_list(collect_conversations(database_path,
  wrapping_key,
  local.account_id,
  session_ids,
  0,
  List.new(),
  List.new()) ?)
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
  Ok(loaded.record.safety_number)
end

fn reject_session_snapshot(state :: consume RatchetState) -> Result <( Bytes, String, Bytes), String > do
  Err("session_snapshot_failed")
end

fn finish_session_snapshot(state :: consume RatchetState,
snapshot_blob :: Bytes,
wrapping_key :: borrow StorageKey,
local :: ClientProfile,
peer :: ClientProfile,
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
  key_changed,
  state.suite) ?
  Ok((session_id, label, seal_local(record, wrapping_key, local_context(label) ?) ?))
end

fn seal_session(state :: consume RatchetState,
wrapping_key :: borrow StorageKey,
local :: ClientProfile,
peer :: ClientProfile,
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

fn finish_upgraded_session_snapshot(state :: consume RatchetState,
snapshot_blob :: Bytes,
wrapping_key :: borrow StorageKey,
previous :: MobileLoadedSession,
local :: ClientProfile,
peer :: ClientProfile,
session_id :: Bytes,
label :: String) -> Result <( Bytes, String, Bytes), String > do
  let safety = safety_number(local, peer) ?
  let changed = !Bytes.secure_equals(previous.record.safety_number, safety)
  let record = % { previous.record | snapshot : snapshot_blob, peer_account_id : peer.account_id, peer_device_id : peer.device_id, peer_username : peer.username, peer_mailbox : peer.entry.mailbox_token, strongest_suite : state.suite, safety_number : safety, verified : previous.record.verified && !changed, key_changed : previous.record.key_changed || changed }
  Ok((session_id,
  label,
  seal_local(updated_session_record(record.snapshot, record) ?,
  wrapping_key,
  local_context(label) ?) ?))
end

fn seal_upgraded_session(state :: consume RatchetState,
wrapping_key :: borrow StorageKey,
previous :: MobileLoadedSession,
local :: ClientProfile,
peer :: ClientProfile) -> Result <( Bytes, String, Bytes), String > do
  let session_id = state.session_id
  let label = session_label(session_id)
  case snapshot(state,
  wrapping_key,
  previous.record.local_account_id,
  previous.record.local_device_id,
  mobile_wide("1") ?) do
    SnapshotRejected( rejected_state, _) -> reject_session_snapshot(rejected_state)
    SnapshotSealed( next_state, snapshot_blob) -> finish_upgraded_session_snapshot(next_state,
    snapshot_blob,
    wrapping_key,
    previous,
    local,
    peer,
    session_id,
    label)
  end
end

fn store_new_session(database_path :: String, label :: String, blob :: Bytes, index_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, label, blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, "sessions/v1", index_blob) do
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

fn store_received_session(database_path :: String,
label :: String,
blob :: Bytes,
index_blob :: Bytes,
updated_labels :: List < String >,
updated_blobs :: List < Bytes >,
removed_labels :: List < String >,
prekey_index_blob :: Bytes,
prekey_active_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, label, blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, "sessions/v1", index_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blobs(database, updated_labels, updated_blobs, 0) do
              Err( error) -> Err(error)
              Ok( _) -> case delete_blobs(database, removed_labels, 0) do
                Err( error) -> Err(error)
                Ok( _) -> case put_blob(database, "one-time-prekeys/v1", prekey_index_blob) do
                  Err( error) -> Err(error)
                  Ok( _) -> case put_blob(database, "one-time-prekey-active/v1", prekey_active_blob) do
                    Err( error) -> Err(error)
                    Ok( _) -> case Sqlite.commit(database) do
                      Err( _) -> Err("database_write_failed")
                      Ok( _) -> Ok(nil)
                    end
                  end
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

fn outer_bytes(mailbox_token :: Bytes, suite :: Int, packet :: Bytes, now :: U64) -> Bytes ! String do
  let expiration = U64.add(now, mobile_wide("2592000000") ?) ?
  case encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : random_bytes(16) ?,
    mailbox_token : mailbox_token,
    suite : suite,
    expiration : expiration,
    padding_bucket : padding_bucket(Bytes.length(packet)) ?,
    ciphertext : packet
  }) do
    Err( _) -> Err("outer_encoding_failed")
    Ok( encoded) -> if Bytes.length(encoded) > 65606 do
      Err("message_too_large")
    else
      Ok(encoded)
    end
  end
end

fn start_conversation(request :: MobileStartRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_encode_client_profile = load_profile(request.database_path) ?
  let local = decode_client_profile(local_encode_client_profile) ?
  let peer = decode_client_profile(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
  let _ = if List.length(pending_ids) >= 64 do
    Err("outbox_full")
  else
    Ok(nil)
  end ?
  let session_ids = load_session_ids(request.database_path, wrapping_key) ?
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
  let plaintext = case encode_initial_plaintext(local_encode_client_profile, inner_bytes(inner) ?) do
    Err( _) -> Err("invalid_initial_plaintext")
    Ok( value) -> Ok(value)
  end ?
  let strongest_suite = strongest_device_suite(request.database_path,
  wrapping_key,
  peer.account_id,
  peer.device_id,
  session_ids,
  0,
  0) ?
  let ( state, initial) = case initiate(local_device,
  local.credential,
  peer.account,
  peer.bundle,
  policy(peer, now),
  strongest_suite,
  plaintext) do
    Err( _) -> Err("session_start_failed")
    Ok( value) -> Ok(value)
  end ?
  let packet = seal_initial_packet(local.entry.account_identity, initial_bytes(initial) ?,
  X25519PublicKey { bytes : peer.credential.dh_public_key }) ?
  let outer = outer_bytes(peer.entry.mailbox_token, initial.suite, packet, now) ?
  let ( session_id, label, session_blob) = seal_session(state,
  wrapping_key,
  local,
  peer,
  conversation_id,
  1,
  false) ?
  let prepared = [MobilePreparedSend {
    envelope : outer,
    session_id : session_id,
    session_label : label,
    session_blob : session_blob,
    new_session : true
  }]
  let index_blob = seal_session_ids(prepared_session_ids(prepared, 0, session_ids), wrapping_key) ?
  let ( history_key, history_blob) = updated_history(request.database_path, wrapping_key, inner, 1) ?
  let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
  pending_ids,
  [outer]) ?
  store_outbound(request.database_path,
  prepared,
  List.new(),
  index_blob,
  history_key,
  history_blob,
  outbox_labels,
  outbox_blobs,
  outbox_index_blob) ?
  Ok(outer)
end

fn receive_initial_message(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_encode_client_profile = load_profile(request.database_path) ?
  let local = decode_client_profile(local_encode_client_profile) ?
  let outer = canonical_outer(request.outer) ?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let wrapping_key = platform_key() ?
    let local_device = open_device(local, wrapping_key, request.database_path) ?
    let ( packet_account_identity, packet_message) = parse_initial_packet(outer.ciphertext, local_device.identity_private_key) ?
    let initial = case decode_initial_message(packet_message) do
      Err( _) -> Err("invalid_initial_message")
      Ok( value) -> Ok(value)
    end ?
    if outer.suite != initial.suite do
      Err("outer_suite_mismatch")
    else
      let initiator_account = case decode_account_identity(packet_account_identity) do
        Err( _) -> Err("invalid_initiator_account")
        Ok( value) -> Ok(value)
      end ?
      let session_ids = load_session_ids(request.database_path, wrapping_key) ?
      let prekeys = load_prekey_pool(local, wrapping_key, request.database_path) ?
      let active_prekeys = load_active_prekey_pool(request.database_path, prekeys, wrapping_key) ?
      let selected_prekey = find_prekey(prekeys, initial.one_time_prekey_id, 0) ?
      let responder_bundle = % { local.bundle | one_time_prekey_id : selected_prekey.id, one_time_prekey : selected_prekey.public_key }
      let initiator_credential = case decode_device_credential(initial.initiator_credential) do
        Err( _) -> Err("invalid_initiator_credential")
        Ok( value) -> Ok(value)
      end ?
      let strongest_suite = strongest_device_suite(request.database_path,
      wrapping_key,
      initiator_account.account_id,
      initiator_credential.device_id,
      session_ids,
      0,
      0) ?
      let ( signed, one_time, post_quantum) = open_prekeys(local,
      wrapping_key,
      request.database_path,
      selected_prekey) ?
      let now = current_time() ?
      let ( state, plaintext) = case receive_initial(local_device,
      local.account,
      responder_bundle,
      signed,
      one_time,
      post_quantum,
      initiator_account,
      policy(local, now),
      VerificationPolicy {
        current_time : now,
        minimum_directory_sequence : initiator_account.directory_sequence
      },
      strongest_suite,
      packet_message) do
        Err( error) -> if is_retryable_session_error(error) do
          Err("initial_crypto_failed")
        else
          Err("initial_receive_failed")
        end
        Ok( value) -> Ok(value)
      end ?
      let decoded = case decode_initial_plaintext(plaintext) do
        Err( _) -> Err("invalid_initial_plaintext")
        Ok( value) -> Ok(value)
      end ?
      let peer = case decode_client_profile(decoded.profile) do
        Err( _) -> Err("invalid_peer_profile")
        Ok( value) -> Ok(value)
      end ?
      let inner = case decode_inner_envelope(decoded.inner) do
        Err( _) -> Err("invalid_inner_envelope")
        Ok( value) -> Ok(value)
      end ?
      let previous = case find_peer_session(request.database_path,
      wrapping_key,
      peer.account_id,
      session_ids,
      0) do
        Ok( loaded) -> Ok(Some(loaded))
        Err( error) -> if error == "session_not_found" do
          Ok(None)
        else
          Err(error)
        end
      end ?
      let self_sync = inner.message_type == 2 && Bytes.secure_equals(peer.account_id,
      local.account_id)
      let valid_kind = self_sync || (inner.message_type == 1 && !Bytes.secure_equals(peer.account_id,
      local.account_id))
      let conversation_mismatch = case previous do
        None -> false
        Some( loaded) -> !Bytes.secure_equals(inner.conversation_id, loaded.record.conversation_id)
      end
      let mismatch = !valid_kind || conversation_mismatch || !Bytes.secure_equals(peer.entry.account_identity,
      packet_account_identity) || !Bytes.secure_equals(inner.sender_account_id, peer.account_id) || !Bytes.secure_equals(inner.sender_device_id,
      peer.device_id) || !Bytes.secure_equals(peer.device_id, initiator_credential.device_id) || !Bytes.secure_equals(inner.recipient_device_id,
      local.device_id)
      if mismatch do
        Err("initial_identity_mismatch")
      else
        let blocked = case previous do
          None -> false
          Some( loaded) -> loaded.record.blocked
        end
        let ( session_id, label, session_blob) = case previous do
          None -> seal_session(state, wrapping_key, local, peer, inner.conversation_id, 0, false)
          Some( loaded) -> seal_upgraded_session(state, wrapping_key, loaded, local, peer)
        end ?
        let remaining_prekeys = remove_prekey(prekeys, selected_prekey.id, 0, List.new())
        let prekey_index_blob = seal_prekey_pool(remaining_prekeys, wrapping_key) ?
        let prekey_active_blob = seal_active_prekey_pool(remove_prekey_id(active_prekeys,
        selected_prekey.id,
        0,
        List.new()),
        wrapping_key) ?
        let prekey_label = one_time_prekey_label(selected_prekey.id)
        let removed_labels = List.append(matching_fanout_prekey_state_labels(request.database_path,
        wrapping_key,
        peer,
        initial.suite) ?,
        prekey_label)
        if blocked do
          let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
          store_received_session(request.database_path,
          label,
          session_blob,
          index_blob,
          List.new(),
          List.new(),
          removed_labels,
          prekey_index_blob,
          prekey_active_blob) ?
          Err("blocked_message")
        else if self_sync do
          let sync = parse_sync_payload(inner.body) ?
          if Bytes.secure_equals(sync.peer_account_id, local.account_id) do
            Err("invalid_sync_payload")
          else
            let history_inner = sync_history_inner(local, sync) ?
            ensure_conversation_alias(request.database_path, wrapping_key, local, sync) ?
            let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
            let ( history_key, history_blob) = updated_history(request.database_path,
            wrapping_key,
            history_inner,
            1) ?
            store_received_session(request.database_path,
            label,
            session_blob,
            index_blob,
            [history_key],
            [history_blob],
            removed_labels,
            prekey_index_blob,
            prekey_active_blob) ?
            Ok(history_inner.body)
          end
        else
          let index_blob = updated_session_index(request.database_path, wrapping_key, session_id) ?
          let ( history_key, history_blob) = updated_history(request.database_path,
          wrapping_key,
          inner,
          2) ?
          store_received_session(request.database_path,
          label,
          session_blob,
          index_blob,
          [history_key],
          [history_blob],
          removed_labels,
          prekey_index_blob,
          prekey_active_blob) ?
          Ok(inner.body)
        end
      end
    end
  end
end

fn ratchet_bytes(value :: RatchetMessage) -> Bytes ! String do
  case encode_ratchet_message(value) do
    Err( _) -> Err("ratchet_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn parse_ratchet_packet(input :: Bytes) -> Bytes ! String do
  case decode_packet(input) do
    Err( _) -> Err("invalid_ratchet_packet")
    Ok( InitialPacket( _, _)) -> Err("invalid_ratchet_packet")
    Ok( RatchetPacket( message)) -> Ok(message)
  end
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
  end) ?) ?, mobile_vector(mobile_write_u32(record.disappearing_seconds) ?) ?, mobile_vector(mobile_byte(record.strongest_suite) ?) ?, mobile_vector(record.safety_number) ?],
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
  let strongest_suite = if state.suite > record.strongest_suite do
    state.suite
  else
    record.strongest_suite
  end
  seal_local(updated_session_record(snapshot_blob, % { record | strongest_suite : strongest_suite }) ?,
  wrapping_key,
  local_context(label) ?)
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

fn fanout_base_profiles(profiles :: List < ClientProfile >, index :: Int) -> Bool do
  if index >= List.length(profiles) do
    true
  else
    let profile = List.get(profiles, index)
    case normalize_prekey_bundle(profile.bundle) do
      Err( _) -> false
      Ok( normalized) -> case encode_prekey_bundle(normalized) do
        Err( _) -> false
        Ok( encoded) -> Bytes.secure_equals(encoded, profile.entry.prekey_bundle) && fanout_base_profiles(profiles,
        index + 1)
      end
    end
  end
end

fn invalid_fanout_sets(local :: ClientProfile,
peers :: MobileVerifiedDeviceSet,
local_devices :: MobileVerifiedDeviceSet) -> Bool do
  !local_device_set(local, local_devices) || Bytes.secure_equals(local.account_id,
  peers.account.account_id) || List.length(peers.profiles) == 0 || !fanout_base_profiles(peers.profiles,
  0) || !fanout_base_profiles(local_devices.profiles, 0)
end

fn append_missing_prekey_claims(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
profiles :: List < ClientProfile >,
local_device_id :: Bytes,
skip_local_device :: Bool,
now :: U64,
index :: Int,
claims :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(profiles) do
    Ok(claims)
  else
    let profile = List.get(profiles, index)
    if skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id) do
      append_missing_prekey_claims(database_path,
      wrapping_key,
      session_ids,
      profiles,
      local_device_id,
      skip_local_device,
      now,
      index + 1,
      claims)
    else
      if !(device_needs_prekey(database_path, wrapping_key, session_ids, profile) ?) do
        append_missing_prekey_claims(database_path,
        wrapping_key,
        session_ids,
        profiles,
        local_device_id,
        skip_local_device,
        now,
        index + 1,
        claims)
      else
        case load_fanout_prekey_reservation(database_path, wrapping_key, profile, now) do
          Err( error) -> Err(error)
          Ok( Some( _)) -> append_missing_prekey_claims(database_path,
          wrapping_key,
          session_ids,
          profiles,
          local_device_id,
          skip_local_device,
          now,
          index + 1,
          claims)
          Ok( None) -> do
            let claim = case load_fanout_prekey_claim(database_path, wrapping_key, profile) do
              Err( error) -> Err(error)
              Ok( Some( value)) -> Ok(value)
              Ok( None) -> create_fanout_prekey_claim(database_path, wrapping_key, profile)
            end ?
            append_missing_prekey_claims(database_path,
            wrapping_key,
            session_ids,
            profiles,
            local_device_id,
            skip_local_device,
            now,
            index + 1,
            List.append(claims, claim))
          end
        end
      end
    end
  end
end

fn fanout_prekey_claim_values(request :: MobileFanoutTargetsRequest) -> List < Bytes > ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let peers = verified_device_set(request.peer_device_set) ?
  let local_devices = verified_device_set(request.local_device_set) ?
  if invalid_fanout_sets(local, peers, local_devices) do
    Err("invalid_fanout_device_set")
  else
    let wrapping_key = platform_key() ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, peers) ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, local_devices) ?
    let session_ids = load_session_ids(request.database_path, wrapping_key) ?
    let now = current_time() ?
    let peer_claims = append_missing_prekey_claims(request.database_path,
    wrapping_key,
    session_ids,
    peers.profiles,
    local.device_id,
    false,
    now,
    0,
    List.new()) ?
    append_missing_prekey_claims(request.database_path,
    wrapping_key,
    session_ids,
    local_devices.profiles,
    local.device_id,
    true,
    now,
    0,
    peer_claims)
  end
end

fn fanout_prekey_claims(request :: MobileFanoutTargetsRequest) -> Bytes ! String do
  encode_output_list(fanout_prekey_claim_values(request) ?)
end

fn fanout_prekey_bundle(input :: Bytes) -> PrekeyBundle ! String do
  case decode_prekey_bundle(input) do
    Err( _) -> Err("invalid_fanout_prekeys")
    Ok( bundle) -> case encode_prekey_bundle(bundle) do
      Err( _) -> Err("invalid_fanout_prekeys")
      Ok( encoded) -> if Bytes.secure_equals(encoded, input) do
        Ok(bundle)
      else
        Err("invalid_fanout_prekeys")
      end
    end
  end
end

fn fanout_prekey_base(bundle :: PrekeyBundle) -> Bytes ! String do
  let normalized = case normalize_prekey_bundle(bundle) do
    Err( _) -> Err("invalid_fanout_prekeys")
    Ok( value) -> Ok(value)
  end ?
  case encode_prekey_bundle(normalized) do
    Err( _) -> Err("invalid_fanout_prekeys")
    Ok( value) -> Ok(value)
  end
end

fn fanout_prekey_reservation_label(profile :: ClientProfile) -> String do
  "fanout-prekey-reservation/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(profile.device_id)}"
end

fn fanout_prekey_claim_label(profile :: ClientProfile) -> String do
  "fanout-prekey-claim/v1/#{Bytes.to_hex(profile.account_id)}/#{Bytes.to_hex(profile.device_id)}"
end

fn matching_fanout_prekey_state_labels(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile,
accepted_suite :: Int) -> List < String > ! String do
  let reservation_label = fanout_prekey_reservation_label(profile)
  case load_blob(database_path, reservation_label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> do
      let reserved = fanout_prekey_bundle(open_local(blob,
      wrapping_key,
      local_context(reservation_label) ?) ?) ?
      if accepted_suite >= reserved.suite && Bytes.secure_equals(fanout_prekey_base(reserved) ?,
      fanout_prekey_base(profile.bundle) ?) do
        Ok([reservation_label, fanout_prekey_claim_label(profile)])
      else
        Ok(List.new())
      end
    end
  end
end

fn load_fanout_prekey_claim(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile) -> Option < Bytes > ! String do
  let label = fanout_prekey_claim_label(profile)
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok( blob) -> do
      let input = open_local(blob, wrapping_key, local_context(label) ?) ?
      let claim = case decode_prekey_claim(input) do
        Err( _) -> Err("invalid_fanout_prekeys")
        Ok( value) -> Ok(value)
      end ?
      if !Bytes.secure_equals(claim.account_id, profile.account_id) || !Bytes.secure_equals(claim.device_id,
      profile.device_id) do
        Err("invalid_fanout_prekeys")
      else if !Bytes.secure_equals(claim.base_bundle_hash,
      Crypto.sha256(profile.entry.prekey_bundle)) do
        Ok(None)
      else
        Ok(Some(input))
      end
    end
  end
end

fn create_fanout_prekey_claim(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile) -> Bytes ! String do
  let claim = encode_prekey_claim(PrekeyClaimRequest {
    account_id : profile.account_id,
    device_id : profile.device_id,
    base_bundle_hash : Crypto.sha256(profile.entry.prekey_bundle),
    reservation_id : random_bytes(16) ?
  }) ?
  let label = fanout_prekey_claim_label(profile)
  store_updated_blobs(database_path,
  [label],
  [seal_local(claim, wrapping_key, local_context(label) ?) ?]) ?
  Ok(claim)
end

fn load_fanout_prekey_reservation(database_path :: String,
wrapping_key :: borrow StorageKey,
profile :: ClientProfile,
now :: U64) -> Option < MobileClaimedPrekey > ! String do
  let label = fanout_prekey_reservation_label(profile)
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(None)
    else
      Err(error)
    end
    Ok( blob) -> do
      let input = open_local(blob, wrapping_key, local_context(label) ?) ?
      let bundle = fanout_prekey_bundle(input) ?
      if !Bytes.secure_equals(fanout_prekey_base(bundle) ?, profile.entry.prekey_bundle) do
        Ok(None)
      else
        Ok(Some(validate_claimed_prekey(input, [profile], List.new(), Bytes.empty(), now) ?))
      end
    end
  end
end

fn store_fanout_prekey_reservation(database_path :: String,
wrapping_key :: borrow StorageKey,
claim :: MobileClaimedPrekey,
now :: U64) -> Result <(), String > do
  let profile = claim.profile
  let label = fanout_prekey_reservation_label(profile)
  case load_fanout_prekey_reservation(database_path, wrapping_key, profile, now) do
    Err( error) -> Err(error)
    Ok( Some( existing)) -> if Bytes.secure_equals(existing.profile.entry.prekey_bundle,
    claim.profile.entry.prekey_bundle) do
      Ok(nil)
    else
      Err("prekey_reservation_exists")
    end
    Ok( None) -> store_updated_blobs(database_path,
    [label],
    [seal_local(claim.profile.entry.prekey_bundle, wrapping_key, local_context(label) ?) ?])
  end
end

fn store_fanout_prekey_reservations(database_path :: String,
wrapping_key :: borrow StorageKey,
claims :: List < MobileClaimedPrekey >,
now :: U64,
index :: Int) -> Result <(), String > do
  if index >= List.length(claims) do
    Ok(nil)
  else
    store_fanout_prekey_reservation(database_path, wrapping_key, List.get(claims, index), now) ?
    store_fanout_prekey_reservations(database_path, wrapping_key, claims, now, index + 1)
  end
end

fn fanout_prekey_reservation_labels(claims :: List < MobileClaimedPrekey >,
index :: Int,
labels :: List < String >) -> List < String > do
  if index >= List.length(claims) do
    labels
  else
    let profile = List.get(claims, index).profile
    fanout_prekey_reservation_labels(claims,
    index + 1,
    List.append(List.append(labels, fanout_prekey_reservation_label(profile)),
    fanout_prekey_claim_label(profile)))
  end
end

fn count_prekey_targets(profiles :: List < ClientProfile >,
base_bundle :: Bytes,
local_device_id :: Bytes,
skip_local_device :: Bool,
index :: Int,
count :: Int) -> Int do
  if index >= List.length(profiles) do
    count
  else
    let profile = List.get(profiles, index)
    let matches = !(skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id)) && Bytes.secure_equals(profile.entry.prekey_bundle,
    base_bundle)
    count_prekey_targets(profiles,
    base_bundle,
    local_device_id,
    skip_local_device,
    index + 1,
    if matches do
      count + 1
    else
      count
    end)
  end
end

fn find_prekey_target(profiles :: List < ClientProfile >,
base_bundle :: Bytes,
local_device_id :: Bytes,
skip_local_device :: Bool,
index :: Int) -> ClientProfile ! String do
  if index >= List.length(profiles) do
    Err("invalid_fanout_prekeys")
  else
    let profile = List.get(profiles, index)
    if !(skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id)) && Bytes.secure_equals(profile.entry.prekey_bundle,
    base_bundle) do
      Ok(profile)
    else
      find_prekey_target(profiles, base_bundle, local_device_id, skip_local_device, index + 1)
    end
  end
end

fn claimed_prekey_exists(claims :: List < MobileClaimedPrekey >, base_bundle :: Bytes, index :: Int) -> Bool do
  if index >= List.length(claims) do
    false
  else if Bytes.secure_equals(List.get(claims, index).base_bundle, base_bundle) do
    true
  else
    claimed_prekey_exists(claims, base_bundle, index + 1)
  end
end

fn claimed_prekey_profile(claims :: List < MobileClaimedPrekey >,
base_bundle :: Bytes,
index :: Int) -> ClientProfile ! String do
  if index >= List.length(claims) do
    Err("invalid_fanout_prekeys")
  else
    let claim = List.get(claims, index)
    if Bytes.secure_equals(claim.base_bundle, base_bundle) do
      Ok(claim.profile)
    else
      claimed_prekey_profile(claims, base_bundle, index + 1)
    end
  end
end

fn validate_claimed_prekey(input :: Bytes,
peers :: List < ClientProfile >,
local_devices :: List < ClientProfile >,
local_device_id :: Bytes,
now :: U64) -> MobileClaimedPrekey ! String do
  let bundle = fanout_prekey_bundle(input) ?
  if U64.compare(bundle.one_time_prekey_id, mobile_wide("0") ?) <= 0 || Bytes.length(bundle.one_time_prekey) != 32 do
    Err("invalid_fanout_prekeys")
  else
    let base_bundle = fanout_prekey_base(bundle) ?
    let peer_count = count_prekey_targets(peers, base_bundle, local_device_id, false, 0, 0)
    let local_count = count_prekey_targets(local_devices, base_bundle, local_device_id, true, 0, 0)
    if peer_count + local_count != 1 do
      Err("invalid_fanout_prekeys")
    else
      let target = if peer_count == 1 do
        find_prekey_target(peers, base_bundle, local_device_id, false, 0) ?
      else
        find_prekey_target(local_devices, base_bundle, local_device_id, true, 0) ?
      end
      let valid = case verify_prekey_bundle(target.account,
      bundle,
      1,
      now,
      target.account.directory_sequence) do
        Err( _) -> false
        Ok( value) -> value
      end
      if !valid do
        Err("invalid_fanout_prekeys")
      else
        let claimed_entry = % { target.entry | prekey_bundle : input }
        let encoded_profile = case encode_client_profile(claimed_entry,
        target.account_id,
        target.device_id) do
          Err( _) -> Err("invalid_fanout_prekeys")
          Ok( value) -> Ok(value)
        end ?
        let claimed_profile = case decode_client_profile(encoded_profile) do
          Err( _) -> Err("invalid_fanout_prekeys")
          Ok( value) -> Ok(value)
        end ?
        Ok(MobileClaimedPrekey {
          base_bundle : base_bundle,
          profile : claimed_profile
        })
      end
    end
  end
end

fn validate_claimed_prekeys(inputs :: List < Bytes >,
peers :: List < ClientProfile >,
local_devices :: List < ClientProfile >,
local_device_id :: Bytes,
now :: U64,
index :: Int,
claims :: List < MobileClaimedPrekey >) -> List < MobileClaimedPrekey > ! String do
  if index >= List.length(inputs) do
    Ok(claims)
  else
    let claim = validate_claimed_prekey(List.get(inputs, index),
    peers,
    local_devices,
    local_device_id,
    now) ?
    if claimed_prekey_exists(claims, claim.base_bundle, 0) do
      Err("invalid_fanout_prekeys")
    else
      validate_claimed_prekeys(inputs,
      peers,
      local_devices,
      local_device_id,
      now,
      index + 1,
      List.append(claims, claim))
    end
  end
end

fn require_claimed_prekeys_needed(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
claims :: List < MobileClaimedPrekey >,
index :: Int) -> Result <(), String > do
  if index >= List.length(claims) do
    Ok(nil)
  else
    let profile = List.get(claims, index).profile
    if device_needs_prekey(database_path, wrapping_key, session_ids, profile) ? do
      require_claimed_prekeys_needed(database_path, wrapping_key, session_ids, claims, index + 1)
    else
      Err("invalid_fanout_prekeys")
    end
  end
end

fn reserve_fanout_prekey(request :: MobileFanoutPrekeyReservationRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let peers = verified_device_set(request.peer_device_set) ?
  let local_devices = verified_device_set(request.local_device_set) ?
  if invalid_fanout_sets(local, peers, local_devices) do
    Err("invalid_fanout_device_set")
  else
    let wrapping_key = platform_key() ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, peers) ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, local_devices) ?
    let now = current_time() ?
    let claims = validate_claimed_prekeys([request.claimed_prekey],
    peers.profiles,
    local_devices.profiles,
    local.device_id,
    now,
    0,
    List.new()) ?
    require_claimed_prekeys_needed(request.database_path,
    wrapping_key,
    load_session_ids(request.database_path, wrapping_key) ?,
    claims,
    0) ?
    store_fanout_prekey_reservations(request.database_path, wrapping_key, claims, now, 0) ?
    Ok(Bytes.empty())
  end
end

fn fetch_fanout_prekey(directory_url :: String, claim :: Bytes) -> Bytes ! String do
  let response = case (Http.build(:post, directory_url <> "/v1/prekeys/bundle")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(claim)
    |> Http.timeout(8000)
    |> Http.max_response_bytes(19312)
    |> Http.max_redirects(0)
    |> Http.send()) do
    Err( error) -> if String.contains(error, "RESPONSE_TOO_LARGE") do
      Err("prekey_claim_too_large")
    else
      Err("prekey_claim_failed")
    end
    Ok( value) -> Ok(value)
  end ?
  if response.status != 200 do
    Err("prekey_claim_failed")
  else if Map.get(response.headers, "cache-control") != "no-store" do
    Err("prekey_claim_cache_policy_invalid")
  else
    Ok(response.body_bytes)
  end
end

fn prepare_fanout_prekey_claims(request :: MobileFanoutPrepareRequest,
claims :: List < Bytes >,
index :: Int) -> Result <(), String > do
  if index >= List.length(claims) do
    Ok(nil)
  else
    let claimed_prekey = fetch_fanout_prekey(request.directory_url, List.get(claims, index)) ?
    let _ = reserve_fanout_prekey(MobileFanoutPrekeyReservationRequest {
      database_path : request.database_path,
      peer_device_set : request.peer_device_set,
      local_device_set : request.local_device_set,
      claimed_prekey : claimed_prekey
    }) ?
    prepare_fanout_prekey_claims(request, claims, index + 1)
  end
end

fn prepare_fanout_prekeys(request :: MobileFanoutPrepareRequest) -> Bytes ! String do
  let claims = fanout_prekey_claim_values(MobileFanoutTargetsRequest {
    database_path : request.database_path,
    peer_device_set : request.peer_device_set,
    local_device_set : request.local_device_set
  }) ?
  prepare_fanout_prekey_claims(request, claims, 0) ?
  Ok(Bytes.empty())
end

fn append_needed_prekeys(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
profiles :: List < ClientProfile >,
local_device_id :: Bytes,
skip_local_device :: Bool,
now :: U64,
claims :: List < MobileClaimedPrekey >,
index :: Int) -> List < MobileClaimedPrekey > ! String do
  if index >= List.length(profiles) do
    Ok(claims)
  else
    let profile = List.get(profiles, index)
    if skip_local_device && Bytes.secure_equals(profile.device_id, local_device_id) do
      append_needed_prekeys(database_path,
      wrapping_key,
      session_ids,
      profiles,
      local_device_id,
      skip_local_device,
      now,
      claims,
      index + 1)
    else
      if !(device_needs_prekey(database_path, wrapping_key, session_ids, profile) ?) do
        append_needed_prekeys(database_path,
        wrapping_key,
        session_ids,
        profiles,
        local_device_id,
        skip_local_device,
        now,
        claims,
        index + 1)
      else
        case load_fanout_prekey_reservation(database_path, wrapping_key, profile, now) do
          Err( error) -> Err(error)
          Ok( None) -> Err("invalid_fanout_prekeys")
          Ok( Some( claim)) -> append_needed_prekeys(database_path,
          wrapping_key,
          session_ids,
          profiles,
          local_device_id,
          skip_local_device,
          now,
          List.append(claims, claim),
          index + 1)
        end
      end
    end
  end
end

fn start_device_session(claimed_prekeys :: List < MobileClaimedPrekey >,
local_device :: borrow DeviceKeys,
local_encode_client_profile :: Bytes,
local :: ClientProfile,
peer :: ClientProfile,
inner :: InnerEnvelope,
wrapping_key :: borrow StorageKey,
previous :: Option < MobileLoadedSession >,
strongest_suite :: Int) -> MobilePreparedSend ! String do
  let claimed_peer = claimed_prekey_profile(claimed_prekeys, peer.entry.prekey_bundle, 0) ?
  let plaintext = case encode_initial_plaintext(local_encode_client_profile, inner_bytes(inner) ?) do
    Err( _) -> Err("invalid_initial_plaintext")
    Ok( value) -> Ok(value)
  end ?
  let ( state, initial) = case initiate(local_device,
  local.credential,
  claimed_peer.account,
  claimed_peer.bundle,
  policy(claimed_peer, inner.client_timestamp),
  strongest_suite,
  plaintext) do
    Err( _) -> Err("session_start_failed")
    Ok( value) -> Ok(value)
  end ?
  let packet = seal_initial_packet(local.entry.account_identity, initial_bytes(initial) ?,
  X25519PublicKey { bytes : peer.credential.dh_public_key }) ?
  let outer = outer_bytes(claimed_peer.entry.mailbox_token,
  initial.suite,
  packet,
  inner.client_timestamp) ?
  let ( session_id, label, session_blob) = case previous do
    None -> seal_session(state, wrapping_key, local, claimed_peer, inner.conversation_id, 1, false)
    Some( loaded) -> seal_upgraded_session(state, wrapping_key, loaded, local, claimed_peer)
  end ?
  Ok(MobilePreparedSend {
    envelope : outer,
    session_id : session_id,
    session_label : label,
    session_blob : session_blob,
    new_session : true
  })
end

fn send_to_device(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
claimed_prekeys :: List < MobileClaimedPrekey >,
local_device :: borrow DeviceKeys,
local_encode_client_profile :: Bytes,
local :: ClientProfile,
peer :: ClientProfile,
inner :: InnerEnvelope) -> MobilePreparedSend ! String do
  case find_device_session(database_path,
  wrapping_key,
  peer.account_id,
  peer.device_id,
  session_ids,
  0) do
    Ok( loaded) -> do
      let changed = !Bytes.secure_equals(loaded.record.peer_mailbox, peer.entry.mailbox_token) || !Bytes.secure_equals(loaded.record.conversation_id,
      inner.conversation_id) || (Bytes.length(loaded.record.safety_number) == 64 && !Bytes.secure_equals(loaded.record.safety_number, safety_number(local, peer) ?))
      if changed do
        Err("peer_keys_changed")
      else if loaded.record.strongest_suite > peer.bundle.suite do
        Err("peer_keys_changed")
      else if loaded.record.strongest_suite < peer.bundle.suite || Bytes.length(loaded.record.safety_number) == 0 do
        let strongest_suite = loaded.record.strongest_suite
        start_device_session(claimed_prekeys,
        local_device,
        local_encode_client_profile,
        local,
        peer,
        inner,
        wrapping_key,
        Some(loaded),
        strongest_suite)
      else
        let state = restore_session(loaded, wrapping_key) ?
        let ( next_state, message) = case encrypt(state,
        inner_bytes(inner) ?,
        session_aad(loaded.session_id) ?) do
          Err( _) -> Err("message_encryption_failed")
          Ok( value) -> Ok(value)
        end ?
        let packet = encode_packet(RatchetPacket(ratchet_bytes(message) ?)) ?
        let outer = outer_bytes(peer.entry.mailbox_token,
        message.suite,
        packet,
        inner.client_timestamp) ?
        let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
        Ok(MobilePreparedSend {
          envelope : outer,
          session_id : loaded.session_id,
          session_label : loaded.label,
          session_blob : session_blob,
          new_session : false
        })
      end
    end
    Err( error) -> if error != "session_not_found" do
      Err(error)
    else
      start_device_session(claimed_prekeys,
      local_device,
      local_encode_client_profile,
      local,
      peer,
      inner,
      wrapping_key,
      None,
      0)
    end
  end
end

fn peer_fanout(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
claimed_prekeys :: List < MobileClaimedPrekey >,
local_device :: borrow DeviceKeys,
local_encode_client_profile :: Bytes,
local :: ClientProfile,
profiles :: List < ClientProfile >,
conversation_id :: Bytes,
client_message_id :: Bytes,
now :: U64,
body :: Bytes,
disappearing_seconds :: Int,
index :: Int,
output :: List < MobilePreparedSend >) -> List < MobilePreparedSend > ! String do
  if index >= List.length(profiles) do
    Ok(output)
  else
    let peer = List.get(profiles, index)
    let inner = InnerEnvelope {
      version : 1,
      sender_account_id : local.account_id,
      sender_device_id : local.device_id,
      recipient_device_id : peer.device_id,
      conversation_id : conversation_id,
      client_message_id : client_message_id,
      client_timestamp : now,
      message_type : 1,
      body : body,
      reply_reference : Bytes.empty(),
      attachment_manifest : Bytes.empty(),
      receipt_policy : 0,
      disappearing_seconds : disappearing_seconds,
      extensions : List.new()
    }
    let prepared = send_to_device(database_path,
    wrapping_key,
    session_ids,
    claimed_prekeys,
    local_device,
    local_encode_client_profile,
    local,
    peer,
    inner) ?
    peer_fanout(database_path,
    wrapping_key,
    session_ids,
    claimed_prekeys,
    local_device,
    local_encode_client_profile,
    local,
    profiles,
    conversation_id,
    client_message_id,
    now,
    body,
    disappearing_seconds,
    index + 1,
    List.append(output, prepared))
  end
end

fn self_fanout(database_path :: String,
wrapping_key :: borrow StorageKey,
session_ids :: List < Bytes >,
claimed_prekeys :: List < MobileClaimedPrekey >,
local_device :: borrow DeviceKeys,
local_encode_client_profile :: Bytes,
local :: ClientProfile,
local_profiles :: List < ClientProfile >,
client_message_id :: Bytes,
now :: U64,
sync_body :: Bytes,
index :: Int,
output :: List < MobilePreparedSend >) -> List < MobilePreparedSend > ! String do
  if index >= List.length(local_profiles) do
    Ok(output)
  else
    let peer = List.get(local_profiles, index)
    if Bytes.secure_equals(peer.device_id, local.device_id) do
      self_fanout(database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      local_device,
      local_encode_client_profile,
      local,
      local_profiles,
      client_message_id,
      now,
      sync_body,
      index + 1,
      output)
    else
      let inner = InnerEnvelope {
        version : 1,
        sender_account_id : local.account_id,
        sender_device_id : local.device_id,
        recipient_device_id : peer.device_id,
        conversation_id : self_sync_conversation_id(local.account_id) ?,
        client_message_id : client_message_id,
        client_timestamp : now,
        message_type : 2,
        body : sync_body,
        reply_reference : Bytes.empty(),
        attachment_manifest : Bytes.empty(),
        receipt_policy : 0,
        disappearing_seconds : 0,
        extensions : List.new()
      }
      let prepared = send_to_device(database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      local_device,
      local_encode_client_profile,
      local,
      peer,
      inner) ?
      self_fanout(database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      local_device,
      local_encode_client_profile,
      local,
      local_profiles,
      client_message_id,
      now,
      sync_body,
      index + 1,
      List.append(output, prepared))
    end
  end
end

fn send_fanout(request :: MobileFanoutRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local_encode_client_profile = load_profile(request.database_path) ?
  let local = decode_client_profile(local_encode_client_profile) ?
  let peers = verified_device_set(request.peer_device_set) ?
  let local_devices = verified_device_set(request.local_device_set) ?
  if invalid_fanout_sets(local, peers, local_devices) do
    Err("invalid_fanout_device_set")
  else
    let wrapping_key = platform_key() ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, peers) ?
    let _ = require_transparency_device_set(request.database_path, wrapping_key, local_devices) ?
    let session_ids = load_session_ids(request.database_path, wrapping_key) ?
    let now = current_time() ?
    let peer_prekeys = append_needed_prekeys(request.database_path,
    wrapping_key,
    session_ids,
    peers.profiles,
    local.device_id,
    false,
    now,
    List.new(),
    0) ?
    let claimed_prekeys = append_needed_prekeys(request.database_path,
    wrapping_key,
    session_ids,
    local_devices.profiles,
    local.device_id,
    true,
    now,
    peer_prekeys,
    0) ?
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
    let anchor = case find_peer_session(request.database_path,
    wrapping_key,
    peers.account.account_id,
    session_ids,
    0) do
      Err( error) -> if error == "session_not_found" do
        let representative = List.head(peers.profiles)
        Ok(MobileSessionRecord {
          snapshot : Bytes.empty(),
          local_account_id : local.account_id,
          local_device_id : local.device_id,
          peer_account_id : representative.account_id,
          peer_device_id : representative.device_id,
          peer_username : representative.username,
          peer_mailbox : representative.entry.mailbox_token,
          conversation_id : random_bytes(16) ?,
          request_state : 1,
          blocked : false,
          verified : false,
          key_changed : false,
          disappearing_seconds : 0,
          strongest_suite : 1,
          safety_number : safety_number(local, representative) ?
        })
      else
        Err(error)
      end
      Ok( loaded) -> Ok(loaded.record)
    end ?
    let added_count = List.length(peers.profiles) + List.length(local_devices.profiles) - 1
    if List.length(pending_ids) + added_count > 64 do
      Err("outbox_full")
    else if anchor.blocked do
      Err("conversation_blocked")
    else if anchor.request_state != 1 do
      Err("message_request_pending")
    else
      let client_message_id = random_bytes(16) ?
      let local_device = open_device(local, wrapping_key, request.database_path) ?
      let prepared_peers = peer_fanout(request.database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      local_device,
      local_encode_client_profile,
      local,
      peers.profiles,
      anchor.conversation_id,
      client_message_id,
      now,
      request.body,
      anchor.disappearing_seconds,
      0,
      List.new()) ?
      let history_inner = InnerEnvelope {
        version : 1,
        sender_account_id : local.account_id,
        sender_device_id : local.device_id,
        recipient_device_id : List.head(peers.profiles).device_id,
        conversation_id : anchor.conversation_id,
        client_message_id : client_message_id,
        client_timestamp : now,
        message_type : 1,
        body : request.body,
        reply_reference : Bytes.empty(),
        attachment_manifest : Bytes.empty(),
        receipt_policy : 0,
        disappearing_seconds : anchor.disappearing_seconds,
        extensions : List.new()
      }
      let ( history_key, history_blob) = updated_history(request.database_path,
      wrapping_key,
      history_inner,
      1) ?
      let sync_body = encode_sync_payload(local, List.head(peers.profiles), history_inner) ?
      let prepared = self_fanout(request.database_path,
      wrapping_key,
      session_ids,
      claimed_prekeys,
      local_device,
      local_encode_client_profile,
      local,
      local_devices.profiles,
      client_message_id,
      now,
      sync_body,
      0,
      prepared_peers) ?
      let envelopes = prepared_envelopes(prepared, 0, List.new())
      let session_index_blob = seal_session_ids(prepared_session_ids(prepared, 0, session_ids),
      wrapping_key) ?
      let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
      pending_ids,
      envelopes) ?
      store_outbound(request.database_path,
      prepared,
      fanout_prekey_reservation_labels(claimed_prekeys, 0, List.new()),
      session_index_blob,
      history_key,
      history_blob,
      outbox_labels,
      outbox_blobs,
      outbox_index_blob) ?
      encode_output_list(envelopes)
    end
  end
end

fn send_message(request :: MobileStartRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let requested_peer = decode_client_profile(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
  let _ = if List.length(pending_ids) >= 64 do
    Err("outbox_full")
  else
    Ok(nil)
  end ?
  let session_ids = load_session_ids(request.database_path, wrapping_key) ?
  let loaded = find_peer_session(request.database_path,
  wrapping_key,
  requested_peer.account_id,
  session_ids,
  0) ?
  let changed = !Bytes.secure_equals(loaded.record.peer_device_id, requested_peer.device_id) || !Bytes.secure_equals(loaded.record.peer_mailbox,
  requested_peer.entry.mailbox_token) || (Bytes.length(loaded.record.safety_number) == 64 && !Bytes.secure_equals(loaded.record.safety_number, safety_number(local, requested_peer) ?))
  if changed do
    Err("peer_keys_changed")
  else if loaded.record.strongest_suite > requested_peer.bundle.suite do
    Err("peer_keys_changed")
  else if loaded.record.strongest_suite < requested_peer.bundle.suite || Bytes.length(loaded.record.safety_number) == 0 do
    Err("session_upgrade_required")
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
    session_aad(loaded.session_id) ?) do
      Err( _) -> Err("message_encryption_failed")
      Ok( value) -> Ok(value)
    end ?
    let packet = encode_packet(RatchetPacket(ratchet_bytes(message) ?)) ?
    let outer = outer_bytes(loaded.record.peer_mailbox, message.suite, packet, now) ?
    let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
    let ( history_key, history_blob) = updated_history(request.database_path,
    wrapping_key,
    inner,
    1) ?
    let prepared = [MobilePreparedSend {
      envelope : outer,
      session_id : loaded.session_id,
      session_label : loaded.label,
      session_blob : session_blob,
      new_session : false
    }]
    let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
    pending_ids,
    [outer]) ?
    store_outbound(request.database_path,
    prepared,
    List.new(),
    seal_session_ids(session_ids, wrapping_key) ?,
    history_key,
    history_blob,
    outbox_labels,
    outbox_blobs,
    outbox_index_blob) ?
    Ok(outer)
  end
end

fn reject_message(state :: consume RatchetState, error :: String) -> Bytes ! String do
  Err(error)
end

fn receive_message(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let local = decode_client_profile(load_profile(request.database_path) ?) ?
  let outer = canonical_outer(request.outer) ?
  if !Bytes.secure_equals(outer.mailbox_token, local.entry.mailbox_token) do
    Err("wrong_mailbox")
  else
    let packet_message = parse_ratchet_packet(outer.ciphertext) ?
    let message = case decode_ratchet_message(packet_message) do
      Err( _) -> Err("invalid_ratchet_message")
      Ok( value) -> Ok(value)
    end ?
    let _ = if outer.suite != message.suite do
      Err("outer_suite_mismatch")
    else
      Ok(nil)
    end ?
    let wrapping_key = platform_key() ?
    let loaded = load_session_record(request.database_path, wrapping_key, message.session_id) ?
    let peer_policy = find_peer_session(request.database_path,
    wrapping_key,
    loaded.record.peer_account_id,
    load_session_ids(request.database_path, wrapping_key) ?,
    0) ?
    let state = restore_session(loaded, wrapping_key) ?
    case decrypt(state, message, session_aad(loaded.session_id) ?) do
      Rejected( rejected_state, error) -> if is_retryable_ratchet_error(error) do
        reject_message(rejected_state, "ratchet_retryable")
      else
        reject_message(rejected_state, "message_rejected")
      end
      Opened( next_state, plaintext) -> do
        let inner = case decode_inner_envelope(plaintext) do
          Err( _) -> Err("invalid_inner_envelope")
          Ok( value) -> Ok(value)
        end ?
        let self_sync = inner.message_type == 2 && Bytes.secure_equals(loaded.record.peer_account_id,
        local.account_id)
        let valid_kind = self_sync || (inner.message_type == 1 && !Bytes.secure_equals(loaded.record.peer_account_id,
        local.account_id))
        let mismatch = !valid_kind || !Bytes.secure_equals(inner.sender_account_id,
        loaded.record.peer_account_id) || !Bytes.secure_equals(inner.sender_device_id,
        loaded.record.peer_device_id) || !Bytes.secure_equals(inner.recipient_device_id,
        local.device_id) || !Bytes.secure_equals(inner.conversation_id,
        loaded.record.conversation_id)
        if mismatch do
          reject_message(next_state, "message_rejected")
        else
          let session_blob = seal_updated_session(next_state, loaded, wrapping_key) ?
          if peer_policy.record.blocked do
            store_updated_session(request.database_path, loaded.label, session_blob) ?
            Err("blocked_message")
          else if self_sync do
            let sync = parse_sync_payload(inner.body) ?
            if Bytes.secure_equals(sync.peer_account_id, local.account_id) do
              Err("invalid_sync_payload")
            else
              let history_inner = sync_history_inner(local, sync) ?
              ensure_conversation_alias(request.database_path, wrapping_key, local, sync) ?
              let ( history_key, history_blob) = updated_history(request.database_path,
              wrapping_key,
              history_inner,
              1) ?
              store_updated_session_and_history(request.database_path,
              loaded.label,
              session_blob,
              history_key,
              history_blob) ?
              Ok(history_inner.body)
            end
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
  else if action == 4 && Bytes.length(record.safety_number) == 64 do
    Ok(% { record | verified : true, key_changed : false })
  else if action == 5 && value >= 0 && value <= 2592000 do
    Ok(% { record | disappearing_seconds : value })
  else
    Err("invalid_conversation_policy")
  end
end

fn updated_peer_policy_blobs(database_path :: String,
wrapping_key :: borrow StorageKey,
peer_account_id :: Bytes,
session_ids :: List < Bytes >,
action :: Int,
value :: Int,
safety :: Bytes,
index :: Int,
labels :: List < String >,
blobs :: List < Bytes >) -> Result <( List < String >, List < Bytes >), String > do
  if index >= List.length(session_ids) do
    Ok((labels, blobs))
  else
    let loaded = load_session_record(database_path, wrapping_key, List.get(session_ids, index)) ?
    if Bytes.secure_equals(loaded.record.peer_account_id, peer_account_id) do
      let record = if action == 4 && !Bytes.secure_equals(loaded.record.safety_number, safety) do
        Ok(% { loaded.record | verified : false, key_changed : true })
      else
        updated_policy(loaded.record, action, value)
      end ?
      let blob = seal_local(updated_session_record(record.snapshot, record) ?,
      wrapping_key,
      local_context(loaded.label) ?) ?
      updated_peer_policy_blobs(database_path,
      wrapping_key,
      peer_account_id,
      session_ids,
      action,
      value,
      safety,
      index + 1,
      List.append(labels, loaded.label),
      List.append(blobs, blob))
    else
      updated_peer_policy_blobs(database_path,
      wrapping_key,
      peer_account_id,
      session_ids,
      action,
      value,
      safety,
      index + 1,
      labels,
      blobs)
    end
  end
end

fn update_conversation(request :: MobilePolicyRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let peer_id = peer_account_id(request.peer_profile) ?
  let wrapping_key = platform_key() ?
  let session_ids = load_session_ids(request.database_path, wrapping_key) ?
  let preferred = find_peer_session(request.database_path, wrapping_key, peer_id, session_ids, 0) ?
  let _ = if request.action == 4 && Bytes.length(preferred.record.safety_number) != 64 do
    Err("safety_number_unavailable")
  else
    Ok(nil)
  end ?
  let ( labels, blobs) = updated_peer_policy_blobs(request.database_path,
  wrapping_key,
  peer_id,
  session_ids,
  request.action,
  request.value,
  preferred.record.safety_number,
  0,
  List.new(),
  List.new()) ?
  store_updated_blobs(request.database_path, labels, blobs) ?
  Ok(Bytes.from_utf8("ok"))
end

fn canonical_push_material_text(input :: Bytes) -> String ! String do
  let text = mobile_utf8(input, "invalid") ?
  if String.trim(text) != text || String.contains(text, "\r") || String.contains(text, "\n") do
    Err("invalid")
  else
    Ok(text)
  end
end

fn parse_expo_raw_token_inner(input :: Bytes) -> MobileExpoRawToken ! String do
  let start = case reader(input, 4362) do
    Err( _) -> Err("invalid")
    Ok( value) -> Ok(value)
  end ?
  let version = take_fixed(start, 1) ?
  let platform = take_fixed(version.state, 1) ?
  let development = take_fixed(platform.state, 1) ?
  let app_id = take_vector(development.state, 255) ?
  let device_token = take_vector(app_id.state, 4096) ?
  let _ = case finish(device_token.state) do
    Err( _) -> Err("invalid")
    Ok( _) -> Ok(nil)
  end ?
  let version_value = mobile_read_byte(version.value) ?
  let platform_value = mobile_read_byte(platform.value) ?
  let development_value = mobile_read_byte(development.value) ?
  if version_value != 1 || (platform_value != 1 && platform_value != 2) || (development_value != 0 && development_value != 1) || (platform_value == 2 && development_value != 0) || Bytes.length(app_id.value) == 0 || Bytes.length(device_token.value) == 0 do
    Err("invalid")
  else
    Ok(MobileExpoRawToken {
      platform : platform_value,
      development : development_value == 1,
      app_id : canonical_push_material_text(app_id.value) ?,
      device_token : canonical_push_material_text(device_token.value) ?
    })
  end
end

fn parse_expo_raw_token(input :: Bytes) -> MobileExpoRawToken ! String do
  case parse_expo_raw_token_inner(input) do
    Err( _) -> Err("push_material_invalid")
    Ok( value) -> Ok(value)
  end
end

fn expo_project_id(input :: Bytes) -> String ! String do
  case Bytes.to_utf8(input) do
    Err( _) -> Err("invalid_push_project_id")
    Ok( value) -> if Regex.is_match(~r/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    value) do
      Ok(value)
    else
      Err("invalid_push_project_id")
    end
  end
end

fn expo_device_id(device_id :: Bytes) -> String ! String do
  if Bytes.length(device_id) != 16 do
    Err("push_device_id_invalid")
  else
    let value = Bytes.to_hex(device_id)
    Ok(String.slice(value, 0, 8) <> "-" <> String.slice(value, 8, 12) <> "-" <> String.slice(value,
    12,
    16) <> "-" <> String.slice(value, 16, 20) <> "-" <> String.slice(value, 20, 32))
  end
end

fn expo_registration_body(material :: MobileExpoRawToken, device_id :: Bytes, project_id :: String) -> String ! String do
  let kind = if material.platform == 1 do
    "apns"
  else
    "fcm"
  end
  let development = if material.development do
    "true"
  else
    "false"
  end
  Ok("{\"type\":" <> Json.encode_string(kind) <> ",\"deviceId\":" <> Json.encode_string(expo_device_id(device_id) ?) <> ",\"development\":" <> development <> ",\"appId\":" <> Json.encode_string(material.app_id) <> ",\"deviceToken\":" <> Json.encode_string(material.device_token) <> ",\"projectId\":" <> Json.encode_string(project_id) <> "}")
end

fn expo_provider_token_inner(body :: String) -> Bytes ! String do
  let root = Json.parse(body) ?
  let data = (root
    |> Json.object_get("data")) ?
  let value = (data
    |> Json.object_get("expoPushToken")) ?
  Ok(Bytes.from_utf8((value
    |> Json.as_string()) ?))
end

fn expo_provider_token(body :: String) -> Bytes ! String do
  case expo_provider_token_inner(body) do
    Err( _) -> Err("push_provider_response_invalid")
    Ok( value) -> Ok(value)
  end
end

fn register_expo_token(material :: MobileExpoRawToken,
device_id :: Bytes,
project_id :: String,
endpoint :: String) -> Bytes ! String do
  let body = expo_registration_body(material, device_id, project_id) ?
  let response = case (Http.build(:post, endpoint)
    |> Http.header("Content-Type", "application/json")
    |> Http.body(body)
    |> Http.timeout(5000)
    |> Http.max_response_bytes(4096)
    |> Http.max_redirects(0)
    |> Http.send()) do
    Err( _) -> Err("push_provider_unavailable")
    Ok( value) -> Ok(value)
  end ?
  if response.status < 200 || response.status >= 300 do
    Err("push_provider_rejected")
  else
    expo_provider_token(response.body)
  end
end

fn contributory_x25519_public_key(input :: Bytes,
invalid_error :: String,
validation_error :: String) -> X25519PublicKey ! String do
  if Bytes.length(input) != 32 do
    Err(invalid_error)
  else
    let probe = case Crypto.x25519_generate() do
      Err( _) -> Err(validation_error)
      Ok( value) -> Ok(value)
    end ?
    let shared = case Crypto.x25519_shared(probe.private_key, X25519PublicKey { bytes : input }) do
      Err( _) -> Err(invalid_error)
      Ok( value) -> Ok(value)
    end ?
    Secret.destroy(shared)
    Ok(X25519PublicKey { bytes : input })
  end
end

fn push_broker_public_key(input :: Bytes) -> X25519PublicKey ! String do
  contributory_x25519_public_key(input,
  "invalid_push_broker_public_key",
  "push_configuration_validation_failed")
end

fn native_push_build_config() -> MobilePushBuildConfig ! String do
  let frame = case Host.push_get_token(Bytes.from_utf8("expo/config/v1")) do
    Err( _) -> Err("push_configuration_required")
    Ok( value) -> Ok(value)
  end ?
  if Bytes.length(frame) != 103 do
    Err("invalid_push_configuration")
  else
    let text = mobile_utf8(frame, "invalid_push_configuration") ?
    let fields = String.split(text, "\n")
    if List.length(fields) != 3 || List.get(fields, 0) != "1" do
      Err("invalid_push_configuration")
    else
      let project_id = Bytes.from_utf8(List.get(fields, 1))
      let _ = expo_project_id(project_id) ?
      let broker_hex = List.get(fields, 2)
      let broker_public_key = case Bytes.from_hex(broker_hex) do
        Err( _) -> Err("invalid_push_broker_public_key")
        Ok( value) -> Ok(value)
      end ?
      if String.length(broker_hex) != 64 || Bytes.to_hex(broker_public_key) != broker_hex do
        Err("invalid_push_broker_public_key")
      else
        let key = push_broker_public_key(broker_public_key) ?
        Ok(MobilePushBuildConfig {
          project_id : project_id,
          broker_public_key : key.bytes
        })
      end
    end
  end
end

fn security_config_key(input :: String) -> Bytes ! String do
  let value = case Bytes.from_hex(input) do
    Err( _) -> Err("invalid_messenger_configuration")
    Ok( parsed) -> Ok(parsed)
  end ?
  if String.length(input) != 64 || Bytes.length(value) != 32 || Bytes.to_hex(value) != input do
    Err("invalid_messenger_configuration")
  else
    Ok(value)
  end
end

fn security_delivery_key(input :: Bytes) -> X25519PublicKey ! String do
  contributory_x25519_public_key(input,
  "invalid_messenger_configuration",
  "messenger_configuration_validation_failed")
end

fn parse_security_config(frame :: Bytes) -> MobileSecurityConfig ! String do
  if Bytes.length(frame) < 263 || Bytes.length(frame) > 264 do
    Err("invalid_messenger_configuration")
  else
    let text = mobile_utf8(frame, "invalid_messenger_configuration") ?
    let fields = String.split(text, "\n")
    if List.length(fields) != 6 || List.get(fields, 0) != "1" do
      Err("invalid_messenger_configuration")
    else
      let service_key = security_config_key(List.get(fields, 1)) ?
      let witness_a = security_config_key(List.get(fields, 2)) ?
      let witness_b = security_config_key(List.get(fields, 3)) ?
      let delivery_bytes = security_config_key(List.get(fields, 4)) ?
      let difficulty = case String.to_int(List.get(fields, 5)) do
        None -> Err("invalid_messenger_configuration")
        Some( value) -> Ok(value)
      end ?
      let canonical = "1\n" <> Bytes.to_hex(service_key) <> "\n" <> Bytes.to_hex(witness_a) <> "\n" <> Bytes.to_hex(witness_b) <> "\n" <> Bytes.to_hex(delivery_bytes) <> "\n" <> Int.to_string(difficulty)
      if difficulty < 1 || difficulty > 24 || text != canonical || Bytes.secure_equals(witness_a,
      witness_b) do
        Err("invalid_messenger_configuration")
      else
        let delivery_key = security_delivery_key(delivery_bytes) ?
        Ok(MobileSecurityConfig {
          transparency_service_public_key : service_key,
          witness_a_public_key : witness_a,
          witness_b_public_key : witness_b,
          delivery_public_key : delivery_key.bytes,
          abuse_difficulty : difficulty
        })
      end
    end
  end
end

fn native_security_config() -> MobileSecurityConfig ! String do
  let frame = case Host.push_get_token(Bytes.from_utf8("messenger/config/v1")) do
    Err( _) -> Err("messenger_configuration_required")
    Ok( value) -> Ok(value)
  end ?
  parse_security_config(frame)
end

fn expo_push_endpoint() -> String do
  "https://exp.host/--/api/v2/push/getExpoPushToken"
end

fn push_state_context(profile :: ClientProfile) -> Bytes ! String do
  context(profile.account_id, profile.device_id, "push-binding/v1", 14)
end

fn push_signature_valid(public_key :: Bytes, signed :: Bytes, signature :: Bytes) -> Bool do
  case Crypto.verify(SigningPublicKey { bytes : public_key },
  signed,
  Signature { bytes : signature }) do
    Err( _) -> false
    Ok( valid) -> valid
  end
end

fn stored_bind_valid(state :: MobilePushState, profile :: ClientProfile) -> Bool do
  case decode_push_bind(state.pending_wire) do
    Err( _) -> false
    Ok( value) -> case encode_push_bind(value) do
      Err( _) -> false
      Ok( canonical) -> case push_bind_signing_bytes(value) do
        Err( _) -> false
        Ok( signed) -> Bytes.secure_equals(canonical, state.pending_wire) && Bytes.secure_equals(value.mailbox_token_hash,
        Crypto.sha256(profile.entry.mailbox_token)) && Bytes.secure_equals(value.wake_token_hash,
        state.wake_token_hash) && U64.compare(value.revision, state.revision) == 0 && value.provider == 1 && push_signature_valid(profile.credential.signing_public_key,
        signed,
        value.signature)
      end
    end
  end
end

fn stored_unbind_valid(state :: MobilePushState, profile :: ClientProfile) -> Bool do
  case decode_push_unbind(state.pending_wire) do
    Err( _) -> false
    Ok( value) -> case encode_push_unbind(value) do
      Err( _) -> false
      Ok( canonical) -> case push_unbind_signing_bytes(value) do
        Err( _) -> false
        Ok( signed) -> Bytes.secure_equals(canonical, state.pending_wire) && Bytes.secure_equals(value.mailbox_token_hash,
        Crypto.sha256(profile.entry.mailbox_token)) && U64.compare(value.revision, state.revision) == 0 && push_signature_valid(profile.credential.signing_public_key,
        signed,
        value.signature)
      end
    end
  end
end

fn stored_push_project_valid(project_id :: Bytes) -> Bool do
  case expo_project_id(project_id) do
    Err( _) -> false
    Ok( _) -> true
  end
end

fn stored_push_config_valid(project_id :: Bytes, broker_public_key :: Bytes) -> Bool do
  stored_push_project_valid(project_id) && Bytes.length(broker_public_key) == 32
end

fn push_state_valid(state :: MobilePushState, profile :: ClientProfile) -> Bool ! String do
  let zero = mobile_zeroes(32) ?
  let revision_zero = U64.compare(state.revision, mobile_wide("0") ?) == 0
  let revision_valid = U64.compare(state.revision, mobile_wide("9223372036854775807") ?) <= 0
  let action_epoch_valid = U64.compare(state.action_epoch, mobile_wide("9223372036854775807") ?) <= 0
  let hashes_zero = Bytes.secure_equals(state.wake_token_hash, zero) && Bytes.secure_equals(state.provider_token_hash,
  zero)
  let pending_shape = if state.pending_kind == 0 do
    Bytes.length(state.pending_wire) == 0
  else if state.pending_kind == 1 do
    Bytes.length(state.pending_wire) > 0 && stored_bind_valid(state, profile)
  else if state.pending_kind == 2 do
    Bytes.length(state.pending_wire) > 0 && stored_unbind_valid(state, profile)
  else
    false
  end
  let mode_shape = if state.mode == 0 do
    hashes_zero && (state.pending_kind == 0 || state.pending_kind == 2)
  else if state.mode == 1 do
    Bytes.length(state.wake_token_hash) == 32 && Bytes.length(state.provider_token_hash) == 32 && !Bytes.secure_equals(state.wake_token_hash,
    zero) && !Bytes.secure_equals(state.provider_token_hash, zero) && !Bytes.secure_equals(state.wake_token_hash,
    Crypto.sha256(profile.entry.mailbox_token)) && (state.pending_kind == 0 || state.pending_kind == 1)
  else
    false
  end
  let config_empty = Bytes.length(state.project_id) == 0 && Bytes.length(state.broker_public_key) == 0
  let config_valid = stored_push_config_valid(state.project_id, state.broker_public_key)
  let config_shape = if state.action_kind == 1 || state.action_kind == 2 || (state.target_mode == 1 && (state.action_kind == 4 || state.action_kind == 5)) do
    config_valid
  else if state.action_kind == 3 do
    config_empty || config_valid
  else if state.action_kind == 0 && state.mode == 1 do
    config_empty || config_valid
  else
    config_empty
  end
  let action_shape = if state.action_kind == 0 do
    state.pending_kind == 0 && state.target_mode == state.mode
  else if state.action_kind == 1 || state.action_kind == 2 do
    state.pending_kind == 0 && state.target_mode == 1
  else if state.action_kind == 3 do
    state.pending_kind == 1 && state.target_mode == 1
  else if state.action_kind == 4 do
    state.pending_kind == 2
  else if state.action_kind == 5 do
    (state.pending_kind == 0 || state.pending_kind == 2) && state.mode == 0
  else
    false
  end
  let action_epoch_shape = state.action_kind == 0 || U64.compare(state.action_epoch,
  mobile_wide("0") ?) > 0
  Ok(revision_valid && action_epoch_valid && pending_shape && mode_shape && config_shape && action_shape && action_epoch_shape && (state.target_mode == 0 || state.target_mode == 1) && (!revision_zero || (state.mode == 0 && state.pending_kind == 0)))
end

fn pristine_push_state() -> MobilePushState ! String do
  Ok(MobilePushState {
    revision : mobile_wide("0") ?,
    mode : 0,
    wake_token_hash : mobile_zeroes(32) ?,
    provider_token_hash : mobile_zeroes(32) ?,
    pending_kind : 0,
    pending_wire : Bytes.empty(),
    action_epoch : mobile_wide("0") ?,
    action_kind : 0,
    target_mode : 0,
    project_id : Bytes.empty(),
    broker_public_key : Bytes.empty()
  })
end

fn push_state_bytes(state :: MobilePushState, profile :: ClientProfile) -> Bytes ! String do
  if !(push_state_valid(state, profile) ?) do
    Err("push_state_corrupt")
  else
    mobile_join([mobile_byte(2) ?, Bytes.from_utf8("PBL"), mobile_write_u64(state.revision) ?, mobile_byte(state.mode) ?, state.wake_token_hash, state.provider_token_hash, mobile_byte(state.pending_kind) ?, mobile_vector(state.pending_wire) ?, mobile_write_u64(state.action_epoch) ?, mobile_byte(state.action_kind) ?, mobile_byte(state.target_mode) ?, mobile_vector(state.project_id) ?, mobile_vector(state.broker_public_key) ?],
    0,
    Bytes.empty())
  end
end

fn parse_push_state(input :: Bytes, profile :: ClientProfile) -> MobilePushState ! String do
  case reader(input, 893) do
    Err( _) -> Err("push_state_corrupt")
    Ok( reader_state) -> do
      let version = take_fixed(reader_state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let revision = take_fixed(magic.state, 8) ?
      let mode = take_fixed(revision.state, 1) ?
      let wake_hash = take_fixed(mode.state, 32) ?
      let provider_hash = take_fixed(wake_hash.state, 32) ?
      let pending_kind = take_fixed(provider_hash.state, 1) ?
      let pending_wire = take_vector(pending_kind.state, 725) ?
      let version_value = mobile_read_byte(version.value) ?
      let mode_value = mobile_read_byte(mode.value) ?
      let pending_value = mobile_read_byte(pending_kind.value) ?
      if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PBL")) do
        Err("push_state_corrupt")
      else if version_value == 1 do
        case finish(pending_wire.state) do
          Err( _) -> Err("push_state_corrupt")
          Ok( _) -> do
            let action_kind = if pending_value == 1 do
              3
            else if pending_value == 2 do
              5
            else if mode_value == 0 do
              5
            else
              0
            end
            let state = MobilePushState {
              revision : mobile_read_u64(revision.value) ?,
              mode : mode_value,
              wake_token_hash : wake_hash.value,
              provider_token_hash : provider_hash.value,
              pending_kind : pending_value,
              pending_wire : pending_wire.value,
              action_epoch : if action_kind == 0 do
                mobile_wide("0") ?
              else
                mobile_wide("1") ?
              end,
              action_kind : action_kind,
              target_mode : if mode_value == 1 || pending_value == 1 do
                1
              else
                0
              end,
              project_id : Bytes.empty(),
              broker_public_key : Bytes.empty()
            }
            if push_state_valid(state, profile) ? do
              Ok(state)
            else
              Err("push_state_corrupt")
            end
          end
        end
      else if version_value == 2 do
        let action_epoch = take_fixed(pending_wire.state, 8) ?
        let action_kind = take_fixed(action_epoch.state, 1) ?
        let target_mode = take_fixed(action_kind.state, 1) ?
        let project_id = take_vector(target_mode.state, 36) ?
        let broker_public_key = take_vector(project_id.state, 32) ?
        case finish(broker_public_key.state) do
          Err( _) -> Err("push_state_corrupt")
          Ok( _) -> do
            let state = MobilePushState {
              revision : mobile_read_u64(revision.value) ?,
              mode : mode_value,
              wake_token_hash : wake_hash.value,
              provider_token_hash : provider_hash.value,
              pending_kind : pending_value,
              pending_wire : pending_wire.value,
              action_epoch : mobile_read_u64(action_epoch.value) ?,
              action_kind : mobile_read_byte(action_kind.value) ?,
              target_mode : mobile_read_byte(target_mode.value) ?,
              project_id : project_id.value,
              broker_public_key : broker_public_key.value
            }
            if push_state_valid(state, profile) ? do
              Ok(state)
            else
              Err("push_state_corrupt")
            end
          end
        end
      else
        Err("push_state_corrupt")
      end
    end
  end
end

fn decode_push_state(input :: Bytes, profile :: ClientProfile) -> MobilePushState ! String do
  case parse_push_state(input, profile) do
    Err( _) -> Err("push_state_corrupt")
    Ok( state) -> Ok(state)
  end
end

fn load_push_state(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey) -> MobilePushState ! String do
  let label = "push-binding/v1"
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      pristine_push_state()
    else
      Err(error)
    end
    Ok( blob) -> case open_local(blob, wrapping_key, push_state_context(profile) ?) do
      Err( _) -> Err("push_state_corrupt")
      Ok( encoded) -> decode_push_state(encoded, profile)
    end
  end
end

fn store_push_state(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState) -> Result <(), String > do
  let label = "push-binding/v1"
  let encoded = push_state_bytes(state, profile) ?
  let sealed = seal_local(encoded, wrapping_key, push_state_context(profile) ?) ?
  store_updated_session(database_path, label, sealed)
end

fn next_push_revision(revision :: U64) -> U64 ! String do
  if U64.compare(revision, mobile_wide("9223372036854775807") ?) >= 0 do
    Err("push_revision_exhausted")
  else
    U64.add(revision, mobile_wide("1") ?)
  end
end

fn next_push_action_epoch(epoch :: U64) -> U64 ! String do
  if U64.compare(epoch, mobile_wide("9223372036854775807") ?) >= 0 do
    Err("push_action_epoch_exhausted")
  else
    U64.add(epoch, mobile_wide("1") ?)
  end
end

fn signed_push_bind(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
wake_token_hash :: Bytes,
revision :: U64,
provider_token_ciphertext :: Bytes) -> Bytes ! String do
  let unsigned = PushBindRequest {
    mailbox_token_hash : Crypto.sha256(profile.entry.mailbox_token),
    wake_token_hash : wake_token_hash,
    revision : revision,
    provider : 1,
    provider_token_ciphertext : provider_token_ciphertext,
    signature : Bytes.empty()
  }
  let device = open_device(profile, wrapping_key, database_path) ?
  let signature = case Crypto.sign(device.signing_private_key, push_bind_signing_bytes(unsigned) ?) do
    Err( _) -> Err("push_binding_sign_failed")
    Ok( value) -> Ok(value.bytes)
  end ?
  encode_push_bind(% { unsigned | signature : signature })
end

fn signed_push_unbind(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
revision :: U64) -> Bytes ! String do
  let unsigned = PushUnbindRequest {
    mailbox_token_hash : Crypto.sha256(profile.entry.mailbox_token),
    revision : revision,
    signature : Bytes.empty()
  }
  let device = open_device(profile, wrapping_key, database_path) ?
  let signature = case Crypto.sign(device.signing_private_key,
  push_unbind_signing_bytes(unsigned) ?) do
    Err( _) -> Err("push_binding_sign_failed")
    Ok( value) -> Ok(value.bytes)
  end ?
  encode_push_unbind(% { unsigned | signature : signature })
end

fn prepare_new_push_bind(request :: MobilePayloadRequest,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState,
project_id :: String,
broker_public_key :: X25519PublicKey,
endpoint :: String,
raw_material :: Bytes) -> Bytes ! String do
  let material = parse_expo_raw_token(raw_material) ?
  let token = register_expo_token(material, profile.device_id, project_id, endpoint) ?
  let sealed = case seal_provider_token(token, broker_public_key) do
    Err( error) -> if error == "invalid provider token" do
      Err("push_provider_response_invalid")
    else
      Err("push_binding_failed")
    end
    Ok( value) -> Ok(value)
  end ?
  let token_hash = Crypto.sha256(token)
  if state.mode == 1 && Bytes.secure_equals(state.provider_token_hash, token_hash) do
    Ok(Bytes.empty())
  else
    let revision = next_push_revision(state.revision) ?
    let wake_hash = if state.mode == 1 do
      state.wake_token_hash
    else
      case Crypto.random_bytes(32) do
        Err( _) -> Err("push_wake_generation_failed")
        Ok( random) -> do
          let generated = Crypto.sha256(random)
          if Bytes.secure_equals(generated, Crypto.sha256(profile.entry.mailbox_token)) do
            Err("push_wake_generation_failed")
          else
            Ok(generated)
          end
        end
      end ?
    end
    let wire = signed_push_bind(request.database_path,
    profile,
    wrapping_key,
    wake_hash,
    revision,
    sealed) ?
    let updated = % { state | revision : revision, mode : 1, wake_token_hash : wake_hash, provider_token_hash : token_hash, pending_kind : 1, pending_wire : wire }
    store_push_state(request.database_path, profile, wrapping_key, updated) ?
    Ok(wire)
  end
end

fn prepare_push_bind_with_config(request :: MobilePayloadRequest,
broker_public_key :: Result < X25519PublicKey, String >,
endpoint :: String) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(request.database_path, profile, wrapping_key) ?
  if state.pending_kind == 1 do
    Ok(state.pending_wire)
  else if state.pending_kind == 2 do
    Err("push_update_pending")
  else
    let project_id = expo_project_id(request.payload) ?
    let broker_public_key = broker_public_key ?
    let raw_material = case Host.push_get_token(Bytes.from_utf8("expo/raw/v1")) do
      Err( _) -> Err("push_material_unavailable")
      Ok( value) -> Ok(value)
    end ?
    let action_state = % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 3, target_mode : 1, project_id : request.payload, broker_public_key : broker_public_key.bytes }
    prepare_new_push_bind(request,
    profile,
    wrapping_key,
    action_state,
    project_id,
    broker_public_key,
    endpoint,
    raw_material)
  end
end

fn prepare_push_unbind_loaded(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState) -> Bytes ! String do
  if state.pending_kind == 2 do
    Ok(state.pending_wire)
  else if state.mode == 0 do
    Ok(Bytes.empty())
  else
    let revision = next_push_revision(state.revision) ?
    let wire = signed_push_unbind(database_path, profile, wrapping_key, revision) ?
    let updated = % { state | revision : revision, mode : 0, wake_token_hash : mobile_zeroes(32) ?, provider_token_hash : mobile_zeroes(32) ?, pending_kind : 2, pending_wire : wire }
    store_push_state(database_path, profile, wrapping_key, updated) ?
    Ok(wire)
  end
end

fn prepare_push_unbind(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    let profile = decode_client_profile(load_profile(database_path) ?) ?
    let wrapping_key = platform_key() ?
    let state = load_push_state(database_path, profile, wrapping_key) ?
    if state.pending_kind == 2 do
      Ok(state.pending_wire)
    else
      let action_state = % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 4, target_mode : 0, project_id : Bytes.empty(), broker_public_key : Bytes.empty() }
      prepare_push_unbind_loaded(database_path, profile, wrapping_key, action_state)
    end
  end
end

fn commit_push_update(request :: MobilePayloadRequest) -> Bytes ! String do
  if Bytes.length(request.payload) > 725 do
    Err("invalid_push_update")
  else
    ensure_schema(request.database_path) ?
    let profile = decode_client_profile(load_profile(request.database_path) ?) ?
    let wrapping_key = platform_key() ?
    let state = load_push_state(request.database_path, profile, wrapping_key) ?
    if state.pending_kind == 0 do
      Err("push_update_not_pending")
    else if !Bytes.secure_equals(state.pending_wire, request.payload) do
      Err("push_update_mismatch")
    else
      let epoch = next_push_action_epoch(state.action_epoch) ?
      store_push_state(request.database_path,
      profile,
      wrapping_key,
      % { state | pending_kind : 0, pending_wire : Bytes.empty(), action_epoch : epoch, action_kind : 0, target_mode : state.mode }) ?
      Ok(Bytes.empty())
    end
  end
end

fn parse_push_action_frame(input :: Bytes) -> MobilePushActionFrame ! String do
  case reader(input, 743) do
    Err( _) -> Err("invalid_push_action")
    Ok( state) -> do
      let version = take_fixed(state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let kind = take_fixed(magic.state, 1) ?
      let flags = take_fixed(kind.state, 1) ?
      let epoch = take_fixed(flags.state, 8) ?
      let payload = take_vector_error(epoch.state, 725, "invalid_push_action") ?
      case finish(payload.state) do
        Err( _) -> Err("invalid_push_action")
        Ok( _) -> do
          let kind_value = mobile_read_byte(kind.value) ?
          let payload_length = Bytes.length(payload.value)
          let payload_shape = if kind_value == 1 || kind_value == 2 || kind_value == 5 do
            payload_length == 0
          else if kind_value == 3 || kind_value == 4 do
            payload_length > 0
          else
            false
          end
          if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("PFA")) || mobile_read_byte(flags.value) ? != 0 || !payload_shape do
            Err("invalid_push_action")
          else
            Ok(MobilePushActionFrame {
              kind : kind_value,
              epoch : mobile_read_u64(epoch.value) ?,
              payload : payload.value
            })
          end
        end
      end
    end
  end
end

fn encode_push_action(kind :: Int, flags :: Int, epoch :: U64, payload :: Bytes) -> Bytes ! String do
  if kind < 0 || kind > 5 || flags < 0 || flags > 1 || Bytes.length(payload) > 725 do
    Err("invalid_push_action")
  else
    mobile_join([mobile_byte(1) ?, Bytes.from_utf8("PFA"), mobile_byte(kind) ?, mobile_byte(flags) ?, mobile_write_u64(epoch) ?, mobile_write_u32(Bytes.length(payload)) ?, payload],
    0,
    Bytes.empty())
  end
end

fn push_status_code(state :: MobilePushState) -> Int do
  if state.action_kind == 1 || state.action_kind == 2 || state.action_kind == 3 do
    2
  else if state.action_kind == 4 || state.action_kind == 5 do
    3
  else if state.pending_kind == 1 do
    2
  else if state.pending_kind == 2 do
    3
  else if state.mode == 1 do
    1
  else
    0
  end
end

fn push_status_bytes(state :: MobilePushState) -> Bytes do
  let status = push_status_code(state)
  if status == 1 do
    Bytes.from_utf8("enabled")
  else if status == 2 do
    Bytes.from_utf8("pending-bind")
  else if status == 3 do
    Bytes.from_utf8("pending-unbind")
  else
    Bytes.from_utf8("disabled")
  end
end

fn push_done_action(state :: MobilePushState, surface_error :: Int) -> Bytes ! String do
  encode_push_action(0, surface_error, state.action_epoch, mobile_byte(push_status_code(state)) ?)
end

fn current_push_action(state :: MobilePushState) -> Bytes ! String do
  if state.action_kind == 0 do
    push_done_action(state, 0)
  else if state.action_kind == 3 || state.action_kind == 4 do
    encode_push_action(state.action_kind, 0, state.action_epoch, state.pending_wire)
  else
    encode_push_action(state.action_kind, 0, state.action_epoch, Bytes.empty())
  end
end

fn store_push_action(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState) -> Bytes ! String do
  store_push_state(database_path, profile, wrapping_key, state) ?
  current_push_action(state)
end

fn push_action(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    let profile = decode_client_profile(load_profile(database_path) ?) ?
    current_push_action(load_push_state(database_path, profile, platform_key() ?) ?)
  end
end

fn push_config_matches(state :: MobilePushState, config :: MobilePushBuildConfig) -> Bool do
  Bytes.secure_equals(state.project_id, config.project_id) && Bytes.secure_equals(state.broker_public_key,
  config.broker_public_key)
end

fn matching_native_push_config(state :: MobilePushState) -> MobilePushBuildConfig ! String do
  let config = native_push_build_config() ?
  if push_config_matches(state, config) do
    Ok(config)
  else
    Err("push_configuration_changed")
  end
end

fn begin_push_cleanup(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState,
target_mode :: Int,
project_id :: Bytes,
broker_public_key :: Bytes) -> Bytes ! String do
  let cleanup = % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 5, target_mode : target_mode, project_id : project_id, broker_public_key : broker_public_key }
  if state.pending_kind == 2 do
    store_push_action(database_path, profile, wrapping_key, cleanup)
  else
    let wire = prepare_push_unbind_loaded(database_path, profile, wrapping_key, cleanup) ?
    if Bytes.length(wire) == 0 do
      store_push_action(database_path, profile, wrapping_key, cleanup)
    else
      encode_push_action(5, 0, cleanup.action_epoch, Bytes.empty())
    end
  end
end

fn retarget_push_enable(database_path :: String,
config :: MobilePushBuildConfig,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState) -> Bytes ! String do
  if state.action_kind == 4 || state.action_kind == 5 do
    store_push_action(database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, target_mode : 1, project_id : config.project_id, broker_public_key : config.broker_public_key })
  else if state.mode == 1 || state.pending_kind == 1 do
    begin_push_cleanup(database_path,
    profile,
    wrapping_key,
    state,
    1,
    config.project_id,
    config.broker_public_key)
  else
    store_push_action(database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, target_mode : 1, project_id : config.project_id, broker_public_key : config.broker_public_key })
  end
end

fn push_intent(request :: MobilePushIntentRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(request.database_path, profile, wrapping_key) ?
  if request.intent == 0 do
    if state.action_kind != 0 do
      if state.target_mode == 0 do
        current_push_action(state)
      else
        let config = native_push_build_config() ?
        if push_config_matches(state, config) do
          current_push_action(state)
        else
          retarget_push_enable(request.database_path, config, profile, wrapping_key, state)
        end
      end
    else if state.mode == 1 do
      let config = native_push_build_config() ?
      if !push_config_matches(state, config) do
        begin_push_cleanup(request.database_path,
        profile,
        wrapping_key,
        state,
        1,
        config.project_id,
        config.broker_public_key)
      else
        store_push_action(request.database_path,
        profile,
        wrapping_key,
        % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 2, target_mode : 1 })
      end
    else
      current_push_action(state)
    end
  else if request.intent == 1 do
    let config = native_push_build_config() ?
    if state.action_kind != 0 do
      if state.target_mode == 1 && push_config_matches(state, config) do
        current_push_action(state)
      else
        retarget_push_enable(request.database_path, config, profile, wrapping_key, state)
      end
    else if state.mode == 1 do
      if push_config_matches(state, config) do
        current_push_action(state)
      else
        begin_push_cleanup(request.database_path,
        profile,
        wrapping_key,
        state,
        1,
        config.project_id,
        config.broker_public_key)
      end
    else
      store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 1, target_mode : 1, project_id : config.project_id, broker_public_key : config.broker_public_key })
    end
  else if state.action_kind == 4 || state.action_kind == 5 do
    if state.target_mode == 0 && Bytes.length(state.project_id) == 0 && Bytes.length(state.broker_public_key) == 0 do
      current_push_action(state)
    else
      store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, target_mode : 0, project_id : Bytes.empty(), broker_public_key : Bytes.empty() })
    end
  else if state.mode == 1 || state.pending_kind == 1 do
    begin_push_cleanup(request.database_path,
    profile,
    wrapping_key,
    state,
    0,
    Bytes.empty(),
    Bytes.empty())
  else if state.action_kind != 0 do
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 5, target_mode : 0, project_id : Bytes.empty(), broker_public_key : Bytes.empty() })
  else
    current_push_action(state)
  end
end

fn complete_push_action_with_config(request :: MobilePushActionCompletion, endpoint :: String) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(request.database_path, profile, wrapping_key) ?
  let completed = parse_push_action_frame(request.action) ?
  let order = U64.compare(completed.epoch, state.action_epoch)
  if order < 0 do
    current_push_action(state)
  else if order > 0 || state.action_kind == 0 || !Bytes.secure_equals(request.action,
  current_push_action(state) ?) do
    Err("push_action_mismatch")
  else if state.action_kind == 5 && state.pending_kind == 2 do
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 4 })
  else if request.outcome == 1 do
    push_done_action(state, 1)
  else if state.action_kind == 1 do
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 2 })
  else if state.action_kind == 2 do
    let config = matching_native_push_config(state) ?
    let project_id = expo_project_id(config.project_id) ?
    let configured_key = push_broker_public_key(config.broker_public_key) ?
    let raw_material = case Host.push_get_token(Bytes.from_utf8("expo/raw/v1")) do
      Err( _) -> Err("push_material_unavailable")
      Ok( value) -> Ok(value)
    end ?
    let epoch = next_push_action_epoch(state.action_epoch) ?
    let bind_state = % { state | action_epoch : epoch, action_kind : 3 }
    let wire = prepare_new_push_bind(MobilePayloadRequest {
      database_path : request.database_path,
      payload : config.project_id
    },
    profile,
    wrapping_key,
    bind_state,
    project_id,
    configured_key,
    endpoint,
    raw_material) ?
    if Bytes.length(wire) == 0 do
      store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch : epoch, action_kind : 0, target_mode : 1 })
    else
      encode_push_action(3, 0, epoch, wire)
    end
  else if state.action_kind == 3 do
    let _ = matching_native_push_config(state) ?
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | pending_kind : 0, pending_wire : Bytes.empty(), action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 0, target_mode : 1 })
  else if state.action_kind == 4 do
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | pending_kind : 0, pending_wire : Bytes.empty(), action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 5 })
  else if state.target_mode == 1 do
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 1 })
  else
    store_push_action(request.database_path,
    profile,
    wrapping_key,
    % { state | action_epoch : next_push_action_epoch(state.action_epoch) ?, action_kind : 0, target_mode : 0, project_id : Bytes.empty(), broker_public_key : Bytes.empty() })
  end
end

fn complete_push_action(request :: MobilePushActionCompletion) -> Bytes ! String do
  complete_push_action_with_config(request, expo_push_endpoint())
end

fn push_status(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    let profile = decode_client_profile(load_profile(database_path) ?) ?
    let wrapping_key = platform_key() ?
    let state = load_push_state(database_path, profile, wrapping_key) ?
    Ok(push_status_bytes(state))
  end
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
  let profile = encode_client_profile(entry, account.account_id, credential.device_id) ?
  let _ = decode_client_profile(profile) ?
  Ok(profile)
end

fn directory_entry_for(database_path :: String) -> Bytes ! String do
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  directory_bytes(profile.entry)
end

fn directory_lookup(input :: Bytes) -> Bytes ! String do
  let username = mobile_utf8(input, "invalid_username") ?
  case encode_directory_lookup(username) do
    Err( _) -> Err("invalid_username")
    Ok( encoded) -> Ok(encoded)
  end
end

fn transparency_checkpoint_bytes(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  let label = "transparency-checkpoint/v1"
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok( blob) -> open_local(blob, wrapping_key, local_context(label) ?)
  end
end

fn transparency_device_set_label(account_id :: Bytes) -> String do
  "transparency-device-set/v1/#{Bytes.to_hex(account_id)}"
end

fn encode_verified_transparency_set(value :: MobileVerifiedTransparencySet) -> Bytes ! String do
  if Bytes.length(value.checkpoint) != 188 || Bytes.length(value.device_set) == 0 || Bytes.length(value.device_set) > 305260 do
    Err("invalid_transparency_cache")
  else
    let checkpoint = decode_checkpoint(value.checkpoint) ?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint) ?, value.checkpoint) do
      Err("invalid_transparency_cache")
    else
      mobile_join([mobile_byte(1) ?, Bytes.from_utf8("KTS"), mobile_vector(value.checkpoint) ?, mobile_vector(value.device_set) ?],
      0,
      Bytes.empty())
    end
  end
end

fn decode_verified_transparency_set(input :: Bytes) -> MobileVerifiedTransparencySet ! String do
  case reader(input, 305460) do
    Err( _) -> Err("invalid_transparency_cache")
    Ok( state) -> do
      let version = take_fixed(state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let checkpoint = take_vector(magic.state, 188) ?
      let device_set = take_vector(checkpoint.state, 305260) ?
      case finish(device_set.state) do
        Err( _) -> Err("invalid_transparency_cache")
        Ok( _) -> do
          let value = MobileVerifiedTransparencySet {
            checkpoint : checkpoint.value,
            device_set : device_set.value
          }
          if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("KTS")) || Bytes.length(checkpoint.value) != 188 || Bytes.length(device_set.value) == 0 || !Bytes.secure_equals(encode_verified_transparency_set(value) ?,
          input) do
            Err("invalid_transparency_cache")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

fn encode_transparency_view(value :: MobileTransparencyView) -> Bytes ! String do
  if Bytes.length(value.checkpoint) != 188 || Bytes.length(value.consistency) == 0 || Bytes.length(value.consistency) > 131086 || Bytes.length(value.service_public_key) != 32 || Bytes.length(value.witness_a_public_key) != 32 || Bytes.length(value.witness_b_public_key) != 32 do
    Err("invalid_transparency_view")
  else
    let checkpoint = decode_checkpoint(value.checkpoint) ?
    let consistency = decode_consistency_proof(value.consistency) ?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint) ?, value.checkpoint) || !Bytes.secure_equals(encode_consistency_proof(consistency) ?,
    value.consistency) do
      Err("invalid_transparency_view")
    else
      mobile_join([mobile_byte(1) ?, Bytes.from_utf8("KTV"), value.service_public_key, value.witness_a_public_key, value.witness_b_public_key, mobile_vector(value.checkpoint) ?, mobile_vector(value.consistency) ?],
      0,
      Bytes.empty())
    end
  end
end

fn decode_transparency_view(input :: Bytes) -> MobileTransparencyView ! String do
  case reader(input, 131382) do
    Err( _) -> Err("invalid_transparency_view")
    Ok( state) -> do
      let version = take_fixed(state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let service_key = take_fixed(magic.state, 32) ?
      let witness_a = take_fixed(service_key.state, 32) ?
      let witness_b = take_fixed(witness_a.state, 32) ?
      let checkpoint = take_vector(witness_b.state, 188) ?
      let consistency = take_vector(checkpoint.state, 131086) ?
      case finish(consistency.state) do
        Err( _) -> Err("invalid_transparency_view")
        Ok( _) -> do
          let value = MobileTransparencyView {
            checkpoint : checkpoint.value,
            consistency : consistency.value,
            service_public_key : service_key.value,
            witness_a_public_key : witness_a.value,
            witness_b_public_key : witness_b.value
          }
          if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("KTV")) || !Bytes.secure_equals(encode_transparency_view(value) ?, input) do
            Err("invalid_transparency_view")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

fn transparency_view_chunk_count(length :: Int) -> Int do
  (length + 65535) / 65536
end

fn transparency_view_chunk_label(index :: Int) -> String do
  "transparency-view-chunk/v1/#{Int.to_string(index)}"
end

fn encode_transparency_manifest(value :: MobileTransparencyView) -> Bytes ! String do
  let consistency_length = Bytes.length(value.consistency)
  let chunk_count = transparency_view_chunk_count(consistency_length)
  if Bytes.length(value.checkpoint) != 188 || consistency_length == 0 || consistency_length > 131086 || chunk_count < 1 || chunk_count > 3 || Bytes.length(value.service_public_key) != 32 || Bytes.length(value.witness_a_public_key) != 32 || Bytes.length(value.witness_b_public_key) != 32 do
    Err("invalid_transparency_view")
  else
    let checkpoint = decode_checkpoint(value.checkpoint) ?
    let consistency = decode_consistency_proof(value.consistency) ?
    if !Bytes.secure_equals(encode_checkpoint(checkpoint) ?, value.checkpoint) || !Bytes.secure_equals(encode_consistency_proof(consistency) ?,
    value.consistency) do
      Err("invalid_transparency_view")
    else
      mobile_join([mobile_byte(1) ?, Bytes.from_utf8("KVM"), value.service_public_key, value.witness_a_public_key, value.witness_b_public_key, value.checkpoint, mobile_write_u32(consistency_length) ?, mobile_byte(chunk_count) ?, Crypto.sha256(value.consistency)],
      0,
      Bytes.empty())
    end
  end
end

fn decode_transparency_manifest(input :: Bytes) -> MobileTransparencyManifest ! String do
  case reader(input, 325) do
    Err( _) -> Err("invalid_transparency_view")
    Ok( state) -> do
      let version = take_fixed(state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let service_key = take_fixed(magic.state, 32) ?
      let witness_a = take_fixed(service_key.state, 32) ?
      let witness_b = take_fixed(witness_a.state, 32) ?
      let checkpoint = take_fixed(witness_b.state, 188) ?
      let consistency_length = take_fixed(checkpoint.state, 4) ?
      let chunk_count = take_fixed(consistency_length.state, 1) ?
      let consistency_hash = take_fixed(chunk_count.state, 32) ?
      case finish(consistency_hash.state) do
        Err( _) -> Err("invalid_transparency_view")
        Ok( _) -> do
          let length_value = mobile_read_u32(consistency_length.value) ?
          let count_value = mobile_read_byte(chunk_count.value) ?
          let manifest = MobileTransparencyManifest {
            checkpoint : checkpoint.value,
            consistency_length : length_value,
            consistency_hash : consistency_hash.value,
            chunk_count : count_value,
            service_public_key : service_key.value,
            witness_a_public_key : witness_a.value,
            witness_b_public_key : witness_b.value
          }
          if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("KVM")) || Bytes.length(checkpoint.value) != 188 || length_value == 0 || length_value > 131086 || count_value != transparency_view_chunk_count(length_value) || count_value < 1 || count_value > 3 || Bytes.length(consistency_hash.value) != 32 do
            Err("invalid_transparency_view")
          else
            Ok(manifest)
          end
        end
      end
    end
  end
end

fn seal_transparency_view_chunks(consistency :: Bytes,
wrapping_key :: borrow StorageKey,
index :: Int,
labels :: List < String >,
blobs :: List < Bytes >) -> MobileTransparencyStorage ! String do
  if index >= 3 do
    Ok(MobileTransparencyStorage {
      labels : labels,
      blobs : blobs
    })
  else
    let offset = index * 65536
    let remaining = Bytes.length(consistency) - offset
    let chunk_length = if remaining <= 0 do
      0
    else if remaining > 65536 do
      65536
    else
      remaining
    end
    let chunk = if chunk_length == 0 do
      Bytes.empty()
    else
      Bytes.slice(consistency, offset, chunk_length) ?
    end
    let label = transparency_view_chunk_label(index)
    let blob = seal_local(chunk, wrapping_key, local_context(label) ?) ?
    seal_transparency_view_chunks(consistency,
    wrapping_key,
    index + 1,
    List.append(labels, label),
    List.append(blobs, blob))
  end
end

fn transparency_view_storage(value :: MobileTransparencyView, wrapping_key :: borrow StorageKey) -> MobileTransparencyStorage ! String do
  let label = "transparency-view/v1"
  let manifest = encode_transparency_manifest(value) ?
  let blob = seal_local(manifest, wrapping_key, local_context(label) ?) ?
  seal_transparency_view_chunks(value.consistency, wrapping_key, 0, [label], [blob])
end

fn load_transparency_view_chunks(database_path :: String,
wrapping_key :: borrow StorageKey,
manifest :: MobileTransparencyManifest,
index :: Int,
output :: Bytes) -> Bytes ! String do
  if index >= 3 do
    Ok(output)
  else
    let label = transparency_view_chunk_label(index)
    let chunk = open_local(load_blob(database_path, label) ?, wrapping_key, local_context(label) ?) ?
    let offset = index * 65536
    let remaining = manifest.consistency_length - offset
    let expected_length = if index >= manifest.chunk_count do
      0
    else if remaining > 65536 do
      65536
    else
      remaining
    end
    if expected_length < 0 || Bytes.length(chunk) != expected_length do
      Err("invalid_transparency_view")
    else
      let updated = if index < manifest.chunk_count do
        mobile_append(output, chunk) ?
      else
        output
      end
      load_transparency_view_chunks(database_path, wrapping_key, manifest, index + 1, updated)
    end
  end
end

fn transparency_view_bytes(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  let label = "transparency-view/v1"
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(Bytes.empty())
    else
      Err(error)
    end
    Ok( blob) -> do
      let manifest = decode_transparency_manifest(open_local(blob,
      wrapping_key,
      local_context(label) ?) ?) ?
      let consistency = load_transparency_view_chunks(database_path,
      wrapping_key,
      manifest,
      0,
      Bytes.empty()) ?
      if Bytes.length(consistency) != manifest.consistency_length || !Bytes.secure_equals(Crypto.sha256(consistency),
      manifest.consistency_hash) do
        Err("invalid_transparency_view")
      else
        encode_transparency_view(MobileTransparencyView {
          checkpoint : manifest.checkpoint,
          consistency : consistency,
          service_public_key : manifest.service_public_key,
          witness_a_public_key : manifest.witness_a_public_key,
          witness_b_public_key : manifest.witness_b_public_key
        })
      end
    end
  end
end

fn load_transparency_view(database_path :: String, wrapping_key :: borrow StorageKey) -> MobileTransparencyView ! String do
  let encoded = transparency_view_bytes(database_path, wrapping_key) ?
  let checkpoint = transparency_checkpoint_bytes(database_path, wrapping_key) ?
  if Bytes.length(encoded) == 0 || Bytes.length(checkpoint) == 0 do
    Err("group_transparency_unverified")
  else
    let view = decode_transparency_view(encoded) ?
    if Bytes.secure_equals(view.checkpoint, checkpoint) do
      Ok(view)
    else
      Err("invalid_transparency_view")
    end
  end
end

fn canonical_transparency_checkpoint(input :: Bytes) -> TransparencyCheckpoint ! String do
  if Bytes.length(input) != 188 do
    Err("invalid_transparency_checkpoint")
  else
    let checkpoint = decode_checkpoint(input) ?
    if Bytes.secure_equals(encode_checkpoint(checkpoint) ?, input) do
      Ok(checkpoint)
    else
      Err("invalid_transparency_checkpoint")
    end
  end
end

fn transparency_checkpoint_in_view(encoded_checkpoint :: Bytes, view :: MobileTransparencyView) -> Bool ! String do
  let anchor = canonical_transparency_checkpoint(encoded_checkpoint) ?
  let current = canonical_transparency_checkpoint(view.checkpoint) ?
  let full_proof = decode_consistency_proof(view.consistency) ?
  let anchor_size = U64.to_int(anchor.tree_size) ?
  let current_size = U64.to_int(current.tree_size) ?
  let sequence_order = U64.compare(anchor.sequence, current.sequence)
  let trusted_key = SigningPublicKey { bytes : view.service_public_key }
  let anchor_proof = ConsistencyProof {
    old_tree_size : anchor_size,
    new_tree_size : current_size,
    leaf_hashes : full_proof.leaf_hashes
  }
  let current_proof = ConsistencyProof {
    old_tree_size : current_size,
    new_tree_size : current_size,
    leaf_hashes : full_proof.leaf_hashes
  }
  if full_proof.new_tree_size != current_size || full_proof.new_tree_size != List.length(full_proof.leaf_hashes) || anchor_size > current_size || sequence_order > 0 || (sequence_order == 0 && !Bytes.secure_equals(encoded_checkpoint,
  view.checkpoint)) do
    Ok(false)
  else
    let anchor_valid = verify_checkpoint(anchor, trusted_key) ?
    let current_valid = verify_checkpoint(current, trusted_key) ?
    let current_tree_valid = verify_consistency(current.tree_root, current.tree_root, current_proof) ?
    let prefix_valid = verify_consistency(anchor.tree_root, current.tree_root, anchor_proof) ?
    Ok(anchor_valid && current_valid && current_tree_valid && prefix_valid)
  end
end

fn transparency_checkpoint_precedes(first :: Bytes, second :: Bytes, view :: MobileTransparencyView) -> Bool ! String do
  let first_checkpoint = canonical_transparency_checkpoint(first) ?
  let second_checkpoint = canonical_transparency_checkpoint(second) ?
  let sequence_order = U64.compare(first_checkpoint.sequence, second_checkpoint.sequence)
  let tree_order = U64.compare(first_checkpoint.tree_size, second_checkpoint.tree_size)
  if sequence_order > 0 || tree_order > 0 || (sequence_order == 0 && !Bytes.secure_equals(first,
  second)) do
    Ok(false)
  else
    Ok(transparency_checkpoint_in_view(first, view) ? && transparency_checkpoint_in_view(second,
    view) ?)
  end
end

fn require_transparency_device_set(database_path :: String,
wrapping_key :: borrow StorageKey,
devices :: MobileVerifiedDeviceSet) -> Bytes ! String do
  let label = transparency_device_set_label(devices.account.account_id)
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Err("device_set_transparency_unverified")
    else
      Err(error)
    end
    Ok( blob) -> do
      let cached = decode_verified_transparency_set(open_local(blob,
      wrapping_key,
      local_context(label) ?) ?) ?
      let view = case load_transparency_view(database_path, wrapping_key) do
        Err( error) -> if error == "group_transparency_unverified" do
          Err("device_set_transparency_unverified")
        else
          Err(error)
        end
        Ok( loaded) -> Ok(loaded)
      end ?
      if Bytes.secure_equals(cached.device_set, devices.wire) && transparency_checkpoint_in_view(cached.checkpoint,
      view) ? do
        Ok(cached.checkpoint)
      else
        Err("device_set_transparency_unverified")
      end
    end
  end
end

fn verified_transparency_device_set(database_path :: String,
wrapping_key :: borrow StorageKey,
devices :: MobileVerifiedDeviceSet,
baseline_checkpoint :: Bytes) -> Bytes ! String do
  let cached_checkpoint = case require_transparency_device_set(database_path, wrapping_key, devices) do
    Err( error) -> if error == "device_set_transparency_unverified" do
      Err("group_transparency_unverified")
    else
      Err(error)
    end
    Ok( checkpoint) -> Ok(checkpoint)
  end ?
  let view = load_transparency_view(database_path, wrapping_key) ?
  if transparency_checkpoint_precedes(baseline_checkpoint, cached_checkpoint, view) ? && transparency_checkpoint_precedes(cached_checkpoint,
  view.checkpoint,
  view) ? do
    Ok(cached_checkpoint)
  else
    Err("group_transparency_unverified")
  end
end

fn transparency_lookup(request :: MobilePayloadRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let username = mobile_utf8(request.payload, "invalid_username") ?
  let checkpoint_bytes = transparency_checkpoint_bytes(request.database_path, platform_key() ?) ?
  let previous_tree_size = if Bytes.length(checkpoint_bytes) == 0 do
    0
  else
    U64.to_int(decode_checkpoint(checkpoint_bytes) ?.tree_size) ?
  end
  case encode_transparency_lookup(TransparencyLookup {
    username : username,
    previous_tree_size : previous_tree_size
  }) do
    Err( _) -> Err("invalid_username")
    Ok( encoded) -> Ok(encoded)
  end
end

fn verify_transparency_response(request :: MobileTransparencyRequest) -> Bytes ! String do
  let config = native_security_config() ?
  ensure_schema(request.database_path) ?
  let evidence = case decode_transparency_evidence(request.evidence) do
    Err( _) -> Err("invalid_transparency_evidence")
    Ok( value) -> Ok(value)
  end ?
  let wrapping_key = platform_key() ?
  let previous = transparency_checkpoint_bytes(request.database_path, wrapping_key) ?
  let existing_view_bytes = transparency_view_bytes(request.database_path, wrapping_key) ?
  let trust_matches = if Bytes.length(existing_view_bytes) == 0 do
    true
  else
    let existing_view = decode_transparency_view(existing_view_bytes) ?
    Bytes.secure_equals(existing_view.checkpoint, previous) && Bytes.secure_equals(existing_view.service_public_key,
    config.transparency_service_public_key) && Bytes.secure_equals(existing_view.witness_a_public_key,
    config.witness_a_public_key) && Bytes.secure_equals(existing_view.witness_b_public_key,
    config.witness_b_public_key)
  end
  let trusted_service_key = SigningPublicKey { bytes : config.transparency_service_public_key }
  let trusted_witnesses = [WitnessKey {
    witness_id : "witness-a",
    public_key : config.witness_a_public_key
  }, WitnessKey {
    witness_id : "witness-b",
    public_key : config.witness_b_public_key
  }]
  if !trust_matches do
    Err("transparency_trust_mismatch")
  else if !verify_evidence(evidence, trusted_service_key, trusted_witnesses, 2, previous) ? do
    Err("transparency_verification_failed")
  else
    let devices = verified_device_set(evidence.entry_bytes) ?
    if devices.value.username != request.username do
      Err("transparency_username_mismatch")
    else
      let checkpoint_label = "transparency-checkpoint/v1"
      let encoded_checkpoint = encode_checkpoint(evidence.checkpoint) ?
      let encoded_consistency = encode_consistency_proof(evidence.consistency) ?
      let checkpoint_blob = seal_local(encoded_checkpoint,
      wrapping_key,
      local_context(checkpoint_label) ?) ?
      let device_set_label = transparency_device_set_label(devices.account.account_id)
      let device_set_blob = seal_local(encode_verified_transparency_set(MobileVerifiedTransparencySet {
        checkpoint : encoded_checkpoint,
        device_set : devices.wire
      }) ?,
      wrapping_key,
      local_context(device_set_label) ?) ?
      let view_storage = transparency_view_storage(MobileTransparencyView {
        checkpoint : encoded_checkpoint,
        consistency : encoded_consistency,
        service_public_key : config.transparency_service_public_key,
        witness_a_public_key : config.witness_a_public_key,
        witness_b_public_key : config.witness_b_public_key
      },
      wrapping_key) ?
      store_updated_blobs(request.database_path,
      List.append(List.append(view_storage.labels, checkpoint_label), device_set_label),
      List.append(List.append(view_storage.blobs, checkpoint_blob), device_set_blob)) ?
      Ok(evidence.entry_bytes)
    end
  end
end

fn mailbox_fetch(database_path :: String) -> Bytes ! String do
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  case encode_mailbox_fetch(MailboxFetch {
    version : 1,
    mailbox_token : profile.entry.mailbox_token,
    after_sequence : mobile_wide("0") ?
  }) do
    Err( _) -> Err("mailbox_fetch_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

fn consume_group_state(value :: consume GroupState) do
  nil
end

fn consume_group_private(value :: consume X25519PrivateKey) do
  nil
end

fn group_state_label(group_id :: Bytes) -> String ! String do
  if Bytes.length(group_id) != 32 do
    Err("invalid_group_id")
  else
    Ok("group-state/v1/#{Bytes.to_hex(group_id)}")
  end
end

fn group_baseline_label(group_id :: Bytes) -> String ! String do
  if Bytes.length(group_id) != 32 do
    Err("invalid_group_id")
  else
    Ok("group-baseline/v1/#{Bytes.to_hex(group_id)}")
  end
end

fn group_baseline_blob(checkpoint :: Bytes, wrapping_key :: borrow StorageKey, group_id :: Bytes) -> Bytes ! String do
  let _ = canonical_transparency_checkpoint(checkpoint) ?
  let label = group_baseline_label(group_id) ?
  seal_local(checkpoint, wrapping_key, local_context(label) ?)
end

fn load_group_baseline(database_path :: String,
wrapping_key :: borrow StorageKey,
group_id :: Bytes) -> Bytes ! String do
  let label = group_baseline_label(group_id) ?
  let checkpoint = open_local(load_blob(database_path, label) ?,
  wrapping_key,
  local_context(label) ?) ?
  let _ = canonical_transparency_checkpoint(checkpoint) ?
  Ok(checkpoint)
end

fn contains_group_id(values :: List < Bytes >, group_id :: Bytes, index :: Int) -> Bool do
  if index >= List.length(values) do
    false
  else if Bytes.secure_equals(List.get(values, index), group_id) do
    true
  else
    contains_group_id(values, group_id, index + 1)
  end
end

fn decode_group_ids_parts(state :: BinaryReader, count :: Int, index :: Int, ids :: List < Bytes >) -> List < Bytes > ! String do
  if index >= count do
    case finish(state) do
      Err( _) -> Err("invalid_group_index")
      Ok( _) -> Ok(ids)
    end
  else
    let id = take_vector(state, 32) ?
    if Bytes.length(id.value) != 32 || contains_group_id(ids, id.value, 0) do
      Err("invalid_group_index")
    else
      decode_group_ids_parts(id.state, count, index + 1, List.append(ids, id.value))
    end
  end
end

fn decode_group_ids(input :: Bytes) -> List < Bytes > ! String do
  case reader(input, 4616) do
    Err( _) -> Err("invalid_group_index")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let count_value = mobile_read_u32(count.value) ?
      if count_value > 128 do
        Err("invalid_group_index")
      else
        decode_group_ids_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn load_group_ids(database_path :: String, wrapping_key :: borrow StorageKey) -> List < Bytes > ! String do
  let label = "groups/v1"
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> decode_group_ids(open_local(blob, wrapping_key, local_context(label) ?) ?)
  end
end

fn updated_group_index_blob(database_path :: String,
wrapping_key :: borrow StorageKey,
group_id :: Bytes) -> Bytes ! String do
  let ids = load_group_ids(database_path, wrapping_key) ?
  let updated = if contains_group_id(ids, group_id, 0) do
    ids
  else if List.length(ids) >= 128 do
    Err("group_limit_reached") ?
  else
    List.append(ids, group_id)
  end
  seal_local(encode_output_list(updated) ?, wrapping_key, local_context("groups/v1") ?)
end

fn group_history_label(group_id :: Bytes) -> String do
  "group-history/v1/#{Bytes.to_hex(group_id)}"
end

fn encode_group_history_entry(value :: MobileGroupHistoryEntry) -> Bytes ! String do
  if (value.direction != 1 && value.direction != 2) || Bytes.length(value.sender_account_id) != 32 || Bytes.length(value.sender_device_id) != 16 || Bytes.length(value.body) > 65346 do
    Err("invalid_group_history")
  else
    encode_output_list([mobile_byte(1) ?, mobile_byte(value.direction) ?, mobile_write_u64(value.epoch) ?, value.sender_account_id, value.sender_device_id, mobile_write_u64(value.timestamp) ?, value.body])
  end
end

fn decode_group_history_entry(input :: Bytes) -> MobileGroupHistoryEntry ! String do
  case reader(input, 65448) do
    Err( _) -> Err("invalid_group_history")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let version = take_vector(count.state, 1) ?
      let direction = take_vector(version.state, 1) ?
      let epoch = take_vector(direction.state, 8) ?
      let account_id = take_vector(epoch.state, 32) ?
      let device_id = take_vector(account_id.state, 16) ?
      let timestamp = take_vector(device_id.state, 8) ?
      let body = take_vector(timestamp.state, 65346) ?
      case finish(body.state) do
        Err( _) -> Err("invalid_group_history")
        Ok( _) -> do
          let direction_value = mobile_read_byte(direction.value) ?
          if mobile_read_u32(count.value) ? != 7 || mobile_read_byte(version.value) ? != 1 || (direction_value != 1 && direction_value != 2) || Bytes.length(account_id.value) != 32 || Bytes.length(device_id.value) != 16 do
            Err("invalid_group_history")
          else
            Ok(MobileGroupHistoryEntry {
              direction : direction_value,
              epoch : mobile_read_u64(epoch.value) ?,
              sender_account_id : account_id.value,
              sender_device_id : device_id.value,
              timestamp : mobile_read_u64(timestamp.value) ?,
              body : body.value
            })
          end
        end
      end
    end
  end
end

fn decode_group_history_parts(state :: BinaryReader,
count :: Int,
index :: Int,
entries :: List < MobileGroupHistoryEntry >) -> List < MobileGroupHistoryEntry > ! String do
  if index >= count do
    case finish(state) do
      Err( _) -> Err("invalid_group_history")
      Ok( _) -> Ok(entries)
    end
  else
    let entry = take_vector(state, 65448) ?
    decode_group_history_parts(entry.state,
    count,
    index + 1,
    List.append(entries, decode_group_history_entry(entry.value) ?))
  end
end

fn decode_group_history(input :: Bytes) -> List < MobileGroupHistoryEntry > ! String do
  case reader(input, 65536) do
    Err( _) -> Err("invalid_group_history")
    Ok( state) -> do
      let count = take_vector(state, 4) ?
      let count_value = mobile_read_u32(count.value) ?
      if count_value > 256 do
        Err("invalid_group_history")
      else
        decode_group_history_parts(count.state, count_value, 0, List.new())
      end
    end
  end
end

fn encode_group_history(values :: List < MobileGroupHistoryEntry >) -> Bytes ! String do
  let bounded = if List.length(values) > 256 do
    List.drop(values, List.length(values) - 256)
  else
    values
  end
  encode_bounded_group_history(bounded)
end

fn encode_bounded_group_history(values :: List < MobileGroupHistoryEntry >) -> Bytes ! String do
  let encoded = encode_group_history_entries(values, 0, List.new()) ?
  let output = encode_output_list(encoded) ?
  if Bytes.length(output) <= 65536 do
    Ok(output)
  else if List.length(values) == 0 do
    Err("invalid_group_history")
  else
    encode_bounded_group_history(List.drop(values, 1))
  end
end

fn encode_group_history_entries(values :: List < MobileGroupHistoryEntry >,
index :: Int,
encoded :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(values) do
    Ok(encoded)
  else
    encode_group_history_entries(values,
    index + 1,
    List.append(encoded, encode_group_history_entry(List.get(values, index)) ?))
  end
end

fn load_group_history(database_path :: String, wrapping_key :: borrow StorageKey, group_id :: Bytes) -> List < MobileGroupHistoryEntry > ! String do
  let label = group_history_label(group_id)
  case load_blob(database_path, label) do
    Err( error) -> if error == "local_state_not_found" do
      Ok(List.new())
    else
      Err(error)
    end
    Ok( blob) -> decode_group_history(open_local(blob, wrapping_key, local_context(label) ?) ?)
  end
end

fn updated_group_history_blob(database_path :: String,
wrapping_key :: borrow StorageKey,
group_id :: Bytes,
entry :: MobileGroupHistoryEntry) -> Bytes ! String do
  let label = group_history_label(group_id)
  let entries = List.append(load_group_history(database_path, wrapping_key, group_id) ?, entry)
  seal_local(encode_group_history(entries) ?, wrapping_key, local_context(label) ?)
end

fn group_join_label(kind :: String) -> String do
  "group-join-#{kind}/v1"
end

fn group_checkpoint(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes ! String do
  let encoded = transparency_checkpoint_bytes(database_path, wrapping_key) ?
  if Bytes.length(encoded) == 0 do
    Err("group_transparency_unverified")
  else
    let view = load_transparency_view(database_path, wrapping_key) ?
    if transparency_checkpoint_in_view(encoded, view) ? do
      Ok(encoded)
    else
      Err("group_transparency_unverified")
    end
  end
end

fn group_member(profile :: ClientProfile,
init_public_key :: X25519PublicKey,
leaf_public_key :: X25519PublicKey,
directory_sequence :: U64,
checkpoint :: Bytes,
witness_count :: Int) -> GroupMember do
  GroupMember {
    version : 1,
    account_id : profile.account_id,
    device_id : profile.device_id,
    signing_public_key : SigningPublicKey { bytes : profile.credential.signing_public_key },
    init_public_key : init_public_key,
    leaf_public_key : leaf_public_key,
    mailbox_token : profile.entry.mailbox_token,
    directory_sequence : directory_sequence,
    transparency_checkpoint_hash : checkpoint,
    witness_count : witness_count,
    extensions : [1]
  }
end

fn group_key_package_unsigned(value :: MobileGroupKeyPackage) -> Bytes ! String do
  mobile_join([mobile_byte(1) ?, Bytes.from_utf8("GKP"), value.account_id, value.device_id, value.init_public_key.bytes, value.leaf_public_key.bytes, value.checkpoint, mobile_byte(value.witness_count) ?],
  0,
  Bytes.empty())
end

fn encode_group_key_package(value :: MobileGroupKeyPackage) -> Bytes ! String do
  let unsigned = group_key_package_unsigned(value) ?
  if Bytes.length(unsigned) != 305 || Bytes.length(value.signature.bytes) != 64 do
    Err("invalid_group_key_package")
  else
    mobile_append(unsigned, value.signature.bytes)
  end
end

fn decode_group_key_package(input :: Bytes) -> MobileGroupKeyPackage ! String do
  if Bytes.length(input) != 369 do
    Err("invalid_group_key_package")
  else
    let state = case reader(input, 369) do
      Err( _) -> Err("invalid_group_key_package")
      Ok( value) -> Ok(value)
    end ?
    let version = take_fixed(state, 1) ?
    let magic = take_fixed(version.state, 3) ?
    let account_id = take_fixed(magic.state, 32) ?
    let device_id = take_fixed(account_id.state, 16) ?
    let init_public = take_fixed(device_id.state, 32) ?
    let leaf_public = take_fixed(init_public.state, 32) ?
    let checkpoint = take_fixed(leaf_public.state, 188) ?
    let witness = take_fixed(checkpoint.state, 1) ?
    let signature = take_fixed(witness.state, 64) ?
    case finish(signature.state) do
      Err( _) -> Err("invalid_group_key_package")
      Ok( _) -> do
        let value = MobileGroupKeyPackage {
          account_id : account_id.value,
          device_id : device_id.value,
          init_public_key : X25519PublicKey { bytes : init_public.value },
          leaf_public_key : X25519PublicKey { bytes : leaf_public.value },
          checkpoint : checkpoint.value,
          witness_count : mobile_read_byte(witness.value) ?,
          signature : Signature { bytes : signature.value }
        }
        if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
        Bytes.from_utf8("GKP")) || Bytes.secure_equals(init_public.value, leaf_public.value) || value.witness_count != 2 || !Bytes.secure_equals(encode_checkpoint(decode_checkpoint(checkpoint.value) ?) ?,
        checkpoint.value) || !Bytes.secure_equals(encode_group_key_package(value) ?, input) do
          Err("invalid_group_key_package")
        else
          Ok(value)
        end
      end
    end
  end
end

fn group_profile(profiles :: List < ClientProfile >,
account_id :: Bytes,
device_id :: Bytes,
index :: Int) -> ClientProfile ! String do
  if index >= List.length(profiles) do
    Err("group_member_not_found")
  else
    let value = List.get(profiles, index)
    if Bytes.secure_equals(value.account_id, account_id) && Bytes.secure_equals(value.device_id,
    device_id) do
      Ok(value)
    else
      group_profile(profiles, account_id, device_id, index + 1)
    end
  end
end

fn verified_group_member(devices :: MobileVerifiedDeviceSet,
encoded_package :: Bytes,
proof_checkpoint :: Bytes,
baseline_checkpoint :: Bytes,
view :: MobileTransparencyView) -> GroupMember ! String do
  let package = decode_group_key_package(encoded_package) ?
  let profile = group_profile(devices.profiles, package.account_id, package.device_id, 0) ?
  let valid_signature = case Crypto.verify(SigningPublicKey { bytes : profile.credential.signing_public_key },
  group_key_package_unsigned(package) ?,
  package.signature) do
    Err( _) -> false
    Ok( value) -> value
  end
  if !valid_signature || !(transparency_checkpoint_precedes(baseline_checkpoint,
  package.checkpoint,
  view) ?) || !(transparency_checkpoint_precedes(package.checkpoint, proof_checkpoint, view) ?) do
    Err("invalid_group_key_package")
  else
    let baseline_hash = checkpoint_hash(canonical_transparency_checkpoint(baseline_checkpoint) ?) ?
    Ok(group_member(profile,
    package.init_public_key,
    package.leaf_public_key,
    devices.value.sequence,
    baseline_hash,
    package.witness_count))
  end
end

fn create_group_key_package(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let checkpoint = group_checkpoint(database_path, wrapping_key) ?
  let view = load_transparency_view(database_path, wrapping_key) ?
  let package_label = group_join_label("package")
  case load_blob(database_path, package_label) do
    Ok( blob) -> do
      let encoded = open_local(blob, wrapping_key, local_context(package_label) ?) ?
      let package = decode_group_key_package(encoded) ?
      let signature_valid = case Crypto.verify(SigningPublicKey { bytes : profile.credential.signing_public_key },
      group_key_package_unsigned(package) ?,
      package.signature) do
        Err( _) -> false
        Ok( value) -> value
      end
      if signature_valid && Bytes.secure_equals(package.account_id, profile.account_id) && Bytes.secure_equals(package.device_id,
      profile.device_id) && transparency_checkpoint_precedes(package.checkpoint, checkpoint, view) ? do
        Ok(encoded)
      else
        Err("group_key_package_pending")
      end
    end
    Err( error) -> if error != "local_state_not_found" do
      Err(error)
    else
      let init_keys = case Crypto.x25519_generate() do
        Err( _) -> Err("group_key_generation_failed")
        Ok( value) -> Ok(value)
      end ?
      let leaf_keys = case Crypto.x25519_generate() do
        Err( _) -> Err("group_key_generation_failed")
        Ok( value) -> Ok(value)
      end ?
      let unsigned = MobileGroupKeyPackage {
        account_id : profile.account_id,
        device_id : profile.device_id,
        init_public_key : init_keys.public_key,
        leaf_public_key : leaf_keys.public_key,
        checkpoint : checkpoint,
        witness_count : 2,
        signature : Signature { bytes : Bytes.empty() }
      }
      let device = open_device(profile, wrapping_key, database_path) ?
      let signature = case Crypto.sign(device.signing_private_key,
      group_key_package_unsigned(unsigned) ?) do
        Err( _) -> Err("group_key_generation_failed")
        Ok( value) -> Ok(value)
      end ?
      let encoded = encode_group_key_package(% { unsigned | signature : signature }) ?
      let init_label = group_join_label("init")
      let leaf_label = group_join_label("leaf")
      let package_blob = seal_local(encoded, wrapping_key, local_context(package_label) ?) ?
      let init_blob = seal_x25519(init_keys.private_key,
      wrapping_key,
      context(profile.account_id, profile.device_id, init_label, 17) ?) ?
      let leaf_blob = seal_x25519(leaf_keys.private_key,
      wrapping_key,
      context(profile.account_id, profile.device_id, leaf_label, 17) ?) ?
      consume_group_private(init_keys.private_key)
      consume_group_private(leaf_keys.private_key)
      store_blobs(database_path,
      [package_label, init_label, leaf_label],
      [package_blob, init_blob, leaf_blob]) ?
      Ok(encoded)
    end
  end
end

fn group_snapshot_blob(state :: consume GroupState,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey) -> Result <( String, Bytes), String > do
  let label = group_state_label(state.group_id) ?
  let version = U64.add(state.snapshot_version, mobile_wide("1") ?) ?
  case group_snapshot(state, wrapping_key, profile.account_id, profile.device_id, version) do
    GroupSnapshotRejected( rejected, _) -> do
      consume_group_state(rejected)
      Err("group_snapshot_failed")
    end
    GroupSnapshotSealed( next, snapshot_blob) -> do
      let stored = seal_local(snapshot_blob, wrapping_key, local_context(label) ?) ?
      consume_group_state(next)
      Ok((label, stored))
    end
  end
end

fn load_group(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
group_id :: Bytes) -> GroupState ! String do
  let label = group_state_label(group_id) ?
  let snapshot_blob = open_local(load_blob(database_path, label) ?,
  wrapping_key,
  local_context(label) ?) ?
  case restore_group(snapshot_blob,
  wrapping_key,
  profile.account_id,
  profile.device_id,
  mobile_wide("1") ?) do
    Err( _) -> Err("group_state_invalid")
    Ok( state) -> if Bytes.secure_equals(state.group_id, group_id) do
      Ok(state)
    else
      consume_group_state(state)
      Err("group_state_invalid")
    end
  end
end

fn group_summary(state :: borrow GroupState) -> Bytes ! String do
  encode_output_list([mobile_byte(1) ?, state.group_id, mobile_write_u64(state.epoch) ?, mobile_write_u32(List.length(indexed_members(state.tree))) ?])
end

fn group_member_summary(value :: IndexedGroupMember, local_leaf :: Int) -> Bytes ! String do
  encode_output_list([mobile_byte(1) ?, mobile_write_u32(value.leaf_index) ?, mobile_byte(if value.leaf_index == local_leaf do
    1
  else
    0
  end) ?, value.member.account_id, value.member.device_id, mobile_write_u64(value.member.directory_sequence) ?, mobile_byte(value.member.witness_count) ?])
end

fn group_member_summaries(values :: List < IndexedGroupMember >,
local_leaf :: Int,
index :: Int,
summaries :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(values) do
    Ok(summaries)
  else
    group_member_summaries(values,
    local_leaf,
    index + 1,
    List.append(summaries, group_member_summary(List.get(values, index), local_leaf) ?))
  end
end

fn inspect_mobile_group(request :: MobileGroupReferenceRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
  let members = group_member_summaries(indexed_members(state.tree), state.local_leaf, 0, List.new()) ?
  let encoded = encode_output_list([mobile_byte(1) ?, state.group_id, mobile_write_u64(state.epoch) ?, mobile_write_u32(state.local_leaf) ?, state.tree_hash_cache, state.policy.checkpoint_hash, encode_output_list(members) ?]) ?
  consume_group_state(state)
  Ok(encoded)
end

fn collect_group_summaries(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
group_ids :: List < Bytes >,
index :: Int,
summaries :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(group_ids) do
    Ok(summaries)
  else
    let state = load_group(database_path, profile, wrapping_key, List.get(group_ids, index)) ?
    let summary = group_summary(state) ?
    consume_group_state(state)
    collect_group_summaries(database_path,
    profile,
    wrapping_key,
    group_ids,
    index + 1,
    List.append(summaries, summary))
  end
end

fn list_mobile_groups(database_path :: String) -> Bytes ! String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path) ?
    let profile = decode_client_profile(load_profile(database_path) ?) ?
    let wrapping_key = platform_key() ?
    encode_output_list(collect_group_summaries(database_path,
    profile,
    wrapping_key,
    load_group_ids(database_path, wrapping_key) ?,
    0,
    List.new()) ?)
  end
end

fn mobile_group_history(request :: MobileGroupReferenceRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
  consume_group_state(state)
  encode_group_history(load_group_history(request.database_path, wrapping_key, request.group_id) ?)
end

fn encode_group_welcome_packet(value :: MobileGroupWelcomePacket) -> Bytes ! String do
  if Bytes.length(value.baseline_checkpoint) != 188 || Bytes.length(value.welcome) == 0 || Bytes.length(value.welcome) > 65327 do
    Err("invalid_group_welcome")
  else
    let _ = canonical_transparency_checkpoint(value.baseline_checkpoint) ?
    mobile_join([mobile_byte(1) ?, Bytes.from_utf8("GWB"), mobile_vector(value.baseline_checkpoint) ?, mobile_vector(value.welcome) ?],
    0,
    Bytes.empty())
  end
end

fn decode_group_welcome_packet_inner(input :: Bytes) -> MobileGroupWelcomePacket ! String do
  case reader(input, 65527) do
    Err( _) -> Err("invalid_group_welcome")
    Ok( state) -> do
      let version = take_fixed(state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let baseline = take_vector(magic.state, 188) ?
      let welcome = take_vector(baseline.state, 65327) ?
      case finish(welcome.state) do
        Err( _) -> Err("invalid_group_welcome")
        Ok( _) -> do
          let value = MobileGroupWelcomePacket {
            baseline_checkpoint : baseline.value,
            welcome : welcome.value
          }
          if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("GWB")) || Bytes.length(baseline.value) != 188 || Bytes.length(welcome.value) == 0 || !Bytes.secure_equals(encode_group_welcome_packet(value) ?,
          input) do
            Err("invalid_group_welcome")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

fn decode_group_welcome_packet(input :: Bytes) -> MobileGroupWelcomePacket ! String do
  case decode_group_welcome_packet_inner(input) do
    Err( _) -> Err("invalid_group_welcome")
    Ok( value) -> Ok(value)
  end
end

fn encode_group_packet(kind :: Int, payload :: Bytes) -> Bytes ! String do
  if kind < 1 || kind > 3 || Bytes.length(payload) == 0 || Bytes.length(payload) > 65527 do
    Err("invalid_group_packet")
  else
    let encoded = mobile_join([mobile_byte(1) ?, Bytes.from_utf8("GRP"), mobile_byte(kind) ?, mobile_vector(payload) ?],
    0,
    Bytes.empty()) ?
    if Bytes.length(encoded) > 65536 do
      Err("group_message_too_large")
    else
      Ok(encoded)
    end
  end
end

fn decode_group_packet_inner(input :: Bytes) -> MobileGroupPacket ! String do
  case reader(input, 65536) do
    Err( _) -> Err("invalid_group_packet")
    Ok( state) -> do
      let version = take_fixed(state, 1) ?
      let magic = take_fixed(version.state, 3) ?
      let kind = take_fixed(magic.state, 1) ?
      let payload = take_vector(kind.state, 65527) ?
      case finish(payload.state) do
        Err( _) -> Err("invalid_group_packet")
        Ok( _) -> do
          let kind_value = mobile_read_byte(kind.value) ?
          let value = MobileGroupPacket {
            kind : kind_value,
            payload : payload.value
          }
          if mobile_read_byte(version.value) ? != 1 || !Bytes.secure_equals(magic.value,
          Bytes.from_utf8("GRP")) || kind_value < 1 || kind_value > 3 || Bytes.length(payload.value) == 0 || !Bytes.secure_equals(encode_group_packet(kind_value,
          payload.value) ?,
          input) do
            Err("invalid_group_packet")
          else
            Ok(value)
          end
        end
      end
    end
  end
end

fn decode_group_packet(input :: Bytes) -> MobileGroupPacket ! String do
  case decode_group_packet_inner(input) do
    Err( _) -> Err("invalid_group_packet")
    Ok( value) -> Ok(value)
  end
end

fn canonical_group_commit(input :: Bytes) -> GroupCommit ! String do
  let value = case decode_group_commit(input) do
    Err( _) -> Err("invalid_group_commit")
    Ok( decoded) -> Ok(decoded)
  end ?
  let encoded = case encode_group_commit(value) do
    Err( _) -> Err("invalid_group_commit")
    Ok( output) -> Ok(output)
  end ?
  if Bytes.secure_equals(encoded, input) do
    Ok(value)
  else
    Err("invalid_group_commit")
  end
end

fn canonical_group_welcome(input :: Bytes) -> GroupWelcome ! String do
  let value = case decode_group_welcome(input) do
    Err( _) -> Err("invalid_group_welcome")
    Ok( decoded) -> Ok(decoded)
  end ?
  let encoded = case encode_group_welcome(value) do
    Err( _) -> Err("invalid_group_welcome")
    Ok( output) -> Ok(output)
  end ?
  if Bytes.secure_equals(encoded, input) do
    Ok(value)
  else
    Err("invalid_group_welcome")
  end
end

fn canonical_group_message(input :: Bytes) -> GroupMessage ! String do
  let value = case decode_group_message(input) do
    Err( _) -> Err("invalid_group_message")
    Ok( decoded) -> Ok(decoded)
  end ?
  let encoded = case encode_group_message(value) do
    Err( _) -> Err("invalid_group_message")
    Ok( output) -> Ok(output)
  end ?
  if Bytes.secure_equals(encoded, input) do
    Ok(value)
  else
    Err("invalid_group_message")
  end
end

fn group_target_envelopes(targets :: List < GroupDeliveryTarget >,
packet :: Bytes,
now :: U64,
index :: Int,
output :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(targets) do
    Ok(output)
  else
    group_target_envelopes(targets,
    packet,
    now,
    index + 1,
    List.append(output, outer_bytes(List.get(targets, index).mailbox_token, 3, packet, now) ?))
  end
end

fn group_add_envelopes(targets :: List < GroupDeliveryTarget >,
recipient_leaf :: Int,
commit_packet :: Bytes,
welcome_packet :: Bytes,
now :: U64,
index :: Int,
output :: List < Bytes >) -> List < Bytes > ! String do
  if index >= List.length(targets) do
    Ok(output)
  else
    let target = List.get(targets, index)
    let packet = if target.leaf_index == recipient_leaf do
      welcome_packet
    else
      commit_packet
    end
    group_add_envelopes(targets,
    recipient_leaf,
    commit_packet,
    welcome_packet,
    now,
    index + 1,
    List.append(output, outer_bytes(target.mailbox_token, 3, packet, now) ?))
  end
end

fn store_new_group(database_path :: String,
state_label :: String,
state_blob :: Bytes,
index_blob :: Bytes,
baseline_label :: String,
baseline_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case insert_blob(database, baseline_label, baseline_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "groups/v1", index_blob) do
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

fn store_group_outbound(database_path :: String,
state_label :: String,
state_blob :: Bytes,
outbox_labels :: List < String >,
outbox_blobs :: List < Bytes >,
outbox_index_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blobs(database, outbox_labels, outbox_blobs, 0) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "outbox/v1", outbox_index_blob) do
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

fn store_group_message_outbound(database_path :: String,
state_label :: String,
state_blob :: Bytes,
history_label :: String,
history_blob :: Bytes,
outbox_labels :: List < String >,
outbox_blobs :: List < Bytes >,
outbox_index_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, history_label, history_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blobs(database, outbox_labels, outbox_blobs, 0) do
              Err( error) -> Err(error)
              Ok( _) -> case put_blob(database, "outbox/v1", outbox_index_blob) do
                Err( error) -> Err(error)
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

fn store_group_state_history(database_path :: String,
state_label :: String,
state_blob :: Bytes,
history_label :: String,
history_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case put_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case put_blob(database, history_label, history_blob) do
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

fn store_group_join(database_path :: String,
state_label :: String,
state_blob :: Bytes,
index_blob :: Bytes,
baseline_label :: String,
baseline_blob :: Bytes,
package_label :: String,
init_label :: String,
leaf_label :: String) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, state_label, state_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case insert_blob(database, baseline_label, baseline_blob) do
            Err( error) -> Err(error)
            Ok( _) -> case put_blob(database, "groups/v1", index_blob) do
              Err( error) -> Err(error)
              Ok( _) -> case delete_blobs(database, [package_label, init_label, leaf_label], 0) do
                Err( error) -> Err(error)
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

fn create_mobile_group(database_path :: String) -> Bytes ! String do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let checkpoint = group_checkpoint(database_path, wrapping_key) ?
  let checkpoint_hash_value = checkpoint_hash(canonical_transparency_checkpoint(checkpoint) ?) ?
  let leaf_keys = case Crypto.x25519_generate() do
    Err( _) -> Err("group_key_generation_failed")
    Ok( value) -> Ok(value)
  end ?
  let creator = group_member(profile,
  X25519PublicKey { bytes : profile.credential.dh_public_key },
  leaf_keys.public_key,
  profile.account.directory_sequence,
  checkpoint_hash_value,
  2)
  let state = case create_group(creator,
  leaf_keys.private_key,
  [1],
  GroupTransparencyPolicy {
    minimum_directory_sequence : profile.account.directory_sequence,
    checkpoint_hash : checkpoint_hash_value,
    witness_threshold : 2
  }) do
    Err( _) -> Err("group_create_failed")
    Ok( value) -> Ok(value)
  end ?
  let group_id = state.group_id
  let ( label, blob) = group_snapshot_blob(state, profile, wrapping_key) ?
  let index_blob = updated_group_index_blob(database_path, wrapping_key, group_id) ?
  let baseline_label = group_baseline_label(group_id) ?
  let baseline_blob = group_baseline_blob(checkpoint, wrapping_key, group_id) ?
  store_new_group(database_path, label, blob, index_blob, baseline_label, baseline_blob) ?
  Ok(group_id)
end

fn add_mobile_group_member(request :: MobileGroupAddRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
  let baseline = load_group_baseline(request.database_path, wrapping_key, request.group_id) ?
  let baseline_hash = checkpoint_hash(canonical_transparency_checkpoint(baseline) ?) ?
  if !Bytes.secure_equals(baseline_hash, state.policy.checkpoint_hash) do
    consume_group_state(state)
    Err("group_state_invalid")
  else
    let view = load_transparency_view(request.database_path, wrapping_key) ?
    let devices = verified_device_set(request.device_set) ?
    let proof_checkpoint = verified_transparency_device_set(request.database_path,
    wrapping_key,
    devices,
    baseline) ?
    let member = verified_group_member(devices,
    request.key_package,
    proof_checkpoint,
    baseline,
    view) ?
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
    let device = open_device(profile, wrapping_key, request.database_path) ?
    case commit_add(state, device.signing_private_key, member) do
      GroupAddRejected( rejected, _) -> do
        consume_group_state(rejected)
        Err("group_add_rejected")
      end
      GroupMemberAdded( next, commit, welcome) -> do
        let commit_wire = case encode_group_commit(commit) do
          Err( _) -> Err("group_commit_encoding_failed")
          Ok( value) -> Ok(value)
        end ?
        let welcome_wire = case encode_group_welcome(welcome) do
          Err( _) -> Err("group_welcome_encoding_failed")
          Ok( value) -> Ok(value)
        end ?
        let welcome_packet = encode_group_welcome_packet(MobileGroupWelcomePacket {
          baseline_checkpoint : baseline,
          welcome : welcome_wire
        }) ?
        let targets = case delivery_targets(next.tree, next.local_leaf) do
          Err( _) -> Err("group_delivery_failed")
          Ok( value) -> Ok(value)
        end ?
        let now = current_time() ?
        let envelopes = group_add_envelopes(targets,
        welcome.recipient_leaf,
        encode_group_packet(2, commit_wire) ?,
        encode_group_packet(1, welcome_packet) ?,
        now,
        0,
        List.new()) ?
        let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        envelopes) ?
        let ( state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        store_group_outbound(request.database_path,
        state_label,
        state_blob,
        outbox_labels,
        outbox_blobs,
        outbox_index_blob) ?
        encode_output_list(envelopes)
      end
    end
  end
end

fn remove_mobile_group_member(request :: MobileGroupRemoveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
  let leaf_index = find_member_index(state.tree, request.account_id, request.device_id)
  if leaf_index < 0 do
    consume_group_state(state)
    Err("group_member_not_found")
  else
    let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
    let device = open_device(profile, wrapping_key, request.database_path) ?
    case commit_remove(state, device.signing_private_key, leaf_index) do
      GroupRemoveRejected( rejected, _) -> do
        consume_group_state(rejected)
        Err("group_remove_rejected")
      end
      GroupMemberRemoved( next, commit) -> do
        let commit_wire = case encode_group_commit(commit) do
          Err( _) -> Err("group_commit_encoding_failed")
          Ok( value) -> Ok(value)
        end ?
        let targets = case delivery_targets(next.tree, next.local_leaf) do
          Err( _) -> Err("group_delivery_failed")
          Ok( value) -> Ok(value)
        end ?
        let envelopes = group_target_envelopes(targets,
        encode_group_packet(2, commit_wire) ?,
        current_time() ?,
        0,
        List.new()) ?
        let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
        pending_ids,
        envelopes) ?
        let ( state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        store_group_outbound(request.database_path,
        state_label,
        state_blob,
        outbox_labels,
        outbox_blobs,
        outbox_index_blob) ?
        encode_output_list(envelopes)
      end
    end
  end
end

fn send_mobile_group_message(request :: MobileGroupSendRequest) -> Bytes ! String do
  if Bytes.length(request.body) > 65342 do
    Err("group_message_too_large")
  else
    ensure_schema(request.database_path) ?
    let profile = decode_client_profile(load_profile(request.database_path) ?) ?
    let wrapping_key = platform_key() ?
    let state = load_group(request.database_path, profile, wrapping_key, request.group_id) ?
    let targets = case delivery_targets(state.tree, state.local_leaf) do
      Err( _) -> Err("group_delivery_failed")
      Ok( value) -> Ok(value)
    end ?
    if List.length(targets) == 0 do
      consume_group_state(state)
      Err("group_has_no_recipients")
    else
      let pending_ids = load_outbox_ids(request.database_path, wrapping_key) ?
      let device = open_device(profile, wrapping_key, request.database_path) ?
      let sender = case member_at(state.tree, state.local_leaf) do
        Err( _) -> Err("group_message_rejected")
        Ok( value) -> Ok(value)
      end ?
      let epoch = state.epoch
      case encrypt_group_message(state,
      device.signing_private_key,
      request.body,
      Bytes.from_utf8("mesh-mobile-group/v1")) do
        GroupEncryptRejected( rejected, _) -> do
          consume_group_state(rejected)
          Err("group_message_rejected")
        end
        GroupMessageEncrypted( next, message) -> do
          let message_wire = case encode_group_message(message) do
            Err( _) -> Err("group_message_encoding_failed")
            Ok( value) -> Ok(value)
          end ?
          let now = current_time() ?
          let envelopes = group_target_envelopes(targets,
          encode_group_packet(3, message_wire) ?,
          now,
          0,
          List.new()) ?
          let ( outbox_labels, outbox_blobs, outbox_index_blob) = prepare_outbox_writes(wrapping_key,
          pending_ids,
          envelopes) ?
          let ( state_label, state_blob) = group_snapshot_blob(next, profile, wrapping_key) ?
          let history_label = group_history_label(request.group_id)
          let history_blob = updated_group_history_blob(request.database_path,
          wrapping_key,
          request.group_id,
          MobileGroupHistoryEntry {
            direction : 1,
            epoch : epoch,
            sender_account_id : sender.account_id,
            sender_device_id : sender.device_id,
            timestamp : now,
            body : request.body
          }) ?
          store_group_message_outbound(request.database_path,
          state_label,
          state_blob,
          history_label,
          history_blob,
          outbox_labels,
          outbox_blobs,
          outbox_index_blob) ?
          encode_output_list(envelopes)
        end
      end
    end
  end
end

fn welcome_member(value :: GroupWelcome) -> GroupMember ! String do
  case value.commit.proposal do
    AddMember( leaf_index, member) -> if leaf_index == value.recipient_leaf do
      Ok(member)
    else
      Err("invalid_group_welcome")
    end
    RemoveMember( _) -> Err("invalid_group_welcome")
  end
end

fn local_welcome_member(profile :: ClientProfile, member :: GroupMember, welcome :: GroupWelcome) -> Bool do
  Bytes.secure_equals(member.account_id, profile.account_id) && Bytes.secure_equals(member.device_id,
  profile.device_id) && Bytes.secure_equals(member.signing_public_key.bytes,
  profile.credential.signing_public_key) && Bytes.secure_equals(member.mailbox_token,
  profile.entry.mailbox_token) && Bytes.secure_equals(member.transparency_checkpoint_hash,
  welcome.policy.checkpoint_hash) && member.witness_count == 2 && welcome.policy.witness_threshold == 2
end

fn join_mobile_group(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
welcome :: GroupWelcome,
baseline_checkpoint :: Bytes) -> Bytes ! String do
  let group_id = welcome.commit.group_id
  let state_label = group_state_label(group_id) ?
  let member = welcome_member(welcome) ?
  let baseline = canonical_transparency_checkpoint(baseline_checkpoint) ?
  let baseline_hash = checkpoint_hash(baseline) ?
  let current_checkpoint = group_checkpoint(database_path, wrapping_key) ?
  let view = load_transparency_view(database_path, wrapping_key) ?
  if !Bytes.secure_equals(baseline_hash, welcome.policy.checkpoint_hash) || !local_welcome_member(profile,
  member,
  welcome) || !(transparency_checkpoint_precedes(baseline_checkpoint, current_checkpoint, view) ?) do
    Err("group_welcome_rejected")
  else
    case load_blob(database_path, state_label) do
      Ok( _) -> do
        let stored_baseline = load_group_baseline(database_path, wrapping_key, group_id) ?
        let existing = load_group(database_path, profile, wrapping_key, group_id) ?
        let existing_valid = Bytes.secure_equals(stored_baseline, baseline_checkpoint) && Bytes.secure_equals(existing.policy.checkpoint_hash,
        baseline_hash)
        consume_group_state(existing)
        if !existing_valid do
          Err("group_welcome_rejected")
        else
          store_updated_session(database_path,
          "groups/v1",
          updated_group_index_blob(database_path, wrapping_key, group_id) ?) ?
          Ok(group_id)
        end
      end
      Err( error) -> if error != "local_state_not_found" do
        Err(error)
      else
        let package_label = group_join_label("package")
        let init_label = group_join_label("init")
        let leaf_label = group_join_label("leaf")
        let stored_package = decode_group_key_package(open_local(load_blob(database_path,
        package_label) ?,
        wrapping_key,
        local_context(package_label) ?) ?) ?
        let package_signature_valid = case Crypto.verify(SigningPublicKey { bytes : profile.credential.signing_public_key },
        group_key_package_unsigned(stored_package) ?,
        stored_package.signature) do
          Err( _) -> false
          Ok( value) -> value
        end
        if !package_signature_valid || !Bytes.secure_equals(stored_package.account_id,
        profile.account_id) || !Bytes.secure_equals(stored_package.device_id, profile.device_id) || !Bytes.secure_equals(stored_package.init_public_key.bytes,
        member.init_public_key.bytes) || !Bytes.secure_equals(stored_package.leaf_public_key.bytes,
        member.leaf_public_key.bytes) || !(transparency_checkpoint_precedes(baseline_checkpoint,
        stored_package.checkpoint,
        view) ?) || !(transparency_checkpoint_precedes(stored_package.checkpoint,
        current_checkpoint,
        view) ?) do
          Err("group_welcome_rejected")
        else
          let init_private = open_x25519(load_blob(database_path, init_label) ?,
          wrapping_key,
          context(profile.account_id, profile.device_id, init_label, 17) ?) ?
          let leaf_private = open_x25519(load_blob(database_path, leaf_label) ?,
          wrapping_key,
          context(profile.account_id, profile.device_id, leaf_label, 17) ?) ?
          let state = case join_from_welcome(welcome, init_private, leaf_private) do
            Err( _) -> Err("group_welcome_rejected")
            Ok( value) -> Ok(value)
          end ?
          consume_group_private(init_private)
          let ( label, blob) = group_snapshot_blob(state, profile, wrapping_key) ?
          let index_blob = updated_group_index_blob(database_path, wrapping_key, group_id) ?
          let baseline_label = group_baseline_label(group_id) ?
          let baseline_blob = group_baseline_blob(baseline_checkpoint, wrapping_key, group_id) ?
          store_group_join(database_path,
          label,
          blob,
          index_blob,
          baseline_label,
          baseline_blob,
          package_label,
          init_label,
          leaf_label) ?
          Ok(group_id)
        end
      end
    end
  end
end

fn apply_mobile_group_commit(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
commit :: GroupCommit) -> Bytes ! String do
  let group_id = commit.group_id
  let state = load_group(database_path, profile, wrapping_key, group_id) ?
  let epoch_order = U64.compare(commit.prior_epoch, state.epoch)
  if epoch_order > 0 do
    consume_group_state(state)
    Err("group_future_epoch")
  else if epoch_order < 0 do
    consume_group_state(state)
    Err("group_stale_epoch")
  else
    case apply_commit(state, commit) do
      CommitRejected( rejected, error) -> do
        consume_group_state(rejected)
        case error do
          FutureEpoch -> Err("group_future_epoch")
          StaleEpoch -> Err("group_stale_epoch")
          _ -> Err("group_commit_rejected")
        end
      end
      CommitApplied( next) -> do
        let ( label, blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        store_updated_session(database_path, label, blob) ?
        Ok(group_id)
      end
    end
  end
end

fn open_mobile_group_message(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
message :: GroupMessage) -> Bytes ! String do
  let state = load_group(database_path, profile, wrapping_key, message.group_id) ?
  let epoch_order = U64.compare(message.epoch, state.epoch)
  if epoch_order > 0 do
    consume_group_state(state)
    Err("group_future_epoch")
  else if epoch_order < 0 do
    consume_group_state(state)
    Err("group_stale_epoch")
  else
    let sender = case member_at(state.tree, message.sender_leaf) do
      Err( _) -> Err("group_message_rejected")
      Ok( value) -> Ok(value)
    end ?
    case decrypt_group_message(state, message, Bytes.from_utf8("mesh-mobile-group/v1")) do
      MessageRejected( rejected, error) -> do
        consume_group_state(rejected)
        case error do
          FutureEpoch -> Err("group_future_epoch")
          StaleEpoch -> Err("group_stale_epoch")
          _ -> Err("group_message_rejected")
        end
      end
      MessageOpened( next, plaintext) -> do
        let ( label, blob) = group_snapshot_blob(next, profile, wrapping_key) ?
        let history_label = group_history_label(message.group_id)
        let history_blob = updated_group_history_blob(database_path,
        wrapping_key,
        message.group_id,
        MobileGroupHistoryEntry {
          direction : 2,
          epoch : message.epoch,
          sender_account_id : sender.account_id,
          sender_device_id : sender.device_id,
          timestamp : current_time() ?,
          body : plaintext
        }) ?
        store_group_state_history(database_path, label, blob, history_label, history_blob) ?
        Ok(plaintext)
      end
    end
  end
end

fn receive_mobile_group_result(request :: MobileReceiveRequest) -> Bytes ! String do
  ensure_schema(request.database_path) ?
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let outer = canonical_outer(request.outer) ?
  if outer.suite != 3 || !Bytes.secure_equals(outer.mailbox_token, profile.entry.mailbox_token) do
    Err("wrong_group_delivery")
  else
    let packet = decode_group_packet(outer.ciphertext) ?
    let wrapping_key = platform_key() ?
    if packet.kind == 1 do
      let welcome_packet = decode_group_welcome_packet(packet.payload) ?
      join_mobile_group(request.database_path,
      profile,
      wrapping_key,
      canonical_group_welcome(welcome_packet.welcome) ?,
      welcome_packet.baseline_checkpoint)
    else if packet.kind == 2 do
      apply_mobile_group_commit(request.database_path,
      profile,
      wrapping_key,
      canonical_group_commit(packet.payload) ?)
    else
      open_mobile_group_message(request.database_path,
      profile,
      wrapping_key,
      canonical_group_message(packet.payload) ?)
    end
  end
end

fn permanent_group_delivery_error(error :: String) -> Bool do
  error == "wrong_group_delivery" || error == "invalid_outer_envelope" || error == "noncanonical_outer_envelope" || error == "invalid_group_packet" || error == "invalid_group_welcome" || error == "group_welcome_rejected" || error == "invalid_group_commit" || error == "group_commit_rejected" || error == "group_stale_epoch" || error == "invalid_group_message" || error == "group_message_rejected" || error == "group_limit_reached"
end

fn receive_mobile_group_classified(request :: MobileReceiveRequest) -> MobileGroupReceiveOutcome do
  case receive_mobile_group_result(request) do
    Ok( output) -> GroupReceiveApplied(output)
    Err( error) -> if permanent_group_delivery_error(error) do
      GroupReceiveRejected(error)
    else
      GroupReceiveRetry(error)
    end
  end
end

fn receive_mobile_group(request :: MobileReceiveRequest) -> Bytes ! String do
  case receive_mobile_group_classified(request) do
    GroupReceiveApplied( output) -> Ok(output)
    GroupReceiveRetry( error) -> Err(error)
    GroupReceiveRejected( error) -> Err(error)
  end
end

fn permanent_direct_delivery_error(error :: String) -> Bool do
  error == "wrong_mailbox" || error == "invalid_outer_envelope" || error == "noncanonical_outer_envelope" || error == "invalid_initial_packet" || error == "invalid_initial_message" || error == "outer_suite_mismatch" || error == "invalid_initiator_account" || error == "invalid_initiator_credential" || error == "initial_receive_failed" || error == "invalid_initial_plaintext" || error == "invalid_peer_profile" || error == "invalid_inner_envelope" || error == "initial_identity_mismatch" || error == "invalid_sync_payload" || error == "sync_conversation_mismatch" || error == "invalid_ratchet_packet" || error == "invalid_ratchet_message" || error == "message_rejected" || error == "one_time_prekey_not_found" || error == "blocked_message"
end

fn receive_mobile_direct_classified(request :: MobileReceiveRequest) -> MobileDirectReceiveOutcome do
  let received = case canonical_outer(request.outer) do
    Err( error) -> Err(error)
    Ok( outer) -> if is_sealed_initial_packet(outer.ciphertext) do
      receive_initial_message(request)
    else
      receive_message(request)
    end
  end
  case received do
    Ok( output) -> DirectReceiveApplied(output)
    Err( error) -> if permanent_direct_delivery_error(error) do
      DirectReceiveRejected(error)
    else
      DirectReceiveRetry(error)
    end
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
        let request = MobileReceiveRequest {
          database_path : database_path,
          outer : delivered.envelope
        }
        let acknowledge = if outer.suite == 3 do
          case receive_mobile_group_classified(request) do
            GroupReceiveApplied( _) -> true
            GroupReceiveRetry( _) -> false
            GroupReceiveRejected( _) -> true
          end
        else
          case receive_mobile_direct_classified(request) do
            DirectReceiveApplied( _) -> true
            DirectReceiveRetry( _) -> false
            DirectReceiveRejected( _) -> true
          end
        end
        let next_ids = if acknowledge do
          List.append(envelope_ids, outer.envelope_id)
        else
          envelope_ids
        end
        process_deliveries(database_path, deliveries, index + 1, next_ids)
      end
    end
  end
end

fn process_delivery_batch(request :: MobileBatchRequest) -> Bytes ! String do
  let profile = decode_client_profile(load_profile(request.database_path) ?) ?
  let deliveries = case decode_delivery_batch(request.batch) do
    Err( _) -> Err("invalid_delivery_batch")
    Ok( values) -> Ok(values)
  end ?
  let envelope_ids = process_deliveries(request.database_path, deliveries, 0, List.new())
  if List.length(envelope_ids) == 0 do
    Ok(Bytes.empty())
  else
    case encode_mailbox_ack(MailboxAck {
      version : 1,
      mailbox_token : profile.entry.mailbox_token,
      envelope_ids : envelope_ids
    }) do
      Err( _) -> Err("mailbox_ack_encoding_failed")
      Ok( encoded) -> Ok(encoded)
    end
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

fn store_envelope(request :: MobileStoreRequest) -> Bytes ! String do
  let envelope = canonical_outer(request.envelope) ?
  if Bytes.length(envelope.ciphertext) < 16 do
    Err("ciphertext_too_short")
  else
    ensure_schema(request.database_path) ?
    let record_hash = Bytes.to_hex(Crypto.sha256(request.record_key))
    case Sqlite.open(request.database_path) do
      Err( _) -> Err("database_open_failed")
      Ok( database) -> case Sqlite.execute_values(database,
      "INSERT INTO encrypted_blobs (record_hash, ciphertext, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP) ON CONFLICT(record_hash) DO UPDATE SET ciphertext = excluded.ciphertext, updated_at = CURRENT_TIMESTAMP",
      [Text(record_hash), Binary(envelope.ciphertext)]) do
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

@ export("mesh_messenger_replenish_prekeys")pub fn replenish_prekeys_export(request :: Bytes) -> Bytes ! String do
  replenish_prekeys(parse_prekey_request(request) ?)
end

@ export("mesh_messenger_reconcile_prekeys")pub fn reconcile_prekeys_export(request :: Bytes) -> Bytes ! String do
  reconcile_prekeys(parse_prekey_reconcile_request(request) ?)
end

@ export("mesh_messenger_create_link_request")pub fn create_link_request_export(request :: Bytes) -> Bytes ! String do
  create_device_link_request(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_device_link_sas")pub fn device_link_sas_export(request :: Bytes) -> Bytes ! String do
  device_link_sas(request)
end

pub fn authorize_device_link_export(request :: Bytes) -> Bytes ! String do
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

pub fn start_conversation_export(request :: Bytes) -> Bytes ! String do
  start_conversation(parse_start_request(request) ?)
end

@ export("mesh_messenger_receive_initial")pub fn receive_initial_export(request :: Bytes) -> Bytes ! String do
  receive_initial_message(parse_receive_request(request) ?)
end

pub fn fanout_prekey_claims_export(request :: Bytes) -> Bytes ! String do
  fanout_prekey_claims(parse_fanout_targets_request(request) ?)
end

pub fn reserve_fanout_prekey_export(request :: Bytes) -> Bytes ! String do
  reserve_fanout_prekey(parse_fanout_prekey_reservation_request(request) ?)
end

@ export("mesh_messenger_prepare_fanout_prekeys")pub fn prepare_fanout_prekeys_export(request :: Bytes) -> Bytes ! String do
  prepare_fanout_prekeys(parse_fanout_prepare_request(request) ?)
end

@ export("mesh_messenger_send_fanout")pub fn send_fanout_export(request :: Bytes) -> Bytes ! String do
  send_fanout(parse_fanout_request(request) ?)
end

pub fn send_message_export(request :: Bytes) -> Bytes ! String do
  send_message(parse_start_request(request) ?)
end

@ export("mesh_messenger_group_key_package")pub fn group_key_package_export(request :: Bytes) -> Bytes ! String do
  let database_path = mobile_utf8(request, "invalid_database_path") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    create_group_key_package(database_path)
  end
end

@ export("mesh_messenger_group_create")pub fn group_create_export(request :: Bytes) -> Bytes ! String do
  let database_path = mobile_utf8(request, "invalid_database_path") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    create_mobile_group(database_path)
  end
end

@ export("mesh_messenger_group_add")pub fn group_add_export(request :: Bytes) -> Bytes ! String do
  add_mobile_group_member(parse_group_add_request(request) ?)
end

@ export("mesh_messenger_group_remove")pub fn group_remove_export(request :: Bytes) -> Bytes ! String do
  remove_mobile_group_member(parse_group_remove_request(request) ?)
end

@ export("mesh_messenger_group_send")pub fn group_send_export(request :: Bytes) -> Bytes ! String do
  send_mobile_group_message(parse_group_send_request(request) ?)
end

@ export("mesh_messenger_group_receive")pub fn group_receive_export(request :: Bytes) -> Bytes ! String do
  receive_mobile_group(parse_receive_request(request) ?)
end

@ export("mesh_messenger_group_list")pub fn group_list_export(request :: Bytes) -> Bytes ! String do
  list_mobile_groups(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_group_inspect")pub fn group_inspect_export(request :: Bytes) -> Bytes ! String do
  inspect_mobile_group(parse_group_reference_request(request) ?)
end

@ export("mesh_messenger_group_history")pub fn group_history_export(request :: Bytes) -> Bytes ! String do
  mobile_group_history(parse_group_reference_request(request) ?)
end

@ export("mesh_messenger_receive_message")pub fn receive_message_export(request :: Bytes) -> Bytes ! String do
  receive_message(parse_receive_request(request) ?)
end

@ export("mesh_messenger_update_conversation")pub fn update_conversation_export(request :: Bytes) -> Bytes ! String do
  update_conversation(parse_policy_request(request) ?)
end

@ export("mesh_messenger_push_intent")pub fn push_intent_export(request :: Bytes) -> Bytes ! String do
  push_intent(parse_push_intent_request(request) ?)
end

pub fn push_action_export(request :: Bytes) -> Bytes ! String do
  push_action(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_push_action_complete")pub fn push_action_complete_export(request :: Bytes) -> Bytes ! String do
  complete_push_action(parse_push_action_completion(request) ?)
end

@ export("mesh_messenger_push_status")pub fn push_status_export(request :: Bytes) -> Bytes ! String do
  push_status(mobile_utf8(request, "invalid_database_path") ?)
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

@ export("mesh_messenger_transparency_lookup")pub fn transparency_lookup_export(request :: Bytes) -> Bytes ! String do
  transparency_lookup(parse_payload_request(request) ?)
end

@ export("mesh_messenger_verify_transparency")pub fn verify_transparency_export(request :: Bytes) -> Bytes ! String do
  verify_transparency_response(parse_transparency_request(request) ?)
end

@ export("mesh_messenger_privacy_submission")pub fn privacy_submission_export(request :: Bytes) -> Bytes ! String do
  privacy_submission(request)
end

@ export("mesh_messenger_mailbox_fetch")pub fn mailbox_fetch_export(request :: Bytes) -> Bytes ! String do
  mailbox_fetch(mobile_utf8(request, "invalid_database_path") ?)
end

@ export("mesh_messenger_process_delivery_batch")pub fn process_delivery_batch_export(request :: Bytes) -> Bytes ! String do
  process_delivery_batch(parse_batch_request(request) ?)
end

@ export("mesh_messenger_outbox_list")pub fn outbox_list_export(request :: Bytes) -> Bytes ! String do
  let database_path = mobile_utf8(request, "invalid_database_path") ?
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    list_outbox(database_path)
  end
end

@ export("mesh_messenger_outbox_ack")pub fn outbox_ack_export(request :: Bytes) -> Bytes ! String do
  acknowledge_outbox(parse_payload_request(request) ?)
end

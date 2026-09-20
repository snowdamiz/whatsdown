from Groups.Mls import GroupError
from Identity.Device import (
  AccountKeys,
  DeviceKeys,
  VerificationPolicy,
  is_retryable_verification_crypto_error,
  issue_device_credential
)
from Mobile.Codec import (
  canonical_outer,
  current_time,
  encode_output_list,
  mobile_append,
  mobile_byte,
  mobile_join,
  mobile_utf8,
  mobile_vector,
  mobile_wide,
  mobile_write_u64,
  mobile_zeroes,
  outer_bytes,
  random_bytes
)
from Mobile.DeviceSet import device_set_label, verified_device_set
from Mobile.FanoutPrekeys import fanout_prekey_claim_label, fanout_prekey_reservation_label
from Mobile.Inbox import permanent_direct_delivery_error
from Mobile.Platform import expo_project_id, expo_registration_body, parse_expo_raw_token
from Mobile.Prekeys import load_prekey_pool
from Mobile.Profile import (
  directory_bytes,
  load_profile,
  open_account,
  open_device,
  open_post_quantum_prekey,
  policy
)
from Mobile.Push import complete_push_action_with_config
from Mobile.PushState import (
  commit_push_update,
  load_push_state,
  next_push_revision,
  prepare_push_bind_with_config,
  prepare_push_unbind,
  push_install_id,
  push_state_context,
  signed_push_unbind
)
from Mobile.Requests import (
  parse_payload_request,
  parse_push_action_completion,
  parse_push_bind_request
)
from Mobile.Sessions import (
  find_peer_session,
  initial_bytes,
  inner_bytes,
  load_session_ids,
  parse_ratchet_packet,
  ratchet_bytes,
  seal_session,
  updated_session_index,
  updated_session_record
)
from Mobile.Transparency import (
  encode_verified_transparency_set,
  load_transparency_view,
  transparency_checkpoint_in_view,
  transparency_device_set_label,
  transparency_view_chunk_label,
  transparency_view_storage
)
from Mobile.Types import (
  MobileExpoRawToken,
  MobileLoadedSession,
  MobileOneTimePrekey,
  MobilePayloadRequest,
  MobilePushActionCompletion,
  MobilePushState,
  MobileSessionRecord,
  MobileTransparencyStorage,
  MobileTransparencyView,
  MobileVerifiedDeviceSet,
  MobileVerifiedTransparencySet
)
from Prekeys.Bundle import (
  OneTimePrekeySecrets,
  PostQuantumPrekeySecrets,
  PrekeyError,
  SignedPrekeySecrets,
  build_prekey_bundle,
  generate_one_time_prekey,
  generate_signed_prekey,
  normalize_prekey_bundle
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.PrekeyWire import encode_prekey_bundle
from Protocol.V1 import (
  AccountIdentity,
  DeviceCredential,
  DeviceSet,
  DirectoryEntry,
  InitialMessage,
  InnerEnvelope,
  OuterEnvelope,
  PrekeyBundle
)
from Session.Handshake import (
  RatchetState,
  SessionError,
  initiate,
  is_retryable_session_crypto_error,
  is_retryable_session_error,
  receive_initial
)
from Session.Ratchet import (
  RatchetError,
  RatchetMessage,
  decode_ratchet_message,
  encode_ratchet_message,
  encrypt,
  is_retryable_ratchet_error,
  ratchet_open_error,
  skipped_key_error
)
from Session.Snapshot import SnapshotOutcome, snapshot
from Storage.Blobs import ensure_schema, insert_blob, load_blob
from Storage.Keys import (
  context,
  local_context,
  one_time_prekey_context,
  one_time_prekey_label,
  open_x25519,
  platform_key,
  seal_local,
  seal_x25519
)
from Storage.Records import (
  delete_blob,
  delete_blobs,
  store_new_session,
  store_updated_blobs,
  store_updated_session
)
from Transparency.Merkle import TransparencyCheckpoint
from Transparency.Wire import decode_checkpoint
from Transport.Packet import (
  ClientProfile,
  TransportPacket,
  decode_client_profile,
  decode_packet,
  encode_client_profile,
  encode_packet,
  session_aad
)
from Transport.Recipient import seal_recipient_packet
from Mobile.Transport import MobileOpenedPacket, open_outer_packet
from Protocol.HandshakeWire import decode_initial_message

pub fn remove_safety_binding_for_test(database_path :: String, peer_profile :: Bytes) -> Bool ! String do
  let peer = decode_client_profile(peer_profile) ?
  let wrapping_key = platform_key() ?
  let loaded = find_peer_session(database_path,
  wrapping_key,
  peer.account_id,
  load_session_ids(database_path, wrapping_key) ?,
  0) ?
  let record = updated_session_record(loaded.record.snapshot, % { loaded.record | verified : true }) ?
  let legacy = Bytes.slice(record, 0, Bytes.length(record) - 68) ?
  let blob = seal_local(legacy, wrapping_key, local_context(loaded.label) ?) ?
  store_updated_session(database_path, loaded.label, blob) ?
  Ok(true)
end

fn store_legacy_prekey_fixture(database_path :: String,
prekey_label :: String,
legacy_blob :: Bytes) -> Result <(), String > do
  case Sqlite.open(database_path) do
    Err( _) -> Err("database_open_failed")
    Ok( database) -> do
      let result = case Sqlite.begin(database) do
        Err( _) -> Err("database_write_failed")
        Ok( _) -> case insert_blob(database, "one-time-prekey/v1", legacy_blob) do
          Err( error) -> Err(error)
          Ok( _) -> case delete_blobs(database,
          [prekey_label, "one-time-prekeys/v1", "one-time-prekey-active/v1", "one-time-prekey-next-id/v1"],
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

pub fn install_group_checkpoint_for_test(database_path :: String, encoded :: Bytes) -> Bool ! String do
  let _ = decode_checkpoint(encoded) ?
  ensure_schema(database_path) ?
  let wrapping_key = platform_key() ?
  let checkpoint_label = "transparency-checkpoint/v1"
  let checkpoint_blob = seal_local(encoded, wrapping_key, local_context(checkpoint_label) ?) ?
  store_updated_blobs(database_path, [checkpoint_label], [checkpoint_blob]) ?
  Ok(true)
end

pub fn install_group_transparency_for_test(database_path :: String,
encoded_checkpoint :: Bytes,
encoded_consistency :: Bytes,
service_public_key :: Bytes,
witness_a_public_key :: Bytes,
witness_b_public_key :: Bytes,
encoded_device_set :: Bytes) -> Bool ! String do
  let devices = verified_device_set(encoded_device_set) ?
  let view = MobileTransparencyView {
    checkpoint : encoded_checkpoint,
    consistency : encoded_consistency,
    service_public_key : service_public_key,
    witness_a_public_key : witness_a_public_key,
    witness_b_public_key : witness_b_public_key
  }
  if !(transparency_checkpoint_in_view(encoded_checkpoint, view) ?) do
    Err("invalid_transparency_view")
  else
    ensure_schema(database_path) ?
    let wrapping_key = platform_key() ?
    let checkpoint_label = "transparency-checkpoint/v1"
    let device_set_label = transparency_device_set_label(devices.account.account_id)
    let checkpoint_blob = seal_local(encoded_checkpoint,
    wrapping_key,
    local_context(checkpoint_label) ?) ?
    let view_storage = transparency_view_storage(view, wrapping_key) ?
    let device_set_blob = seal_local(encode_verified_transparency_set(MobileVerifiedTransparencySet {
      checkpoint : encoded_checkpoint,
      device_set : devices.wire
    }) ?,
    wrapping_key,
    local_context(device_set_label) ?) ?
    store_updated_blobs(database_path,
    List.append(List.append(view_storage.labels, checkpoint_label), device_set_label),
    List.append(List.append(view_storage.blobs, checkpoint_blob), device_set_blob)) ?
    Ok(true)
  end
end

pub fn replace_group_transparency_chunk_for_test(database_path :: String,
index :: Int,
value :: Bytes) -> Bool ! String do
  if index < 0 || index >= 3 || Bytes.length(value) > 65536 do
    Err("invalid_transparency_chunk")
  else
    let wrapping_key = platform_key() ?
    let label = transparency_view_chunk_label(index)
    let blob = seal_local(value, wrapping_key, local_context(label) ?) ?
    store_updated_blobs(database_path, [label], [blob]) ?
    Ok(true)
  end
end

pub fn remove_group_transparency_chunk_for_test(database_path :: String, index :: Int) -> Bool ! String do
  if index < 0 || index >= 3 do
    Err("invalid_transparency_chunk")
  else
    case Sqlite.open(database_path) do
      Err( _) -> Err("database_open_failed")
      Ok( database) -> do
        let label = transparency_view_chunk_label(index)
        let result = delete_blob(database, label)
        Sqlite.close(database)
        result ?
        Ok(true)
      end
    end
  end
end

pub fn group_transparency_valid_for_test(database_path :: String) -> Bool ! String do
  let _ = load_transparency_view(database_path, platform_key() ?) ?
  Ok(true)
end

pub fn prepare_legacy_prekey_fixture_path(database_path :: String) -> Result <(), String > do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let id = profile.bundle.one_time_prekey_id
  let label = one_time_prekey_label(id)
  let current_context = one_time_prekey_context(profile, id) ?
  let legacy_context = context(profile.account_id, profile.device_id, "one-time-prekey/v1", 10) ?
  let entries = load_prekey_pool(profile, wrapping_key, database_path) ?
  if List.length(entries) != 1 do
    Err("invalid_legacy_prekey_fixture")
  else
    let private_key = open_x25519(load_blob(database_path, label) ?, wrapping_key, current_context) ?
    let legacy_blob = seal_x25519(private_key, wrapping_key, legacy_context) ?
    store_legacy_prekey_fixture(database_path, label, legacy_blob)
  end
end

pub fn migrated_prekey_matches_profile_path(database_path :: String) -> Bool ! String do
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let id = profile.bundle.one_time_prekey_id
  let private_key = open_x25519(load_blob(database_path, one_time_prekey_label(id)) ?,
  platform_key() ?,
  one_time_prekey_context(profile, id) ?) ?
  case Crypto.x25519_public(private_key) do
    Err( _) -> Err("invalid_migrated_prekey")
    Ok( public_key) -> Ok(Bytes.secure_equals(public_key.bytes, profile.bundle.one_time_prekey))
  end
end

# Delivery cannot read or alter a sealed packet, so these fixtures act as the
# only parties who can: they open an envelope with the recipient's own device
# key, and reseal whatever they change.

fn test_opened_packet(recipient_path :: String, outer :: OuterEnvelope) -> MobileOpenedPacket ! String do
  let profile = decode_client_profile(load_profile(recipient_path) ?) ?
  let device = open_device(profile, platform_key() ?, recipient_path) ?
  open_outer_packet(outer, device.identity_private_key)
end

## The protocol suite inside a sealed envelope: visible to its recipient only.

pub fn test_inner_suite(recipient_path :: String, input :: Bytes) -> Int ! String do
  let opened = test_opened_packet(recipient_path, canonical_outer(input) ?) ?
  case decode_packet(opened.packet) do
    Err( _) -> Err("invalid_test_packet")
    Ok( InitialPacket( _, message)) -> case decode_initial_message(message) do
      Err( _) -> Err("invalid_initial_message")
      Ok( initial) -> Ok(initial.suite)
    end
    Ok( RatchetPacket( message)) -> case decode_ratchet_message(message) do
      Err( _) -> Err("invalid_ratchet_message")
      Ok( ratchet) -> Ok(ratchet.suite)
    end
  end
end

fn test_ratchet_outer(recipient_path :: String, input :: Bytes) -> Result <( OuterEnvelope, RatchetMessage), String > do
  let outer = canonical_outer(input) ?
  let opened = test_opened_packet(recipient_path, outer) ?
  let packet_message = parse_ratchet_packet(opened.packet) ?
  case decode_ratchet_message(packet_message) do
    Err( _) -> Err("invalid_ratchet_message")
    Ok( message) -> Ok((outer, message))
  end
end

fn test_encode_ratchet_outer(recipient_path :: String,
outer :: OuterEnvelope,
message :: RatchetMessage) -> Bytes ! String do
  let encoded_message = case encode_ratchet_message(message) do
    Err( _) -> Err("ratchet_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end ?
  let recipient = decode_client_profile(load_profile(recipient_path) ?) ?
  let sealed = seal_recipient_packet(encode_packet(RatchetPacket(encoded_message)) ?,
  X25519PublicKey { bytes : recipient.credential.dh_public_key }) ?
  case encode_outer_envelope(% { outer | ciphertext : sealed }) do
    Err( _) -> Err("outer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

pub fn test_ratchet_jump_envelope(recipient_path :: String, input :: Bytes) -> Bytes ! String do
  let ( outer, message) = test_ratchet_outer(recipient_path, input) ?
  test_encode_ratchet_outer(recipient_path, outer, % { message | message_number : 65 })
end

pub fn test_ratchet_tamper_envelope(recipient_path :: String, input :: Bytes) -> Bytes ! String do
  let ( outer, message) = test_ratchet_outer(recipient_path, input) ?
  let length = Bytes.length(message.ciphertext)
  let last = case Bytes.get(message.ciphertext, length - 1) do
    Err( _) -> Err("invalid_ratchet_message")
    Ok( value) -> Ok(value)
  end ?
  let replacement = if last == 0 do
    1
  else
    0
  end
  let ciphertext = mobile_append(Bytes.slice(message.ciphertext, 0, length - 1) ?,
  mobile_byte(replacement) ?) ?
  test_encode_ratchet_outer(recipient_path, outer, % { message | ciphertext : ciphertext })
end

## What a delivery service or network attacker can do: flip a byte of the sealed
## envelope without any key.

pub fn test_sealed_tamper_envelope(input :: Bytes) -> Bytes ! String do
  let outer = canonical_outer(input) ?
  let length = Bytes.length(outer.ciphertext)
  let last = case Bytes.get(outer.ciphertext, length - 1) do
    Err( _) -> Err("invalid_outer_envelope")
    Ok( value) -> Ok(value)
  end ?
  let replacement = if last == 0 do
    1
  else
    0
  end
  let ciphertext = mobile_append(Bytes.slice(outer.ciphertext, 0, length - 1) ?,
  mobile_byte(replacement) ?) ?
  case encode_outer_envelope(% { outer | ciphertext : ciphertext }) do
    Err( _) -> Err("outer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

pub fn direct_delivery_classification_for_test() -> Bool do
  let verification = is_retryable_verification_crypto_error(InternalFailure) && !is_retryable_verification_crypto_error(InvalidPublicKey)
  let session = is_retryable_session_crypto_error(InternalFailure) && !is_retryable_session_crypto_error(InvalidPublicKey) && is_retryable_session_error(PrekeyFailure(InvalidBundle))
  let ratchet = is_retryable_ratchet_error(CryptoFailure) && is_retryable_ratchet_error(ExcessiveJump) && !is_retryable_ratchet_error(AuthenticationRejected) && !is_retryable_ratchet_error(Replay) && !is_retryable_ratchet_error(InvalidMessage)
  let skipped = !is_retryable_ratchet_error(skipped_key_error(InvalidKey)) && is_retryable_ratchet_error(skipped_key_error(InternalFailure))
  let opened = !is_retryable_ratchet_error(ratchet_open_error(AuthenticationFailed)) && is_retryable_ratchet_error(ratchet_open_error(InternalFailure))
  verification && session && ratchet && skipped && opened && !permanent_direct_delivery_error("initial_crypto_failed") && !permanent_direct_delivery_error("ratchet_retryable")
end

pub fn push_install_id_for_test(database_path :: String) -> Bytes ! String do
  push_install_id(database_path, platform_key() ?)
end

pub fn expo_registration_body_for_test(raw_material :: Bytes,
device_id :: Bytes,
project_id :: Bytes) -> String ! String do
  expo_registration_body(parse_expo_raw_token(raw_material) ?,
  device_id,
  expo_project_id(project_id) ?)
end

pub fn push_bind_prepare_with_test_config(input :: Bytes,
broker_public_key :: Bytes,
endpoint :: String) -> Bytes ! String do
  let request = parse_push_bind_request(input) ?
  let configured_key = if Bytes.length(broker_public_key) != 32 do
    Err("invalid push broker key")
  else
    Ok(X25519PublicKey { bytes : broker_public_key })
  end
  prepare_push_bind_with_config(request, configured_key, endpoint)
end

pub fn push_unbind_prepare_export(request :: Bytes) -> Bytes ! String do
  prepare_push_unbind(mobile_utf8(request, "invalid_database_path") ?)
end

pub fn push_update_commit_export(request :: Bytes) -> Bytes ! String do
  commit_push_update(parse_payload_request(request) ?)
end

pub fn push_action_complete_with_test_config(input :: Bytes, endpoint :: String) -> Bytes ! String do
  complete_push_action_with_config(parse_push_action_completion(input) ?, endpoint)
end

fn store_legacy_push_state_for_test(database_path :: String,
profile :: ClientProfile,
wrapping_key :: borrow StorageKey,
state :: MobilePushState) -> Bool ! String do
  let encoded = mobile_join([mobile_byte(1) ?, Bytes.from_utf8("PBL"), mobile_write_u64(state.revision) ?, mobile_byte(state.mode) ?, state.wake_token_hash, state.provider_token_hash, mobile_byte(state.pending_kind) ?, mobile_vector(state.pending_wire) ?],
  0,
  Bytes.empty()) ?
  let sealed = seal_local(encoded, wrapping_key, push_state_context(profile) ?) ?
  store_updated_session(database_path, "push-binding/v1", sealed) ?
  Ok(true)
end

pub fn install_legacy_disabled_push_state_for_test(database_path :: String) -> Bool ! String do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(database_path, profile, wrapping_key) ?
  store_legacy_push_state_for_test(database_path,
  profile,
  wrapping_key,
  % { state | mode : 0, wake_token_hash : mobile_zeroes(32) ?, provider_token_hash : mobile_zeroes(32) ?, pending_kind : 0, pending_wire : Bytes.empty() })
end

pub fn install_legacy_enabled_push_state_for_test(database_path :: String) -> Bool ! String do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(database_path, profile, wrapping_key) ?
  if state.mode != 1 || state.pending_kind != 0 do
    Err("push state is not stably enabled")
  else
    store_legacy_push_state_for_test(database_path, profile, wrapping_key, state)
  end
end

pub fn install_legacy_pending_unbind_push_state_for_test(database_path :: String) -> Bool ! String do
  ensure_schema(database_path) ?
  let profile = decode_client_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(database_path, profile, wrapping_key) ?
  let revision = next_push_revision(state.revision) ?
  let wire = signed_push_unbind(database_path, profile, wrapping_key, revision) ?
  store_legacy_push_state_for_test(database_path,
  profile,
  wrapping_key,
  % { state | revision : revision, mode : 0, wake_token_hash : mobile_zeroes(32) ?, provider_token_hash : mobile_zeroes(32) ?, pending_kind : 2, pending_wire : wire })
end

pub fn install_classical_session_for_test(initiator_path :: String, responder_path :: String) -> Bytes ! String do
  let wrapping_key = platform_key() ?
  let initiator = decode_client_profile(load_profile(initiator_path) ?) ?
  let responder = decode_client_profile(load_profile(responder_path) ?) ?
  let initiator_device = open_device(initiator, wrapping_key, initiator_path) ?
  let responder_account = open_account(responder, wrapping_key, responder_path) ?
  let responder_device = open_device(responder, wrapping_key, responder_path) ?
  let now = current_time() ?
  let expires_at = U64.add(now, mobile_wide("31536000000") ?) ?
  let credential = case issue_device_credential(responder_account,
  responder_device,
  mobile_wide("1") ?,
  now,
  expires_at,
  responder.account.directory_sequence) do
    Err( _) -> Err("classical_credential_failed")
    Ok( value) -> Ok(value)
  end ?
  let signed = case generate_signed_prekey(responder_device,
  credential,
  mobile_wide("9001") ?,
  expires_at) do
    Err( _) -> Err("classical_prekey_failed")
    Ok( value) -> Ok(value)
  end ?
  let one_time = case generate_one_time_prekey(mobile_wide("9002") ?) do
    Err( _) -> Err("classical_prekey_failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle = case build_prekey_bundle(credential, signed, one_time) do
    Err( _) -> Err("classical_bundle_failed")
    Ok( value) -> Ok(value)
  end ?
  let bundle_wire = case encode_prekey_bundle(bundle) do
    Err( _) -> Err("classical_bundle_failed")
    Ok( value) -> Ok(value)
  end ?
  let classical_profile = encode_client_profile(% { responder.entry | prekey_bundle : bundle_wire },
  responder.account_id,
  responder.device_id) ?
  let classical_responder = decode_client_profile(classical_profile) ?
  let ( initiator_state, initial) = case initiate(initiator_device,
  initiator.credential,
  responder.account,
  bundle,
  policy(classical_responder, now),
  0,
  Bytes.from_utf8("classical session fixture")) do
    Err( _) -> Err("classical_session_start_failed")
    Ok( value) -> Ok(value)
  end ?
  let post_quantum = open_post_quantum_prekey(responder, wrapping_key, responder_path) ?
  let ( responder_state, opened) = case receive_initial(responder_device,
  responder.account,
  bundle,
  signed,
  one_time,
  post_quantum,
  initiator.account,
  policy(classical_responder, now),
  policy(initiator, now),
  0,
  initial_bytes(initial) ?) do
    Err( _) -> Err("classical_session_receive_failed")
    Ok( value) -> Ok(value)
  end ?
  if !Bytes.secure_equals(opened, Bytes.from_utf8("classical session fixture")) || initiator_state.suite != 1 || responder_state.suite != 1 || !Bytes.secure_equals(initiator_state.session_id,
  responder_state.session_id) do
    Err("classical_session_mismatch")
  else
    let conversation_id = random_bytes(16) ?
    let delayed = InnerEnvelope {
      version : 1,
      sender_account_id : responder.account_id,
      sender_device_id : responder.device_id,
      recipient_device_id : initiator.device_id,
      conversation_id : conversation_id,
      client_message_id : random_bytes(16) ?,
      client_timestamp : now,
      message_type : 1,
      body : Bytes.from_utf8("delayed suite-1"),
      reply_reference : Bytes.empty(),
      attachment_manifest : Bytes.empty(),
      receipt_policy : 0,
      disappearing_seconds : 0,
      extensions : List.new()
    }
    let session_id = responder_state.session_id
    let ( next_responder_state, message) = case encrypt(responder_state,
    inner_bytes(delayed) ?,
    session_aad(session_id) ?) do
      Err( _) -> Err("classical_ratchet_failed")
      Ok( value) -> Ok(value)
    end ?
    let envelope = outer_bytes(initiator.entry.mailbox_token,
    message.suite,
    encode_packet(RatchetPacket(ratchet_bytes(message) ?)) ?,
    now) ?
    let ( initiator_session_id, initiator_label, initiator_blob) = seal_session(initiator_state,
    wrapping_key,
    initiator,
    classical_responder,
    conversation_id,
    1,
    false) ?
    let ( responder_session_id, responder_label, responder_blob) = seal_session(next_responder_state,
    wrapping_key,
    responder,
    initiator,
    conversation_id,
    0,
    false) ?
    store_new_session(initiator_path,
    initiator_label,
    initiator_blob,
    updated_session_index(initiator_path, wrapping_key, initiator_session_id) ?) ?
    store_new_session(responder_path,
    responder_label,
    responder_blob,
    updated_session_index(responder_path, wrapping_key, responder_session_id) ?) ?
    let base = case normalize_prekey_bundle(classical_responder.bundle) do
      Err( _) -> Err("classical_bundle_failed")
      Ok( value) -> Ok(value)
    end ?
    let base_wire = case encode_prekey_bundle(base) do
      Err( _) -> Err("classical_bundle_failed")
      Ok( value) -> Ok(value)
    end ?
    encode_output_list([envelope, directory_bytes(% { classical_responder.entry | prekey_bundle : base_wire }) ?, classical_profile])
  end
end

pub fn has_fanout_prekey_state_for_test(database_path :: String, profile_wire :: Bytes) -> Bool ! String do
  let profile = decode_client_profile(profile_wire) ?
  let reservation = case load_blob(database_path, fanout_prekey_reservation_label(profile)) do
    Ok( _) -> true
    Err( error) -> if error == "local_state_not_found" do
      false
    else
      return Err(error)
    end
  end
  let claim = case load_blob(database_path, fanout_prekey_claim_label(profile)) do
    Ok( _) -> true
    Err( error) -> if error == "local_state_not_found" do
      false
    else
      return Err(error)
    end
  end
  Ok(reservation || claim)
end

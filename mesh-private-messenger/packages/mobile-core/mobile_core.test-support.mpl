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
  let profile = parse_profile(load_profile(database_path) ?) ?
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
  let profile = parse_profile(load_profile(database_path) ?) ?
  let id = profile.bundle.one_time_prekey_id
  let private_key = open_x25519(load_blob(database_path, one_time_prekey_label(id)) ?,
  platform_key() ?,
  one_time_prekey_context(profile, id) ?) ?
  case Crypto.x25519_public(private_key) do
    Err( _) -> Err("invalid_migrated_prekey")
    Ok( public_key) -> Ok(Bytes.secure_equals(public_key.bytes, profile.bundle.one_time_prekey))
  end
end

fn test_ratchet_outer(input :: Bytes) -> Result <( OuterEnvelope, RatchetMessage), String > do
  let outer = canonical_outer(input) ?
  let packet = parse_ratchet_packet(outer.ciphertext) ?
  case decode_ratchet_message(packet.message) do
    Err( _) -> Err("invalid_ratchet_message")
    Ok( message) -> Ok((outer, message))
  end
end

fn test_encode_ratchet_outer(outer :: OuterEnvelope, message :: RatchetMessage) -> Bytes ! String do
  let encoded_message = case encode_ratchet_message(message) do
    Err( _) -> Err("ratchet_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end ?
  case encode_outer_envelope(% { outer | ciphertext : encode_ratchet_packet(encoded_message) ? }) do
    Err( _) -> Err("outer_encoding_failed")
    Ok( encoded) -> Ok(encoded)
  end
end

pub fn test_ratchet_jump_envelope(input :: Bytes) -> Bytes ! String do
  let ( outer, message) = test_ratchet_outer(input) ?
  test_encode_ratchet_outer(outer, % { message | message_number : 65 })
end

pub fn test_ratchet_tamper_envelope(input :: Bytes) -> Bytes ! String do
  let ( outer, message) = test_ratchet_outer(input) ?
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
  test_encode_ratchet_outer(outer, % { message | ciphertext : ciphertext })
end

pub fn direct_delivery_classification_for_test() -> Bool do
  let verification = is_retryable_verification_crypto_error(InternalFailure) && !is_retryable_verification_crypto_error(InvalidPublicKey)
  let session = is_retryable_session_crypto_error(InternalFailure) && !is_retryable_session_crypto_error(InvalidPublicKey) && is_retryable_session_error(PrekeyFailure(InvalidBundle))
  let ratchet = is_retryable_ratchet_error(CryptoFailure) && is_retryable_ratchet_error(ExcessiveJump) && !is_retryable_ratchet_error(AuthenticationRejected) && !is_retryable_ratchet_error(Replay) && !is_retryable_ratchet_error(InvalidMessage)
  let skipped = !is_retryable_ratchet_error(skipped_key_error(InvalidKey)) && is_retryable_ratchet_error(skipped_key_error(InternalFailure))
  let opened = !is_retryable_ratchet_error(ratchet_open_error(AuthenticationFailed)) && is_retryable_ratchet_error(ratchet_open_error(InternalFailure))
  verification && session && ratchet && skipped && opened && !permanent_direct_delivery_error("initial_crypto_failed") && !permanent_direct_delivery_error("ratchet_retryable")
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
profile :: MobileProfile,
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
  let profile = parse_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(database_path, profile, wrapping_key) ?
  store_legacy_push_state_for_test(database_path,
  profile,
  wrapping_key,
  % { state | mode : 0, wake_token_hash : mobile_zeroes(32) ?, provider_token_hash : mobile_zeroes(32) ?, pending_kind : 0, pending_wire : Bytes.empty() })
end

pub fn install_legacy_enabled_push_state_for_test(database_path :: String) -> Bool ! String do
  ensure_schema(database_path) ?
  let profile = parse_profile(load_profile(database_path) ?) ?
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
  let profile = parse_profile(load_profile(database_path) ?) ?
  let wrapping_key = platform_key() ?
  let state = load_push_state(database_path, profile, wrapping_key) ?
  let revision = next_push_revision(state.revision) ?
  let wire = signed_push_unbind(database_path, profile, wrapping_key, revision) ?
  store_legacy_push_state_for_test(database_path,
  profile,
  wrapping_key,
  % { state | revision : revision, mode : 0, wake_token_hash : mobile_zeroes(32) ?, provider_token_hash : mobile_zeroes(32) ?, pending_kind : 2, pending_wire : wire })
end

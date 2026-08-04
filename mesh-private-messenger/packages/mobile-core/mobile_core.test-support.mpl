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

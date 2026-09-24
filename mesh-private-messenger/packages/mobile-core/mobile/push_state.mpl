from Binary.Reader import BinaryReader, finish, reader
from Identity.Device import DeviceKeys
from Mobile.Codec import (
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u64,
  mobile_vector,
  mobile_wide,
  mobile_write_u64,
  mobile_zeroes,
  random_bytes,
  take_fixed,
  take_vector
)
from Mobile.Platform import expo_project_id, parse_expo_raw_token, register_expo_token
from Mobile.Profile import load_profile, open_device
from Mobile.Types import MobileExpoRawToken, MobilePayloadRequest, MobilePushState, MobileReadBytes
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, PrekeyBundle
from Push.Binding import (
  PushBindRequest,
  PushUnbindRequest,
  decode_push_bind,
  decode_push_unbind,
  encode_push_bind,
  encode_push_unbind,
  push_bind_signing_bytes,
  push_unbind_signing_bytes
)
from Push.Token import seal_provider_token
from Storage.Blobs import ensure_schema, load_blob
from Storage.Keys import context, local_context, open_local, platform_key, seal_local
from Storage.Records import store_updated_session
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.PushState implementation.

pub fn push_state_context(profile :: ClientProfile) -> Bytes!String do
  context(profile.account_id, profile.device_id, "push-binding/v1", 14)
end

fn push_signature_valid(public_key :: Bytes, signed :: Bytes, signature :: Bytes) -> Bool do
  case Crypto.verify(SigningPublicKey { bytes: public_key }, signed, Signature { bytes: signature }) do
    Err(_) -> false
    Ok(valid) -> valid
  end
end

fn stored_bind_valid(state :: MobilePushState, profile :: ClientProfile) -> Bool do
  case decode_push_bind(state.pending_wire) do
    Err(_) -> false
    Ok(value) -> case encode_push_bind(value) do
      Err(_) -> false
      Ok(canonical) -> case push_bind_signing_bytes(value) do
        Err(_) -> false
        Ok(signed) -> Bytes.secure_equals(canonical, state.pending_wire) && Bytes.secure_equals(value.mailbox_token_hash,
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
    Err(_) -> false
    Ok(value) -> case encode_push_unbind(value) do
      Err(_) -> false
      Ok(canonical) -> case push_unbind_signing_bytes(value) do
        Err(_) -> false
        Ok(signed) -> Bytes.secure_equals(canonical, state.pending_wire) && Bytes.secure_equals(value.mailbox_token_hash,
          Crypto.sha256(profile.entry.mailbox_token)) && U64.compare(value.revision, state.revision) == 0 && push_signature_valid(profile.credential.signing_public_key,
          signed,
          value.signature)
      end
    end
  end
end

fn stored_push_project_valid(project_id :: Bytes) -> Bool do
  case expo_project_id(project_id) do
    Err(_) -> false
    Ok(_) -> true
  end
end

fn stored_push_config_valid(project_id :: Bytes, broker_public_key :: Bytes) -> Bool do
  stored_push_project_valid(project_id) && Bytes.length(broker_public_key) == 32
end

fn push_state_valid(state :: MobilePushState, profile :: ClientProfile) -> Bool!String do
  let zero = mobile_zeroes(32)?
  let revision_zero = U64.compare(state.revision, mobile_wide("0")?) == 0
  let revision_valid = U64.compare(state.revision, mobile_wide("9223372036854775807")?) <= 0
  let action_epoch_valid = U64.compare(state.action_epoch, mobile_wide("9223372036854775807")?) <= 0
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
    mobile_wide("0")?) > 0
  Ok(revision_valid && action_epoch_valid && pending_shape && mode_shape && config_shape && action_shape && action_epoch_shape && (state.target_mode == 0 || state.target_mode == 1) && (!revision_zero || (state.mode == 0 && state.pending_kind == 0)))
end

fn pristine_push_state() -> MobilePushState!String do
  Ok(MobilePushState {
    revision: mobile_wide("0")?,
    mode: 0,
    wake_token_hash: mobile_zeroes(32)?,
    provider_token_hash: mobile_zeroes(32)?,
    pending_kind: 0,
    pending_wire: Bytes.empty(),
    action_epoch: mobile_wide("0")?,
    action_kind: 0,
    target_mode: 0,
    project_id: Bytes.empty(),
    broker_public_key: Bytes.empty()
  })
end

fn push_state_bytes(state :: MobilePushState, profile :: ClientProfile) -> Bytes!String do
  if !(push_state_valid(state, profile)?) do
    Err("push_state_corrupt")
  else
    mobile_join([
        mobile_byte(2)?,
        Bytes.from_utf8("PBL"),
        mobile_write_u64(state.revision)?,
        mobile_byte(state.mode)?,
        state.wake_token_hash,
        state.provider_token_hash,
        mobile_byte(state.pending_kind)?,
        mobile_vector(state.pending_wire)?,
        mobile_write_u64(state.action_epoch)?,
        mobile_byte(state.action_kind)?,
        mobile_byte(state.target_mode)?,
        mobile_vector(state.project_id)?,
        mobile_vector(state.broker_public_key)?
      ],
      0,
      Bytes.empty())
  end
end

fn parse_push_state(input :: Bytes, profile :: ClientProfile) -> MobilePushState!String do
  case reader(input, 893) do
    Err(_) -> Err("push_state_corrupt")
    Ok(reader_state) -> do
      let version = take_fixed(reader_state, 1)?
      let magic = take_fixed(version.state, 3)?
      let revision = take_fixed(magic.state, 8)?
      let mode = take_fixed(revision.state, 1)?
      let wake_hash = take_fixed(mode.state, 32)?
      let provider_hash = take_fixed(wake_hash.state, 32)?
      let pending_kind = take_fixed(provider_hash.state, 1)?
      let pending_wire = take_vector(pending_kind.state, 725)?
      let version_value = mobile_read_byte(version.value)?
      let mode_value = mobile_read_byte(mode.value)?
      let pending_value = mobile_read_byte(pending_kind.value)?
      if !Bytes.secure_equals(magic.value, Bytes.from_utf8("PBL")) do
        Err("push_state_corrupt")
      else if version_value == 1 do
        case finish(pending_wire.state) do
          Err(_) -> Err("push_state_corrupt")
          Ok(_) -> do
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
              revision: mobile_read_u64(revision.value)?,
              mode: mode_value,
              wake_token_hash: wake_hash.value,
              provider_token_hash: provider_hash.value,
              pending_kind: pending_value,
              pending_wire: pending_wire.value,
              action_epoch: if action_kind == 0 do
                mobile_wide("0")?
              else
                mobile_wide("1")?
              end,
              action_kind: action_kind,
              target_mode: if mode_value == 1 || pending_value == 1 do
                1
              else
                0
              end,
              project_id: Bytes.empty(),
              broker_public_key: Bytes.empty()
            }
            if push_state_valid(state, profile)? do
              Ok(state)
            else
              Err("push_state_corrupt")
            end
          end
        end
      else if version_value == 2 do
        let action_epoch = take_fixed(pending_wire.state, 8)?
        let action_kind = take_fixed(action_epoch.state, 1)?
        let target_mode = take_fixed(action_kind.state, 1)?
        let project_id = take_vector(target_mode.state, 36)?
        let broker_public_key = take_vector(project_id.state, 32)?
        case finish(broker_public_key.state) do
          Err(_) -> Err("push_state_corrupt")
          Ok(_) -> do
            let state = MobilePushState {
              revision: mobile_read_u64(revision.value)?,
              mode: mode_value,
              wake_token_hash: wake_hash.value,
              provider_token_hash: provider_hash.value,
              pending_kind: pending_value,
              pending_wire: pending_wire.value,
              action_epoch: mobile_read_u64(action_epoch.value)?,
              action_kind: mobile_read_byte(action_kind.value)?,
              target_mode: mobile_read_byte(target_mode.value)?,
              project_id: project_id.value,
              broker_public_key: broker_public_key.value
            }
            if push_state_valid(state, profile)? do
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

fn decode_push_state(input :: Bytes, profile :: ClientProfile) -> MobilePushState!String do
  case parse_push_state(input, profile) do
    Err(_) -> Err("push_state_corrupt")
    Ok(state)
  end
end

pub fn load_push_state(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey) -> MobilePushState!String do
  let label = "push-binding/v1"
  case load_blob(database_path, label) do
    Err(error) -> if error == "local_state_not_found" do
      pristine_push_state()
    else
      Err(error)
    end
    Ok(blob) -> case open_local(blob, wrapping_key, push_state_context(profile)?) do
      Err(_) -> Err("push_state_corrupt")
      Ok(encoded) -> decode_push_state(encoded, profile)
    end
  end
end

pub fn store_push_state(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  state :: MobilePushState) -> Result<(), String> do
  let label = "push-binding/v1"
  let encoded = push_state_bytes(state, profile)?
  let sealed = seal_local(encoded, wrapping_key, push_state_context(profile)?)?
  store_updated_session(database_path, label, sealed)
end

## Expo receives the APNs or FCM token, so the identifier sent with it must not
## be the protocol device ID: that ID is public in the directory and would let
## Expo tie a push token to a Morse account. This one is random, never leaves
## the device except to Expo, and is stable so Expo can replace a rotated token.

pub fn push_install_id(database_path :: String, wrapping_key :: borrow StorageKey) -> Bytes!String do
  let label = "push-install-id/v1"
  case load_blob(database_path, label) do
    Ok(blob) -> case open_local(blob, wrapping_key, local_context(label)?) do
      Err(_) -> Err("push_state_corrupt")
      Ok(value) -> if Bytes.length(value) == 16 do
        Ok(value)
      else
        Err("push_state_corrupt")
      end
    end
    Err(error) -> if error == "local_state_not_found" do
      let value = random_bytes(16)?
      let sealed = seal_local(value, wrapping_key, local_context(label)?)?
      store_updated_session(database_path, label, sealed)?
      Ok(value)
    else
      Err(error)
    end
  end
end

pub fn next_push_revision(revision :: U64) -> U64!String do
  if U64.compare(revision, mobile_wide("9223372036854775807")?) >= 0 do
    Err("push_revision_exhausted")
  else
    U64.add(revision, mobile_wide("1")?)
  end
end

pub fn next_push_action_epoch(epoch :: U64) -> U64!String do
  if U64.compare(epoch, mobile_wide("9223372036854775807")?) >= 0 do
    Err("push_action_epoch_exhausted")
  else
    U64.add(epoch, mobile_wide("1")?)
  end
end

fn signed_push_bind(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  wake_token_hash :: Bytes,
  revision :: U64,
  provider_token_ciphertext :: Bytes) -> Bytes!String do
  let unsigned = PushBindRequest {
    mailbox_token_hash: Crypto.sha256(profile.entry.mailbox_token),
    wake_token_hash: wake_token_hash,
    revision: revision,
    provider: 1,
    provider_token_ciphertext: provider_token_ciphertext,
    signature: Bytes.empty()
  }
  let device = open_device(profile, wrapping_key, database_path)?
  let signature = case Crypto.sign(device.signing_private_key, push_bind_signing_bytes(unsigned)?) do
    Err(_) -> Err("push_binding_sign_failed")
    Ok(value) -> Ok(value.bytes)
  end?
  encode_push_bind(%{unsigned | signature: signature})
end

pub fn signed_push_unbind(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  revision :: U64) -> Bytes!String do
  let unsigned = PushUnbindRequest {
    mailbox_token_hash: Crypto.sha256(profile.entry.mailbox_token),
    revision: revision,
    signature: Bytes.empty()
  }
  let device = open_device(profile, wrapping_key, database_path)?
  let signature = case Crypto.sign(device.signing_private_key, push_unbind_signing_bytes(unsigned)?) do
    Err(_) -> Err("push_binding_sign_failed")
    Ok(value) -> Ok(value.bytes)
  end?
  encode_push_unbind(%{unsigned | signature: signature})
end

pub fn prepare_new_push_bind(request :: MobilePayloadRequest,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  state :: MobilePushState,
  project_id :: String,
  broker_public_key :: X25519PublicKey,
  endpoint :: String,
  raw_material :: Bytes) -> Bytes!String do
  let material = parse_expo_raw_token(raw_material)?
  let install_id = push_install_id(request.database_path, wrapping_key)?
  let token = register_expo_token(material, install_id, project_id, endpoint)?
  let sealed = case seal_provider_token(token, broker_public_key) do
    Err(error) -> if error == "invalid provider token" do
      Err("push_provider_response_invalid")
    else
      Err("push_binding_failed")
    end
    Ok(value)
  end?
  let token_hash = Crypto.sha256(token)
  if state.mode == 1 && Bytes.secure_equals(state.provider_token_hash, token_hash) do
    Ok(Bytes.empty())
  else
    let revision = next_push_revision(state.revision)?
    let wake_hash = if state.mode == 1 do
      state.wake_token_hash
    else
      case Crypto.random_bytes(32) do
        Err(_) -> Err("push_wake_generation_failed")
        Ok(random) -> do
          let generated = Crypto.sha256(random)
          if Bytes.secure_equals(generated, Crypto.sha256(profile.entry.mailbox_token)) do
            Err("push_wake_generation_failed")
          else
            Ok(generated)
          end
        end
      end?
    end
    let wire = signed_push_bind(request.database_path,
      profile,
      wrapping_key,
      wake_hash,
      revision,
      sealed)?
    let updated = %{state | revision: revision, mode: 1, wake_token_hash: wake_hash, provider_token_hash: token_hash, pending_kind: 1, pending_wire: wire}
    store_push_state(request.database_path, profile, wrapping_key, updated)?
    Ok(wire)
  end
end

pub fn prepare_push_bind_with_config(request :: MobilePayloadRequest,
  broker_public_key :: Result<X25519PublicKey, String>,
  endpoint :: String) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let state = load_push_state(request.database_path, profile, wrapping_key)?
  if state.pending_kind == 1 do
    Ok(state.pending_wire)
  else if state.pending_kind == 2 do
    Err("push_update_pending")
  else
    let project_id = expo_project_id(request.payload)?
    let broker_public_key = broker_public_key?
    let raw_material = case Host.push_get_token(Bytes.from_utf8("expo/raw/v1")) do
      Err(_) -> Err("push_material_unavailable")
      Ok(value)
    end?
    let action_state = %{state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 3, target_mode: 1, project_id: request.payload, broker_public_key: broker_public_key.bytes}
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

pub fn prepare_push_unbind_loaded(database_path :: String,
  profile :: ClientProfile,
  wrapping_key :: borrow StorageKey,
  state :: MobilePushState) -> Bytes!String do
  if state.pending_kind == 2 do
    Ok(state.pending_wire)
  else if state.mode == 0 do
    Ok(Bytes.empty())
  else
    let revision = next_push_revision(state.revision)?
    let wire = signed_push_unbind(database_path, profile, wrapping_key, revision)?
    let updated = %{state | revision: revision, mode: 0, wake_token_hash: mobile_zeroes(32)?, provider_token_hash: mobile_zeroes(32)?, pending_kind: 2, pending_wire: wire}
    store_push_state(database_path, profile, wrapping_key, updated)?
    Ok(wire)
  end
end

pub fn prepare_push_unbind(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path)?
    let profile = decode_client_profile(load_profile(database_path)?)?
    let wrapping_key = platform_key()?
    let state = load_push_state(database_path, profile, wrapping_key)?
    if state.pending_kind == 2 do
      Ok(state.pending_wire)
    else
      let action_state = %{state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 4, target_mode: 0, project_id: Bytes.empty(), broker_public_key: Bytes.empty()}
      prepare_push_unbind_loaded(database_path, profile, wrapping_key, action_state)
    end
  end
end

pub fn commit_push_update(request :: MobilePayloadRequest) -> Bytes!String do
  if Bytes.length(request.payload) > 725 do
    Err("invalid_push_update")
  else
    ensure_schema(request.database_path)?
    let profile = decode_client_profile(load_profile(request.database_path)?)?
    let wrapping_key = platform_key()?
    let state = load_push_state(request.database_path, profile, wrapping_key)?
    if state.pending_kind == 0 do
      Err("push_update_not_pending")
    else if !Bytes.secure_equals(state.pending_wire, request.payload) do
      Err("push_update_mismatch")
    else
      let epoch = next_push_action_epoch(state.action_epoch)?
      store_push_state(request.database_path,
        profile,
        wrapping_key,
        %{state | pending_kind: 0, pending_wire: Bytes.empty(), action_epoch: epoch, action_kind: 0, target_mode: state.mode})?
      Ok(Bytes.empty())
    end
  end
end

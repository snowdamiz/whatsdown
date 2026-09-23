from Binary.Reader import BinaryReader, finish, reader
from Mobile.Codec import (
  mobile_byte,
  mobile_join,
  mobile_read_byte,
  mobile_read_u64,
  mobile_write_u32,
  mobile_write_u64,
  take_fixed,
  take_vector_error
)
from Mobile.Platform import (
  expo_project_id,
  expo_push_endpoint,
  native_push_build_config,
  push_broker_public_key
)
from Mobile.Profile import load_profile
from Mobile.PushState import (
  load_push_state,
  next_push_action_epoch,
  prepare_new_push_bind,
  prepare_push_unbind_loaded,
  store_push_state
)
from Mobile.Types import (
  MobilePayloadRequest,
  MobilePushActionCompletion,
  MobilePushActionFrame,
  MobilePushBuildConfig,
  MobilePushIntentRequest,
  MobilePushState,
  MobileReadBytes
)
from Protocol.V1 import AccountIdentity, DeviceCredential, DirectoryEntry, PrekeyBundle
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Transport.Packet import ClientProfile, decode_client_profile

##! Mobile.Push implementation.

fn parse_push_action_frame(input :: Bytes) -> MobilePushActionFrame!String do
  case reader(input, 743) do
    Err(_) -> Err("invalid_push_action")
    Ok(state) -> do
      let version = take_fixed(state, 1)?
      let magic = take_fixed(version.state, 3)?
      let kind = take_fixed(magic.state, 1)?
      let flags = take_fixed(kind.state, 1)?
      let epoch = take_fixed(flags.state, 8)?
      let payload = take_vector_error(epoch.state, 725, "invalid_push_action")?
      case finish(payload.state) do
        Err(_) -> Err("invalid_push_action")
        Ok(_) -> do
          let kind_value = mobile_read_byte(kind.value)?
          let payload_length = Bytes.length(payload.value)
          let payload_shape = if kind_value == 1 || kind_value == 2 || kind_value == 5 do
            payload_length == 0
          else if kind_value == 3 || kind_value == 4 do
            payload_length > 0
          else
            false
          end
          if mobile_read_byte(version.value)? != 1 || !Bytes.secure_equals(magic.value,
            Bytes.from_utf8("PFA")) || mobile_read_byte(flags.value)? != 0 || !payload_shape do
            Err("invalid_push_action")
          else
            Ok(MobilePushActionFrame {
              kind: kind_value,
              epoch: mobile_read_u64(epoch.value)?,
              payload: payload.value
            })
          end
        end
      end
    end
  end
end

fn encode_push_action(kind :: Int, flags :: Int, epoch :: U64, payload :: Bytes) -> Bytes!String do
  if kind < 0 || kind > 5 || flags < 0 || flags > 1 || Bytes.length(payload) > 725 do
    Err("invalid_push_action")
  else
    mobile_join([
        mobile_byte(1)?,
        Bytes.from_utf8("PFA"),
        mobile_byte(kind)?,
        mobile_byte(flags)?,
        mobile_write_u64(epoch)?,
        mobile_write_u32(Bytes.length(payload))?,
        payload
      ],
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

fn push_done_action(state :: MobilePushState, surface_error :: Int) -> Bytes!String do
  encode_push_action(0, surface_error, state.action_epoch, mobile_byte(push_status_code(state))?)
end

fn current_push_action(state :: MobilePushState) -> Bytes!String do
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
  state :: MobilePushState) -> Bytes!String do
  store_push_state(database_path, profile, wrapping_key, state)?
  current_push_action(state)
end

pub fn push_action(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path)?
    let profile = decode_client_profile(load_profile(database_path)?)?
    current_push_action(load_push_state(database_path, profile, platform_key()?)?)
  end
end

fn push_config_matches(state :: MobilePushState, config :: MobilePushBuildConfig) -> Bool do
  Bytes.secure_equals(state.project_id, config.project_id) && Bytes.secure_equals(state.broker_public_key,
    config.broker_public_key)
end

fn matching_native_push_config(state :: MobilePushState) -> MobilePushBuildConfig!String do
  let config = native_push_build_config()?
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
  broker_public_key :: Bytes) -> Bytes!String do
  let cleanup = % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 5, target_mode: target_mode, project_id: project_id, broker_public_key: broker_public_key }
  if state.pending_kind == 2 do
    store_push_action(database_path, profile, wrapping_key, cleanup)
  else
    let wire = prepare_push_unbind_loaded(database_path, profile, wrapping_key, cleanup)?
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
  state :: MobilePushState) -> Bytes!String do
  if state.action_kind == 4 || state.action_kind == 5 do
    store_push_action(database_path,
      profile,
      wrapping_key,
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, target_mode: 1, project_id: config.project_id, broker_public_key: config.broker_public_key })
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
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, target_mode: 1, project_id: config.project_id, broker_public_key: config.broker_public_key })
  end
end

pub fn push_intent(request :: MobilePushIntentRequest) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let state = load_push_state(request.database_path, profile, wrapping_key)?
  if request.intent == 0 do
    if state.action_kind != 0 do
      if state.target_mode == 0 do
        current_push_action(state)
      else
        let config = native_push_build_config()?
        if push_config_matches(state, config) do
          current_push_action(state)
        else
          retarget_push_enable(request.database_path, config, profile, wrapping_key, state)
        end
      end
    else if state.mode == 1 do
      let config = native_push_build_config()?
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
          % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 2, target_mode: 1 })
      end
    else
      current_push_action(state)
    end
  else if request.intent == 1 do
    let config = native_push_build_config()?
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
        % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 1, target_mode: 1, project_id: config.project_id, broker_public_key: config.broker_public_key })
    end
  else if state.action_kind == 4 || state.action_kind == 5 do
    if state.target_mode == 0 && Bytes.length(state.project_id) == 0 && Bytes.length(state.broker_public_key) == 0 do
      current_push_action(state)
    else
      store_push_action(request.database_path,
        profile,
        wrapping_key,
        % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, target_mode: 0, project_id: Bytes.empty(), broker_public_key: Bytes.empty() })
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
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 5, target_mode: 0, project_id: Bytes.empty(), broker_public_key: Bytes.empty() })
  else
    current_push_action(state)
  end
end

pub fn complete_push_action_with_config(request :: MobilePushActionCompletion, endpoint :: String) -> Bytes!String do
  ensure_schema(request.database_path)?
  let profile = decode_client_profile(load_profile(request.database_path)?)?
  let wrapping_key = platform_key()?
  let state = load_push_state(request.database_path, profile, wrapping_key)?
  let completed = parse_push_action_frame(request.action)?
  let order = U64.compare(completed.epoch, state.action_epoch)
  if order < 0 do
    current_push_action(state)
  else if order > 0 || state.action_kind == 0 || !Bytes.secure_equals(request.action,
    current_push_action(state)?) do
    Err("push_action_mismatch")
  else if state.action_kind == 5 && state.pending_kind == 2 do
    store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 4 })
  else if request.outcome == 1 do
    push_done_action(state, 1)
  else if state.action_kind == 1 do
    store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 2 })
  else if state.action_kind == 2 do
    let config = matching_native_push_config(state)?
    let project_id = expo_project_id(config.project_id)?
    let configured_key = push_broker_public_key(config.broker_public_key)?
    let raw_material = case Host.push_get_token(Bytes.from_utf8("expo/raw/v1")) do
      Err(_) -> Err("push_material_unavailable")
      Ok(value)
    end?
    let epoch = next_push_action_epoch(state.action_epoch)?
    let bind_state = % { state | action_epoch: epoch, action_kind: 3 }
    let wire = prepare_new_push_bind(MobilePayloadRequest {
        database_path: request.database_path,
        payload: config.project_id
      },
      profile,
      wrapping_key,
      bind_state,
      project_id,
      configured_key,
      endpoint,
      raw_material)?
    if Bytes.length(wire) == 0 do
      store_push_action(request.database_path,
        profile,
        wrapping_key,
        % { state | action_epoch: epoch, action_kind: 0, target_mode: 1 })
    else
      encode_push_action(3, 0, epoch, wire)
    end
  else if state.action_kind == 3 do
    matching_native_push_config(state)?
    store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | pending_kind: 0, pending_wire: Bytes.empty(), action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 0, target_mode: 1 })
  else if state.action_kind == 4 do
    store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | pending_kind: 0, pending_wire: Bytes.empty(), action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 5 })
  else if state.target_mode == 1 do
    store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 1 })
  else
    store_push_action(request.database_path,
      profile,
      wrapping_key,
      % { state | action_epoch: next_push_action_epoch(state.action_epoch)?, action_kind: 0, target_mode: 0, project_id: Bytes.empty(), broker_public_key: Bytes.empty() })
  end
end

pub fn complete_push_action(request :: MobilePushActionCompletion) -> Bytes!String do
  complete_push_action_with_config(request, expo_push_endpoint())
end

pub fn push_status(database_path :: String) -> Bytes!String do
  if String.length(database_path) == 0 || String.length(database_path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(database_path)?
    let profile = decode_client_profile(load_profile(database_path)?)?
    let wrapping_key = platform_key()?
    let state = load_push_state(database_path, profile, wrapping_key)?
    Ok(push_status_bytes(state))
  end
end

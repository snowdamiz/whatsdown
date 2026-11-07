from Mobile.AccountState import load_bound_account
from Mobile.Codec import mobile_reader, mobile_finish, take_vector_error, mobile_utf8
from Mobile.Codec import mobile_byte, mobile_join, mobile_vector, mobile_write_u64
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import expo_push_endpoint, native_push_build_config
from Mobile.Push import (
  push_intent,
  push_intent_with_basis,
  current_push_action,
  push_status_code,
  complete_push_action_with_basis
)
from Mobile.PushState import profile_from_push_basis, push_state_from_basis
from Mobile.Requests import (
  parse_push_intent_request,
  parse_push_action_completion,
  parse_payload_request
)
from Mobile.Types import MobilePushActionCompletion, MobilePushState, MobilePushIntentRequest
from Storage.Keys import platform_key
from Storage.PushGuard import PushBasis, load_push_basis, require_current_push

fn valid_path(path :: String) -> Result<(), String> do
  if String.length(path) == 0 || String.length(path) > 4096 || String.contains(path, "\0") do
    Err("invalid_database_path")
  else
    Ok(nil)
  end
end

fn state_from(before :: PushBasis) -> MobilePushState!String do
  let wrapping = platform_key()?
  push_state_from_basis(before, profile_from_push_basis(before, wrapping)?, wrapping)
end

## PFA2 carries only an intent kind, epoch and an opaque 32-byte ticket. The
## signed binding, mailbox identity and encrypted provider token stay in Mesh.
fn frame(path :: String,
  before :: PushBasis,
  state :: MobilePushState,
  failure :: Bool) -> Bytes!String do
  let done = state.action_kind == 0 || failure
  let ticket = if done do
    mobile_byte(push_status_code(state))?
  else
    Crypto.sha256(mobile_join([
        Bytes.from_utf8("mesh-msg/v2/push-action"),
        mobile_vector(Bytes.from_utf8(path))?,
        Crypto.sha256(before.profile),
        Crypto.sha256(before.push)
      ],
      0,
      Bytes.empty())?)
  end
  mobile_join([
      mobile_byte(2)?,
      Bytes.from_utf8("PFA"),
      mobile_byte(if done do
        0
      else
        state.action_kind
      end)?,
      mobile_byte(if failure do
        1
      else
        0
      end)?,
      mobile_write_u64(state.action_epoch)?,
      mobile_vector(ticket)?
    ],
    0,
    Bytes.empty())
end

fn current_frame(path :: String, failure :: Bool) -> Bytes!String do
  let before = load_push_basis(path)?
  frame(path, before, state_from(before)?, failure)
end

fn bound_frame(path :: String, profile :: Bytes, failure :: Bool) -> Bytes!String do
  let before = load_push_basis(path)?
  if !Bytes.secure_equals(before.profile, profile) do
    return Err("push_state_changed")
  end
  frame(path, before, state_from(before)?, failure)
end

fn require_ticket(path :: String,
  before :: PushBasis,
  state :: MobilePushState,
  input :: Bytes) -> Result<(), String> do
  if state.action_kind == 0
    || Bytes.length(input) != 50
    || !Bytes.secure_equals(input, frame(path, before, state, false)?) do
    Err("push_action_mismatch")
  else
    Ok(nil)
  end
end

pub fn native_push_intent(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) > 4105 do
    return Err("invalid_push_intent")
  end
  let request = parse_push_intent_request(input)?
  valid_path(request.database_path)?
  push_intent(request)?
  current_frame(request.database_path, false)
end

## Only permission, platform token registration and platform clear can be
## reported by the UI. A UI success byte can never settle a bind or unbind.
pub fn native_push_complete_with_endpoint(input :: Bytes, endpoint :: String) -> Bytes!String do
  if Bytes.length(input) > 4159 do
    return Err("invalid_push_action_completion")
  end
  let request = parse_push_action_completion(input)?
  valid_path(request.database_path)?
  let before = load_push_basis(request.database_path)?
  let state = state_from(before)?
  require_ticket(request.database_path, before, state, request.action)?
  if state.action_kind != 1 && state.action_kind != 2 && state.action_kind != 5 do
    return Err("push_native_transport_required")
  end
  let result = complete_push_action_with_basis(MobilePushActionCompletion {
      database_path: request.database_path,
      action: current_push_action(state)?,
      outcome: request.outcome
    },
    endpoint,
    before)?
  bound_frame(request.database_path, before.profile, Bytes.get(result, 5)? == 1)
end

pub fn native_push_complete(input :: Bytes) -> Bytes!String do
  native_push_complete_with_endpoint(input, expo_push_endpoint())
end

fn require_bind_config(state :: MobilePushState) -> Result<(), String> do
  if state.action_kind != 3 do
    return Ok(nil)
  end
  let config = native_push_build_config()?
  if !Bytes.secure_equals(config.project_id, state.project_id)
    || !Bytes.secure_equals(config.broker_public_key, state.broker_public_key) do
    Err("push_configuration_changed")
  else
    Ok(nil)
  end
end

## The request supplies no URL, wire bytes or success claim. On an unknown
## transport result the exact signed pending operation remains durable.
pub fn native_push_send(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) > 4154 do
    return Err("invalid_push_action")
  end
  let request = parse_payload_request(input)?
  valid_path(request.database_path)?
  let before = load_push_basis(request.database_path)?
  let state = state_from(before)?
  require_ticket(request.database_path, before, state, request.payload)?
  if state.action_kind != 3 && state.action_kind != 4 do
    return Err("push_network_action_required")
  end
  let origin = native_network_pins()?.core_origin
  require_bind_config(state)?
  require_current_push(request.database_path, before)?
  let response = case Http.build(if state.action_kind == 3 do
      :put
    else
      :post
    end,
    origin
      <> if state.action_kind == 3 do
        "/v1/push/bind"
      else
        "/v1/push/unbind"
      end)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(state.pending_wire)
    |> Http.timeout(8000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> return Err("push_transport_unavailable")
    Ok(value) -> value
  end
  if native_network_pins()?.core_origin != origin do
    return Err("push_configuration_changed")
  end
  require_bind_config(state)?
  require_current_push(request.database_path, before)?
  let expected_status = if state.action_kind == 3 do
    201
  else
    200
  end
  if response.status != expected_status do
    return Err("push_http_" <> Int.to_string(response.status))
  end
  if Bytes.length(response.body_bytes) != 0 do
    return Err("push_response_invalid")
  end
  complete_push_action_with_basis(MobilePushActionCompletion {
      database_path: request.database_path,
      action: current_push_action(state)?,
      outcome: 0
    },
    expo_push_endpoint(),
    before)?
  bound_frame(request.database_path, before.profile, false)
end

## An intent belongs to the identity shown when it was queued. Routine
## credential renewal may change public profile bytes, but not its identity keys.
pub fn native_push_begin(input :: Bytes) -> Bytes!String do
  let state = mobile_reader(input, 40243, "invalid_push_begin")?
  let path = take_vector_error(state, 4096, "invalid_push_begin")?
  let expected = take_vector_error(path.state, 36134, "invalid_push_begin")?
  let intent = take_vector_error(expected.state, 1, "invalid_push_begin")?
  mobile_finish(intent.state, "invalid_push_begin")?
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  valid_path(database_path)?
  if Bytes.length(intent.value) != 1 do
    return Err("invalid_push_intent")
  end
  let intent_kind = Bytes.get(intent.value, 0)?
  if intent_kind > 2 do
    return Err("invalid_push_intent")
  end
  let account = load_bound_account(database_path, expected.value, false)?
  let before = load_push_basis(database_path)?
  if !Bytes.secure_equals(before.profile, account.before.profile) do
    return Err("push_state_changed")
  end
  push_intent_with_basis(MobilePushIntentRequest {
      database_path: database_path,
      intent: intent_kind
    },
    before)?
  bound_frame(database_path, before.profile, false)
end

## Trusted native platform controllers validate immediately before OS work and
## again before caching an asynchronous result. This never advances an action.
pub fn native_push_validate(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) > 4154 do
    return Err("invalid_push_action")
  end
  let request = parse_payload_request(input)?
  valid_path(request.database_path)?
  let before = load_push_basis(request.database_path)?
  let state = state_from(before)?
  require_ticket(request.database_path, before, state, request.payload)?
  if state.action_kind != 2 && state.action_kind != 5 do
    return Err("push_platform_action_required")
  end
  require_current_push(request.database_path, before)?
  mobile_byte(state.action_kind)
end

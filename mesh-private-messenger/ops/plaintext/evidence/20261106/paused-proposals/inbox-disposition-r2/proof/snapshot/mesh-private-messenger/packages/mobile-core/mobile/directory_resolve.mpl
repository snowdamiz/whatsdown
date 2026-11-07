from Mobile.Codec import mobile_utf8
from Mobile.Resolve import resolution_requests_for_config
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import native_security_config, decode_native_security_config
from Mobile.OhttpContext import (
  NativeOhttpContext,
  capture_native_ohttp_context,
  require_current_ohttp_context,
  fetch_guarded_ohttp_lookup
)
from Ohttp.LookupPolicy import OhttpLookupOperation
from Mobile.Profile import load_profile
from Mobile.Types import MobilePayloadRequest, MobileTransparencyRequest
from Mobile.Transparency import (
  NativeTransparencyBasis,
  capture_native_transparency_basis,
  native_transparency_checkpoint,
  verify_transparency_response_native
)
from Storage.Blobs import load_blob
from Transparency.Config import encode_security_config
from Transparency.Wire import decode_transparency_evidence

fn current(path :: String, profile :: Bytes, origin :: String, security :: Bytes) -> Bool do
  let loaded = case load_blob(path, "profile/v1") do
    Err(_) -> return false
    Ok(value) -> value
  end
  let pins = case native_network_pins() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let config = case native_security_config() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let encoded = case encode_security_config(config) do
    Err(_) -> return false
    Ok(value) -> value
  end
  pins.core_origin == origin
    && Bytes.secure_equals(loaded, profile)
    && Bytes.secure_equals(encoded, security)
end

fn remaining(started :: Int) -> Int!String do
  let elapsed = Monotonic.elapsed(started, Monotonic.now_nanos())?
  Ok(30000 - elapsed / 1000000)
end

fn fetch_evidence(path :: String,
  username :: String,
  profile :: Bytes,
  origin :: String,
  security :: Bytes,
  started :: Int,
  before :: NativeTransparencyBasis) -> Bytes!String do
  let steps = resolution_requests_for_config(MobilePayloadRequest {
      database_path: path,
      payload: Bytes.from_utf8(username)
    },
    decode_native_security_config(before.context.security_frame)?,
    native_transparency_checkpoint(before)?)?
  for index in 0..List.length(steps) do
    if !current(path, profile, origin, security) do
      return Err("directory_identity_changed")
    end
    let step = List.get(steps, index)
    let budget = remaining(started)?
    if budget <= 0 do
      return Err("directory_transport_budget_exhausted")
    end
    let response = fetch_guarded_ohttp_lookup(path,
      before.context,
      OhttpDirectoryLookup(step.version),
      step.body,
      if budget < 8000 do
        budget
      else
        8000
      end)?
    if response.status == 404
      && index + 1 < List.length(steps)
      && Bytes.secure_equals(response.body, Bytes.from_utf8("transparency_v2_not_active")) do
      nil
    else
      if response.status != 200 do
        return Err("directory_http_" <> Int.to_string(response.status))
      end
      let decoded = case decode_transparency_evidence(response.body) do
        Err(_) -> return Err("invalid_transparency_evidence")
        Ok(value) -> value
      end
      if decoded.checkpoint.version != step.version do
        return Err("transparency_response_version_mismatch")
      end
      return Ok(response.body)
    end
  end
  Err("invalid_resolution_plan")
end

fn resolve_attempt(path :: String,
  username :: String,
  profile :: Bytes,
  origin :: String,
  security :: Bytes,
  started :: Int,
  attempt :: Int,
  context :: NativeOhttpContext) -> Bytes!String do
  let before = capture_native_transparency_basis(path, context)?
  let evidence = fetch_evidence(path, username, profile, origin, security, started, before)?
  let result = verify_transparency_response_native(MobileTransparencyRequest {
      database_path: path,
      username: username,
      evidence: evidence,
      directory_url: origin
    },
    before)
  if !current(path, profile, origin, security) do
    return Err("directory_identity_changed")
  end
  case result do
    Ok(value)
    Err(error) -> do
      if attempt >= 4
        || (error != "transparency_state_changed" && error != "transparency_verification_failed") do
        return Err(error)
      end
      let delay = if error == "transparency_state_changed" do
        0
      else
        1000 * (attempt + 1)
      end
      if remaining(started)? <= delay do
        return Err("directory_transport_budget_exhausted")
      end
      if delay > 0 do
        Timer.sleep(delay)
      end
      # Rebuild work and fetch new signed evidence for the now-current checkpoint.
      resolve_attempt(path, username, profile, origin, security, started, attempt + 1, context)
    end
  end
end

pub fn resolve_directory_device_set_at_profile(path :: String,
  username :: String,
  profile :: Bytes) -> Bytes!String do
  load_profile(path)?
  if !Bytes.secure_equals(profile, load_blob(path, "profile/v1")?) do
    return Err("directory_identity_changed")
  end
  let context = capture_native_ohttp_context(path, profile)?
  let security = encode_security_config(decode_native_security_config(context.security_frame)?)?
  resolve_attempt(path,
    username,
    profile,
    context.pins.network.core_origin,
    security,
    Monotonic.now_nanos(),
    0,
    context)
end

pub fn resolve_directory_device_set(path :: String, username :: String) -> Bytes!String do
  resolve_directory_device_set_at_profile(path, username, load_blob(path, "profile/v1")?)
end

from Mobile.Requests import parse_payload_request

pub fn native_directory_resolve(input :: Bytes) -> Bytes!String do
  if Bytes.length(input) > 4169 do
    return Err("invalid_directory_request")
  end
  let request = parse_payload_request(input)?
  if Bytes.length(request.payload) > 65 || String.contains(request.database_path, "\0") do
    return Err("invalid_directory_request")
  end
  resolve_directory_device_set(request.database_path,
    mobile_utf8(request.payload, "invalid_username")?)
end

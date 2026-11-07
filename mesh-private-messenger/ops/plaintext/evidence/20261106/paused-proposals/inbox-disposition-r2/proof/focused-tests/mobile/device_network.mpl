from Mobile.Account import create_device_revocation, forget_on_proof_at_profile
from Mobile.AccountState import account_network_current
from Mobile.Codec import (
  mobile_reader,
  mobile_finish,
  take_vector_error,
  mobile_utf8,
  mobile_byte,
  mobile_write_u16,
  current_time
)
from Mobile.Credits import native_credit_signup_policy_online
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.DeviceSet import verified_device_set, local_device_set
from Mobile.NetworkPins import native_network_pins
from Mobile.Platform import native_security_config
from Mobile.Profile import load_profile
from Mobile.Renewal import renew_devices_at, renewal_basis
from Mobile.RenewalQueue import (
  load_renewal_publication,
  save_renewal_publication,
  clear_renewal_publication
)
from Mobile.Transparency import require_transparency_device_set
from Mobile.TransparencySafety import require_log_changes_allowed
from Mobile.Types import MobileTriplePayloadRequest
from Storage.AccountGuard import AccountBasis, same_account_basis, account_basis_current
from Storage.Keys import platform_key
from Transport.Packet import decode_client_profile
from Transparency.Config import encode_security_config
from Privacy.Edge import encode_stamped_request, mint_request_stamp
from Credits.SignupPolicy import decode_credit_signup_policy

struct DeviceRequest do
  path :: String
  devices :: Bytes
  target :: Bytes
end

struct RenewalPlan do
  before :: AccountBasis
  entries :: List<Bytes>
end

struct RegistrationWork do
  difficulty :: Int
  issued_at :: U64
  expires_at :: Option<U64>
end

fn parse_device_request(input :: Bytes, revoke :: Bool) -> DeviceRequest!String do
  let state = mobile_reader(input,
    if revoke do
      309384
    else
      309364
    end,
    "invalid_device_action")?
  let path = take_vector_error(state, 4096, "invalid_device_action")?
  let devices = take_vector_error(path.state, 305260, "invalid_device_action")?
  let target = if revoke do
    let parsed = take_vector_error(devices.state, 16, "invalid_device_action")?
    mobile_finish(parsed.state, "invalid_device_action")?
    if Bytes.length(parsed.value) != 16 do
      return Err("invalid_device_action")
    end
    parsed.value
  else
    mobile_finish(devices.state, "invalid_device_action")?
    Bytes.empty()
  end
  let database_path = mobile_utf8(path.value, "invalid_database_path")?
  if Bytes.length(path.value) == 0
    || String.contains(database_path, "\0")
    || Bytes.length(devices.value) == 0 do
    return Err("invalid_device_action")
  end
  Ok(DeviceRequest { path: database_path, devices: devices.value, target: target })
end

fn source_current(path :: String,
  before :: AccountBasis,
  origin :: String,
  security :: Bytes) -> Bool do
  if !account_network_current(path, before.profile, origin)
    || !account_basis_current(path, before) do
    return false
  end
  let config = case native_security_config() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let key = case platform_key() do
    Err(_) -> return false
    Ok(value) -> value
  end
  if Result.is_err(require_log_changes_allowed(path, key)) do
    return false
  end
  case encode_security_config(config) do
    Err(_) -> false
    Ok(value) -> Bytes.secure_equals(value, security)
  end
end

fn prepared_renewal(path :: String, wire :: Bytes) -> RenewalPlan!String do
  let local = decode_client_profile(load_profile(path)?)?
  let key = platform_key()?
  let before = renewal_basis(path, key, local)?
  require_log_changes_allowed(path, key)?
  let devices = verified_device_set(wire)?
  require_transparency_device_set(path, key, devices)?
  if !local_device_set(local, devices) do
    return Err("renewal_device_set_mismatch")
  end
  case load_renewal_publication(before, local, key)? do
    Some(pending) -> do
      if Bytes.secure_equals(pending.devices_hash, Crypto.sha256(wire)) do
        return Ok(RenewalPlan { before: before, entries: pending.entries })
      end
      if U64.compare(devices.value.sequence, pending.sequence) <= 0 do
        return Err("renewal_device_set_mismatch")
      end
      # Only a newer witnessed view releases this exact publication queue.
      clear_renewal_publication(path, before)?
    end
    None -> nil
  end
  let plan = stable_renewal(path, wire, 0)?
  if List.length(plan.entries) == 0 do
    return Ok(plan)
  end
  let current = decode_client_profile(load_profile(path)?)?
  let committed = save_renewal_publication(path,
    plan.before,
    current,
    key,
    wire,
    devices.value.sequence,
    plan.entries)?
  Ok(RenewalPlan { before: committed, entries: plan.entries })
end

fn remaining(started :: Int) -> Int!String do
  Ok(30000 - Monotonic.elapsed(started, Monotonic.now_nanos())? / 1000000)
end

## Planning may adopt a witnessed successor or create pending keys. Repeat only
## local planning until a pass changes no captured source; never bind stale
## entries to a fresh, unrelated snapshot read after their computation.
fn stable_renewal(path :: String, devices :: Bytes, attempt :: Int) -> RenewalPlan!String do
  let profile = decode_client_profile(load_profile(path)?)?
  let key = platform_key()?
  let before = renewal_basis(path, key, profile)?
  let entries = renew_devices_at(path, devices, U64.parse("0")?)?
  let current_profile = decode_client_profile(load_profile(path)?)?
  let observed = renewal_basis(path, key, current_profile)?
  if !same_account_basis(before, observed) do
    if attempt >= 3 do
      return Err("account_state_changed")
    end
    return stable_renewal(path, devices, attempt + 1)
  end
  if List.length(entries) > 8 do
    return Err("invalid_renewal_plan")
  end
  Ok(RenewalPlan { before: before, entries: entries })
end

fn registration_work(path :: String) -> RegistrationWork!String do
  let statement = case native_credit_signup_policy_online(pack_credit_parts([
    Bytes.from_utf8(path)
  ])?) do
    Err("credits_disabled") -> return Ok(RegistrationWork {
      difficulty: native_security_config()?.abuse_difficulty,
      issued_at: U64.parse("0")?,
      expires_at: None
    })
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  let fields = unpack_credit_parts(statement, 8, 88)?
  if List.length(fields) != 8 || Bytes.to_hex(List.get(fields, 0)) != "02535056" do
    return Err("untrusted_credit_signup_policy")
  end
  # The online helper verified this signed statement against native service and
  # purpose pins. Keep its native expiry so slow work cannot outlive the policy.
  let policy = decode_credit_signup_policy(List.get(fields, 7))?
  Ok(RegistrationWork {
    difficulty: policy.current_difficulty,
    issued_at: policy.issued_at,
    expires_at: Some(policy.expires_at)
  })
end

fn work_current(work :: RegistrationWork) -> Bool!String do
  case work.expires_at do
    None -> Ok(true)
    Some(expires) -> do
      let now = U64.divide(current_time()?, U64.parse("1000")?)?
      Ok(U64.compare(now, work.issued_at) >= 0 && U64.compare(now, expires) < 0)
    end
  end
end

fn renewal_result(sent :: Int, status :: Int, removal :: Int) -> Bytes!String do
  Bytes.concat(Bytes.concat(Bytes.from_hex("01444e52")?, mobile_byte(sent)?)?,
    Bytes.concat(mobile_write_u16(status)?, mobile_byte(removal)?)?)
end

fn publish(path :: String,
  plan :: RenewalPlan,
  origin :: String,
  security :: Bytes,
  work :: RegistrationWork,
  started :: Int,
  index :: Int) -> Bytes!String do
  if !source_current(path, plan.before, origin, security) do
    return Err("account_state_changed")
  end
  if index >= List.length(plan.entries) do
    return renewal_result(index, 0, 0)
  end
  if !work_current(work)? do
    return Err("untrusted_credit_signup_policy")
  end
  let payload = List.get(plan.entries, index)
  let wire = encode_stamped_request(mint_request_stamp("mesh-msg/v1/work/register",
      payload,
      U64.add(current_time()?, U64.parse("240000")?)?,
      work.difficulty)?,
    payload)?
  let budget = remaining(started)?
  if budget <= 0 do
    return Err("device_transport_budget_exhausted")
  end
  if !source_current(path, plan.before, origin, security) do
    return Err("account_state_changed")
  end
  if !work_current(work)? do
    return Err("untrusted_credit_signup_policy")
  end
  let response = case Http.build(:put, origin <> "/v1/devices/register")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(wire)
    |> Http.timeout(if budget < 8000 do
      budget
    else
      8000
    end)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> do
      if !source_current(path, plan.before, origin, security) do
        return Err("account_state_changed")
      end
      return Err("device_transport_unavailable")
    end
    Ok(value) -> value
  end
  if !source_current(path, plan.before, origin, security) do
    return Err("account_state_changed")
  end
  if response.status == 410 do
    let removal = forget_on_proof_at_profile(path, plan.before.profile, response.body_bytes)?
    return renewal_result(index, 410, Bytes.get(removal, 0)?)
  end
  if response.status != 200 && response.status != 201 && response.status != 204 do
    return renewal_result(index, response.status, 0)
  end
  publish(path, plan, origin, security, work, started, index + 1)
end

pub fn native_devices_renew(input :: Bytes) -> Bytes!String do
  let request = parse_device_request(input, false)?
  let pins = native_network_pins()?
  let security = encode_security_config(native_security_config()?)?
  let started = Monotonic.now_nanos()
  let plan = prepared_renewal(request.path, request.devices)?
  if List.length(plan.entries) == 0 do
    if !source_current(request.path, plan.before, pins.core_origin, security) do
      return Err("account_state_changed")
    end
    return renewal_result(0, 0, 0)
  end
  let work = registration_work(request.path)?
  publish(request.path, plan, pins.core_origin, security, work, started, 0)
end

pub fn native_device_revoke(input :: Bytes) -> Bytes!String do
  let request = parse_device_request(input, true)?
  let pins = native_network_pins()?
  let security = encode_security_config(native_security_config()?)?
  let local = decode_client_profile(load_profile(request.path)?)?
  let key = platform_key()?
  let before = renewal_basis(request.path, key, local)?
  require_log_changes_allowed(request.path, key)?
  let devices = verified_device_set(request.devices)?
  require_transparency_device_set(request.path, key, devices)?
  if !local_device_set(local, devices) || Bytes.secure_equals(request.target, local.device_id) do
    return Err("invalid_device_revocation")
  end
  if List.contains(devices.value.revoked_device_ids, request.target) do
    if !source_current(request.path, before, pins.core_origin, security) do
      return Err("account_state_changed")
    end
    return Bytes.concat(Bytes.from_hex("01445256")?, mobile_write_u16(200)?)
  end
  let wire = create_device_revocation(MobileTriplePayloadRequest {
    database_path: request.path,
    first: request.devices,
    second: request.target
  })?
  if !source_current(request.path, before, pins.core_origin, security) do
    return Err("account_state_changed")
  end
  let response = case Http.build(:post, pins.core_origin <> "/v1/devices/revoke")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(wire)
    |> Http.timeout(8000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> do
      if !source_current(request.path, before, pins.core_origin, security) do
        return Err("account_state_changed")
      end
      return Err("device_transport_unavailable")
    end
    Ok(value) -> value
  end
  if !source_current(request.path, before, pins.core_origin, security) do
    return Err("account_state_changed")
  end
  if response.status != 200 do
    return Err("device_http_" <> Int.to_string(response.status))
  end
  Bytes.concat(Bytes.from_hex("01445256")?, mobile_write_u16(200)?)
end

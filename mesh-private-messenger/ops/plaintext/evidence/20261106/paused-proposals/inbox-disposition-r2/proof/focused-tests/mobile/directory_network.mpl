from Mobile.Codec import mobile_read_u32
from Mobile.NetworkPins import native_network_pins
from Mobile.Prekeys import replenish_prekeys, reconcile_prekeys
from Storage.Blobs import load_blob
from Mobile.Types import MobilePrekeyRequest, MobilePrekeyReconcileRequest

fn current(path :: String, identity :: Bytes, origin :: String) -> Bool do
  let pins = case native_network_pins() do
    Err(_) -> return false
    Ok(value) -> value
  end
  let profile = case load_blob(path, "profile/v1") do
    Err(_) -> return false
    Ok(value) -> value
  end
  pins.core_origin == origin && Bytes.secure_equals(profile, identity)
end

fn remaining(started :: Int) -> Int!String do
  let elapsed = Monotonic.elapsed(started, Monotonic.now_nanos())?
  Ok(12000 - elapsed / 1000000)
end

fn publish(path :: String,
  identity :: Bytes,
  origin :: String,
  started :: Int,
  count :: Int) -> Int!String do
  if !current(path, identity, origin) do
    return Err("directory_identity_changed")
  end
  let wire = replenish_prekeys(MobilePrekeyRequest { database_path: path, count: count })?
  if !current(path, identity, origin) do
    return Err("directory_identity_changed")
  end
  let budget = remaining(started)?
  if budget <= 0 do
    return Err("directory_transport_budget_exhausted")
  end
  let response = case Http.build(:post, origin <> "/v1/prekeys/one-time/batch")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(wire)
    |> Http.timeout(if budget < 8000 do
      budget
    else
      8000
    end)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(565)
    |> Http.send() do
    Err(_) -> return Err("directory_transport_unavailable")
    Ok(value) -> value
  end
  if !current(path, identity, origin) do
    return Err("directory_identity_changed")
  end
  if response.status != 200 && response.status != 201 && response.status != 429 do
    return Err("prekey_http_" <> Int.to_string(response.status))
  end
  mobile_read_u32(reconcile_prekeys(MobilePrekeyReconcileRequest {
    database_path: path,
    response: response.body_bytes
  })?)
end

## Reconcile before replenishing: a publication whose acknowledgement was lost
## remains durable locally and is republished before any new key generation.
## A full-pool 429 carries the canonical active IDs and must also reconcile.
pub fn synchronize_directory_prekeys(path :: String) -> Int!String do
  let pins = native_network_pins()?
  let identity = load_blob(path, "profile/v1")?
  let started = Monotonic.now_nanos()
  let active = publish(path, identity, pins.core_origin, started, 0)?
  if active == 64 do
    return Ok(active)
  end
  let refilled = publish(path, identity, pins.core_origin, started, 64 - active)?
  if refilled != 64 do
    Err("incomplete_prekey_refill")
  else
    Ok(refilled)
  end
end

from Mobile.Credits import native_credit_signup_policy_online, native_register_signup_policy
from Mobile.CreditState import pack_credit_parts, unpack_credit_parts
from Mobile.Account import directory_entry_for, forget_on_proof_at_profile
from Mobile.SignupDraft import require_free_registration_allowed
from Mobile.Platform import stamped_request
from Mobile.Codec import mobile_read_byte

pub struct DirectoryRegistrationResult do
  active_prekeys :: Int
  removal_kind :: Int
end

fn registration_wire(path :: String) -> Bytes!String do
  # Paid drafts cannot be converted to ordinary registration by startup.
  require_free_registration_allowed(path)?
  let statement = case native_credit_signup_policy_online(pack_credit_parts([
    Bytes.from_utf8(path)
  ])?) do
    Err("credits_disabled") -> return stamped_request("mesh-msg/v1/work/register",
      directory_entry_for(path)?)
    Err(error) -> return Err(error)
    Ok(value) -> value
  end
  let fields = unpack_credit_parts(statement, 8, 88)?
  if List.length(fields) != 8
    || Bytes.to_hex(List.get(fields, 0)) != "02535056"
    || Bytes.length(List.get(fields, 7)) != 88 do
    return Err("untrusted_credit_signup_policy")
  end
  native_register_signup_policy(pack_credit_parts([Bytes.from_utf8(path), List.get(fields, 7)])?)
end

## The request, destination, signed difficulty and removal decision remain in
## Mesh. Only a verified removal kind may leave this domain operation.
pub fn register_directory(path :: String) -> DirectoryRegistrationResult!String do
  let pins = native_network_pins()?
  let identity = load_blob(path, "profile/v1")?
  let wire = registration_wire(path)?
  if !current(path, identity, pins.core_origin) do
    return Err("directory_identity_changed")
  end
  let response = case Http.build(:put, pins.core_origin <> "/v1/devices/register")
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Cache-Control", "no-store")
    |> Http.body_bytes(wire)
    |> Http.timeout(8000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(1024)
    |> Http.send() do
    Err(_) -> do
      if !current(path, identity, pins.core_origin) do
        return Err("directory_identity_changed")
      end
      return Err("directory_transport_unavailable")
    end
    Ok(value) -> value
  end
  if !current(path, identity, pins.core_origin) do
    return Err("directory_identity_changed")
  end
  if response.status == 409 do
    return Err("registration_refused")
  end
  if response.status == 410 do
    let removal = forget_on_proof_at_profile(path, identity, response.body_bytes)?
    return Ok(DirectoryRegistrationResult {
      active_prekeys: 0,
      removal_kind: mobile_read_byte(removal)?
    })
  end
  if response.status != 200 && response.status != 201 && response.status != 204 do
    return Err("directory_http_" <> Int.to_string(response.status))
  end
  let active = synchronize_directory_prekeys(path)?
  Ok(DirectoryRegistrationResult { active_prekeys: active, removal_kind: 0 })
end

fn request_path(input :: Bytes) -> String!String do
  if Bytes.length(input) == 0 || Bytes.length(input) > 4096 do
    return Err("invalid_database_path")
  end
  let path = case Bytes.to_utf8(input) do
    Err(_) -> return Err("invalid_database_path")
    Ok(value) -> value
  end
  if String.contains(path, "\0") do
    return Err("invalid_database_path")
  end
  Ok(path)
end

fn encoded_count(count :: Int) -> Bytes!String do
  case Bytes.write_u16_be(count) do
    Err(_) -> Err("invalid_prekey_count")
    Ok(value)
  end
end

pub fn native_directory_register(input :: Bytes) -> Bytes!String do
  let result = register_directory(request_path(input)?)?
  Bytes.concat(Bytes.concat(Bytes.from_hex("01445247")?, encoded_count(result.active_prekeys)?)?,
    case Bytes.from_list([result.removal_kind]) do
      Err(_) -> return Err("invalid_removal")
      Ok(value) -> value
    end)
end

pub fn native_prekeys_synchronize(input :: Bytes) -> Bytes!String do
  let count = synchronize_directory_prekeys(request_path(input)?)?
  Bytes.concat(Bytes.from_hex("0144504b")?, encoded_count(count)?)
end

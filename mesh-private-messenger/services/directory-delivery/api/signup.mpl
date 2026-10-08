##! Registration under load (plan §6.10, "Priority sign-up"): PWR at the
##! current difficulty, or CRD (20 credits, action 3) in front of PWR at the
##! pinned base.

from Api.Binary import Admission, BinaryResult, admit_request, register_device_request
from Credits.CreditFrames import CreditFrame, credits_detach, credits_encode_work
from Protocol.DirectoryWire import decode_directory_entry
from Storage.Devices import DeviceWrite, register_device_paid
from Storage.SignupSurge import signup_difficulty, signup_price

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

fn label() -> String do
  "mesh-msg/v1/work/register"
end

fn work_needed(difficulty :: Int) -> BinaryResult do
  case credits_encode_work(difficulty, signup_price()) do
    Ok(body) -> BinaryResult { status: 429, body: body }
    Err(_) -> empty(429)
  end
end

fn paid_status(result :: Result<DeviceWrite, String>) -> BinaryResult do
  case result do
    Err(error) -> if String.contains(error, "credit_short") do
      empty(402)
    else if String.contains(error, "credit_refused") || String.contains(error, "credit_spent") do
      empty(422)
    else if String.contains(error, "credit_closed") do
      empty(403)
    else
      empty(500)
    end
    Ok(DeviceAccepted) -> empty(201)
    Ok(DeviceUnchanged) -> empty(200)
    Ok(DeviceConflict) -> empty(409)
    Ok(DeviceInvalid) -> empty(400)
    Ok(DeviceRemoved(statement)) -> BinaryResult { status: 410, body: statement }
    Ok(DeviceRetired(_)) -> empty(500)
  end
end

fn paid(pool :: PoolHandle,
  payload :: Bytes,
  frame :: CreditFrame,
  mode :: String,
  now_ms :: Int) -> BinaryResult do
  case decode_directory_entry(payload) do
    Err(_) -> empty(400)
    Ok(entry) -> paid_status(register_device_paid(pool, entry, mode, frame, signup_price(), now_ms))
  end
end

## PUT /v1/devices/register. Without credits the stamp must meet the current
## difficulty; 429 answers WRK (the difficulty now, and the 20-credit price)
## when it does not. With a CRD frame of at least 20 credits the stamp need
## only meet the pinned base: 402 fewer credits, 422 credits that are not
## usable (invalid or already spent), 403 credits off. The credits are spent
## only if the registration succeeds.

pub fn signup_request(pool :: PoolHandle,
  body :: Bytes,
  now_ms :: Int,
  base :: Int,
  target :: Int,
  mode :: String) -> BinaryResult do
  let required = case signup_difficulty(pool, base, target) do
    Err(_) -> return empty(503)
    Ok(value) -> value
  end
  let (frame, stamped) = case credits_detach(body) do
    Err(_) -> return empty(400)
    Ok(pair) -> pair
  end
  let difficulty = case frame do
    None -> required
    Some(_) -> base
  end
  let now = case U64.parse(Int.to_string(now_ms)) do
    Err(_) -> return empty(500)
    Ok(value) -> value
  end
  case admit_request(pool, label(), stamped, 36006, now, difficulty) do
    Err(_) -> empty(500)
    Ok(AdmissionMalformed) -> empty(400)
    Ok(AdmissionRefused) -> work_needed(difficulty)
    Ok(Admitted(payload)) -> case frame do
      None -> register_device_request(pool, payload)
      Some(value) -> paid(pool, payload, value, mode, now_ms)
    end
  end
end

## GET /v1/devices/register/work: WRK, so a device can mint once for the
## difficulty in force instead of learning it from a 429.

pub fn signup_work_request(pool :: PoolHandle, base :: Int, target :: Int) -> BinaryResult do
  case signup_difficulty(pool, base, target) do
    Err(_) -> empty(503)
    Ok(difficulty) -> case credits_encode_work(difficulty, signup_price()) do
      Ok(encoded) -> BinaryResult { status: 200, body: encoded }
      Err(_) -> empty(500)
    end
  end
end

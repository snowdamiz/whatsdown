from Api.Binary import BinaryResult
from Credits.ActionWire import decode_credit_action_submission
from Storage.CreditSignup import apply_credit_signup
from Storage.CreditIssuers import configured_credit_purpose
from Credits.SignupPolicy import sign_credit_signup_policy, encode_credit_signup_policy
from Runtime.Registry import get_pool
from Runtime.WorkPolicy import configured_signup_difficulty

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

pub fn credit_signup_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  if Env.get("MORSE_PAID_SIGNUP", "off") != "on" do
    return empty(503)
  end
  let submission = case decode_credit_action_submission(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case apply_credit_signup(pool, submission) do
    Err(error) -> if List.contains([
        "credit_operation_conflict",
        "credit_already_spent",
        "credit_effect_conflict",
        "credit_not_required",
        "credit_signup_already_registered",
        "messenger_devices_conflict",
        "messenger_account_deleted"
      ],
      error)
      || String.contains(error, "messenger_device_revoked") do
      empty(409)
    else if List.contains([
        "invalid_credit_signup_request",
        "invalid_credit_signup_registration",
        "credit_action_request_mismatch",
        "expired_credit_action",
        "invalid_credit_token",
        "credit_amount_mismatch",
        "credit_binding_mismatch"
      ],
      error) do
      empty(400)
    else if String.contains(error, "transparency_log_full") do
      empty(507)
    else
      empty(503)
    end
    Ok(value) -> BinaryResult {
      status: if value.created do
        201
      else
        200
      end,
      body: value.receipt
    }
  end
end

pub fn handle_credit_signup(request :: Request) -> Response do
  let result = credit_signup_request(get_pool(), Request.body_bytes(request))
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

fn current_policy() -> Bytes!String do
  let seed = case Env.get_secret_hex("MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX") do
    Err(_) -> return Err("credit_signup_policy_unavailable")
    Ok(value) -> value
  end
  let key = case Crypto.signing_from_secret(seed) do
    Err(_) -> return Err("credit_signup_policy_unavailable")
    Ok(value) -> value
  end
  let now = U64.divide(U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now())))?,
    U64.parse("1000")?)?
  encode_credit_signup_policy(sign_credit_signup_policy(key.private_key,
    configured_credit_purpose()?,
    Env.get("MORSE_PAID_SIGNUP", "off") == "on",
    Env.get_int("MESSENGER_ABUSE_BASE_DIFFICULTY", 16),
    configured_signup_difficulty(),
    now)?)
end

# Also available with paid signup disabled: the authenticated current difficulty
# lets the free client choose its work without trusting edge-supplied prices.
pub fn handle_credit_signup_policy(request :: Request) -> Response do
  let result = if Bytes.length(Request.body_bytes(request)) != 0 do
    empty(400)
  else
    case current_policy() do
      Err(_) -> empty(503)
      Ok(body) -> BinaryResult { status: 200, body: body }
    end
  end
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

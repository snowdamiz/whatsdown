from Api.Binary import BinaryResult
from Credits.PostageBox import decode_sealed_postage_batch
from Credits.PostagePolicy import decode_postage_policy
from Storage.CreditPostage import apply_credit_postage, reconcile_credit_postage
from Storage.CreditPostagePolicy import publish_postage_policy
from Runtime.Registry import get_pool
import RuntimeJobs

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

fn postage_error(error :: String) -> BinaryResult do
  if error == "credit_action_not_expired" do
    empty(425)
  else if List.contains([
      "credit_operation_conflict",
      "credit_already_spent",
      "credit_effect_conflict",
      "credit_postage_snapshot_conflict",
      "credit_postage_already_delivered",
      "credit_not_required",
      "postage_policy_conflict"
    ],
    error) do
    empty(409)
  else if error == "postage_policy_rate_limited"
    || String.contains(error, "messenger_mailbox_capacity")
    || String.contains(error, "messenger_rate_limited") do
    empty(429)
  else if error == "invalid_postage_policy_authority" do
    empty(403)
  else if String.starts_with(error, "invalid_")
    || List.contains([
        "expired_credit_action",
        "expired_postage_policy",
        "credit_action_request_mismatch",
        "credit_amount_mismatch",
        "credit_binding_mismatch",
        "duplicate_credit_token",
        "unknown_credit_account"
      ],
      error) do
    empty(400)
  else
    empty(503)
  end
end

fn delivery_key() -> X25519PrivateKey!String do
  let material = case Env.get_secret_hex("MESSENGER_DELIVERY_SEALING_SEED_HEX") do
    Err(_) -> return Err("postage_delivery_key_unavailable")
    Ok(value) -> value
  end
  case Crypto.x25519_from_secret(material) do
    Err(_) -> Err("postage_delivery_key_unavailable")
    Ok(value) -> Ok(value.private_key)
  end
end

pub fn credit_postage_request(pool :: PoolHandle,
  body :: Bytes,
  recovery :: Bool) -> BinaryResult do
  if !recovery && Env.get("MORSE_PAID_INBOX_POSTAGE", "off") != "on" do
    return empty(503)
  end
  let batch = case decode_sealed_postage_batch(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  let key = case delivery_key() do
    Err(_) -> return empty(503)
    Ok(value) -> value
  end
  if recovery do
    case reconcile_credit_postage(pool, batch, key) do
      Err(error) -> postage_error(error)
      Ok(value) -> BinaryResult { status: 200, body: value }
    end
  else
    case apply_credit_postage(pool, batch, key) do
      Err(error) -> postage_error(error)
      Ok(value) -> BinaryResult {
        status: if value.created do
          201
        else
          200
        end,
        body: value.response
      }
    end
  end
end

pub fn postage_policy_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let policy = case decode_postage_policy(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  if policy.credits != 0 && Env.get("MORSE_PAID_INBOX_POSTAGE", "off") != "on" do
    return empty(503)
  end
  case publish_postage_policy(pool, policy) do
    Err(error) -> postage_error(error)
    Ok(value) -> case Bytes.write_u64_be(value.device_set_revision) do
      Err(_) -> empty(503)
      Ok(revision) -> BinaryResult {
        status: if value.created do
          201
        else
          200
        end,
        body: revision
      }
    end
  end
end

fn response(result :: BinaryResult) -> Response do
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

# The public edge forwards only opaque PSB bytes. Both private hops require the
# existing consuming-service credential; CAR/CCR never cross the edge plaintext.
pub fn handle_credit_postage(request :: Request) -> Response do
  response(if RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    credit_postage_request(get_pool(), Request.body_bytes(request), false)
  else
    empty(401)
  end)
end

pub fn handle_credit_postage_reconcile(request :: Request) -> Response do
  response(if RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    credit_postage_request(get_pool(), Request.body_bytes(request), true)
  else
    empty(401)
  end)
end

# This acknowledgement is not a witnessed policy admission. The publishing
# device must obtain and verify the new directory evidence before relying on it.
pub fn handle_postage_policy(request :: Request) -> Response do
  response(postage_policy_request(get_pool(), Request.body_bytes(request)))
end

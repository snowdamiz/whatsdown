from Api.Binary import BinaryResult
from Credits.ActionWire import decode_credit_action_submission
from Storage.CreditAttachment import apply_credit_attachment_grant
from Runtime.Registry import get_pool
import RuntimeJobs

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

pub fn credit_attachment_grant_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  if Env.get("MORSE_PAID_LARGE_ATTACHMENTS", "off") != "on" do
    return empty(503)
  end
  let submission = case decode_credit_action_submission(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case apply_credit_attachment_grant(pool, submission) do
    Ok(value) -> BinaryResult {
      status: if value.created do
        201
      else
        200
      end,
      body: value.receipt
    }
    Err(error) -> if List.contains([
        "credit_operation_conflict",
        "credit_already_spent",
        "credit_effect_conflict"
      ],
      error) do
      empty(409)
    else if List.contains([
        "invalid_credit_attachment_grant",
        "invalid_large_attachment_size",
        "invalid_large_attachment_manifest",
        "invalid_credit_attachment_expiry",
        "credit_action_request_mismatch",
        "expired_credit_action",
        "invalid_credit_token",
        "credit_amount_mismatch",
        "credit_binding_mismatch",
        "duplicate_credit_token"
      ],
      error) do
      empty(400)
    else
      empty(503)
    end
  end
end

# Consuming-service authority only; public clients cannot ask this route to
# accept caller keys or issue arbitrary storage entitlements.
pub fn handle_credit_attachment_grant(request :: Request) -> Response do
  let result = if !RuntimeJobs.internal_request_authorized(request,
    Env.get("MESSENGER_DELIVERY_INTERNAL_TOKEN", "")) do
    empty(401)
  else
    credit_attachment_grant_request(get_pool(), Request.body_bytes(request))
  end
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

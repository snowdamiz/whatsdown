from Api.Binary import BinaryResult
from Credits.ActionWire import decode_credit_action_submission
from Storage.CreditRetention import apply_credit_retention

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

pub fn credit_retention_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  # Enable only after the matching client can preserve old bundle secrets and
  # authenticate the exact signed completion. Free parking stays unchanged.
  if Env.get("MORSE_PAID_RETENTION", "off") != "on" do
    return empty(503)
  end
  let submission = case decode_credit_action_submission(body) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case apply_credit_retention(pool, submission) do
    Err("credit_retention_unauthorized") -> empty(403)
    Err(error) -> if List.contains([
        "credit_operation_conflict",
        "credit_already_spent",
        "credit_effect_conflict"
      ],
      error) do
      empty(409)
    else if List.contains([
        "invalid_credit_retention_request",
        "credit_action_request_mismatch",
        "expired_credit_action",
        "invalid_credit_token",
        "credit_amount_mismatch",
        "credit_binding_mismatch"
      ],
      error) do
      empty(400)
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

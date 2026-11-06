from Api.Binary import BinaryResult
from Credits.ActionWire import decode_credit_action_submission
from Storage.CreditRecovery import reconcile_credit_action
from Runtime.Registry import get_pool

fn recover(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  let input = case decode_credit_action_submission(body) do
    Err(_) -> return BinaryResult { status: 400, body: Bytes.empty() }
    Ok(value) -> value
  end
  case reconcile_credit_action(pool, input) do
    Ok(receipt) -> BinaryResult { status: 200, body: receipt }
    Err(error) -> BinaryResult {
      status: if error == "credit_action_not_expired" do
        425
      else if error == "credit_operation_conflict" || error == "credit_already_spent" do
        409
      else if List.contains([
          "invalid_credit_token",
          "credit_amount_mismatch",
          "credit_binding_mismatch",
          "unknown_credit_issuer",
          "inactive_credit_issuer"
        ],
        error) do
        400
      else
        503
      end,
      body: Bytes.empty()
    }
  end
end

# Recovery stays available when paid actions are disabled during an incident.
pub fn handle_credit_recovery(request :: Request) -> Response do
  let result = recover(get_pool(), Request.body_bytes(request))
  HTTP.response_bytes_with_headers(result.status,
    result.body,
    Map.new()
      |> Map.put("Content-Type", "application/octet-stream")
      |> Map.put("Cache-Control", "no-store"))
end

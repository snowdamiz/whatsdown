from Credits.LightningCancellation import decode_lightning_cancellation
from Credits.Lightning import (
  decode_lightning_quote_request,
  decode_lightning_issue_request,
  decode_signed_lightning_quote
)
from Credits.QuoteAuth import decode_signed_credit_quote
from Credits.SignupPolicy import decode_credit_signup_policy
from Credits.Cancellation import decode_credit_cancellation
from Api.Binary import EdgeResult
from Credits.Action import encode_credit_action, credit_action_id
from Credits.ActionWire import decode_credit_action_submission, decode_credit_action_receipt
from Credits.Retention import (
  decode_credit_retention_request,
  decode_credit_retention_result,
  credit_retention_action
)
from Credits.Signup import (
  decode_credit_signup_request,
  decode_credit_signup_result,
  credit_signup_action
)
from Credits.Wire import encode_credit_frame
from Credits.Discovery import decode_credit_issuer_query
from Credits.Issuance import (
  decode_credit_quote_request,
  decode_credit_issue_request,
  decode_credit_issue_response,
  credit_batch_hash
)
from Privacy.Edge import internal_delivery_authorization
from Transparency.Wire import decode_transparency_evidence

fn empty(status :: Int) -> EdgeResult do
  EdgeResult { status: status, body: Bytes.empty() }
end

fn valid_retention_request(body :: Bytes) -> Bool!String do
  let input = decode_credit_action_submission(body)?
  let retention = decode_credit_retention_request(input.request_body)?
  Ok(Bytes.secure_equals(encode_credit_action(input.action)?,
    encode_credit_action(credit_retention_action(retention)?)?))
end

fn valid_signup_request(body :: Bytes) -> Bool!String do
  let input = decode_credit_action_submission(body)?
  let signup = decode_credit_signup_request(input.request_body)?
  Ok(Bytes.secure_equals(encode_credit_action(input.action)?,
    encode_credit_action(credit_signup_action(signup)?)?))
end

fn public_core_operation(operation :: String) -> Bool do
  operation == "issuer"
    || operation == "retention"
    || operation == "signup"
    || operation == "signup-policy"
    || operation == "reconcile"
end

fn paid_action(operation :: String) -> Bool do
  operation == "retention" || operation == "signup"
end

fn valid_request(operation :: String, body :: Bytes) -> Bool do
  case operation do
    "reconcile" -> Result.is_ok(decode_credit_action_submission(body))
    "signup-policy" -> Bytes.length(body) == 0
    "signup" -> case valid_signup_request(body) do
      Ok(valid) -> valid
      Err(_) -> false
    end
    "retention" -> case valid_retention_request(body) do
      Ok(valid) -> valid
      Err(_) -> false
    end
    "issuer" -> Result.is_ok(decode_credit_issuer_query(body))
    "lightning/quote" -> Result.is_ok(decode_lightning_quote_request(body))
    "lightning/issue" -> Result.is_ok(decode_lightning_issue_request(body))
    "quote" -> Result.is_ok(decode_credit_quote_request(body))
    "issue" -> Result.is_ok(decode_credit_issue_request(body))
    _ -> false
  end
end

fn valid_response(operation :: String, request :: Bytes, body :: Bytes) -> Bool!String do
  if operation == "reconcile" do
    let input = decode_credit_action_submission(request)?
    let (id, action_hash, frame_hash) = if Bytes.length(body) == 172 do
      let output = decode_credit_cancellation(body)?
      if U64.compare(output.cancelled_at, input.action.expires_at) < 0 do
        return Ok(false)
      end
      (output.operation_id, output.action_sha256, output.frame_sha256)
    else
      let output = decode_credit_action_receipt(body)?
      (output.operation_id, output.action_sha256, output.frame_sha256)
    end
    Ok(Bytes.secure_equals(id, credit_action_id(input.action)?)
      && Bytes.secure_equals(action_hash, Crypto.sha256(encode_credit_action(input.action)?))
      && Bytes.secure_equals(frame_hash, Crypto.sha256(encode_credit_frame(input.frame)?)))
  else if operation == "signup-policy" do
    Ok(Result.is_ok(decode_credit_signup_policy(body)))
  else if paid_action(operation) do
    let input = decode_credit_action_submission(request)?
    let output = decode_credit_action_receipt(body)?
    let result_matches = if operation == "retention" do
      let retention = decode_credit_retention_request(input.request_body)?
      let result = decode_credit_retention_result(output.result)?
      Bytes.secure_equals(result.mailbox_hash, retention.mailbox_hash)
        && result.days == retention.days
    else
      let signup = decode_credit_signup_request(input.request_body)?
      let result = decode_credit_signup_result(output.result)?
      Bytes.secure_equals(result.account_id, input.action.target)
        && Bytes.secure_equals(result.entry_sha256, Crypto.sha256(signup.entry))
    end
    # The native client verifies the core signature against its pinned key.
    # This proxy rejects a canonical response for any other reserved operation.
    Ok(Bytes.secure_equals(output.operation_id, credit_action_id(input.action)?)
      && Bytes.secure_equals(output.action_sha256,
        Crypto.sha256(encode_credit_action(input.action)?))
      && Bytes.secure_equals(output.frame_sha256, Crypto.sha256(encode_credit_frame(input.frame)?))
      && result_matches)
  else if operation == "issuer" do
    Ok(Result.is_ok(decode_transparency_evidence(body)))
  else if operation == "lightning/quote" do
    let input = decode_lightning_quote_request(request)?
    let output = decode_signed_lightning_quote(body)?.quote
    Ok(input.credits == output.credits
      && input.network == output.network
      && input.purpose == output.purpose
      && Bytes.secure_equals(input.issuer_key_id, output.issuer_key_id)
      && Bytes.secure_equals(input.batch_hash, output.batch_hash))
  else if operation == "lightning/issue" do
    let input = decode_lightning_issue_request(request)?
    if Bytes.length(body) == 205 do
      let canceled = decode_lightning_cancellation(body)?
      # The native journal authenticates the witnessed issuer signature.
      # The privacy proxy still binds the statement to this exact request.
      return Ok(Bytes.secure_equals(input.quote_id, canceled.quote_id)
        && Bytes.secure_equals(input.payment_hash, canceled.payment_hash)
        && Bytes.secure_equals(credit_batch_hash(input.requests)?, canceled.batch_hash))
    end
    let output = decode_credit_issue_response(body)?
    Ok(List.length(input.requests) == List.length(output.signatures)
      && Bytes.secure_equals(input.quote_id, output.quote_id)
      && Bytes.secure_equals(credit_batch_hash(input.requests)?, output.batch_hash))
  else if operation == "quote" do
    let input = decode_credit_quote_request(request)?
    let output = decode_signed_credit_quote(body)?.quote
    Ok(input.credits == output.credits
      && input.asset == output.asset
      && input.purpose == output.purpose
      && Bytes.secure_equals(input.issuer_key_id, output.issuer_key_id)
      && Bytes.secure_equals(input.batch_hash, output.batch_hash))
  else
    let input = decode_credit_issue_request(request)?
    let output = decode_credit_issue_response(body)?
    Ok(List.length(input.requests) == List.length(output.signatures)
      && Bytes.secure_equals(input.quote_id, output.quote_id)
      && Bytes.secure_equals(credit_batch_hash(input.requests)?, output.batch_hash))
  end
end

# Only canonical bytes are forwarded. Caller headers, cookies, device/account
# identifiers and IP forwarding headers are absent from this API by design.
pub fn forward_credit(operation :: String,
  body :: Bytes,
  internal_url :: String,
  internal_token :: String) -> EdgeResult!String do
  if !valid_request(operation, body) do
    return Ok(empty(400))
  end
  if String.length(internal_url) == 0 do
    return Ok(empty(503))
  end
  let path = if public_core_operation(operation) do
    "/v1/credits/" <> operation
  else
    "/internal/v1/credits/" <> operation
  end
  let request = Http.build(:post, internal_url <> path)
    |> Http.header("Content-Type", "application/octet-stream")
    |> Http.header("Accept", "application/octet-stream")
    |> Http.body_bytes(body)
    |> Http.timeout(30000)
    |> Http.max_redirects(0)
    |> Http.max_response_bytes(if operation == "issue" || operation == "lightning/issue" do
      512070
    else if paid_action(operation) || operation == "reconcile" do
      462
    else if operation == "lightning/quote" do
      7352
    else if operation == "quote" do
      292
    else if operation == "signup-policy" do
      88
    else
      32768
    end)
  let request = if public_core_operation(operation) do
    request
  else
    let authorization = case internal_delivery_authorization(internal_token) do
      Ok(value) -> value
      Err(_) -> return Ok(empty(503))
    end
    Http.header(request, "Authorization", authorization)
  end
  let response = case Http.send(request) do
    Ok(value) -> value
    Err(_) -> return Ok(empty(502))
  end
  if response.status == 200 || (paid_action(operation) && response.status == 201) do
    case valid_response(operation, body, response.body_bytes) do
      Ok(true) -> Ok(EdgeResult { status: response.status, body: response.body_bytes })
      _ -> Ok(empty(502))
    end
  else if List.contains([400, 409, 425, 503], response.status)
    || (operation == "retention" && response.status == 403)
    || (operation == "signup" && response.status == 507) do
    # Never relay internal diagnostic bodies or upstream response headers.
    Ok(empty(response.status))
  else
    Ok(empty(502))
  end
end

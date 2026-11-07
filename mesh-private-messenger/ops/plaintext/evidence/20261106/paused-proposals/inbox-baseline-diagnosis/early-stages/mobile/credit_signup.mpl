from Credits.Action import encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Signup import (
  decode_credit_signup_request,
  credit_signup_action,
  decode_credit_signup_result
)

pub fn verify_signup_receipt(submission :: CreditActionSubmission,
  core :: SigningPublicKey,
  account_id :: Bytes,
  response :: Bytes) -> Result<(), String> do
  let receipt = decode_credit_action_receipt(response)?
  if !verify_credit_action_receipt(receipt, core, submission)? || submission.action.kind != 4 do
    return Err("unverified_credit_receipt")
  end
  let request = decode_credit_signup_request(submission.request_body)?
  let result = decode_credit_signup_result(receipt.result)?
  let earliest = if U64.compare(submission.action.expires_at, U64.parse("900")?) < 0 do
    U64.parse("0")?
  else
    U64.subtract(submission.action.expires_at, U64.parse("900")?)?
  end
  if !Bytes.secure_equals(encode_credit_action(credit_signup_action(request)?)?,
    encode_credit_action(submission.action)?)
    || !Bytes.secure_equals(submission.action.target, account_id)
    || !Bytes.secure_equals(result.account_id, account_id)
    || !Bytes.secure_equals(result.entry_sha256, Crypto.sha256(request.entry))
    || U64.compare(receipt.applied_at, earliest) < 0
    || U64.compare(receipt.applied_at, submission.action.expires_at) >= 0 do
    return Err("invalid_credit_signup_receipt")
  end
  Ok(nil)
end

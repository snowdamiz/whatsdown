from Credits.Action import encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  decode_credit_action_receipt,
  verify_credit_action_receipt
)
from Credits.Retention import (
  decode_credit_retention_request,
  credit_retention_action,
  decode_credit_retention_result
)

# This checks an immutable paid effect, including when recovered after expiry.
# It does not interpret an unsigned edge success or use a caller-provided key.
pub fn verified_retention_until(submission :: CreditActionSubmission,
  core :: SigningPublicKey,
  mailbox_hash :: Bytes,
  response :: Bytes) -> U64!String do
  let receipt = decode_credit_action_receipt(response)?
  if !verify_credit_action_receipt(receipt, core, submission)? || submission.action.kind != 2 do
    return Err("unverified_credit_receipt")
  end
  let request = decode_credit_retention_request(submission.request_body)?
  let result = decode_credit_retention_result(receipt.result)?
  let expires = submission.action.expires_at
  let earliest = if U64.compare(expires, U64.parse("900")?) < 0 do
    U64.parse("0")?
  else
    U64.subtract(expires, U64.parse("900")?)?
  end
  let applied_ms = U64.multiply(receipt.applied_at, U64.parse("1000")?)?
  let requested = U64.add(applied_ms,
    U64.multiply(U64.parse(Int.to_string(request.days))?, U64.parse("86400000")?)?)?
  let maximum = U64.add(applied_ms, U64.parse("15552000000")?)?
  if !Bytes.secure_equals(encode_credit_action(credit_retention_action(request)?)?,
    encode_credit_action(submission.action)?)
    || !Bytes.secure_equals(request.mailbox_hash, mailbox_hash)
    || !Bytes.secure_equals(result.mailbox_hash, mailbox_hash)
    || result.days != request.days
    || U64.compare(receipt.applied_at, earliest) < 0
    || U64.compare(receipt.applied_at, expires) >= 0
    || U64.compare(result.effective_until_ms, requested) < 0
    || U64.compare(result.effective_until_ms, maximum) > 0 do
    return Err("invalid_credit_retention_receipt")
  end
  Ok(result.effective_until_ms)
end

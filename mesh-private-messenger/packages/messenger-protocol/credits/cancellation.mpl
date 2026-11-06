from Credits.Action import credit_action_id, encode_credit_action
from Credits.ActionWire import CreditActionSubmission, encode_credit_action_submission
from Credits.Wire import encode_credit_frame

pub struct CreditCancellation do
  operation_id :: Bytes
  action_sha256 :: Bytes
  frame_sha256 :: Bytes
  cancelled_at :: U64
  signature :: Bytes
end

fn content(value :: CreditCancellation) -> Bytes!String do
  if Bytes.length(value.operation_id) != 32
    || Bytes.length(value.action_sha256) != 32
    || Bytes.length(value.frame_sha256) != 32
    || value.cancelled_at == U64.parse("0")? do
    return Err("invalid_credit_cancellation")
  end
  let clock = case Bytes.write_u64_be(value.cancelled_at) do
    Err(_) -> return Err("invalid_credit_cancellation")
    Ok(value) -> value
  end
  let head = Bytes.concat(Bytes.from_hex("01434352")?, value.operation_id)?
  Bytes.concat(Bytes.concat(Bytes.concat(head, value.action_sha256)?, value.frame_sha256)?, clock)
end

fn signing_bytes(value :: CreditCancellation) -> Bytes!String do
  Bytes.concat(Bytes.from_utf8("morse-credit-cancellation-v1"), content(value)?)
end

pub fn encode_credit_cancellation(value :: CreditCancellation) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_credit_cancellation")
  end
  Bytes.concat(content(value)?, value.signature)
end

pub fn decode_credit_cancellation(input :: Bytes) -> CreditCancellation!String do
  if Bytes.length(input) != 172 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01434352" do
    return Err("invalid_credit_cancellation")
  end
  let clock = case Bytes.read_u64_be(input, 100) do
    Err(_) -> return Err("invalid_credit_cancellation")
    Ok(value) -> value
  end
  let value = CreditCancellation {
    operation_id: Bytes.slice(input, 4, 32)?,
    action_sha256: Bytes.slice(input, 36, 32)?,
    frame_sha256: Bytes.slice(input, 68, 32)?,
    cancelled_at: clock,
    signature: Bytes.slice(input, 108, 64)?
  }
  encode_credit_cancellation(value)?
  Ok(value)
end

# The core must serialize with redemption/consumption and persist this exact
# receipt plus the cancellation fence in the transaction that releases a hold.
pub fn sign_credit_cancellation(private :: borrow SigningPrivateKey,
  submission :: CreditActionSubmission,
  cancelled_at :: U64) -> CreditCancellation!String do
  encode_credit_action_submission(submission)?
  if U64.compare(cancelled_at, submission.action.expires_at) < 0 do
    return Err("credit_action_not_expired")
  end
  let value = CreditCancellation {
    operation_id: credit_action_id(submission.action)?,
    action_sha256: Crypto.sha256(encode_credit_action(submission.action)?),
    frame_sha256: Crypto.sha256(encode_credit_frame(submission.frame)?),
    cancelled_at: cancelled_at,
    signature: Bytes.empty()
  }
  let signature = case Crypto.sign(private, signing_bytes(value)?) do
    Err(_) -> return Err("credit_cancellation_signing_failed")
    Ok(value) -> value.bytes
  end
  Ok(%{value | signature: signature})
end

pub fn verify_credit_cancellation(value :: CreditCancellation,
  pinned_core :: SigningPublicKey,
  submission :: CreditActionSubmission) -> Bool!String do
  encode_credit_action_submission(submission)?
  encode_credit_cancellation(value)?
  if U64.compare(value.cancelled_at, submission.action.expires_at) < 0
    || !Bytes.secure_equals(value.operation_id, credit_action_id(submission.action)?)
    || !Bytes.secure_equals(value.action_sha256,
      Crypto.sha256(encode_credit_action(submission.action)?))
    || !Bytes.secure_equals(value.frame_sha256,
      Crypto.sha256(encode_credit_frame(submission.frame)?)) do
    return Ok(false)
  end
  case Crypto.verify(pinned_core, signing_bytes(value)?, Signature { bytes: value.signature }) do
    Err(_) -> Ok(false)
    Ok(valid)
  end
end

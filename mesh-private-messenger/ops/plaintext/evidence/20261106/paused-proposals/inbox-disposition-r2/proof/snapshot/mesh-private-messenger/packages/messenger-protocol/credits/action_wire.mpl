from Credits.Action import (
  CreditAction,
  encode_credit_action,
  decode_credit_action,
  credit_action_id
)
from Credits.Wire import CreditFrame, encode_credit_frame, decode_credit_frame

pub struct CreditActionSubmission do
  action :: CreditAction
  request_body :: Bytes
  frame :: CreditFrame
end

pub struct CreditActionReceipt do
  operation_id :: Bytes
  action_sha256 :: Bytes
  frame_sha256 :: Bytes
  effect_id :: Bytes
  applied_at :: U64
  result :: Bytes
  signature :: Bytes
end

fn join(parts :: List<Bytes>, maximum :: Int) -> Bytes!String do
  let builder = case BytesBuilder.new(maximum) do
    Err(_) -> return Err("invalid_credit_action_wire")
    Ok(value) -> value
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_credit_action_wire")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value)
  end
end

fn size(value :: Int) -> Bytes!String do
  let number = U64.parse(Int.to_string(value))?
  case Bytes.write_u32_be(number) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value)
  end
end

fn narrow(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value)
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value)
  end
end

fn read_size(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u32_be(input, offset) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value) -> U64.to_int(value)
  end
end

fn read_narrow(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(input, offset) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value)
  end
end

fn read_wide(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_credit_action_wire")
    Ok(value)
  end
end

pub fn encode_credit_action_submission(value :: CreditActionSubmission) -> Bytes!String do
  if Bytes.length(value.request_body) > 65536
    || !Bytes.secure_equals(value.action.request_sha256, Crypto.sha256(value.request_body))
    || !Bytes.secure_equals(value.frame.binding, value.action.request_sha256) do
    return Err("credit_action_request_mismatch")
  end
  let action = encode_credit_action(value.action)?
  let frame = encode_credit_frame(value.frame)?
  join([
      Bytes.from_hex("01434150")?,
      action,
      size(Bytes.length(value.request_body))?,
      value.request_body,
      size(Bytes.length(frame))?,
      frame
    ],
    88355)
end

pub fn decode_credit_action_submission(input :: Bytes) -> CreditActionSubmission!String do
  let length = Bytes.length(input)
  if length < 129 || length > 88355 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01434150" do
    return Err("invalid_credit_action_wire")
  end
  let body_size = read_size(input, 121)?
  if body_size > 65536 || 129 + body_size > length do
    return Err("invalid_credit_action_wire")
  end
  let frame_size = read_size(input, 125 + body_size)?
  if frame_size > 22694 || 129 + body_size + frame_size != length do
    return Err("invalid_credit_action_wire")
  end
  let value = CreditActionSubmission {
    action: decode_credit_action(Bytes.slice(input, 4, 117)?)?,
    request_body: Bytes.slice(input, 125, body_size)?,
    frame: decode_credit_frame(Bytes.slice(input, 129 + body_size, frame_size)?)?
  }
  encode_credit_action_submission(value)?
  Ok(value)
end

fn receipt_content(value :: CreditActionReceipt) -> Bytes!String do
  if Bytes.length(value.operation_id) != 32
    || Bytes.length(value.action_sha256) != 32
    || Bytes.length(value.frame_sha256) != 32
    || Bytes.length(value.effect_id) != 32
    || Bytes.to_hex(value.effect_id) == String.repeat("00", 32)
    || value.applied_at == U64.parse("0")?
    || Bytes.length(value.result) < 1
    || Bytes.length(value.result) > 256 do
    return Err("invalid_credit_action_receipt")
  end
  join([
      Bytes.from_hex("01434152")?,
      value.operation_id,
      value.action_sha256,
      value.frame_sha256,
      value.effect_id,
      wide(value.applied_at)?,
      narrow(Bytes.length(value.result))?,
      value.result
    ],
    398)
end

fn receipt_signing_bytes(value :: CreditActionReceipt) -> Bytes!String do
  join([Bytes.from_utf8("morse-credit-action-receipt-v1"), receipt_content(value)?], 512)
end

pub fn encode_credit_action_receipt(value :: CreditActionReceipt) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_credit_action_receipt")
  end
  join([receipt_content(value)?, value.signature], 462)
end

pub fn decode_credit_action_receipt(input :: Bytes) -> CreditActionReceipt!String do
  let length = Bytes.length(input)
  if length < 207 || length > 462 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01434152" do
    return Err("invalid_credit_action_receipt")
  end
  let result_size = read_narrow(input, 140)?
  if result_size < 1 || result_size > 256 || length != 206 + result_size do
    return Err("invalid_credit_action_receipt")
  end
  let value = CreditActionReceipt {
    operation_id: Bytes.slice(input, 4, 32)?,
    action_sha256: Bytes.slice(input, 36, 32)?,
    frame_sha256: Bytes.slice(input, 68, 32)?,
    effect_id: Bytes.slice(input, 100, 32)?,
    applied_at: read_wide(input, 132)?,
    result: Bytes.slice(input, 142, result_size)?,
    signature: Bytes.slice(input, 142 + result_size, 64)?
  }
  encode_credit_action_receipt(value)?
  Ok(value)
end

# Call only after the action effect is durable in the same transaction as its
# hold consumption. Store the exact signed bytes for deterministic recovery.
pub fn sign_credit_action_receipt(private :: borrow SigningPrivateKey,
  submission :: CreditActionSubmission,
  effect_id :: Bytes,
  applied_at :: U64,
  result :: Bytes) -> CreditActionReceipt!String do
  encode_credit_action_submission(submission)?
  let value = CreditActionReceipt {
    operation_id: credit_action_id(submission.action)?,
    action_sha256: Crypto.sha256(encode_credit_action(submission.action)?),
    frame_sha256: Crypto.sha256(encode_credit_frame(submission.frame)?),
    effect_id: effect_id,
    applied_at: applied_at,
    result: result,
    signature: Bytes.empty()
  }
  let signature = case Crypto.sign(private, receipt_signing_bytes(value)?) do
    Err(_) -> return Err("credit_receipt_signing_failed")
    Ok(signed) -> signed.bytes
  end
  Ok(%{value | signature: signature})
end

# The caller supplies its pinned core key and its durably reserved exact
# submission. A key or generic success response supplied by an edge is no proof.
pub fn verify_credit_action_receipt(value :: CreditActionReceipt,
  pinned_core :: SigningPublicKey,
  submission :: CreditActionSubmission) -> Bool!String do
  encode_credit_action_submission(submission)?
  encode_credit_action_receipt(value)?
  if !Bytes.secure_equals(value.operation_id, credit_action_id(submission.action)?)
    || !Bytes.secure_equals(value.action_sha256,
      Crypto.sha256(encode_credit_action(submission.action)?))
    || !Bytes.secure_equals(value.frame_sha256,
      Crypto.sha256(encode_credit_frame(submission.frame)?)) do
    return Ok(false)
  end
  case Crypto.verify(pinned_core,
    receipt_signing_bytes(value)?,
    Signature { bytes: value.signature }) do
    Err(_) -> Ok(false)
    Ok(valid)
  end
end

from Credits.Action import CreditAction, credit_action_id, encode_credit_action
from Credits.ActionWire import (
  CreditActionSubmission,
  CreditActionReceipt,
  verify_credit_action_receipt
)
from Credits.PostageBox import postage_batch_digest
from Credits.PostagePolicy import postage_policy_from_device_set
from Protocol.DirectoryWire import encode_device_set
from Protocol.IdentityWire import decode_account_identity
from Protocol.V1 import DeviceSet

# One account/message request covers the full ordered active device set. The
# reply key is inside the CRD-bound descriptor; the edge cannot replace it.
pub struct CreditPostageRequest do
  operation_nonce :: Bytes
  recipient_account_id :: Bytes
  policy_revision :: U64
  device_set_revision :: U64
  device_set_sha256 :: Bytes
  batch_digest :: Bytes
  reply_public_key :: Bytes
  action_expires_at :: U64
end

pub struct CreditPostageResult do
  recipient_account_id :: Bytes
  batch_digest :: Bytes
  policy_revision :: U64
  device_set_revision :: U64
  enqueued_count :: Int
  charged_credits :: Int
end

fn postage_join(parts :: List<Bytes>) -> Bytes!String do
  let builder = case BytesBuilder.new(256) do
    Err(_) -> return Err("invalid_credit_postage")
    Ok(value) -> value
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_credit_postage")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_credit_postage")
    Ok(value)
  end
end

fn postage_wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_postage")
    Ok(value)
  end
end

fn postage_number(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_credit_postage")
    Ok(value)
  end
end

fn postage_identity(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

pub fn encode_credit_postage_request(value :: CreditPostageRequest) -> Bytes!String do
  if !postage_identity(value.operation_nonce)
    || !postage_identity(value.recipient_account_id)
    || !postage_identity(value.device_set_sha256)
    || !postage_identity(value.batch_digest)
    || !postage_identity(value.reply_public_key)
    || value.policy_revision == U64.parse("0")?
    || value.device_set_revision == U64.parse("0")?
    || value.action_expires_at == U64.parse("0")? do
    return Err("invalid_credit_postage")
  end
  postage_join([
    Bytes.from_hex("01505354")?,
    value.operation_nonce,
    value.recipient_account_id,
    postage_wide(value.policy_revision)?,
    postage_wide(value.device_set_revision)?,
    value.device_set_sha256,
    value.batch_digest,
    value.reply_public_key,
    postage_wide(value.action_expires_at)?
  ])
end

pub fn decode_credit_postage_request(input :: Bytes) -> CreditPostageRequest!String do
  if Bytes.length(input) != 188 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01505354" do
    return Err("invalid_credit_postage")
  end
  let value = CreditPostageRequest {
    operation_nonce: Bytes.slice(input, 4, 32)?,
    recipient_account_id: Bytes.slice(input, 36, 32)?,
    policy_revision: postage_number(input, 68)?,
    device_set_revision: postage_number(input, 76)?,
    device_set_sha256: Bytes.slice(input, 84, 32)?,
    batch_digest: Bytes.slice(input, 116, 32)?,
    reply_public_key: Bytes.slice(input, 148, 32)?,
    action_expires_at: postage_number(input, 180)?
  }
  encode_credit_postage_request(value)?
  Ok(value)
end

pub fn credit_postage_action(value :: CreditPostageRequest) -> CreditAction!String do
  Ok(CreditAction {
    kind: 3,
    operation_nonce: value.operation_nonce,
    target: value.recipient_account_id,
    quantity: U64.parse("0")?,
    expires_at: value.action_expires_at,
    request_sha256: Crypto.sha256(encode_credit_postage_request(value)?)
  })
end

pub fn credit_postage_effect_id(value :: CreditAction) -> Bytes!String do
  Ok(Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-credit-postage-effect-v1"),
    credit_action_id(value)?)?))
end

# `devices` must already be authenticated by the caller's witnessed directory
# admission. A raw DeviceSet and its account signature do not establish trust.
pub fn credit_postage_request_for_devices(devices :: DeviceSet,
  deliveries :: List<Bytes>,
  operation_nonce :: Bytes,
  reply_public_key :: X25519PublicKey,
  action_expires_at :: U64) -> CreditPostageRequest!String do
  let policy = case postage_policy_from_device_set(devices)? do
    None -> return Err("credit_postage_not_required")
    Some(value) -> value
  end
  if policy.credits == 0 || List.length(deliveries) != List.length(devices.devices) do
    return Err("invalid_credit_postage_set")
  end
  let encoded = case encode_device_set(devices) do
    Err(_) -> return Err("invalid_credit_postage_set")
    Ok(value) -> value
  end
  let identity = case decode_account_identity(devices.account_identity) do
    Err(_) -> return Err("invalid_credit_postage_set")
    Ok(value) -> value
  end
  let value = CreditPostageRequest {
    operation_nonce: operation_nonce,
    recipient_account_id: identity.account_id,
    policy_revision: policy.revision,
    device_set_revision: devices.sequence,
    device_set_sha256: Crypto.sha256(encoded),
    batch_digest: postage_batch_digest(deliveries)?,
    reply_public_key: reply_public_key.bytes,
    action_expires_at: action_expires_at
  }
  encode_credit_postage_request(value)?
  Ok(value)
end

pub fn encode_credit_postage_result(value :: CreditPostageResult) -> Bytes!String do
  if !postage_identity(value.recipient_account_id)
    || !postage_identity(value.batch_digest)
    || value.policy_revision == U64.parse("0")?
    || value.device_set_revision == U64.parse("0")?
    || value.enqueued_count < 1
    || value.enqueued_count > 8
    || !List.contains([1, 5, 25], value.charged_credits) do
    return Err("invalid_credit_postage_result")
  end
  let tail = case Bytes.from_list([value.enqueued_count, value.charged_credits]) do
    Err(_) -> return Err("invalid_credit_postage_result")
    Ok(value) -> value
  end
  postage_join([
    Bytes.from_hex("01504452")?,
    value.recipient_account_id,
    value.batch_digest,
    postage_wide(value.policy_revision)?,
    postage_wide(value.device_set_revision)?,
    tail
  ])
end

pub fn decode_credit_postage_result(input :: Bytes) -> CreditPostageResult!String do
  if Bytes.length(input) != 86 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01504452" do
    return Err("invalid_credit_postage_result")
  end
  let value = CreditPostageResult {
    recipient_account_id: Bytes.slice(input, 4, 32)?,
    batch_digest: Bytes.slice(input, 36, 32)?,
    policy_revision: postage_number(input, 68)?,
    device_set_revision: postage_number(input, 76)?,
    enqueued_count: Bytes.get(input, 84)?,
    charged_credits: Bytes.get(input, 85)?
  }
  encode_credit_postage_result(value)?
  Ok(value)
end

pub fn verify_credit_postage_receipt(receipt :: CreditActionReceipt,
  core :: SigningPublicKey,
  submission :: CreditActionSubmission,
  devices :: DeviceSet,
  deliveries :: List<Bytes>) -> Bool!String do
  let request = decode_credit_postage_request(submission.request_body)?
  let expected = credit_postage_request_for_devices(devices,
    deliveries,
    request.operation_nonce,
    X25519PublicKey { bytes: request.reply_public_key },
    request.action_expires_at)?
  if !Bytes.secure_equals(encode_credit_postage_request(request)?,
    encode_credit_postage_request(expected)?)
    || !Bytes.secure_equals(encode_credit_action(submission.action)?,
      encode_credit_action(credit_postage_action(request)?)?)
    || !verify_credit_action_receipt(receipt, core, submission)? do
    return Ok(false)
  end
  let result = decode_credit_postage_result(receipt.result)?
  let policy = case postage_policy_from_device_set(devices)? do
    None -> return Ok(false)
    Some(value) -> value
  end
  let earliest = if U64.compare(request.action_expires_at, U64.parse("900")?) >= 0 do
    U64.subtract(request.action_expires_at, U64.parse("900")?)?
  else
    U64.parse("0")?
  end
  Ok(Bytes.secure_equals(receipt.effect_id, credit_postage_effect_id(submission.action)?)
    && Bytes.secure_equals(result.recipient_account_id, request.recipient_account_id)
    && Bytes.secure_equals(result.batch_digest, request.batch_digest)
    && result.policy_revision == request.policy_revision
    && result.device_set_revision == request.device_set_revision
    && result.enqueued_count == List.length(deliveries)
    && result.charged_credits == policy.credits
    && List.length(submission.frame.tokens) == policy.credits
    && U64.compare(receipt.applied_at, earliest) >= 0
    && U64.compare(receipt.applied_at, request.action_expires_at) < 0)
end

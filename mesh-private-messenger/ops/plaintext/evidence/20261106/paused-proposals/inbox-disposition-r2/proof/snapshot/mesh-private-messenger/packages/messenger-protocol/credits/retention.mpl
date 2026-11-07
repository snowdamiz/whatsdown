from Credits.Action import CreditAction
from Protocol.MailboxWire import mailbox_request_is_fresh

pub struct CreditRetentionRequest do
  mailbox_hash :: Bytes
  operation_nonce :: Bytes
  days :: Int
  action_expires_at :: U64
  issued_at_ms :: U64
  signature :: Bytes
end

pub struct CreditRetentionResult do
  mailbox_hash :: Bytes
  days :: Int
  effective_until_ms :: U64
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  let builder = case BytesBuilder.new(256) do
    Err(_) -> return Err("invalid_credit_retention_request")
    Ok(value) -> value
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_credit_retention_request")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_credit_retention_request")
    Ok(value)
  end
end

fn narrow(value :: Int) -> Bytes!String do
  case Bytes.write_u16_be(value) do
    Err(_) -> Err("invalid_credit_retention_request")
    Ok(value)
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_retention_request")
    Ok(value)
  end
end

fn read_narrow(input :: Bytes, offset :: Int) -> Int!String do
  case Bytes.read_u16_be(input, offset) do
    Err(_) -> Err("invalid_credit_retention_request")
    Ok(value)
  end
end

fn read_wide(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_credit_retention_request")
    Ok(value)
  end
end

fn valid_days(days :: Int) -> Bool do
  days >= 32 && days <= 180
end

fn content(value :: CreditRetentionRequest) -> Bytes!String do
  if Bytes.length(value.mailbox_hash) != 32
    || Bytes.length(value.operation_nonce) != 32
    || Bytes.to_hex(value.operation_nonce) == String.repeat("00", 32)
    || !valid_days(value.days)
    || value.action_expires_at == U64.parse("0")?
    || value.issued_at_ms == U64.parse("0")? do
    return Err("invalid_credit_retention_request")
  end
  join([
    Bytes.from_hex("01524554")?,
    value.mailbox_hash,
    value.operation_nonce,
    narrow(value.days)?,
    wide(value.action_expires_at)?,
    wide(value.issued_at_ms)?
  ])
end

fn signing_bytes(value :: CreditRetentionRequest) -> Bytes!String do
  join([Bytes.from_utf8("morse-credit-retention-request-v1"), content(value)?])
end

pub fn encode_credit_retention_request(value :: CreditRetentionRequest) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_credit_retention_request")
  end
  join([content(value)?, value.signature])
end

pub fn decode_credit_retention_request(input :: Bytes) -> CreditRetentionRequest!String do
  if Bytes.length(input) != 150 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01524554" do
    return Err("invalid_credit_retention_request")
  end
  let value = CreditRetentionRequest {
    mailbox_hash: Bytes.slice(input, 4, 32)?,
    operation_nonce: Bytes.slice(input, 36, 32)?,
    days: read_narrow(input, 68)?,
    action_expires_at: read_wide(input, 70)?,
    issued_at_ms: read_wide(input, 78)?,
    signature: Bytes.slice(input, 86, 64)?
  }
  encode_credit_retention_request(value)?
  Ok(value)
end

pub fn sign_credit_retention_request(private :: borrow SigningPrivateKey,
  mailbox_hash :: Bytes,
  operation_nonce :: Bytes,
  days :: Int,
  action_expires_at :: U64,
  issued_at_ms :: U64) -> CreditRetentionRequest!String do
  let value = CreditRetentionRequest {
    mailbox_hash: mailbox_hash,
    operation_nonce: operation_nonce,
    days: days,
    action_expires_at: action_expires_at,
    issued_at_ms: issued_at_ms,
    signature: Bytes.empty()
  }
  let signed = case Crypto.sign(private, signing_bytes(value)?) do
    Err(_) -> return Err("credit_retention_signing_failed")
    Ok(signature) -> signature.bytes
  end
  Ok(%{value | signature: signed})
end

pub fn verify_credit_retention_request(value :: CreditRetentionRequest,
  owner :: SigningPublicKey,
  now_ms :: U64) -> Bool!String do
  encode_credit_retention_request(value)?
  if !mailbox_request_is_fresh(value.issued_at_ms, now_ms) do
    return Ok(false)
  end
  case Crypto.verify(owner, signing_bytes(value)?, Signature { bytes: value.signature }) do
    Err(_) -> Ok(false)
    Ok(valid)
  end
end

pub fn credit_retention_action(value :: CreditRetentionRequest) -> CreditAction!String do
  Ok(CreditAction {
    kind: 2,
    operation_nonce: value.operation_nonce,
    target: value.mailbox_hash,
    expires_at: value.action_expires_at,
    quantity: U64.parse(Int.to_string(value.days))?,
    request_sha256: Crypto.sha256(encode_credit_retention_request(value)?)
  })
end

pub fn encode_credit_retention_result(value :: CreditRetentionResult) -> Bytes!String do
  if Bytes.length(value.mailbox_hash) != 32
    || !valid_days(value.days)
    || value.effective_until_ms == U64.parse("0")? do
    return Err("invalid_credit_retention_result")
  end
  join([
    Bytes.from_hex("01525445")?,
    value.mailbox_hash,
    narrow(value.days)?,
    wide(value.effective_until_ms)?
  ])
end

pub fn decode_credit_retention_result(input :: Bytes) -> CreditRetentionResult!String do
  if Bytes.length(input) != 46 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01525445" do
    return Err("invalid_credit_retention_result")
  end
  let value = CreditRetentionResult {
    mailbox_hash: Bytes.slice(input, 4, 32)?,
    days: read_narrow(input, 36)?,
    effective_until_ms: read_wide(input, 38)?
  }
  encode_credit_retention_result(value)?
  Ok(value)
end

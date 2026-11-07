from Credits.Action import CreditAction
from Protocol.DirectoryWire import decode_directory_entry
from Protocol.IdentityWire import decode_account_identity

pub struct CreditSignupRequest do
  operation_nonce :: Bytes
  action_expires_at :: U64
  entry :: Bytes
end

pub struct CreditSignupResult do
  account_id :: Bytes
  entry_sha256 :: Bytes
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  let builder = case BytesBuilder.new(36054) do
    Err(_) -> return Err("invalid_credit_signup_request")
    Ok(value) -> value
  end
  for part in parts do
    case BytesBuilder.write_bytes(builder, part) do
      Err(_) -> return Err("invalid_credit_signup_request")
      Ok(_) -> nil
    end
  end
  case BytesBuilder.finish(builder) do
    Err(_) -> Err("invalid_credit_signup_request")
    Ok(value)
  end
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_signup_request")
    Ok(value)
  end
end

fn size(value :: Int) -> Bytes!String do
  case Bytes.write_u32_be(U64.parse(Int.to_string(value))?) do
    Err(_) -> Err("invalid_credit_signup_request")
    Ok(value)
  end
end

pub fn credit_signup_account(value :: CreditSignupRequest) -> Bytes!String do
  let entry = case decode_directory_entry(value.entry) do
    Err(_) -> return Err("invalid_credit_signup_request")
    Ok(value) -> value
  end
  let account = case decode_account_identity(entry.account_identity) do
    Err(_) -> return Err("invalid_credit_signup_request")
    Ok(value) -> value
  end
  Ok(account.account_id)
end

pub fn encode_credit_signup_request(value :: CreditSignupRequest) -> Bytes!String do
  if Bytes.length(value.operation_nonce) != 32
    || Bytes.to_hex(value.operation_nonce) == String.repeat("00", 32)
    || value.action_expires_at == U64.parse("0")?
    || Bytes.length(value.entry) < 1
    || Bytes.length(value.entry) > 36006 do
    return Err("invalid_credit_signup_request")
  end
  credit_signup_account(value)?
  join([
    Bytes.from_hex("01505355")?,
    value.operation_nonce,
    wide(value.action_expires_at)?,
    size(Bytes.length(value.entry))?,
    value.entry
  ])
end

pub fn decode_credit_signup_request(input :: Bytes) -> CreditSignupRequest!String do
  if Bytes.length(input) < 49
    || Bytes.length(input) > 36054
    || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01505355" do
    return Err("invalid_credit_signup_request")
  end
  let length = case Bytes.read_u32_be(input, 44) do
    Err(_) -> return Err("invalid_credit_signup_request")
    Ok(value) -> U64.to_int(value)?
  end
  if length != Bytes.length(input) - 48 do
    return Err("invalid_credit_signup_request")
  end
  let expiry = case Bytes.read_u64_be(input, 36) do
    Err(_) -> return Err("invalid_credit_signup_request")
    Ok(value) -> value
  end
  let value = CreditSignupRequest {
    operation_nonce: Bytes.slice(input, 4, 32)?,
    action_expires_at: expiry,
    entry: Bytes.slice(input, 48, length)?
  }
  encode_credit_signup_request(value)?
  Ok(value)
end

pub fn credit_signup_action(value :: CreditSignupRequest) -> CreditAction!String do
  Ok(CreditAction {
    kind: 4,
    operation_nonce: value.operation_nonce,
    target: credit_signup_account(value)?,
    expires_at: value.action_expires_at,
    quantity: U64.parse("0")?,
    request_sha256: Crypto.sha256(encode_credit_signup_request(value)?)
  })
end

pub fn encode_credit_signup_result(value :: CreditSignupResult) -> Bytes!String do
  if Bytes.length(value.account_id) != 32 || Bytes.length(value.entry_sha256) != 32 do
    return Err("invalid_credit_signup_result")
  end
  join([Bytes.from_hex("01534752")?, value.account_id, value.entry_sha256])
end

pub fn decode_credit_signup_result(input :: Bytes) -> CreditSignupResult!String do
  if Bytes.length(input) != 68 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01534752" do
    return Err("invalid_credit_signup_result")
  end
  Ok(CreditSignupResult {
    account_id: Bytes.slice(input, 4, 32)?,
    entry_sha256: Bytes.slice(input, 36, 32)?
  })
end

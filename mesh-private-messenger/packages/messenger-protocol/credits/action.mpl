from Credits.Policy import attachment_credits, retention_credits, postage_credits, signup_credits

# Canonical descriptor for a paid action, not an entitlement by itself. A caller
# must consume its core hold atomically with the action, checking actual inputs.
pub struct CreditAction do
  # 1 attachment, 2 mailbox retention, 3 recipient postage, 4 priority signup.
  kind :: Int
  operation_nonce :: Bytes
  target :: Bytes
  expires_at :: U64
  quantity :: U64
  request_sha256 :: Bytes
end

fn byte(value :: Int) -> Bytes!String do
  case Bytes.from_list([value]) do
    Err(_) -> Err("invalid_credit_action")
    Ok(output)
  end
end

fn write_wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_action")
    Ok(output)
  end
end

fn read_wide(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_credit_action")
    Ok(output)
  end
end

fn quantity(value :: CreditAction) -> Int!String do
  let maximum = if value.kind == 1 do
    "536870912"
  else
    "180"
  end
  if U64.compare(value.quantity, U64.parse(maximum)?) > 0 do
    return Err("invalid_credit_action_quantity")
  end
  case String.to_int(U64.to_string(value.quantity)) do
    None -> Err("invalid_credit_action_quantity")
    Some(output) -> Ok(output)
  end
end

fn valid(value :: CreditAction) -> Result<(), String> do
  if value.kind < 1
    || value.kind > 4
    || Bytes.length(value.operation_nonce) != 32
    || Bytes.length(value.target) != 32
    || Bytes.length(value.request_sha256) != 32
    || Bytes.secure_equals(value.operation_nonce, Bytes.from_hex(String.repeat("00", 32))?)
    || value.expires_at == U64.parse("0")? do
    return Err("invalid_credit_action")
  end
  if value.kind == 1 do
    attachment_credits(quantity(value)?)?
  else if value.kind == 2 do
    retention_credits(quantity(value)?)?
  else if value.quantity != U64.parse("0")? do
    return Err("invalid_credit_action_quantity")
  else
    0
  end
  Ok(nil)
end

pub fn encode_credit_action(value :: CreditAction) -> Bytes!String do
  valid(value)?
  let kind = byte(value.kind)?
  let first = Bytes.concat(Bytes.from_hex("01434143")?, kind)?
  let second = Bytes.concat(Bytes.concat(first, value.operation_nonce)?, value.target)?
  let third = Bytes.concat(Bytes.concat(second, write_wide(value.expires_at)?)?,
    write_wide(value.quantity)?)?
  Bytes.concat(third, value.request_sha256)
end

pub fn decode_credit_action(input :: Bytes) -> CreditAction!String do
  if Bytes.length(input) != 117 || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01434143" do
    return Err("invalid_credit_action")
  end
  let value = CreditAction {
    kind: Bytes.get(input, 4)?,
    operation_nonce: Bytes.slice(input, 5, 32)?,
    target: Bytes.slice(input, 37, 32)?,
    expires_at: read_wide(input, 69)?,
    quantity: read_wide(input, 77)?,
    request_sha256: Bytes.slice(input, 85, 32)?
  }
  valid(value)?
  Ok(value)
end

# Operation identity excludes mutable request/price fields so nonce reuse with
# another intent conflicts rather than creating a second action hold.
pub fn credit_action_id(value :: CreditAction) -> Bytes!String do
  valid(value)?
  let prefix = Bytes.concat(Bytes.from_utf8("morse-credit-hold-v1"), byte(value.kind)?)?
  Ok(Crypto.sha256(Bytes.concat(Bytes.concat(prefix, value.target)?, value.operation_nonce)?))
end

pub fn validate_credit_action(value :: CreditAction,
  request_body :: Bytes,
  now_seconds :: U64) -> Result<(), String> do
  valid(value)?
  if Bytes.length(request_body) > 65536
    || !Bytes.secure_equals(value.request_sha256, Crypto.sha256(request_body)) do
    return Err("credit_action_request_mismatch")
  end
  if U64.compare(value.expires_at, now_seconds) <= 0
    || U64.compare(value.expires_at, U64.add(now_seconds, U64.parse("900")?)?) > 0 do
    return Err("expired_credit_action")
  end
  Ok(nil)
end

# Postage and difficulty MUST come from trusted server state, never the request.
# Size/days are bounded descriptor fields; adapters must compare actual action
# parameters before consuming the matching hold.
pub fn credit_action_price(value :: CreditAction,
  server_postage :: Int,
  base_difficulty :: Int,
  current_difficulty :: Int) -> Int!String do
  valid(value)?
  case value.kind do
    1 -> attachment_credits(quantity(value)?)
    2 -> retention_credits(quantity(value)?)
    3 -> postage_credits(server_postage)
    4 -> signup_credits(base_difficulty, current_difficulty)
    _ -> Err("invalid_credit_action")
  end
end

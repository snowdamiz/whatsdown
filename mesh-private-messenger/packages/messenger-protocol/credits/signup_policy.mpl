from Credits.Policy import signup_credits

pub struct CreditSignupPolicy do
  purpose :: Int
  credits_enabled :: Bool
  base_difficulty :: Int
  current_difficulty :: Int
  issued_at :: U64
  expires_at :: U64
  signature :: Bytes
end

fn wide(value :: U64) -> Bytes!String do
  case Bytes.write_u64_be(value) do
    Err(_) -> Err("invalid_credit_signup_policy")
    Ok(value)
  end
end

fn read_wide(input :: Bytes, offset :: Int) -> U64!String do
  case Bytes.read_u64_be(input, offset) do
    Err(_) -> Err("invalid_credit_signup_policy")
    Ok(value)
  end
end

fn content(value :: CreditSignupPolicy) -> Bytes!String do
  if value.purpose < 0
    || value.purpose > 1
    || value.issued_at == U64.parse("0")?
    || value.expires_at != U64.add(value.issued_at, U64.parse("60")?)? do
    return Err("invalid_credit_signup_policy")
  end
  signup_credits(value.base_difficulty, value.current_difficulty)?
  let flags = case Bytes.from_list([
    value.purpose,
    if value.credits_enabled do
      1
    else
      0
    end,
    value.base_difficulty,
    value.current_difficulty
  ]) do
    Err(_) -> return Err("invalid_credit_signup_policy")
    Ok(value) -> value
  end
  Bytes.concat(Bytes.concat(Bytes.from_hex("01535059")?, flags)?,
    Bytes.concat(wide(value.issued_at)?, wide(value.expires_at)?)?)
end

fn signed_content(value :: CreditSignupPolicy) -> Bytes!String do
  Bytes.concat(Bytes.from_utf8("morse-credit-signup-policy-v1"), content(value)?)
end

pub fn encode_credit_signup_policy(value :: CreditSignupPolicy) -> Bytes!String do
  if Bytes.length(value.signature) != 64 do
    return Err("invalid_credit_signup_policy")
  end
  Bytes.concat(content(value)?, value.signature)
end

pub fn decode_credit_signup_policy(input :: Bytes) -> CreditSignupPolicy!String do
  if Bytes.length(input) != 88
    || Bytes.to_hex(Bytes.slice(input, 0, 4)?) != "01535059"
    || Bytes.get(input, 5)? > 1 do
    return Err("invalid_credit_signup_policy")
  end
  let value = CreditSignupPolicy {
    purpose: Bytes.get(input, 4)?,
    credits_enabled: Bytes.get(input, 5)? == 1,
    base_difficulty: Bytes.get(input, 6)?,
    current_difficulty: Bytes.get(input, 7)?,
    issued_at: read_wide(input, 8)?,
    expires_at: read_wide(input, 16)?,
    signature: Bytes.slice(input, 24, 64)?
  }
  encode_credit_signup_policy(value)?
  Ok(value)
end

pub fn sign_credit_signup_policy(private :: borrow SigningPrivateKey,
  purpose :: Int,
  credits_enabled :: Bool,
  base_difficulty :: Int,
  current_difficulty :: Int,
  now :: U64) -> CreditSignupPolicy!String do
  let value = CreditSignupPolicy {
    purpose: purpose,
    credits_enabled: credits_enabled,
    base_difficulty: base_difficulty,
    current_difficulty: current_difficulty,
    issued_at: now,
    expires_at: U64.add(now, U64.parse("60")?)?,
    signature: Bytes.empty()
  }
  let signature = case Crypto.sign(private, signed_content(value)?) do
    Err(_) -> return Err("credit_signup_policy_signing_failed")
    Ok(value) -> value.bytes
  end
  Ok(%{value | signature: signature})
end

pub fn verify_credit_signup_policy(value :: CreditSignupPolicy,
  core :: SigningPublicKey,
  purpose :: Int,
  now :: U64) -> Bool!String do
  encode_credit_signup_policy(value)?
  if value.purpose != purpose
    || U64.compare(now, value.issued_at) < 0
    || U64.compare(now, value.expires_at) >= 0 do
    return Ok(false)
  end
  case Crypto.verify(core, signed_content(value)?, Signature { bytes: value.signature }) do
    Err(_) -> Ok(false)
    Ok(valid)
  end
end

pub fn credit_signup_policy_price(value :: CreditSignupPolicy,
  core :: SigningPublicKey,
  purpose :: Int,
  now :: U64) -> Int!String do
  if !verify_credit_signup_policy(value, core, purpose, now)? do
    return Err("untrusted_credit_signup_policy")
  end
  if !value.credits_enabled do
    return Err("credit_signup_disabled")
  end
  signup_credits(value.base_difficulty, value.current_difficulty)
end

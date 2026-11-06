from Credits.SignupPolicy import (
  sign_credit_signup_policy,
  encode_credit_signup_policy,
  decode_credit_signup_policy,
  verify_credit_signup_policy,
  credit_signup_policy_price
)

fn pair() -> SigningKeyPair!String do
  case Crypto.signing_generate() do
    Err(_) -> Err("test key failed")
    Ok(value)
  end
end

fn proof() -> Bool!String do
  let core = pair()?
  let other = pair()?
  let now = U64.parse("1000")?
  let policy = sign_credit_signup_policy(core.private_key, 1, true, 16, 17, now)?
  let wire = encode_credit_signup_policy(policy)?
  assert(Bytes.length(wire) == 88)
  let decoded = decode_credit_signup_policy(wire)?
  assert(verify_credit_signup_policy(decoded, core.public_key, 1, now)?)
  assert(credit_signup_policy_price(decoded, core.public_key, 1, now)? == 20)
  assert(!verify_credit_signup_policy(decoded, other.public_key, 1, now)?)
  assert(!verify_credit_signup_policy(decoded, core.public_key, 0, now)?)
  assert(!verify_credit_signup_policy(decoded, core.public_key, 1, U64.parse("999")?)?)
  assert(!verify_credit_signup_policy(decoded, core.public_key, 1, U64.parse("1060")?)?)
  assert(!verify_credit_signup_policy(%{decoded | current_difficulty: 18},
    core.public_key,
    1,
    now)?)
  assert(!verify_credit_signup_policy(%{decoded | credits_enabled: false},
    core.public_key,
    1,
    now)?)
  assert(Result.is_err(decode_credit_signup_policy(Bytes.concat(wire, Bytes.from_utf8("x"))?)))
  assert(Result.is_err(sign_credit_signup_policy(core.private_key, 1, true, 16, 15, now)))
  assert(Result.is_err(sign_credit_signup_policy(core.private_key, 1, true, 16, 25, now)))
  let free = sign_credit_signup_policy(core.private_key, 1, true, 16, 16, now)?
  assert(credit_signup_policy_price(free, core.public_key, 1, now)? == 0)
  let disabled = sign_credit_signup_policy(core.private_key, 1, false, 16, 17, now)?
  assert(verify_credit_signup_policy(disabled, core.public_key, 1, now)?)
  assert(Result.is_err(credit_signup_policy_price(disabled, core.public_key, 1, now)))
  Ok(true)
end

test("signed signup difficulty is short lived and bound to the native core key and credit purpose") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

from Credits.MailboxExtras import (
  MailboxPolicy,
  credits_decode_claim_answer,
  credits_decode_policy,
  credits_decode_retention,
  credits_decode_retention_answer,
  credits_encode_claim_answer,
  credits_encode_retention_answer,
  credits_retention_days,
  credits_retention_price,
  credits_sign_policy,
  credits_sign_retention,
  credits_verify_policy,
  credits_verify_retention
)

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn refused<T>(value :: Result<T, String>) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

fn device() -> SigningKeyPair!String do
  case Crypto.signing_from_seed(repeated(3, 32)) do
    Err(_) -> Err("key failed")
    Ok(value)
  end
end

fn other_device() -> SigningKeyPair!String do
  case Crypto.signing_from_seed(repeated(4, 32)) do
    Err(_) -> Err("key failed")
    Ok(value)
  end
end

fn policies() -> Bool!String do
  let key = device()?
  let other = other_device()?
  let signed = credits_sign_policy(key.private_key, repeated(9, 32), 1790000000000, 5)?
  let policy = credits_decode_policy(signed)?
  let raised = Bytes.concat(Bytes.slice(signed, 0, 44)?, Bytes.from_hex("19")?)?
  let forged = Bytes.concat(raised, Bytes.slice(signed, 45, 64)?)?
  Ok(Bytes.length(signed) == 109
    && policy.postage == 5
    && policy.sequence == 1790000000000
    && Bytes.secure_equals(policy.mailbox_hash, repeated(9, 32))
    && credits_verify_policy(policy, key.public_key.bytes)
    && !credits_verify_policy(policy, other.public_key.bytes)
    && !credits_verify_policy(credits_decode_policy(forged)?, key.public_key.bytes)
    && refused(credits_sign_policy(key.private_key, repeated(9, 32), 1, 2))
    && refused(credits_decode_policy(Bytes.concat(signed, Bytes.from_hex("00")?)?)))
end

test("a mailbox policy is the device's signed price, and nobody else can raise it") do
  case policies() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn retention() -> Bool!String do
  let key = device()?
  let request = credits_sign_retention(key.private_key, repeated(9, 32), 3, 1790000000000)?
  let decoded = credits_decode_retention(request)?
  Ok(decoded.periods == 3
    && credits_verify_retention(decoded, key.public_key.bytes)
    && credits_retention_days(3) == 120
    && credits_retention_price(3) == 30
    && credits_retention_days(5) == 180
    && credits_decode_retention_answer(credits_encode_retention_answer(120,
      1790000000000)?) == Ok((120, 1790000000000))
    && refused(credits_sign_retention(key.private_key, repeated(9, 32), 6, 1790000000000))
    && refused(credits_sign_retention(key.private_key, repeated(9, 32), 0, 1790000000000)))
end

test("a storage request names 1 to 5 extra 30-day periods, 10 credits each") do
  case retention() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn claims() -> Bool!String do
  let key = device()?
  let policy = credits_sign_policy(key.private_key, repeated(9, 32), 7, 1)?
  let (bundle, found) = credits_decode_claim_answer(credits_encode_claim_answer(Bytes.from_utf8("PKB"),
    Some(policy))?)?
  let (_same, none) = credits_decode_claim_answer(credits_encode_claim_answer(Bytes.from_utf8("PKB"),
    None)?)?
  Ok(Bytes.secure_equals(bundle, Bytes.from_utf8("PKB"))
    && case found do
      Some(value) -> value.postage == 1
      None -> false
    end
    && none == None)
end

test("a version 2 prekey claim answers the bundle with the mailbox's policy") do
  case claims() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

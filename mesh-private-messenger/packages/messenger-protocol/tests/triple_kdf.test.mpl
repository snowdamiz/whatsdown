from Session.TripleKdf import triple_message_material
from Session.State import RatchetError

fn triple_test_bytes(value :: Int, length :: Int) -> Bytes!RatchetError do
  case Bytes.repeat(value, length) do
    Err(_) -> Err(InvalidMessage)
    Ok(value)
  end
end

fn triple_test_secret(name :: String) -> SecretBytes!RatchetError do
  case Env.get_secret_hex(name) do
    Err(_) -> Err(CryptoFailure)
    Ok(value)
  end
end

fn triple_test_vector(ec_name :: String,
  pq_name :: String,
  configuration :: Int,
  session :: Int,
  expected :: String) -> Bool!RatchetError do
  let ec = triple_test_secret(ec_name)?
  let pq = triple_test_secret(pq_name)?
  let combined = triple_message_material(triple_test_bytes(configuration, 32)?,
    triple_test_bytes(session, 32)?,
    ec,
    pq)?
  let tag = case Crypto.hmac_sha256_tag(combined,
    Bytes.from_utf8("TEST ONLY Morse triple combiner oracle v1")) do
    Err(_) -> return Err(CryptoFailure)
    Ok(value) -> value
  end
  Secret.destroy(combined)
  let wanted = case Bytes.from_hex(expected) do
    Err(_) -> return Err(InvalidMessage)
    Ok(value) -> value
  end
  Ok(Bytes.secure_equals(tag, wanted))
end

fn triple_test_refusal(configuration_length :: Int, session_length :: Int) -> Bool!RatchetError do
  let ec = triple_test_secret("MORSE_C1_TRIPLE_EC")?
  let pq = triple_test_secret("MORSE_C1_TRIPLE_PQ")?
  Ok(case triple_message_material(triple_test_bytes(17, configuration_length)?,
    triple_test_bytes(34, session_length)?,
    ec,
    pq) do
    Err(InvalidMessage) -> true
    _ -> false
  end)
end

test("triple combiner matches independent vectors for both keys and scope") do
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_EC",
      "MORSE_C1_TRIPLE_PQ",
      17,
      34,
      "8807be105bad137239092358e322fee0162e50a2c0706a7f5f23f3403b6c4e0d"),
    false))
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_CHANGED_EC",
      "MORSE_C1_TRIPLE_PQ",
      17,
      34,
      "0a9bb517e44d3da73c17beabb7b726f7831a9867fd5213006cdcff0fc78bbc80"),
    false))
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_EC",
      "MORSE_C1_TRIPLE_CHANGED_PQ",
      17,
      34,
      "24e22e5bff26e7eea665534dc765e798569ec7d209c919063f619d47c57e2d72"),
    false))
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_PQ",
      "MORSE_C1_TRIPLE_EC",
      17,
      34,
      "2e86e4eb19b981ea708da70b89ceefc87a3b1fee23d0a249010a3b5550f87686"),
    false))
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_EC",
      "MORSE_C1_TRIPLE_PQ",
      18,
      34,
      "2ab7fdbeae9215770a8c44e087d54a8b983d9c56e7116aeb9d506661eeb5f5b5"),
    false))
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_EC",
      "MORSE_C1_TRIPLE_PQ",
      17,
      35,
      "152cef444887176d2842dd06b5cecbf9377e7784e82bd931136b7421ee6de479"),
    false))
end

test("triple combiner rejects malformed scope with a valid control") do
  assert(Result.unwrap_or(triple_test_refusal(0, 32), false))
  assert(Result.unwrap_or(triple_test_refusal(31, 32), false))
  assert(Result.unwrap_or(triple_test_refusal(33, 32), false))
  assert(Result.unwrap_or(triple_test_refusal(32, 0), false))
  assert(Result.unwrap_or(triple_test_refusal(32, 31), false))
  assert(Result.unwrap_or(triple_test_refusal(32, 33), false))
  assert(Result.unwrap_or(triple_test_vector("MORSE_C1_TRIPLE_EC",
      "MORSE_C1_TRIPLE_PQ",
      17,
      34,
      "8807be105bad137239092358e322fee0162e50a2c0706a7f5f23f3403b6c4e0d"),
    false))
end

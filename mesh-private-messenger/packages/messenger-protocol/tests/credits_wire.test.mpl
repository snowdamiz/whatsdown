from Credits.Wire import (
  CreditToken,
  CreditTokenInput,
  CreditTokenRequest,
  CreditFrame,
  encode_token_input,
  decode_token_input,
  encode_credit_token,
  decode_credit_token,
  encode_token_request,
  decode_token_request,
  credit_nullifier,
  credit_challenge,
  encode_credit_frame,
  decode_credit_frame,
  check_credit_frame
)

fn bytes(value :: String, count :: Int) -> Bytes!String do
  Bytes.from_hex(String.repeat(value, count))
end

fn token(nonce :: String) -> CreditToken!String do
  Ok(CreditToken {
    input: CreditTokenInput {
      nonce: bytes(nonce, 32)?,
      challenge_digest: bytes("22", 32)?,
      token_key_id: bytes("33", 32)?
    },
    authenticator: bytes("44", 256)?
  })
end

fn canonical() -> Bool!String do
  let value = token("11")?
  let input = "0002"
    <> String.repeat("11", 32)
    <> String.repeat("22", 32)
    <> String.repeat("33", 32)
  assert(Bytes.to_hex(encode_token_input(value.input)?) == input)
  assert(Bytes.to_hex(encode_credit_token(value)?) == input <> String.repeat("44", 256))
  assert(Bytes.secure_equals(encode_token_input(decode_token_input(Bytes.from_hex(input)?)?)?,
    Bytes.from_hex(input)?))
  let decoded = decode_credit_token(encode_credit_token(value)?)?
  assert(Bytes.secure_equals(decoded.input.nonce, value.input.nonce))
  assert(Bytes.secure_equals(decoded.authenticator, value.authenticator))
  # Independent SHA-256 vector for the fixed 98-byte input, not the signature.
  assert(Bytes.to_hex(credit_nullifier(value.input)?) == "2231252dd24d0b4bcc1b7dc28b8a76ecebbbbac3dae00b8de0d3a40c852836cc")
  let request = CreditTokenRequest { truncated_key_id: 51, blinded_message: bytes("55", 256)? }
  assert(Bytes.to_hex(encode_token_request(request)?) == "000233" <> String.repeat("55", 256))
  let restored = decode_token_request(encode_token_request(request)?)?
  assert(restored.truncated_key_id == 51)
  assert(Bytes.secure_equals(restored.blinded_message, request.blinded_message))
  Ok(true)
end

test("Privacy Pass type 2 has canonical input, token and request bytes") do
  case canonical() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn rejects() -> Bool!String do
  let value = token("11")?
  let wire = encode_credit_token(value)?
  for length in [0, 1, 97, 98, 353] do
    assert(Result.is_err(decode_credit_token(Bytes.slice(wire, 0, length)?)))
  end
  assert(Result.is_err(decode_credit_token(Bytes.concat(wire, bytes("00", 1)?)?)))
  assert(Result.is_err(decode_credit_token(Bytes.concat(Bytes.from_hex("0001")?,
    Bytes.slice(wire, 2, 352)?)?)))
  assert(Result.is_err(decode_token_input(wire)))
  assert(Result.is_err(encode_token_input(%{value.input | nonce: bytes("11", 31)?})))
  assert(Result.is_err(encode_token_input(%{value.input | challenge_digest: bytes("22", 33)?})))
  assert(Result.is_err(encode_credit_token(%{value | authenticator: bytes("44", 255)?})))
  for key_id in [-1, 256] do
    assert(Result.is_err(encode_token_request(CreditTokenRequest {
      truncated_key_id: key_id,
      blinded_message: bytes("55", 256)?
    })))
  end
  assert(Result.is_err(decode_token_request(bytes("00", 259)?)))
  Ok(true)
end

test("credit codecs reject noncanonical types, lengths and trailing bytes") do
  case rejects() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn frames() -> Bool!String do
  let first = token("11")?
  let second = token("12")?
  let payload = Bytes.from_utf8("request-body")
  let frame = CreditFrame { binding: Crypto.sha256(payload), tokens: [first, second] }
  let encoded = encode_credit_frame(frame)?
  assert(Bytes.length(encoded) == 38 + 354 * 2)
  assert(Bytes.to_hex(Bytes.slice(encoded, 0, 4)?) == "01435244")
  let decoded = decode_credit_frame(encoded)?
  assert(List.length(check_credit_frame(decoded, payload, 2)?) == 2)
  assert(Result.is_err(check_credit_frame(decoded, Bytes.from_utf8("other-body"), 2)))
  assert(Result.is_err(check_credit_frame(decoded, payload, 1)))
  assert(Result.is_err(check_credit_frame(decoded, payload, 3)))
  assert(Result.is_err(encode_credit_frame(%{frame | tokens: []})))
  assert(Result.is_err(encode_credit_frame(%{frame | tokens: [first, first]})))
  # Altering a signature does not create a different spendable token.
  assert(Result.is_err(encode_credit_frame(%{frame |
    tokens: [first, %{first | authenticator: bytes("99", 256)?}]
  })))
  let duplicate_wire = Bytes.concat(Bytes.slice(encoded, 0, 38)?,
    Bytes.concat(encode_credit_token(first)?, encode_credit_token(first)?)?)?
  assert(Result.is_err(decode_credit_frame(duplicate_wire)))
  assert(Result.is_err(decode_credit_frame(Bytes.concat(encoded, bytes("00", 1)?)?)))
  let maximum = for index in 0..64 do
    %{first | input: %{first.input | nonce: Crypto.sha256(Bytes.from_utf8(Int.to_string(index)))}}
  end
  assert(List.length(decode_credit_frame(encode_credit_frame(%{frame |
    tokens: maximum
  })?)?.tokens) == 64)
  assert(Result.is_err(encode_credit_frame(%{frame | tokens: maximum ++ [second]})))
  Ok(true)
end

test("CRD binds one exact request and rejects duplicate nullifiers as a whole") do
  case frames() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

fn challenges() -> Bool!String do
  let service_key = bytes("ab", 32)?
  let live = credit_challenge(service_key, 0)?
  let test_value = credit_challenge(service_key, 1)?
  assert(Bytes.to_hex(live) == "6d6f7273652d6372656469742d763100"
      <> String.repeat("ab", 32)
      <> "00")
  assert(!Bytes.secure_equals(live, test_value))
  assert(!Bytes.secure_equals(live, credit_challenge(bytes("cd", 32)?, 0)?))
  assert(Result.is_err(credit_challenge(service_key, 2)))
  assert(Result.is_err(credit_challenge(bytes("ab", 31)?, 0)))
  Ok(true)
end

test("credit challenges are shared per service and separate live from test") do
  case challenges() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

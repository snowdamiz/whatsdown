from Credits.Wire import (
  decode_credit_token,
  encode_credit_token,
  encode_token_input,
  decode_token_request,
  encode_token_request,
  credit_nullifier
)

fn fixture(roots :: List<String>) -> String!String do
  if List.length(roots) == 0 do
    return Err("RFC9578 credit vectors not found")
  end
  case File.read(List.head(roots) <> "/tests/fixtures/credits/rfc9578-type2.json") do
    Ok(contents)
    Err(_) -> fixture(List.tail(roots))
  end
end

fn field(row :: Json, name :: String) -> Bytes!String do
  Bytes.from_hex(Json.as_string(Json.object_get(row, name)?)?)
end

fn vectors() -> Bool!String do
  let parsed = Json.parse(fixture([
    ".",
    "packages/messenger-protocol",
    "mesh-private-messenger/packages/messenger-protocol"
  ])?)?
  let cases = Json.object_get(parsed, "vectors")?
  assert(Json.array_length(cases)? == 5)
  for index in 0..5 do
    let row = Json.array_get(cases, index)?
    let token = decode_credit_token(field(row, "token")?)?
    assert(Bytes.secure_equals(encode_credit_token(token)?, field(row, "token")?))
    assert(Bytes.secure_equals(encode_token_input(token.input)?, field(row, "token_input")?))
    assert(Bytes.secure_equals(token.input.nonce, field(row, "nonce")?))
    assert(Bytes.secure_equals(token.input.challenge_digest,
      Crypto.sha256(field(row, "token_challenge")?)))
    assert(Bytes.secure_equals(token.input.token_key_id, Crypto.sha256(field(row, "pkI")?)))
    assert(Bytes.secure_equals(token.authenticator, field(row, "authenticator")?))
    assert(Bytes.secure_equals(credit_nullifier(token.input)?,
      Crypto.sha256(field(row, "token_input")?)))
    let request = decode_token_request(field(row, "token_request")?)?
    assert(request.truncated_key_id == Bytes.get(token.input.token_key_id, 31)?)
    assert(Bytes.secure_equals(encode_token_request(request)?, field(row, "token_request")?))
    let public = case Crypto.blind_rsa_public_from_spki(field(row, "pkI")?) do
      Err(_) -> return Err("RFC9578 public key rejected")
      Ok(value) -> value
    end
    case Crypto.blind_rsa_verify(public, encode_token_input(token.input)?, token.authenticator) do
      Ok(valid) -> assert(valid)
      Err(_) -> return Err("RFC9578 token rejected")
    end
  end
  Ok(true)
end

test("all five RFC9578 Type 2 tokens cross the Morse codecs and Mesh verifier") do
  case vectors() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

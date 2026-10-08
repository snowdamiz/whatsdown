from Credits.CreditToken import (
  CreditToken,
  credits_challenge,
  credits_decode_challenge,
  credits_decode_token,
  credits_encode_challenge,
  credits_encode_token,
  credits_issuer_name,
  credits_nullifier,
  credits_token_input
)

fn fixture_path() -> String do
  let candidates = [
    Env.get("MESSENGER_CREDITS_FIXTURE_DIR", ""),
    "mesh-private-messenger/tests/fixtures/credits",
    "../mesh-private-messenger/tests/fixtures/credits",
    "tests/fixtures/credits",
    "../../tests/fixtures/credits"
  ]
  case List.find(candidates,
    fn dir -> dir != "" && File.exists(dir <> "/rfc9578-type2.json") end) do
    Some(dir) -> dir <> "/rfc9578-type2.json"
    None -> ""
  end
end

fn field(vector :: Json, name :: String) -> Bytes!String do
  Bytes.from_hex(Json.as_string(Json.object_get(vector, name)?)?)
end

fn slice(value :: Bytes, start :: Int, length :: Int) -> Bytes!String do
  Bytes.slice(value, start, length)
end

# Every RFC 9578 type-2 token decodes to the layout Morse uses: its key ID is
# the SHA-256 of the SPKI, its challenge digest the SHA-256 of the challenge,
# and the challenge re-encodes byte for byte.

fn rfc_vector(vector :: Json) -> Bool!String do
  let challenge = field(vector, "token_challenge")?
  let token_bytes = field(vector, "token")?
  let token = credits_decode_token(token_bytes)?
  let reencoded = credits_encode_challenge(credits_decode_challenge(challenge)?)?
  Ok(Bytes.secure_equals(token.token_key_id, Crypto.sha256(field(vector, "pkI")?))
    && Bytes.secure_equals(token.challenge_digest, Crypto.sha256(challenge))
    && Bytes.secure_equals(token.nonce, field(vector, "nonce")?)
    && Bytes.secure_equals(reencoded, challenge)
    && Bytes.secure_equals(credits_encode_token(token)?, token_bytes)
    && Bytes.secure_equals(credits_nullifier(token_bytes)?,
      Crypto.sha256(slice(token_bytes, 0, 98)?)))
end

fn rfc_vectors() -> Int!String do
  let path = fixture_path()
  if path == "" do
    Err("credits fixtures not found; set MESSENGER_CREDITS_FIXTURE_DIR")
  else
    let vectors = Json.object_get(Json.parse(File.read(path)?)?, "vectors")?
    let count = Json.array_length(vectors)?
    let passed = for index in 0..count do
      case Json.array_get(vectors, index) do
        Err(_) -> false
        Ok(vector) -> rfc_vector(vector) == Ok(true)
      end
    end
    Ok(List.length(List.filter(passed, fn value -> value end)))
  end
end

test("RFC 9578 type-2 tokens decode to the Morse token layout") do
  case rfc_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(passed) -> assert_eq(passed, 5)
  end
end

test("the Morse challenge names the issuer host and morseapp.io, with no redemption context") do
  let expected = "0002"
    <> "0013"
    <> Bytes.to_hex(Bytes.from_utf8("credits.morseapp.io"))
    <> "00"
    <> "000b"
    <> Bytes.to_hex(Bytes.from_utf8("morseapp.io"))
  case credits_challenge("credits.morseapp.io") do
    Err(_) -> assert(false)
    Ok(challenge) -> assert_eq(Bytes.to_hex(challenge), expected)
  end
end

fn refused<T>(value :: Result<T, String>) -> Bool do
  case value do
    Err(_) -> true
    Ok(_) -> false
  end
end

test("the issuer name is the host of an https origin and nothing else") do
  assert(credits_issuer_name("https://credits.morseapp.io") == Ok("credits.morseapp.io"))
  assert(refused(credits_issuer_name("http://credits.morseapp.io")))
  assert(refused(credits_issuer_name("https://credits.morseapp.io/v1")))
  assert(refused(credits_issuer_name("https://me@credits.morseapp.io")))
  assert(refused(credits_issuer_name("https://Credits.morseapp.io")))
  assert(refused(credits_challenge("credits.morseapp.io:443")))
end

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn malformed_tokens() -> Bool!String do
  let token = credits_encode_token(CreditToken {
    nonce: repeated(1, 32),
    challenge_digest: repeated(2, 32),
    token_key_id: repeated(3, 32),
    authenticator: repeated(4, 256)
  })?
  let input = credits_token_input(repeated(1, 32), repeated(2, 32), repeated(3, 32))?
  let wrong_type = Bytes.concat(Bytes.from_hex("0001")?, slice(token, 2, 352)?)?
  let trailing = Bytes.concat(token, Bytes.from_hex("00")?)?
  Ok(Bytes.length(token) == 354
    && Bytes.secure_equals(slice(token, 0, 98)?, input)
    && refused(credits_decode_token(wrong_type))
    && refused(credits_decode_token(trailing))
    && refused(credits_decode_token(slice(token, 0, 353)?))
    && refused(credits_decode_challenge(Bytes.concat(credits_challenge("a.example")?,
      Bytes.from_hex("00")?)?)))
end

test("tokens and challenges refuse other types, lengths and trailing bytes") do
  case malformed_tokens() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

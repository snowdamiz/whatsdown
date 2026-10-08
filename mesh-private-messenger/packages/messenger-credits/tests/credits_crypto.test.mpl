from Credits.CreditCrypto import (
  credits_blind_batch,
  credits_new_inputs,
  credits_verify_authenticator,
  credits_verify_token
)
from Credits.IssuerKey import credits_issuer_key
from Credits.CreditToken import credits_decode_token, credits_token_key_id

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

fn crypto(value :: Result<Bytes, CryptoError>) -> Bytes!String do
  case value do
    Err(_) -> Err("crypto failed")
    Ok(output)
  end
end

# The RFC's tokens carry the RFC's own challenges (issuer.example): each
# verifies as an RSA signature under pkI, and a flipped bit does not.

fn rfc_vector(vector :: Json) -> Bool!String do
  let spki = field(vector, "pkI")?
  let token = field(vector, "token")?
  let last = if Bytes.get(token, 353) == Ok(0) do
    "01"
  else
    "00"
  end
  let flipped = Bytes.concat(Bytes.slice(token, 0, 353)?, Bytes.from_hex(last)?)?
  Ok(credits_verify_authenticator(spki, token)? && !credits_verify_authenticator(spki, flipped)?)
end

fn rfc_vectors() -> Int!String do
  let path = fixture_path()
  if path == "" do
    Err("credits fixtures not found; set MESSENGER_CREDITS_FIXTURE_DIR")
  else
    let vectors = Json.object_get(Json.parse(File.read(path)?)?, "vectors")?
    let results = for index in 0..Json.array_length(vectors)? do
      case Json.array_get(vectors, index) do
        Err(_) -> false
        Ok(vector) -> rfc_vector(vector) == Ok(true)
      end
    end
    Ok(List.length(List.filter(results, fn value -> value end)))
  end
end

test("RFC 9578 type-2 tokens verify under their key, and a flipped bit does not") do
  case rfc_vectors() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(passed) -> assert_eq(passed, 5)
  end
end

# One token by hand: the issuer signs a blinded Morse input; the result is a
# Morse credit for its key only, and only under the Morse challenge.

fn one_token() -> Bool!String do
  let issuer = case Crypto.blind_rsa_generate() do
    Err(_) -> Err("key generation failed")
    Ok(value)
  end?
  let other = case Crypto.blind_rsa_generate() do
    Err(_) -> Err("key generation failed")
    Ok(value)
  end?
  let public = case Crypto.blind_rsa_public(issuer) do
    Err(_) -> Err("public key failed")
    Ok(value)
  end?
  let other_public = case Crypto.blind_rsa_public(other) do
    Err(_) -> Err("public key failed")
    Ok(value)
  end?
  let key = credits_issuer_key(2, "credits.morseapp.io", 690, public.bytes)?
  let input = List.get(credits_new_inputs(key, 1)?, 0)
  let blinded = case Crypto.blind_rsa_blind(public, input) do
    Err(_) -> Err("blinding failed")
    Ok(value)
  end?
  let request = blinded.blinded
  let signature = crypto(Crypto.blind_rsa_sign(issuer, request))?
  let authenticator = crypto(Crypto.blind_rsa_finalize(public, input, signature, blinded.state))?
  let token = Bytes.concat(input, authenticator)?
  let decoded = credits_decode_token(token)?
  Ok(credits_verify_token(key, token)?
    && Bytes.secure_equals(decoded.token_key_id, credits_token_key_id(public.bytes))
    && !credits_verify_token(%{key | spki: other_public.bytes}, token)?
    && !credits_verify_token(%{key | issuer_name: "other.morseapp.io"}, token)?)
end

test("a Morse token verifies under its issuer key and challenge only") do
  case one_token() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn failing_exchange() -> Bool!String do
  let issuer = case Crypto.blind_rsa_generate() do
    Err(_) -> Err("key generation failed")
    Ok(value)
  end?
  let public = case Crypto.blind_rsa_public(issuer) do
    Err(_) -> Err("public key failed")
    Ok(value)
  end?
  let key = credits_issuer_key(2, "credits.morseapp.io", 690, public.bytes)?
  let inputs = credits_new_inputs(key, 3)?
  let garbage = credits_blind_batch(key,
    inputs,
    fn blinded -> Ok(List.map(blinded, fn value -> value end)) end)
  let short = credits_blind_batch(key, inputs, fn blinded -> Ok(List.drop(blinded, 1)) end)
  let offline = credits_blind_batch(key, inputs, fn _blinded -> Err("issuer offline") end)
  Ok(garbage == Err("credit signature does not verify")
    && short == Err("the issuer answered a different number of signatures")
    && offline == Err("issuer offline"))
end

test("a batch fails whole when the issuer's answer does not finalize") do
  case failing_exchange() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

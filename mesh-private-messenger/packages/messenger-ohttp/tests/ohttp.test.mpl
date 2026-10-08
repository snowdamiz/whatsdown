from Privacy.Bhttp import bhttp_decode_request, bhttp_decode_response
from Privacy.Ohttp import (
  OhttpContext,
  ohttp_decapsulate_request,
  ohttp_decapsulate_response,
  ohttp_encapsulate_request,
  ohttp_encapsulate_response
)
from Privacy.OhttpWire import (
  OhttpKeyConfig,
  ohttp_request_key_id,
  ohttp_request_message,
  ohttp_response_message
)

fn hex(text :: String) -> Bytes!String do
  case Bytes.from_hex(text) do
    Err(_) -> Err("bad hex in test")
    Ok(value)
  end
end

fn text(bytes :: Bytes) -> String!String do
  case Bytes.to_utf8(bytes) do
    Err(_) -> Err("not UTF-8")
    Ok(value)
  end
end

fn slice(input :: Bytes, offset :: Int, length :: Int) -> Bytes!String do
  case Bytes.slice(input, offset, length) do
    Err(_) -> Err("slice failed")
    Ok(value)
  end
end

fn repeated(value :: Int, length :: Int) -> Bytes!String do
  case Bytes.repeat(value, length) do
    Err(_) -> Err("repeat failed")
    Ok(bytes)
  end
end

fn join(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts,
    Ok(Bytes.empty()),
    fn acc, part -> case acc do
      Err(error)
      Ok(bytes) -> case Bytes.concat(bytes, part) do
        Err(_) -> Err("concat failed")
        Ok(value)
      end
    end end)
end

fn refused<T>(result :: Result<T, String>) -> Bool do
  case result do
    Ok(_) -> false
    Err(_) -> true
  end
end

fn refused_with<T>(result :: Result<T, String>, expected :: String) -> Bool do
  case result do
    Ok(_) -> false
    Err(error) -> error == expected
  end
end

fn open_error(result :: Result<(Bytes, OhttpContext), String>) -> String do
  case result do
    Ok(_) -> ""
    Err(error) -> error
  end
end

fn replaced(input :: Bytes, offset :: Int, value :: Int) -> Bytes!String do
  let head = case Bytes.slice(input, 0, offset) do
    Err(_) -> Err("slice failed")
    Ok(bytes)
  end?
  let tail = case Bytes.slice(input, offset + 1, Bytes.length(input) - offset - 1) do
    Err(_) -> Err("slice failed")
    Ok(bytes)
  end?
  let middle = case Bytes.from_list([value]) do
    Err(_) -> Err("byte failed")
    Ok(bytes)
  end?
  join([head, middle, tail])
end

fn flipped(input :: Bytes, offset :: Int) -> Bytes!String do
  let old = case Bytes.get(input, offset) do
    Err(_) -> Err("get failed")
    Ok(value)
  end?
  replaced(input, offset, (old + 1) % 256)
end

fn gateway_pair() -> X25519KeyPair!String do
  case Crypto.x25519_from_seed(hex("3c168975674b2fa8e465970b79c8dcf09f1c741626480bd4c6162fc5b6a98e1a")?) do
    Err(_) -> Err("gateway key failed")
    Ok(pair)
  end
end

fn known_answer_proof() -> Bool!String do
  let pair = gateway_pair()?
  let encapsulated = hex("010020000100034b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472c956d3d9bc7cb56a25766a5ad36c4d5c3f40480e331005e514b03bd29c38e1dc74753d6e1c310fdd7f")?
  assert(ohttp_request_key_id(encapsulated)? == 1)
  let (request, context) = ohttp_decapsulate_request(1, pair.private_key, encapsulated)?
  assert(Bytes.to_hex(request) == "00034745540568747470730b6578616d706c652e636f6d012f")
  let response = ohttp_decapsulate_response(context,
    hex("c789e7151fcba46158ca84b04464910dc789e7151fcba46158ca84b04464910d682d0cfaf89cd461faeca9b2451f504fc3d432")?)?
  assert(Bytes.to_hex(response) == "0140c8")
  Ok(true)
end

test("the gateway opens an independently encapsulated request and reads its known response") do
  case known_answer_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn refusal_proof() -> Bool!String do
  let pair = gateway_pair()?
  let encapsulated = hex("010020000100034b28f881333e7c164ffc499ad9796f877f4e1051ee6d31bad19dec96c208b472c956d3d9bc7cb56a25766a5ad36c4d5c3f40480e331005e514b03bd29c38e1dc74753d6e1c310fdd7f")?
  # The key a request names is the one it must be opened with.
  assert(open_error(ohttp_decapsulate_request(2,
    pair.private_key,
    encapsulated)) == "ohttp_unknown_key")
  assert(open_error(ohttp_decapsulate_request(1,
    pair.private_key,
    replaced(encapsulated, 0, 2)?)) == "ohttp_unknown_key")
  # Another KEM, KDF or AEAD is refused before anything is decrypted.
  assert(open_error(ohttp_decapsulate_request(1,
    pair.private_key,
    replaced(encapsulated, 6, 1)?)) == "ohttp_unsupported_suite")
  assert(open_error(ohttp_decapsulate_request(1,
    pair.private_key,
    replaced(encapsulated, 2, 16)?)) == "ohttp_unsupported_suite")
  # A changed byte of the ciphertext or of enc fails authentication.
  let last = Bytes.length(encapsulated) - 1
  assert(open_error(ohttp_decapsulate_request(1,
    pair.private_key,
    flipped(encapsulated, last)?)) == "ohttp_decryption_failed")
  assert(open_error(ohttp_decapsulate_request(1,
    pair.private_key,
    flipped(encapsulated, 10)?)) == "ohttp_decryption_failed")
  assert(open_error(ohttp_decapsulate_request(1,
    pair.private_key,
    hex("0100200001000301")?)) == "ohttp_malformed")
  # A tampered response, or one for another request, is refused.
  let (_, context) = ohttp_decapsulate_request(1, pair.private_key, encapsulated)?
  let good = hex("c789e7151fcba46158ca84b04464910dc789e7151fcba46158ca84b04464910d682d0cfaf89cd461faeca9b2451f504fc3d432")?
  assert(refused(ohttp_decapsulate_response(context, flipped(good, Bytes.length(good) - 1)?)))
  assert(refused(ohttp_decapsulate_response(context, flipped(good, 0)?)))
  assert(refused(ohttp_decapsulate_response(context, hex("c789")?)))
  let config = OhttpKeyConfig { key_id: 1, public_key: pair.public_key.bytes }
  let (_, other) = ohttp_encapsulate_request(config, Bytes.from_utf8("another"))?
  assert(refused(ohttp_decapsulate_response(other, good)))
  Ok(true)
end

test("a tampered message, a wrong key id or another suite is refused") do
  case refusal_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn round_trip_proof() -> Bool!String do
  let pair = gateway_pair()?
  let config = OhttpKeyConfig { key_id: 1, public_key: pair.public_key.bytes }
  let message = ohttp_request_message("POST", "/v1/devices/resolve", Bytes.from_utf8("lookup"))?
  let (sent, client) = ohttp_encapsulate_request(config, message)?
  # What a relay forwards holds no plaintext: not the path, not the body.
  assert(!String.contains(Bytes.to_hex(sent), Bytes.to_hex(Bytes.from_utf8("resolve"))))
  assert(!String.contains(Bytes.to_hex(sent), Bytes.to_hex(Bytes.from_utf8("lookup"))))
  let (received, gateway) = ohttp_decapsulate_request(1, pair.private_key, sent)?
  let request = bhttp_decode_request(received)?
  assert(request.method == "POST" && request.path == "/v1/devices/resolve")
  assert(text(request.content)? == "lookup")
  # Every encapsulation is fresh, so the same message twice looks different.
  let (again, _) = ohttp_encapsulate_request(config, message)?
  assert(!Bytes.secure_equals(slice(sent, 7, 32)?, slice(again, 7, 32)?))
  # A response as large as a full mailbox batch goes back in one piece.
  let batch = repeated(9, 524949)?
  let answer = ohttp_encapsulate_response(gateway, ohttp_response_message(200, batch)?)?
  let opened = bhttp_decode_response(ohttp_decapsulate_response(client, answer)?)?
  assert(opened.status == 200 && Bytes.secure_equals(opened.content, batch))
  Ok(true)
end

test("a request and a mailbox-sized response round trip between client and gateway") do
  case round_trip_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

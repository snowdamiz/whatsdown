from Privacy.Edge import AnonymousAbuseToken, PrivacySubmission, RequestStamp, decode_privacy_submission, decode_stamped_request, encode_privacy_submission, encode_stamped_request, mint_request_stamp, mint_submission, open_delivery_with_key, request_stamp_key, seal_delivery, verify_request_stamp, verify_submission
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope

fn repeated(value :: Int, count :: Int) -> Bytes ! String do
  case Bytes.repeat(value, count) do
    Err( _) -> Err("bytes failed")
    Ok( output) -> Ok(output)
  end
end

fn wide(value :: String) -> U64 ! String do
  U64.parse(value)
end

fn protocol(value :: Result < Bytes, ProtocolError >) -> Bytes ! String do
  case value do
    Err( _) -> Err("protocol failed")
    Ok( output) -> Ok(output)
  end
end

fn key_pair() -> X25519KeyPair ! String do
  case Crypto.x25519_from_seed(Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a") ?) do
    Err( _) -> Err("key failed")
    Ok( value) -> Ok(value)
  end
end

fn token_rejects_alternate(expires_at :: U64,
nonce :: Int,
public_key :: X25519PublicKey,
attempt :: Int) -> Bool ! String do
  if attempt >= 16 do
    Ok(false)
  else
    let sealed = seal_delivery(protocol(encode_outer_envelope(OuterEnvelope {
      version : 1,
      envelope_id : repeated(4 + attempt, 16) ?,
      mailbox_token : repeated(2, 32) ?,
      suite : 1,
      expiration : wide("4102444800000") ?,
      padding_bucket : 256,
      ciphertext : repeated(3, 32) ?
    })) ?,
    public_key) ?
    let encoded = encode_privacy_submission(PrivacySubmission {
      token : AnonymousAbuseToken {
        expires_at : expires_at,
        nonce : nonce
      },
      sealed : sealed
    }) ?
    if verify_submission(encoded, wide("1000") ?, wide("5000") ?, 8) ? do
      token_rejects_alternate(expires_at, nonce, public_key, attempt + 1)
    else
      Ok(true)
    end
  end
end

fn edge_proof() -> Bool ! String do
  let pair = key_pair() ?
  let public_key = pair.public_key
  let outer = protocol(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(1, 16) ?,
    mailbox_token : repeated(2, 32) ?,
    suite : 1,
    expiration : wide("4102444800000") ?,
    padding_bucket : 256,
    ciphertext : repeated(3, 32) ?
  })) ?
  let sealed = seal_delivery(outer, public_key) ?
  let submission = mint_submission(sealed, wide("2000") ?, 8) ?
  let encoded = encode_privacy_submission(submission) ?
  assert(verify_submission(encoded, wide("1000") ?, wide("5000") ?, 8) ?)
  assert(!verify_submission(encoded, wide("2001") ?, wide("5000") ?, 8) ?)
  let decoded = decode_privacy_submission(encoded) ?
  let token_expires_at = decoded.token.expires_at
  let token_nonce = decoded.token.nonce
  let opened = open_delivery_with_key(decoded.sealed, pair.private_key) ?
  assert(Bytes.secure_equals(opened, outer))
  assert(token_rejects_alternate(token_expires_at, token_nonce, public_key, 0) ?)
  Ok(true)
end

test("privacy edge cannot read sealed delivery and anonymous work tokens bind exact ciphertext") do
  case edge_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

fn stamp_proof() -> Bool ! String do
  let now = wide("1700000000000") ?
  let window = wide("300000") ?
  let expires_at = wide("1700000060000") ?
  let payload = repeated(7, 100) ?
  let stamp = mint_request_stamp("mesh-msg/v1/work/resolve", payload, expires_at, 8) ?
  assert(verify_request_stamp("mesh-msg/v1/work/resolve", payload, stamp, now, window, 8) ?)
  # Work done for one endpoint buys nothing at another, and nothing for other bytes.
  assert(!(verify_request_stamp("mesh-msg/v1/work/register", payload, stamp, now, window, 8) ?))
  assert(!(verify_request_stamp("mesh-msg/v1/work/resolve",
  repeated(8, 100) ?,
  stamp,
  now,
  window,
  8) ?))
  # It is only good inside its window, so it cannot be stockpiled.
  assert(!(verify_request_stamp("mesh-msg/v1/work/resolve",
  payload,
  stamp,
  wide("1700000060001") ?,
  window,
  8) ?))
  assert(!(verify_request_stamp("mesh-msg/v1/work/resolve",
  payload,
  stamp,
  wide("1699999000000") ?,
  window,
  8) ?))
  assert(!(verify_request_stamp("mesh-msg/v1/work/resolve", payload, stamp, now, window, 0) ?))
  case mint_request_stamp("mesh-msg/v1/work/resolve", payload, expires_at, 25) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  let wire = encode_stamped_request(stamp, payload) ?
  assert(Bytes.length(wire) == 120)
  let ( decoded, body) = decode_stamped_request(wire, 100) ?
  assert(Bytes.secure_equals(body, payload))
  assert(U64.compare(decoded.expires_at, expires_at) == 0)
  assert(decoded.nonce == stamp.nonce)
  case decode_stamped_request(wire, 99) do
    Err( _) -> assert(true)
    Ok( _) -> assert(false)
  end
  # Known answer computed independently (Python hashlib) from the documented
  # layout: SHA-256(label || u64be expires_at || u32be nonce || SHA-256(payload)).
  # It pins the label, field order, widths and byte order against silent drift.
  let known = RequestStamp {
    expires_at : expires_at,
    nonce : 4955
  }
  assert(Bytes.to_hex(request_stamp_key("mesh-msg/v1/work/resolve", payload, known) ?) == "00023b3d0a240d4533a3e38336235c04f53b49c378093ffa92de14159221d639")
  assert(verify_request_stamp("mesh-msg/v1/work/resolve", payload, known, now, window, 14) ?)
  assert(!(verify_request_stamp("mesh-msg/v1/work/resolve", payload, known, now, window, 15) ?))
  # The key that marks a stamp as spent is unique to the stamp and the endpoint.
  let spent = request_stamp_key("mesh-msg/v1/work/resolve", payload, stamp) ?
  assert(Bytes.length(spent) == 32)
  assert(!Bytes.secure_equals(spent,
  request_stamp_key("mesh-msg/v1/work/register", payload, stamp) ?))
  assert(!Bytes.secure_equals(spent,
  request_stamp_key("mesh-msg/v1/work/resolve", payload, % { stamp | nonce : stamp.nonce + 1 }) ?))
  Ok(true)
end

test("request stamps bind work to one endpoint, one request and one window") do
  case stamp_proof() do
    Err( error) -> do
      println(error)
      assert(false)
    end
    Ok( value) -> assert(value)
  end
end

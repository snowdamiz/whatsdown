from Privacy.Edge import PrivacySubmission, decode_privacy_submission, encode_privacy_submission, mint_submission, open_delivery, seal_delivery, verify_submission
from Protocol.V1 import OuterEnvelope, encode_outer_envelope

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
  let opened = open_delivery(decoded.sealed,
  Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a") ?) ?
  assert(Bytes.secure_equals(opened, outer))
  let other = mint_submission(seal_delivery(protocol(encode_outer_envelope(OuterEnvelope {
    version : 1,
    envelope_id : repeated(4, 16) ?,
    mailbox_token : repeated(2, 32) ?,
    suite : 1,
    expiration : wide("4102444800000") ?,
    padding_bucket : 256,
    ciphertext : repeated(3, 32) ?
  })) ?,
  public_key) ?,
  wide("2000") ?,
  8) ?
  assert(!verify_submission(encode_privacy_submission(PrivacySubmission {
    token : decoded.token,
    sealed : other.sealed
  }) ?,
  wide("1000") ?,
  wide("5000") ?,
  8) ?)
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

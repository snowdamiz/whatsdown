from Api.Binary import prepare_submission
from Privacy.Edge import encode_privacy_submission, encode_sealed_delivery, mint_submission, seal_delivery
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("bytes failed")
    Ok(output)
  end
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn protocol(value :: Result<Bytes, ProtocolError>) -> Bytes!String do
  case value do
    Err(_) -> Err("protocol failed")
    Ok(output)
  end
end

fn proof() -> Bool!String do
  let pair = case Crypto.x25519_from_seed(Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?) do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let sealed = seal_delivery(protocol(encode_outer_envelope(OuterEnvelope {
      version: 1,
      envelope_id: repeated(1, 16)?,
      mailbox_token: repeated(2, 32)?,
      suite: 1,
      expiration: wide("4102444800000")?,
      padding_bucket: 256,
      ciphertext: repeated(3, 32)?
    }))?,
    pair.public_key)?
  let valid = prepare_submission(encode_privacy_submission(mint_submission(sealed, wide("2000")?, 8)?)?,
    wide("1000")?,
    wide("5000")?,
    8)
  assert(valid.status == 200)
  assert(Bytes.secure_equals(valid.body, encode_sealed_delivery(sealed)?))
  let expired = prepare_submission(encode_privacy_submission(mint_submission(sealed,
      wide("999")?,
      8)?)?,
    wide("1000")?,
    wide("5000")?,
    8)
  assert(expired.status == 429)
  assert(prepare_submission(Bytes.from_utf8("hostile"), wide("1000")?, wide("5000")?, 8).status == 400)
  Ok(true)
end

test("privacy edge forwards only valid sealed delivery bytes") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

from Privacy.Edge import (
  RequestStamp,
  abuse_endpoint_difficulty,
  encode_privacy_submission,
  encode_sealed_delivery,
  mint_request_stamp,
  mint_submission,
  request_stamp_key,
  seal_delivery,
  verify_request_stamp,
  verify_submission
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope

# Every endpoint's work is a fixed step down from the one pinned difficulty,
# the base: registering keeps it, lookups and prekey claims take two fewer bits,
# envelopes four fewer (sealed-delivery-v1.md, "Per-endpoint difficulty"). A
# phone and a server that agree on the base therefore agree on every endpoint.

fn check(value :: Bool, message :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(message)
  end
end

fn repeated(value :: Int, count :: Int) -> Bytes!String do
  case Bytes.repeat(value, count) do
    Err(_) -> Err("test allocation failed")
    Ok(output)
  end
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn byte_zeros(value :: Int, bits :: Int) -> Int do
  if bits >= 8 || value >= 128 do
    bits
  else
    byte_zeros(value * 2, bits + 1)
  end
end

fn zero_bits(hash :: Bytes, index :: Int, total :: Int) -> Int do
  case Bytes.get(hash, index) do
    Err(_) -> total
    Ok(0) -> zero_bits(hash, index + 1, total + 8)
    Ok(value) -> total + byte_zeros(value, 0)
  end
end

fn table_proof() -> Result<(), String> do
  let expected = [
    ("mesh-msg/v1/work/register", 16),
    ("mesh-msg/v1/work/resolve", 14),
    ("mesh-msg/v1/work/prekey-claim", 14),
    ("mesh-msg/v1/anonymous-abuse-token", 12),
    ("mesh-msg/v1/work/unlisted", 16)
  ]
  for (label, difficulty) in expected do
    check(abuse_endpoint_difficulty(16, label) == difficulty,
      "#{label} is not #{difficulty} at base 16")?
  end
  check(abuse_endpoint_difficulty(24, "mesh-msg/v1/work/register") == 24,
    "registering left the pinned base")?
  check(abuse_endpoint_difficulty(2, "mesh-msg/v1/anonymous-abuse-token") == 1,
    "an endpoint went below one bit")
end

test("each endpoint's difficulty is a fixed step from the pinned base") do
  case table_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

# A stamp minted at a base carries at least its endpoint's bits, and a server
# at that base asks for exactly those bits: one base higher refuses the stamp
# the moment its work falls short of the endpoint's step.

fn stamp_check(label :: String, offset :: Int) -> Result<(), String> do
  let now = wide("1700000000000")?
  let window = wide("300000")?
  let payload = repeated(7, 100)?
  let stamp = mint_request_stamp(label, payload, wide("1700000060000")?, 10)?
  let bits = zero_bits(request_stamp_key(label, payload, stamp)?, 0, 0)
  check(bits >= 10 + offset, "#{label} was minted below its step")?
  check(verify_request_stamp(label, payload, stamp, now, window, bits - offset)?,
    "#{label} refused work that met its step")?
  check(!(verify_request_stamp(label, payload, stamp, now, window, bits - offset + 1)?),
    "#{label} accepted work below its step")
end

fn submission_check() -> Result<(), String> do
  let pair = case Crypto.x25519_generate() do
    Err(_) -> Err("delivery key generation failed")
    Ok(output)
  end?
  let outer = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(1, 16)?,
    mailbox_token: repeated(2, 32)?,
    suite: 4,
    expiration: wide("4102444800000")?,
    padding_bucket: 256,
    ciphertext: repeated(3, 32)?
  }) do
    Err(_) -> Err("outer envelope encoding failed")
    Ok(output)
  end?
  let sealed = seal_delivery(outer, pair.public_key)?
  let submission = mint_submission(sealed, wide("2000")?, 10)?
  let encoded = encode_privacy_submission(submission)?
  let stamp = RequestStamp {
    expires_at: submission.token.expires_at,
    nonce: submission.token.nonce
  }
  let bits = zero_bits(request_stamp_key("mesh-msg/v1/anonymous-abuse-token",
      encode_sealed_delivery(sealed)?,
      stamp)?,
    0,
    0)
  check(bits >= 6, "an envelope was minted below its step")?
  check(verify_submission(encoded, wide("1000")?, wide("5000")?, bits + 4)?,
    "an envelope's work that met its step was refused")?
  check(!(verify_submission(encoded, wide("1000")?, wide("5000")?, bits + 5)?),
    "an envelope's work below its step was accepted")
end

fn verify_proof() -> Result<(), String> do
  stamp_check("mesh-msg/v1/work/register", 0)?
  stamp_check("mesh-msg/v1/work/resolve", -2)?
  stamp_check("mesh-msg/v1/work/prekey-claim", -2)?
  submission_check()
end

test("stamps and envelopes are minted and checked at their endpoint's difficulty") do
  case verify_proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

from Credits.CreditFrames import (
  CreditRedemption,
  credits_attach,
  credits_decode_held,
  credits_decode_redeem,
  credits_encode_redemption
)
from Credits.CreditToken import CreditToken, credits_encode_token
from Privacy.CreditEdge import CreditEdgeResult, credit_edge_paid, credit_edge_submit
from Privacy.Edge import (
  encode_privacy_submission,
  encode_sealed_delivery,
  mint_submission,
  seal_delivery
)
from Protocol.EnvelopeWire import encode_outer_envelope
from Protocol.V1 import OuterEnvelope

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn wide(value :: String) -> U64!String do
  U64.parse(value)
end

fn sealed() -> Bytes!String do
  let pair = case Crypto.x25519_from_seed(Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?) do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let outer = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(1, 16),
    mailbox_token: repeated(2, 32),
    suite: 1,
    expiration: wide("4102444800000")?,
    padding_bucket: 256,
    ciphertext: repeated(3, 32)
  }) do
    Err(_) -> Err("envelope failed")
    Ok(value)
  end?
  encode_sealed_delivery(seal_delivery(outer, pair.public_key)?)
end

fn work(expires :: String) -> Bytes!String do
  let pair = case Crypto.x25519_from_seed(Bytes.from_hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")?) do
    Err(_) -> Err("key failed")
    Ok(value)
  end?
  let outer = case encode_outer_envelope(OuterEnvelope {
    version: 1,
    envelope_id: repeated(1, 16),
    mailbox_token: repeated(2, 32),
    suite: 1,
    expiration: wide("4102444800000")?,
    padding_bucket: 256,
    ciphertext: repeated(3, 32)
  }) do
    Err(_) -> Err("envelope failed")
    Ok(value)
  end?
  encode_privacy_submission(mint_submission(seal_delivery(outer, pair.public_key)?,
    wide(expires)?,
    8)?)
end

fn token(seed :: Int) -> Bytes!String do
  credits_encode_token(CreditToken {
    nonce: repeated(seed, 32),
    challenge_digest: repeated(2, 32),
    token_key_id: repeated(3, 32),
    authenticator: repeated(4, 256)
  })
end

fn echo(status :: Int) -> Fun(Bytes) -> CreditEdgeResult!String do
  fn request -> Ok(CreditEdgeResult { status: status, body: request }) end
end

fn redeemed() -> Fun(Bytes) -> CreditEdgeResult!String do
  fn request -> case credits_decode_redeem(request) do
    Err(error)
    Ok((action, _frame)) -> case credits_encode_redemption(CreditRedemption {
      redemption_id: repeated(action, 16),
      credits: 1
    }) do
      Err(error)
      Ok(body) -> Ok(CreditEdgeResult { status: 201, body: body })
    end
  end end
end

fn submit(body :: Bytes,
  redeem :: Fun(Bytes) -> CreditEdgeResult!String) -> CreditEdgeResult!String do
  Ok(credit_edge_submit(body, wide("1000")?, wide("5000")?, 8, redeem, echo(202)))
end

fn paths() -> Bool!String do
  let sed = sealed()?
  let prv = work("2000")?
  let by_work = submit(prv, echo(500))?
  let instead = submit(credits_attach([token(1)?], sed)?, redeemed())?
  let beside = submit(credits_attach([token(1)?], prv)?, redeemed())?
  let (hold, forwarded) = credits_decode_held(instead.body)?
  let (beside_hold, _) = credits_decode_held(beside.body)?
  Ok(by_work.status == 202
    && instead.status == 202
    && hold == Some(repeated(1, 16))
    && Bytes.secure_equals(forwarded, sed)
    && beside.status == 202
    && beside_hold == Some(repeated(1, 16)))
end

test("the edge forwards work as before and redeemed credits as a held delivery") do
  case paths() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn refusals() -> Bool!String do
  let sed = sealed()?
  let request = credits_attach([token(1)?], sed)?
  let tampered = Bytes.concat(request, Bytes.from_utf8("x"))?
  let stale_work = credits_attach([token(1)?], work("999")?)?
  let spent = submit(request, echo(409))?
  let invalid = submit(request, echo(422))?
  let unreachable = submit(request, fn _request -> Err("connection refused") end)?
  let broken = submit(request, echo(500))?
  Ok(spent.status == 409
    && Bytes.length(spent.body) == 0
    && invalid.status == 422
    && unreachable.status == 503
    && broken.status == 503
    && submit(tampered, redeemed())?.status == 400
    && submit(stale_work, redeemed())?.status == 429
    && submit(sed, redeemed())?.status == 400)
end

test("the edge delivers nothing unless the core redeemed every token") do
  case refusals() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

fn paid_only() -> Bool!String do
  let body = Bytes.from_utf8("storage request")
  let paid = credit_edge_paid(credits_attach([token(5)?], body)?, 2, redeemed(), echo(201))
  let (hold, forwarded) = credits_decode_held(paid.body)?
  let unpaid = credit_edge_paid(body, 2, redeemed(), echo(201))
  let spent = credit_edge_paid(credits_attach([token(5)?], body)?, 2, echo(409), echo(201))
  Ok(paid.status == 201
    && hold == Some(repeated(2, 16))
    && Bytes.secure_equals(forwarded, body)
    && unpaid.status == 402
    && spent.status == 409)
end

test("a request only credits pay for is redeemed for its action, and refused without them") do
  case paid_only() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

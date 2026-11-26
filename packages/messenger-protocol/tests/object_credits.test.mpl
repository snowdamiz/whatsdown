from Credits.CreditFrames import (
  CreditFrame,
  CreditRedemption,
  credits_attach,
  credits_decode_redeem,
  credits_encode_redemption
)
from Credits.CreditToken import CreditToken, credits_encode_token
from Objects.CreditGrant import object_grant_entitle, object_grant_price, object_grant_split
from Objects.Grant import decode_grant, encode_grant, mint_grant
from Privacy.CreditEdge import CreditEdgeResult

# A grant for an object above 16 MiB pays for it with a CRD frame in front of
# the OGR (opaque-object-wire-v1.md, "Large objects"). The store redeems the
# frame with the core before it grants anything; these tests stand in for the
# core, whose own checks run in the directory's credits tests.

fn repeated(value :: Int, count :: Int) -> Bytes do
  case Bytes.repeat(value, count) do
    Err(_) -> Bytes.empty()
    Ok(output) -> output
  end
end

fn token(seed :: Int) -> Bytes!String do
  credits_encode_token(CreditToken {
    nonce: repeated(seed, 32),
    challenge_digest: repeated(2, 32),
    token_key_id: repeated(3, 32),
    authenticator: repeated(4, 256)
  })
end

fn grant_for(parts :: Int) -> Bytes!String do
  encode_grant(mint_grant(repeated(7, 32),
    parts,
    U64.parse("4102444800000")?,
    U64.parse("4102444800000")?,
    repeated(8, 32),
    repeated(9, 32),
    1)?)
end

fn check(value :: Bool, message :: String) -> Result<(), String> do
  if value do
    Ok(nil)
  else
    Err(message)
  end
end

fn prove(result :: Result<(), String>) do
  case result do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> assert(true)
  end
end

fn refused_price(parts :: Int) -> Bool do
  case object_grant_price(parts) do
    Err(_) -> true
    Ok(_) -> false
  end
end

# A grant of up to 257 parts is a file of at most 16 MiB (or any backup): free.
# Above that only a padded attachment bucket is granted, 64 KiB per chunk plus
# the manifest part, and it costs what the bucket costs.

fn price_proof() -> Result<(), String> do
  let prices = [(1, 0), (257, 0), (321, 1), (385, 1), (513, 1), (641, 2), (897, 3), (8193, 31)]
  for (parts, credits) in prices do
    check(object_grant_price(parts)? == credits, "#{parts} parts did not cost #{credits}")?
  end
  check(refused_price(0) && refused_price(258) && refused_price(322) && refused_price(8194),
    "a part count that is not a bucket was priced")?
  check(Bytes.length(grant_for(8193)?) == 124, "a 512 MiB grant was not encoded")?
  case encode_grant(%{decode_grant(grant_for(8193)?)? | part_count: 8194}) do
    Ok(_) -> Err("a grant of 8,194 parts was encoded")
    Err(_) -> Ok(nil)
  end
end

test("a grant costs nothing up to 16 MiB and one credit per extra 16 MiB above") do
  prove(price_proof())
end

fn never(_request :: Bytes) -> CreditEdgeResult!String do
  Err("the core was asked to redeem")
end

fn answering(status :: Int) -> Fun(Bytes) -> CreditEdgeResult!String do
  fn _request -> Ok(CreditEdgeResult { status: status, body: Bytes.empty() }) end
end

fn split_frame(request :: Bytes) -> Option<CreditFrame>!String do
  let (frame, _) = object_grant_split(request)?
  Ok(frame)
end

# The core sees action 4 and exactly the frame the phone sent, bound to its
# OGR; its 201 names a redemption of those credits.

fn core(grant :: Bytes) -> Fun(Bytes) -> CreditEdgeResult!String do
  fn(request) do
    let (action, frame) = credits_decode_redeem(request)?
    if action != 4 || !Bytes.secure_equals(frame.binding, Crypto.sha256(grant)) do
      Err("the core was sent the wrong redemption")
    else
      Ok(CreditEdgeResult {
        status: 201,
        body: credits_encode_redemption(CreditRedemption {
          redemption_id: repeated(5, 16),
          credits: List.length(frame.tokens)
        })?
      })
    end
  end
end

fn entitle_proof() -> Result<(), String> do
  let grant = grant_for(641)?
  let (plain, body) = object_grant_split(grant)?
  check(Option.is_none(plain) && Bytes.secure_equals(body, grant),
    "a plain grant did not split to itself")?
  let one = split_frame(credits_attach([token(1)?], grant)?)?
  let two = credits_attach([token(1)?, token(2)?], grant)?
  let (paid, paid_body) = object_grant_split(two)?
  check(Bytes.secure_equals(paid_body, grant), "the paid grant lost its OGR")?
  check(object_grant_entitle(None, 641, never) == 402, "a 40 MiB grant without credits passed")?
  check(object_grant_entitle(one, 641, never) == 402, "a 40 MiB grant with 1 credit passed")?
  check(object_grant_entitle(paid, 641, core(grant)) == 0, "a 40 MiB grant with 2 credits failed")?
  check(object_grant_entitle(one, 321, core(grant)) == 0, "a 20 MiB grant with 1 credit failed")?
  check(object_grant_entitle(paid, 641, answering(409)) == 409, "a spent frame was not refused")?
  check(object_grant_entitle(paid, 641, answering(422)) == 422, "a forged frame was not refused")?
  check(object_grant_entitle(paid, 641, answering(403)) == 403, "credits off did not refuse")?
  check(object_grant_entitle(paid, 641, answering(500)) == 503
      && object_grant_entitle(paid, 641, never) == 503,
    "a core failure did not fail closed")?
  check(object_grant_entitle(None, 257, never) == 0 && object_grant_entitle(paid, 257, never) == 0,
    "a free grant was sent to the core")?
  check(object_grant_entitle(paid, 258, never) == 400, "a part count off the ladder was entitled")?
  let rebound = Bytes.concat(Bytes.slice(two, 0, 37 + 2 * 354)?, grant_for(8193)?)?
  case object_grant_split(rebound) do
    Ok(_) -> Err("a frame moved onto another grant was accepted")
    Err(_) -> Ok(nil)
  end
end

test("a large grant is entitled only by a redeemed frame of enough credits") do
  prove(entitle_proof())
end

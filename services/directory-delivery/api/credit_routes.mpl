##! Credit routes of the core (protocol/credits-v1.md "Routes").

from Api.Binary import BinaryResult
from Credits.CreditFrames import credits_decode_redeem, credits_encode_redemption
from Storage.Credits import (
  IssuerLeafWrite,
  RedeemOutcome,
  credits_accepted_key_count,
  credits_append_issuer_leaf,
  credits_issuer_keys,
  credits_redeem,
  credits_spend_totals
)
from Transparency.Codec import tcodec_decimal

fn empty(status :: Int) -> BinaryResult do
  BinaryResult { status: status, body: Bytes.empty() }
end

## POST /internal/v1/credits/redeem: 201 RDR when every token was a credit of
## an accepted key and none was spent; 422 a token that is not; 409 one was
## spent before (nothing is spent); 403 this core redeems no credits; 503 the
## spent set is unavailable (nothing is spent).

pub fn credits_redeem_request(pool :: PoolHandle,
  mode :: String,
  body :: Bytes,
  now_ms :: Int) -> BinaryResult do
  case credits_decode_redeem(body) do
    Err(_) -> empty(400)
    Ok((action, frame)) -> case credits_redeem(pool, mode, action, frame, now_ms) do
      Err(_) -> empty(503)
      Ok(RedeemRefused) -> empty(422)
      Ok(RedeemSpent) -> empty(409)
      Ok(RedeemClosed) -> empty(403)
      Ok(Redeemed(redemption)) -> case credits_encode_redemption(redemption) do
        Err(_) -> empty(500)
        Ok(encoded) -> BinaryResult { status: 201, body: encoded }
      end
    end
  end
end

## POST /internal/v1/credits/issuer-keys: 201 appended, 200 already in the
## log, 409 conflicts with the log, 400 not an issuer leaf.

pub fn credits_issuer_leaf_request(pool :: PoolHandle, body :: Bytes) -> BinaryResult do
  case credits_append_issuer_leaf(pool, body) do
    Err(_) -> empty(503)
    Ok(IssuerLeafStored) -> empty(201)
    Ok(IssuerLeafDuplicate) -> empty(200)
    Ok(IssuerLeafConflict) -> empty(409)
    Ok(IssuerLeafInvalid) -> empty(400)
  end
end

## GET /v1/credits/issuer-keys[?previous_tree_size=N]: CIK with KTE v2
## evidence for each accepted key.

pub fn credits_issuer_keys_request(pool :: PoolHandle,
  previous_tree_size :: Option<String>,
  now_ms :: Int) -> BinaryResult do
  let previous = case previous_tree_size do
    None -> Ok(0)
    Some(text) -> tcodec_decimal(text)
  end
  case previous do
    Err(_) -> empty(400)
    Ok(size) -> case credits_issuer_keys(pool, size, now_ms) do
      Err(error) -> if String.contains(error, "invalid consistency size") do
        empty(400)
      else if String.contains(error, "checkpoint") || String.contains(error, "empty") do
        empty(404)
      else
        empty(500)
      end
      Ok(encoded) -> BinaryResult { status: 200, body: encoded }
    end
  end
end

## GET /v1/credits/health: JSON for alerting (plan §12): the mode, how many
## keys of each purpose are accepted now, and this process's redemption count,
## spent-set failures and p95 milliseconds. 503 when the database does not
## answer.

pub fn credits_health_request(pool :: PoolHandle,
  mode :: String,
  stats :: (Int, Int, Int),
  now_ms :: Int) -> BinaryResult do
  case (credits_accepted_key_count(pool, "live", now_ms),
    credits_accepted_key_count(pool, "test", now_ms)) do
    (Ok(live), Ok(test)) -> do
      let (redemptions, failures, p95) = stats
      BinaryResult {
        status: 200,
        body: Bytes.from_utf8("{\"mode\":"
          <> Json.encode_string(mode)
          <> ",\"live_keys\":"
          <> Int.to_string(live)
          <> ",\"test_keys\":"
          <> Int.to_string(test)
          <> ",\"redemptions\":"
          <> Int.to_string(redemptions)
          <> ",\"spent_set_failures\":"
          <> Int.to_string(failures)
          <> ",\"redeem_p95_ms\":"
          <> Int.to_string(p95)
          <> "}")
      }
    end
    _ -> BinaryResult { status: 503, body: Bytes.from_utf8("{\"status\":\"unavailable\"}") }
  end
end

## GET /internal/v1/credits/totals?week=YYYY-MM-DD (bearer): credits spent in
## that week (a Monday, UTC) by action. Credit revenue is split when credits
## are bought (the issuer's settlement); these totals say what they were spent
## on. Postage pays the network, never the recipient (plan D12).

pub fn credits_totals_request(pool :: PoolHandle, week :: Option<String>) -> BinaryResult do
  let week_start = case week do
    Some(value) -> value
    None -> return empty(400)
  end
  if String.length(week_start) != 10 do
    return empty(400)
  end
  case credits_spend_totals(pool, week_start) do
    Err(_) -> empty(400)
    Ok((envelope, storage, signup, file)) -> BinaryResult {
      status: 200,
      body: Bytes.from_utf8("{\"week_start\":"
        <> Json.encode_string(week_start)
        <> ",\"postage\":"
        <> Int.to_string(envelope)
        <> ",\"storage\":"
        <> Int.to_string(storage)
        <> ",\"signup\":"
        <> Int.to_string(signup)
        <> ",\"file\":"
        <> Int.to_string(file)
        <> "}")
    }
  end
end

##! The issuer's routes (README.md "Routes"), reached through the privacy edge
##! so the issuer never sees a buyer's network address.

from Credits.CreditFrames import (
  CreditQuoteRequest,
  credits_quote_work_label,
  credits_decode_issue_request,
  credits_decode_quote_request,
  credits_encode_issue_response,
  credits_encode_quote
)
from Credits.IssuerKey import credits_epoch_at
from Issuer.Issuance import IssueOutcome, issuer_issue
from Issuer.KeyStore import issuer_key_health
from Issuer.Quotes import QuoteOutcome, issuer_admit_quote, issuer_quote
from Privacy.Edge import decode_stamped_request, request_stamp_key, verify_request_stamp
from Issuer.Settings import IssuerSettings, issuer_purpose

pub struct IssuerResult do
  status :: Int
  body :: Bytes
end

fn empty(status :: Int) -> IssuerResult do
  IssuerResult { status: status, body: Bytes.empty() }
end

fn stamped(body :: Bytes,
  settings :: IssuerSettings,
  now_ms :: Int) -> Result<(Bytes, Bytes), Int> do
  let (stamp, payload) = case decode_stamped_request(body, 6) do
    Err(_) -> return Err(400)
    Ok(pair) -> pair
  end
  let label = credits_quote_work_label()
  let checked = case (U64.parse(Int.to_string(now_ms)), U64.parse("300000")) do
    (Ok(now), Ok(window)) -> verify_request_stamp(label,
      payload,
      stamp,
      now,
      window,
      settings.quote_difficulty)
    _ -> Err("clock")
  end
  case (checked, request_stamp_key(label, payload, stamp)) do
    (Ok(true), Ok(key)) -> Ok((payload, key))
    (Ok(false), _) -> Err(429)
    _ -> Err(400)
  end
end

## POST /v1/credits/quote: PWR(label mesh-msg/v1/work/credit-quote, CQR) →
## 201 CQT; 429 missing, stale, short or spent work, or too many open quotes;
## 503 credits off or no key this epoch; 422 asset not offered; 400
## malformed; 502 the oracle or Lightning node failed.

pub fn issuer_quote_request(pool :: PoolHandle,
  settings :: IssuerSettings,
  body :: Bytes,
  now_ms :: Int) -> IssuerResult do
  let (payload, stamp_key) = case stamped(body, settings, now_ms) do
    Err(status) -> return empty(status)
    Ok(pair) -> pair
  end
  let request = case credits_decode_quote_request(payload) do
    Err(_) -> return empty(400)
    Ok(value) -> value
  end
  case issuer_admit_quote(pool, settings, stamp_key) do
    Err(_) -> empty(502)
    Ok(false) -> empty(429)
    Ok(true) -> quoted(pool, settings, request, now_ms)
  end
end

fn quoted(pool :: PoolHandle,
  settings :: IssuerSettings,
  request :: CreditQuoteRequest,
  now_ms :: Int) -> IssuerResult do
  case issuer_quote(pool, settings, request, now_ms) do
    Err(_) -> empty(502)
    Ok(QuoteClosed) -> empty(503)
    Ok(QuoteRefused) -> empty(422)
    Ok(Quoted(quote)) -> case credits_encode_quote(quote) do
      Err(_) -> empty(500)
      Ok(encoded) -> IssuerResult { status: 201, body: encoded }
    end
  end
end

## POST /v1/credits/issue: CIR → 200 CIS; 202 payment not final yet (retry);
## 402 unpaid, underpaid or late; 404 unknown quote; 409 another batch or a
## payment used before; 410 expired unpaid; 412 blinded for another key
## (re-blind for the current one); 503 not signing now.

pub fn issuer_issue_request(pool :: PoolHandle,
  settings :: IssuerSettings,
  body :: Bytes,
  wrapping :: borrow X25519PrivateKey,
  now_ms :: Int) -> IssuerResult do
  case credits_decode_issue_request(body) do
    Err(_) -> empty(400)
    Ok(request) -> case issuer_issue(pool, settings, request, wrapping, now_ms) do
      Err(_) -> empty(502)
      Ok(IssuePending) -> empty(202)
      Ok(IssueUnpaid) -> empty(402)
      Ok(IssueUnknown) -> empty(404)
      Ok(IssueConflict) -> empty(409)
      Ok(IssueExpired) -> empty(410)
      Ok(IssueStaleKey) -> empty(412)
      Ok(IssueClosed) -> empty(503)
      Ok(Issued(response)) -> case credits_encode_issue_response(response) do
        Err(_) -> empty(500)
        Ok(encoded) -> IssuerResult { status: 200, body: encoded }
      end
    end
  end
end

fn count(pool :: PoolHandle, sql :: String) -> Int!String do
  let rows = Pool.query_values(pool, sql, [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(text) -> case String.to_int(text) do
        Some(value) -> Ok(value)
        None -> Err("invalid count")
      end
      _ -> Err("invalid count")
    end
    _ -> Err("count failed")
  end
end

fn flag(value :: Bool) -> String do
  if value do
    "true"
  else
    "false"
  end
end

## GET /health: 200 while credits are off or this epoch's key is announced,
## else 503. next_key_provisioned false means rotation will stop quotes at the
## next epoch boundary (alert on it a week ahead).

fn health_report(pool :: PoolHandle,
  settings :: IssuerSettings,
  now_ms :: Int) -> (Bool, String)!String do
  let (current, next) = issuer_key_health(pool, issuer_purpose(settings), now_ms)?
  let open = count(pool,
    "SELECT count(*)::text AS value FROM quotes WHERE state = 'open' AND expires_at > now()")?
  let unswept = count(pool,
    "SELECT count(*)::text AS value FROM quotes WHERE state = 'issued' AND asset <> 'btc' AND swept_at IS NULL")?
  Ok((current,
    "{\"mode\":"
      <> Json.encode_string(settings.mode)
      <> ",\"purpose\":"
      <> Json.encode_string(issuer_purpose(settings))
      <> ",\"epoch\":"
      <> Int.to_string(credits_epoch_at(now_ms))
      <> ",\"current_key\":"
      <> flag(current)
      <> ",\"next_key_provisioned\":"
      <> flag(next)
      <> ",\"open_quotes\":"
      <> Int.to_string(open)
      <> ",\"unswept_deposits\":"
      <> Int.to_string(unswept)
      <> "}"))
end

pub fn issuer_health_request(pool :: PoolHandle,
  settings :: IssuerSettings,
  now_ms :: Int) -> IssuerResult do
  case health_report(pool, settings, now_ms) do
    Err(_) -> empty(503)
    Ok((current, report)) -> IssuerResult {
      status: if current || settings.mode == "off" do
        200
      else
        503
      end,
      body: Bytes.from_utf8(report)
    }
  end
end

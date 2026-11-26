from Binary.Reader import BinaryReader, reader
from Credits.CreditFrames import (
  CreditQuote,
  CreditQuoteRequest,
  credits_decode_quote,
  credits_encode_quote_request,
  credits_pack_size,
  credits_quote_work_label
)
from Credits.CreditToken import credits_issuer_name
from Credits.IssuerKey import credits_key_valid_at
from Mobile.CreditsStore import (
  CreditWrites,
  credits_find_key,
  credits_random,
  credits_zeroes,
  credits_load_keys,
  credits_load_sealed,
  credits_sealed_write
)
from Mobile.Platform import native_security_config, stamped_request
from Mobile.Types import MobileSecurityConfig
from Security.Config import SecurityConfig
from Storage.Blobs import ensure_schema
from Storage.Keys import platform_key
from Storage.Records import store_record_changes
from Transparency.Codec import (
  tcodec_done,
  tcodec_join,
  tcodec_start,
  tcodec_take_fixed,
  tcodec_take_u32,
  tcodec_take_u64,
  tcodec_take_u8,
  tcodec_take_vector,
  tcodec_u16,
  tcodec_u32,
  tcodec_u64,
  tcodec_u8,
  tcodec_vector
)

##! Mobile.CreditsBuy: quotes and the local record of each purchase
##! (protocol/credits-v1.md "Client"). Quotes go through the privacy edge, so
##! the issuer never sees this device's address.
##!
##! A purchase moves through these states:
##!
##!   1 quoted    the quote is here; nothing is paid yet as far as this device knows
##!   2 paid      the wallet's payment signature is recorded
##!   3 issuing   a blinded batch was sent and no answer has been handled yet
##!   4 issued    the tokens are stored
##!   5 expired   the quote ran out unpaid (or the issuer no longer knows it)
##!   6 unpaid    the payment was short, late or not to this quote: refundable
##!               on request, with the purchase reference
##!   7 reissue   the key that signed it was revoked: collect it again
##!   8 operator  the app stopped between the issuer signing and this device
##!               storing the tokens: only Morse can help, with the reference
##!
##! Local frame "credits/v1/purchases": u8 1 || "CPH" || u8 n || n x
##! vector32(record); record = id16 || u8 state || u64 created_ms || u64
##! updated_ms || u32 issued || key_id32 (the key it was issued under, zero
##! before) || vector32(CQT) || vector32(payment signature).

pub struct CreditPurchase do
  id :: Bytes
  state :: Int
  created_at :: Int
  updated_at :: Int
  issued :: Int
  key_id :: Bytes
  quote :: Bytes
  payment :: String
end

pub struct CreditResponse do
  status :: Int
  body :: Bytes
end

pub fn credits_state_quoted() -> Int do
  1
end

pub fn credits_state_paid() -> Int do
  2
end

pub fn credits_state_issuing() -> Int do
  3
end

pub fn credits_state_issued() -> Int do
  4
end

pub fn credits_state_expired() -> Int do
  5
end

pub fn credits_state_unpaid() -> Int do
  6
end

pub fn credits_state_reissue() -> Int do
  7
end

pub fn credits_state_operator() -> Int do
  8
end

fn purchases_label() -> String do
  "credits/v1/purchases"
end

fn history_limit() -> Int do
  24
end

fn finished(state :: Int) -> Bool do
  state == 4 || state == 5 || state == 6
end

# Request fields: `count` vector32 values, nothing else.

fn take_fields(state :: BinaryReader,
  count :: Int,
  output :: List<Bytes>) -> (BinaryReader, List<Bytes>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let value = tcodec_take_vector(state, 1048576)?
    take_fields(value.state, count, List.append(output, value.value))
  end
end

pub fn credits_fields(input :: Bytes, count :: Int) -> List<Bytes>!String do
  let state = case reader(input, 4194304) do
    Err(_) -> Err("invalid_credits_request")
    Ok(value)
  end?
  case take_fields(state, count, List.new()) do
    Err(_) -> Err("invalid_credits_request")
    Ok((rest, values)) -> case tcodec_done(rest) do
      Err(_) -> Err("invalid_credits_request")
      Ok(_) -> Ok(values)
    end
  end
end

pub fn credits_text(value :: Bytes) -> String!String do
  case Bytes.to_utf8(value) do
    Err(_) -> Err("invalid_credits_request")
    Ok(text)
  end
end

pub fn credits_path(value :: Bytes) -> String!String do
  let path = credits_text(value)?
  if String.length(path) == 0 || String.length(path) > 4096 do
    Err("invalid_database_path")
  else
    ensure_schema(path)?
    Ok(path)
  end
end

pub fn credits_small(value :: Bytes) -> Int!String do
  if Bytes.length(value) != 1 do
    Err("invalid_credits_request")
  else
    case Bytes.get(value, 0) do
      Err(_) -> Err("invalid_credits_request")
      Ok(byte)
    end
  end
end

pub fn credits_now() -> Int do
  DateTime.to_unix_ms(DateTime.utc_now())
end

# A Morse service URL: https, or plain http to this machine (development).

pub fn credits_service_url(value :: Bytes) -> String!String do
  let text = credits_text(value)?
  let url = if String.ends_with(text, "/") do
    String.slice(text, 0, String.length(text) - 1)
  else
    text
  end
  let local = String.starts_with(url, "http://127.0.0.1:")
    || String.starts_with(url, "http://localhost:")
  if (!String.starts_with(url, "https://") && !local)
    || String.contains(url, "?")
    || String.contains(url, "#")
    || String.contains(url, "@")
    || String.length(url) > 2048 do
    Err("invalid_service_url")
  else
    Ok(url)
  end
end

## One request to a Morse service. No answer at all is Err("credits_network").

pub fn credits_http(method :: String,
  url :: String,
  body :: Bytes,
  maximum :: Int) -> CreditResponse!String do
  credits_http_within(method, url, body, maximum, 15000)
end

## The same, waiting up to `timeout_ms` for the answer.

pub fn credits_http_within(method :: String,
  url :: String,
  body :: Bytes,
  maximum :: Int,
  timeout_ms :: Int) -> CreditResponse!String do
  let built = if method == "GET" do
    Http.build(:get, url)
  else if method == "PUT" do
    Http.build(:put, url)
      |> Http.header("Content-Type", "application/octet-stream")
      |> Http.body_bytes(body)
  else
    Http.build(:post, url)
      |> Http.header("Content-Type", "application/octet-stream")
      |> Http.body_bytes(body)
  end
  case built
    |> Http.header("Cache-Control", "no-store")
    |> Http.timeout(timeout_ms)
    |> Http.max_response_bytes(maximum)
    |> Http.max_redirects(0)
    |> Http.send() do
    Err(_) -> Err("credits_network")
    Ok(response) -> Ok(CreditResponse { status: response.status, body: response.body_bytes })
  end
end

# Purchase records.

fn encode_record(value :: CreditPurchase) -> Bytes!String do
  tcodec_join([
    value.id,
    tcodec_u8(value.state)?,
    tcodec_u64(value.created_at)?,
    tcodec_u64(value.updated_at)?,
    tcodec_u32(value.issued)?,
    value.key_id,
    tcodec_vector(value.quote)?,
    tcodec_vector(Bytes.from_utf8(value.payment))?
  ])
end

fn decode_record(input :: Bytes) -> CreditPurchase!String do
  let state = case reader(input, 65536) do
    Err(_) -> Err("invalid_credit_purchase")
    Ok(value)
  end?
  let id = tcodec_take_fixed(state, 16)?
  let kind = tcodec_take_u8(id.state)?
  let created = tcodec_take_u64(kind.state)?
  let updated = tcodec_take_u64(created.state)?
  let issued = tcodec_take_u32(updated.state)?
  let key_id = tcodec_take_fixed(issued.state, 32)?
  let quote = tcodec_take_vector(key_id.state, 8192)?
  let payment = tcodec_take_vector(quote.state, 128)?
  tcodec_done(payment.state)?
  Ok(CreditPurchase {
    id: id.value,
    state: kind.value,
    created_at: created.value,
    updated_at: updated.value,
    issued: issued.value,
    key_id: key_id.value,
    quote: quote.value,
    payment: credits_text(payment.value)?
  })
end

fn take_records(state :: BinaryReader,
  count :: Int,
  output :: List<CreditPurchase>) -> (BinaryReader, List<CreditPurchase>)!String do
  if List.length(output) >= count do
    Ok((state, output))
  else
    let record = tcodec_take_vector(state, 65536)?
    take_records(record.state, count, List.append(output, decode_record(record.value)?))
  end
end

pub fn credits_load_purchases(database_path :: String,
  wrapping_key :: borrow StorageKey) -> List<CreditPurchase>!String do
  let encoded = credits_load_sealed(database_path, wrapping_key, purchases_label())?
  if Bytes.length(encoded) == 0 do
    Ok(List.new())
  else
    let state = tcodec_start(encoded, 65536, 1, "CPH")?
    let count = tcodec_take_u8(state)?
    let (rest, records) = take_records(count.state, count.value, List.new())?
    tcodec_done(rest)?
    Ok(records)
  end
end

fn encode_records(values :: List<CreditPurchase>) -> Bytes!String do
  let rows = for value in values do
    tcodec_vector(encode_record(value)?)?
  end
  tcodec_join([tcodec_u8(1)?, Bytes.from_utf8("CPH"), tcodec_u8(List.length(values))?] ++ rows)
end

# The newest records, and every unfinished one, within what one sealed record
# holds: the oldest finished purchases are forgotten first.

fn trimmed(values :: List<CreditPurchase>) -> List<CreditPurchase>!String do
  let encoded = encode_records(values)?
  let excess = List.length(values) > history_limit() || Bytes.length(encoded) > 60000
  if !excess do
    Ok(values)
  else
    case List.find(values, fn value -> finished(value.state) end) do
      None -> Err("credits_too_many_purchases")
      Some(oldest) -> trimmed(List.filter(values,
        fn value -> !Bytes.secure_equals(value.id, oldest.id) end))
    end
  end
end

## The writes that store `value` in place of the record with its ID (or add it).

pub fn credits_purchase_write(values :: List<CreditPurchase>,
  value :: CreditPurchase,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  let replaced = List.any(values, fn known -> Bytes.secure_equals(known.id, value.id) end)
  let next = if replaced do
    for known in values do
      if Bytes.secure_equals(known.id, value.id) do
        value
      else
        known
      end
    end
  else
    List.append(values, value)
  end
  credits_purchases_write(trimmed(next)?, wrapping_key)
end

pub fn credits_purchases_write(values :: List<CreditPurchase>,
  wrapping_key :: borrow StorageKey) -> CreditWrites!String do
  credits_sealed_write(purchases_label(), encode_records(values)?, wrapping_key)
end

pub fn credits_find_purchase(values :: List<CreditPurchase>,
  id :: Bytes) -> CreditPurchase!String do
  case List.find(values, fn value -> Bytes.secure_equals(value.id, id) end) do
    None -> Err("credits_purchase_unknown")
    Some(value) -> Ok(value)
  end
end

pub fn credits_store_writes(database_path :: String,
  writes :: CreditWrites) -> Result<(), String> do
  store_record_changes(database_path, writes.labels, writes.blobs, writes.removed)
end

## What the app shows of a purchase: id16 || u8 state || u8 pack || u8 asset ||
## u16 batch || u64 amount || u64 created_ms || u64 updated_ms || u64
## expires_ms || u32 issued || quote_id32 || vector32(payment request) ||
## vector32(payment signature).

pub fn credits_encode_purchase(value :: CreditPurchase) -> Bytes!String do
  let quote = credits_decode_quote(value.quote)?
  tcodec_join([
    value.id,
    tcodec_u8(value.state)?,
    tcodec_u8(quote.pack)?,
    tcodec_u8(quote.asset)?,
    tcodec_u16(quote.batch)?,
    tcodec_u64(quote.amount)?,
    tcodec_u64(value.created_at)?,
    tcodec_u64(value.updated_at)?,
    tcodec_u64(quote.expires_at)?,
    tcodec_u32(value.issued)?,
    quote.quote_id,
    tcodec_vector(Bytes.from_utf8(quote.payment_request))?,
    tcodec_vector(Bytes.from_utf8(value.payment))?
  ])
end

## The issuer origin this build pins, or Err when it sells no credits.

pub fn credits_issuer_origin() -> String!String do
  let config = native_security_config()?
  if config.config.issuer_origin == "" do
    Err("credits_unavailable")
  else
    credits_issuer_name(config.config.issuer_origin)?
    Ok(config.config.issuer_origin)
  end
end

fn quote_status(status :: Int) -> String do
  if status == 429 do
    "credits_quote_busy"
  else if status == 422 do
    "credits_asset_unavailable"
  else if status == 503 || status == 404 do
    "credits_unavailable"
  else
    "credits_quote_failed"
  end
end

fn checked_quote(quote :: CreditQuote,
  pack :: Int,
  asset :: Int,
  now :: Int) -> CreditQuote!String do
  if quote.pack != pack
    || quote.asset != asset
    || quote.batch != credits_pack_size(pack)?
    || quote.expires_at <= now
    || String.length(quote.payment_request) == 0 do
    Err("credits_quote_invalid")
  else
    Ok(quote)
  end
end

## Asks for a quote (pack 1/2/3 x asset 1 USDC/2 SOL/3 BTC) through the edge
## and keeps it as a new purchase. Request: vector32(path) || vector32(edge
## URL) || vector32(u8 pack) || vector32(u8 asset). Answer: the purchase.

pub fn credits_quote(request :: Bytes) -> Bytes!String do
  let fields = credits_fields(request, 4)?
  let path = credits_path(List.get(fields, 0))?
  let edge = credits_service_url(List.get(fields, 1))?
  let pack = credits_small(List.get(fields, 2))?
  let asset = credits_small(List.get(fields, 3))?
  credits_issuer_origin()?
  credits_pack_size(pack)?
  if asset < 1 || asset > 3 do
    return Err("invalid_credits_request")
  end
  let wrapping_key = platform_key()?
  let now = credits_now()
  let keys = credits_load_keys(path, wrapping_key)?
  if !List.any(keys.keys, fn key -> credits_key_valid_at(key, now) end) do
    return Err("credits_keys_needed")
  end
  let stamped = stamped_request(credits_quote_work_label(),
    credits_encode_quote_request(CreditQuoteRequest { pack: pack, asset: asset })?)?
  let answer = credits_http("POST", edge <> "/v1/credits/quote", stamped, 16384)?
  if answer.status != 201 do
    return Err(quote_status(answer.status))
  end
  let quote = case credits_decode_quote(answer.body) do
    Err(_) -> Err("credits_quote_invalid")
    Ok(value) -> checked_quote(value, pack, asset, now)
  end?
  case credits_find_key(keys.keys, quote.token_key_id) do
    None -> return Err("credits_key_unknown")
    Some(_) -> nil
  end
  let record = CreditPurchase {
    id: credits_random(16)?,
    state: credits_state_quoted(),
    created_at: now,
    updated_at: now,
    issued: 0,
    key_id: credits_zeroes(32)?,
    quote: answer.body,
    payment: ""
  }
  let purchases = credits_load_purchases(path, wrapping_key)?
  credits_store_writes(path, credits_purchase_write(purchases, record, wrapping_key)?)?
  credits_encode_purchase(record)
end

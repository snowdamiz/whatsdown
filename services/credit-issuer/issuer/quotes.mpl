##! Quotes (plan §6.10 issuance step 2): a fixed pack, an asset, a fresh
##! deposit address or Lightning invoice, the amount, 15 minutes, and the key
##! the batch must be blinded for.

from Credits.CreditFrames import (
  CreditQuote,
  CreditQuoteRequest,
  credits_asset_name,
  credits_pack_price,
  credits_pack_size
)
from Issuer.Derivation import issuer_deposit_key
from Issuer.KeyStore import issuer_signing_key
from Issuer.Lightning import issuer_lnd_invoice
from Issuer.Oracle import issuer_lamports_for, issuer_price, issuer_sats_for
from Issuer.Settings import (
  IssuerSettings,
  issuer_asset_enabled,
  issuer_btc_feed,
  issuer_purpose,
  issuer_quote_lifetime_ms,
  issuer_sol_feed
)

pub type QuoteOutcome do
  Quoted(quote :: CreditQuote)
  QuoteClosed
  QuoteRefused
end

struct Destination do
  amount :: Int
  deposit_index :: Option<Int>
  deposit_address :: Option<String>
  invoice_hash :: Option<Bytes>
  payment_request :: String
end

fn trim_zeros(text :: String) -> String do
  if String.ends_with(text, "0") do
    trim_zeros(String.slice(text, 0, String.length(text) - 1))
  else
    text
  end
end

fn power10(exponent :: Int) -> Int do
  if exponent <= 0 do
    1
  else
    10 * power10(exponent - 1)
  end
end

## A base-unit amount as the decimal a Solana Pay URL carries: 5000000 at 6
## decimals is "5", 33333334 at 9 is "0.033333334".

pub fn issuer_decimal(value :: Int, decimals :: Int) -> String do
  let unit = power10(decimals)
  let fraction = value % unit
  if fraction == 0 do
    Int.to_string(value / unit)
  else
    let digits = Int.to_string(fraction)
    Int.to_string(value / unit)
      <> "."
      <> trim_zeros(String.repeat("0", decimals - String.length(digits)) <> digits)
  end
end

## The Solana Pay reference of a quote. Not the quote ID itself: a reference
## is public on-chain, and the quote ID is what lets its holder collect the
## tokens (issue requests name it), so it must stay with the buyer.

pub fn issuer_reference(quote_id :: Bytes) -> Bytes!String do
  case Bytes.concat(Bytes.from_utf8("morse-credits/v1/solana-pay-reference"), quote_id) do
    Err(_) -> Err("reference allocation failed")
    Ok(joined) -> Ok(Crypto.sha256(joined))
  end
end

fn solana_pay(address :: String,
  amount :: Int,
  decimals :: Int,
  mint :: String,
  reference :: Bytes,
  batch :: Int) -> String do
  let token = if mint == "" do
    ""
  else
    "&spl-token=" <> mint
  end
  "solana:"
    <> address
    <> "?amount="
    <> issuer_decimal(amount, decimals)
    <> token
    <> "&reference="
    <> Bytes.to_base58(reference)
    <> "&label=Morse&message="
    <> Int.to_string(batch)
    <> "%20Morse%20credits"
end

fn next_index(pool :: PoolHandle) -> Int!String do
  let rows = Pool.query_values(pool, "SELECT nextval('deposit_index_seq')::text AS value", [])?
  case rows do
    [row] -> case Map.get(row, "value") do
      Text(text) -> case String.to_int(text) do
        Some(value) -> Ok(value)
        None -> Err("invalid deposit index")
      end
      _ -> Err("invalid deposit index")
    end
    _ -> Err("deposit index failed")
  end
end

fn solana_destination(pool :: PoolHandle,
  settings :: IssuerSettings,
  asset :: String,
  price_micro_usd :: Int,
  quote_id :: Bytes,
  batch :: Int,
  now_ms :: Int) -> Destination!String do
  let amount = if asset == "usdc" do
    price_micro_usd
  else
    issuer_lamports_for(price_micro_usd,
      issuer_price(settings.oracle_url, issuer_sol_feed(), now_ms / 1000)?)?
  end
  let index = next_index(pool)?
  let deposit = issuer_deposit_key(settings.deposit_seed, index)?
  let reference = issuer_reference(quote_id)?
  let request = if asset == "usdc" do
    solana_pay(deposit.address, amount, 6, settings.usdc_mint, reference, batch)
  else
    solana_pay(deposit.address, amount, 9, "", reference, batch)
  end
  Ok(Destination {
    amount: amount,
    deposit_index: Some(index),
    deposit_address: Some(deposit.address),
    invoice_hash: None,
    payment_request: request
  })
end

fn lightning_destination(settings :: IssuerSettings,
  price_micro_usd :: Int,
  batch :: Int,
  now_ms :: Int) -> Destination!String do
  let sats = issuer_sats_for(price_micro_usd,
    issuer_price(settings.oracle_url, issuer_btc_feed(), now_ms / 1000)?)?
  let invoice = issuer_lnd_invoice(settings.lnd_url,
    settings.lnd_macaroon,
    sats,
    Int.to_string(batch) <> " Morse credits")?
  Ok(Destination {
    amount: sats,
    deposit_index: None,
    deposit_address: None,
    invoice_hash: Some(invoice.r_hash),
    payment_request: invoice.payment_request
  })
end

fn optional_text(value :: Option<String>) -> DbValue do
  case value do
    None -> Null
    Some(text) -> Text(text)
  end
end

fn optional_int(value :: Option<Int>) -> DbValue do
  case value do
    None -> Null
    Some(number) -> Text(Int.to_string(number))
  end
end

fn optional_bytes(value :: Option<Bytes>) -> DbValue do
  case value do
    None -> Null
    Some(bytes) -> Binary(bytes)
  end
end

## Admits one quote request: its stamp (`stamp_key`, from the PWR frame it
## came in) was not spent before, and fewer than MORSE_CREDIT_MAX_OPEN_QUOTES
## quotes are open and unexpired. Expired quotes stop counting. Spent stamps
## are forgotten 10 minutes on, twice their window.

pub fn issuer_admit_quote(pool :: PoolHandle,
  settings :: IssuerSettings,
  stamp_key :: Bytes) -> Bool!String do
  Pool.execute(pool, "DELETE FROM quote_stamps WHERE forget_after < now()", [])?
  let open = Pool.query_values(pool,
    "SELECT (count(*) < $1::integer)::text AS value FROM quotes WHERE state = 'open' AND expires_at > now()",
    [Text(Int.to_string(settings.max_open_quotes))])?
  let room = case open do
    [row] -> case Map.get(row, "value") do
      Text(value) -> value == "true"
      _ -> false
    end
    _ -> false
  end
  if !room do
    Ok(false)
  else
    let spent = Pool.execute_values(pool,
      "INSERT INTO quote_stamps (stamp_key, forget_after) VALUES ($1, now() + interval '10 minutes') ON CONFLICT DO NOTHING",
      [Binary(stamp_key)])?
    Ok(spent == 1)
  end
end

## A quote for `request`, or QuoteClosed (credits off, or no announced key for
## this epoch) or QuoteRefused (the asset is not offered).

pub fn issuer_quote(pool :: PoolHandle,
  settings :: IssuerSettings,
  request :: CreditQuoteRequest,
  now_ms :: Int) -> QuoteOutcome!String do
  let asset = credits_asset_name(request.asset)?
  if settings.mode == "off" do
    return Ok(QuoteClosed)
  end
  if !issuer_asset_enabled(settings, asset) do
    return Ok(QuoteRefused)
  end
  let key = case issuer_signing_key(pool, issuer_purpose(settings), now_ms)? do
    None -> return Ok(QuoteClosed)
    Some(value) -> value
  end
  let quote_id = case Crypto.random_bytes(32) do
    Err(_) -> Err("quote id generation failed")
    Ok(value)
  end?
  let batch = credits_pack_size(request.pack)?
  let price = credits_pack_price(request.pack)?
  let destination = if asset == "btc" do
    lightning_destination(settings, price, batch, now_ms)?
  else
    solana_destination(pool, settings, asset, price, quote_id, batch, now_ms)?
  end
  let expires_at = now_ms + issuer_quote_lifetime_ms()
  Pool.execute_values(pool,
    "INSERT INTO quotes (quote_id, purpose, pack, batch, asset, amount, price_micro_usd, deposit_index, deposit_address, invoice_hash, payment_request, expires_at) VALUES ($1, $2, $3::smallint, $4::integer, $5, $6::bigint, $7::bigint, $8::integer, $9, $10, $11, to_timestamp($12::bigint / 1000.0))",
    [
      Binary(quote_id),
      Text(issuer_purpose(settings)),
      Text(Int.to_string(request.pack)),
      Text(Int.to_string(batch)),
      Text(asset),
      Text(Int.to_string(destination.amount)),
      Text(Int.to_string(price)),
      optional_int(destination.deposit_index),
      optional_text(destination.deposit_address),
      optional_bytes(destination.invoice_hash),
      Text(destination.payment_request),
      Text(Int.to_string(expires_at))
    ])?
  Ok(Quoted(CreditQuote {
    quote_id: quote_id,
    pack: request.pack,
    asset: request.asset,
    batch: batch,
    amount: destination.amount,
    expires_at: expires_at,
    token_key_id: key.key_id,
    payment_request: destination.payment_request
  }))
end

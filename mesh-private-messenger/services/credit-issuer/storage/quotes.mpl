from Payment.RevenuePolicy import credit_revenue_policy_hash
from Credits.Issuance import (
  CreditQuoteRequest,
  CreditQuote,
  encode_credit_quote_request,
  decode_credit_quote
)
from Credits.Policy import credit_pack, issuer_epoch
from Payment.Verify import payment_token_address
from Storage.Issuance import insert_quote_with_revenue_policy

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_issuer_row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_issuer_row")
  end
end

# The SOL price is supplied by the issuer's configured oracle adapter, never
# by an HTTP caller. Integer ceil prevents a fraction of a lamport underpaying.
pub fn quote_amount(credits :: Int, asset :: Int, usd_micros_per_sol :: U64) -> U64!String do
  let pack = credit_pack(credits)?
  if asset == 0 do
    return Ok(pack.usd_micros)
  end
  if asset != 1 || usd_micros_per_sol == U64.parse("0")? do
    return Err("invalid_credit_price")
  end
  let denominator = U128.parse(U64.to_string(usd_micros_per_sol))?
  let numerator = U128.multiply(U128.parse(U64.to_string(pack.usd_micros))?,
    U128.parse("1000000000")?)?
  let rounded = U128.divide(U128.add(numerator, U128.subtract(denominator, U128.parse("1")?)?)?,
    denominator)?
  U64.parse(U128.to_string(rounded))
end

fn root_context(service_key :: Bytes) -> Bytes!String do
  if Bytes.length(service_key) != 32 do
    return Err("invalid_issuer_context")
  end
  Bytes.from_hex("01"
    <> Bytes.to_hex(service_key)
    <> String.repeat("00", 48)
    <> Bytes.to_hex(Crypto.sha256(Bytes.from_utf8("morse-credit-deposit-root-v1")))
    <> "00010000000000000001")
end

fn deposit_root(conn :: borrow PgConn,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> SecretBytes!String do
  let ctx = root_context(service_key)?
  let rows = Pg.query_values(conn,
    "SELECT sealed_seed FROM issuer_deposit_root WHERE singleton FOR UPDATE",
    [])?
  if List.length(rows) == 1 do
    return case Secret.unseal_from_storage(binary(Map.get(List.head(rows), "sealed_seed"))?,
      wrapping,
      ctx) do
      Ok(value)
      Err(_) -> Err("deposit_root_unavailable")
    end
  end
  let seed = case Secret.random(32) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_entropy_unavailable")
  end
  let sealed = case Secret.seal_for_storage(seed, wrapping, ctx) do
    Ok(value) -> value
    Err(_) -> return Err("deposit_root_seal_failed")
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_deposit_root (singleton, sealed_seed) VALUES (true, $1)",
    [Binary(sealed)])?
  Ok(seed)
end

# Run in a transaction. The key+batch unique constraint makes retries of a
# lost quote response return the original deposit and expiry, never a new bill.
pub fn existing_quote_on_connection(conn :: borrow PgConn,
  request :: CreditQuoteRequest,
  pinned_mint :: Bytes) -> Option<CreditQuote>!String do
  let rows = Pg.query_values(conn,
    "SELECT quote FROM issuer_quotes WHERE key_id = $1 AND batch_hash = $2",
    [Binary(request.issuer_key_id), Binary(request.batch_hash)])?
  if List.length(rows) == 0 do
    return Ok(None)
  end
  if List.length(rows) != 1 do
    return Err("invalid_issuer_row")
  end
  let quote = decode_credit_quote(binary(Map.get(List.head(rows), "quote"))?)?
  if quote.credits != request.credits
    || quote.asset != request.asset
    || quote.purpose != request.purpose
    || (quote.asset == 0 && !Bytes.secure_equals(quote.mint, pinned_mint)) do
    return Err("credit_quote_conflict")
  end
  Ok(Some(quote))
end

pub fn create_quote_on_connection(conn :: borrow PgConn,
  request :: CreditQuoteRequest,
  pinned_mint :: Bytes,
  usd_micros_per_sol :: U64,
  price_observed_at :: U64,
  now :: U64,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> CreditQuote!String do
  create_quote_with_revenue_policy(conn,
    request,
    pinned_mint,
    usd_micros_per_sol,
    price_observed_at,
    now,
    wrapping,
    service_key,
    1)
end

pub fn create_quote_with_revenue_policy(conn :: borrow PgConn,
  request :: CreditQuoteRequest,
  pinned_mint :: Bytes,
  usd_micros_per_sol :: U64,
  price_observed_at :: U64,
  now :: U64,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  version :: Int) -> CreditQuote!String do
  credit_revenue_policy_hash(version)?
  encode_credit_quote_request(request)?
  if Bytes.length(pinned_mint) != 32 || Bytes.to_hex(pinned_mint) == String.repeat("00", 32) do
    return Err("invalid_payment_mint")
  end
  # This lock is confined to quote creation/root initialization, not signing
  # or RPC traffic. It also serializes the missing-row case for a commitment.
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365491)", [])?
  let previous = Pg.query_values(conn,
    "SELECT quote FROM issuer_quotes WHERE key_id = $1 AND batch_hash = $2 FOR UPDATE",
    [Binary(request.issuer_key_id), Binary(request.batch_hash)])?
  if List.length(previous) == 1 do
    let quote = decode_credit_quote(binary(Map.get(List.head(previous), "quote"))?)?
    if quote.credits != request.credits
      || quote.asset != request.asset
      || quote.purpose != request.purpose
      || (quote.asset == 0 && !Bytes.secure_equals(quote.mint, pinned_mint)) do
      return Err("credit_quote_conflict")
    end
    return Ok(quote)
  end
  let lightning = Pg.query_values(conn,
    "SELECT quote_id FROM issuer_lightning_quotes WHERE key_id=$1 AND batch_hash=$2",
    [Binary(request.issuer_key_id), Binary(request.batch_hash)])?
  if List.length(lightning) != 0 do
    return Err("credit_quote_conflict")
  end
  let keys = Pg.query_values(conn,
    "SELECT epoch::text, purpose::text, admitted_evidence FROM issuer_keys WHERE key_id = $1 FOR SHARE",
    [Binary(request.issuer_key_id)])?
  if List.length(keys) != 1 do
    return Err("unknown_issuer_key")
  end
  let key = List.head(keys)
  if text(Map.get(key, "epoch"))? != U64.to_string(issuer_epoch(now)?)
    || text(Map.get(key, "purpose"))? != Int.to_string(request.purpose) do
    return Err("inactive_credit_issuer")
  end
  binary(Map.get(key, "admitted_evidence"))?
  if request.asset == 1
    && (U64.compare(price_observed_at, now) > 0
      || U64.compare(U64.subtract(now, price_observed_at)?, U64.parse("60")?) > 0) do
    return Err("stale_payment_price")
  end
  let quote_id = case Crypto.random_bytes(32) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_entropy_unavailable")
  end
  let root = deposit_root(conn, wrapping, service_key)?
  let derived = case Crypto.hkdf_sha256(root,
    quote_id,
    Bytes.from_utf8("morse-credit-deposit-ed25519-v1"),
    32) do
    Ok(value) -> value
    Err(_) -> return Err("deposit_derivation_failed")
  end
  let deposit = case Crypto.signing_from_secret(derived) do
    Ok(value) -> value
    Err(_) -> return Err("deposit_derivation_failed")
  end
  let quote = CreditQuote {
    quote_id: quote_id,
    deposit_owner: deposit.public_key.bytes,
    destination: if request.asset == 0 do
      payment_token_address(deposit.public_key.bytes, pinned_mint)?
    else
      deposit.public_key.bytes
    end,
    mint: if request.asset == 0 do
      pinned_mint
    else
      Bytes.from_hex(String.repeat("00", 32))?
    end,
    asset: request.asset,
    amount: quote_amount(request.credits, request.asset, usd_micros_per_sol)?,
    purpose: request.purpose,
    credits: request.credits,
    issued_at: now,
    expires_at: U64.add(now, U64.parse("900")?)?,
    issuer_key_id: request.issuer_key_id,
    batch_hash: request.batch_hash
  }
  insert_quote_with_revenue_policy(conn,
    quote,
    deposit.private_key,
    wrapping,
    service_key,
    price_observed_at,
    version)?
  Ok(quote)
end

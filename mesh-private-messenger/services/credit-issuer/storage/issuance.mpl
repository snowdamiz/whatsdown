from Payment.RevenuePolicy import credit_revenue_policy_hash
from Storage.KeyMaterial import (
  issuer_key_context,
  issuer_quote_key_context,
  issuer_key_rows,
  issuer_key_from_row
)
from Storage.Treasury import record_issued_credit_revenue
from Credits.QuoteAuth import (
  SignedCreditQuote,
  sign_credit_quote,
  verify_credit_quote,
  encode_signed_credit_quote,
  decode_signed_credit_quote
)
from Credits.Issuance import (
  CreditQuote,
  CreditIssueRequest,
  CreditIssueResponse,
  encode_credit_quote,
  decode_credit_quote,
  encode_credit_issue_response,
  decode_credit_issue_response,
  validate_quote_for_key,
  validate_issue_for_quote
)
from Credits.Issuer import CreditIssuerKey, issuer_key_id, verify_issuer_key
from Credits.Policy import issuer_epoch_accepted
from Credits.Token import sign_credit_request
from Payment.Verify import PaymentReceipt, payment_token_address
from Transparency.Merkle import WitnessKey
from Transparency.Wire import TransparencyEvidence, encode_transparency_evidence, encode_checkpoint

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

# Caller owns the transaction. New keys must subsequently be admitted through
# witnessed transparency before they can authorize a quote.
pub fn insert_issuer_key(conn :: borrow PgConn,
  key :: CreditIssuerKey,
  private :: borrow BlindRsaSecretKey,
  quote_private :: borrow SigningPrivateKey,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> Result<(), String> do
  let id = issuer_key_id(key)?
  let public = case Crypto.blind_rsa_public(private) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_key_unavailable")
  end
  if !Bytes.secure_equals(public.bytes, key.spki) do
    return Err("issuer_key_mismatch")
  end
  let binding = Bytes.concat(Bytes.from_utf8("morse-credit-quote-key-binding-v1"), id)?
  let signed = case Crypto.sign(quote_private, binding) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_quote_key_unavailable")
  end
  let matches = case Crypto.verify(SigningPublicKey { bytes: key.quote_public_key },
    binding,
    signed) do
    Ok(value) -> value
    Err(_) -> false
  end
  if !matches do
    return Err("issuer_quote_key_mismatch")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365490)", [])?
  let previous = Pg.query_values(conn,
    "SELECT key_id FROM issuer_keys WHERE (epoch = $1::numeric AND purpose = $2::smallint) OR key_id = $3",
    [Text(U64.to_string(key.epoch)), Text(Int.to_string(key.purpose)), Binary(id)])?
  if List.length(previous) != 0 do
    if List.length(previous) != 1
      || !Bytes.secure_equals(binary(Map.get(List.head(previous), "key_id"))?, id) do
      return Err("issuer_key_replacement_refused")
    end
    let stored = issuer_key_from_row(List.head(issuer_key_rows(conn, id)?))?
    if stored.epoch != key.epoch
      || stored.purpose != key.purpose
      || !Bytes.secure_equals(stored.quote_public_key, key.quote_public_key) do
      return Err("issuer_key_reuse_refused")
    end
    return Ok(nil)
  end
  let sealed = case BlindRsaSecretKey.seal_for_storage(private,
    wrapping,
    issuer_key_context(service_key, id, 18)?) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_key_seal_failed")
  end
  let quote_sealed = case SigningPrivateKey.seal_for_storage(quote_private,
    wrapping,
    issuer_quote_key_context(service_key, id)?) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_quote_key_seal_failed")
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_keys (key_id, epoch, purpose, spki, sealed_private_key, quote_public_key, sealed_quote_key) VALUES ($1, $2::numeric, $3::smallint, $4, $5, $6, $7)",
    [
      Binary(id),
      Text(U64.to_string(key.epoch)),
      Text(Int.to_string(key.purpose)),
      Binary(key.spki),
      Binary(sealed),
      Binary(key.quote_public_key),
      Binary(quote_sealed)
    ])?
  Ok(nil)
end

pub fn admit_issuer_key(conn :: borrow PgConn,
  evidence :: TransparencyEvidence,
  service_key :: SigningPublicKey,
  witnesses :: List<WitnessKey>,
  threshold :: Int,
  now :: U64,
  purpose :: Int) -> Result<(), String> do
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365490)", [])?
  let cursor = Pg.query_values(conn,
    "SELECT checkpoint FROM issuer_transparency_cursor WHERE singleton FOR UPDATE",
    [])?
  let previous = if List.length(cursor) == 0 do
    Bytes.empty()
  else
    binary(Map.get(List.head(cursor), "checkpoint"))?
  end
  let key = verify_issuer_key(evidence, service_key, witnesses, threshold, previous, now, purpose)?
  let id = issuer_key_id(key)?
  let rows = issuer_key_rows(conn, id)?
  if List.length(rows) != 1 do
    return Err("unknown_issuer_key")
  end
  let stored = issuer_key_from_row(List.head(rows))?
  if stored.epoch != key.epoch
    || stored.purpose != key.purpose
    || !Bytes.secure_equals(stored.quote_public_key, key.quote_public_key) do
    return Err("issuer_key_mismatch")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_keys SET admitted_evidence = $2 WHERE key_id = $1",
    [Binary(id), Binary(encode_transparency_evidence(evidence)?)])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_transparency_cursor (singleton, checkpoint) VALUES (true, $1) ON CONFLICT (singleton) DO UPDATE SET checkpoint = EXCLUDED.checkpoint",
    [Binary(encode_checkpoint(evidence.checkpoint)?)])?
  Ok(nil)
end

pub fn insert_quote(conn :: borrow PgConn,
  quote :: CreditQuote,
  deposit :: borrow SigningPrivateKey,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  price_observed_at :: U64) -> Result<(), String> do
  insert_quote_with_revenue_policy(conn,
    quote,
    deposit,
    wrapping,
    service_key,
    price_observed_at,
    1)
end

pub fn insert_quote_with_revenue_policy(conn :: borrow PgConn,
  quote :: CreditQuote,
  deposit :: borrow SigningPrivateKey,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  price_observed_at :: U64,
  version :: Int) -> Result<(), String> do
  let policy_hash = credit_revenue_policy_hash(version)?
  let encoded = encode_credit_quote(quote)?
  let keys = issuer_key_rows(conn, quote.issuer_key_id)?
  if List.length(keys) != 1 do
    return Err("unknown_issuer_key")
  end
  let row = List.head(keys)
  binary(Map.get(row, "admitted_evidence"))?
  validate_quote_for_key(quote, issuer_key_from_row(row)?, quote.issued_at)?
  let challenge = Bytes.concat(Bytes.from_utf8("morse-credit-deposit-key-binding-v1"),
    quote.quote_id)?
  let signature = case Crypto.sign(deposit, challenge) do
    Ok(value) -> value
    Err(_) -> return Err("deposit_key_unavailable")
  end
  let owns_key = case Crypto.verify(SigningPublicKey { bytes: quote.deposit_owner },
    challenge,
    signature) do
    Ok(value) -> value
    Err(_) -> false
  end
  if !owns_key
    || Bytes.secure_equals(quote.quote_id, quote.deposit_owner)
    || Bytes.secure_equals(quote.quote_id, quote.destination) do
    return Err("deposit_key_mismatch")
  end
  if quote.asset == 0 do
    if !Bytes.secure_equals(quote.destination,
      payment_token_address(quote.deposit_owner, quote.mint)?) do
      return Err("invalid_deposit_destination")
    end
  else if U64.compare(price_observed_at, quote.issued_at) > 0
    || U64.compare(U64.subtract(quote.issued_at, price_observed_at)?, U64.parse("60")?) > 0 do
    return Err("stale_payment_price")
  end
  let sealed = case SigningPrivateKey.seal_for_storage(deposit,
    wrapping,
    issuer_key_context(service_key, quote.quote_id, 6)?) do
    Ok(value) -> value
    Err(_) -> return Err("deposit_key_seal_failed")
  end
  let quote_private = case SigningPrivateKey.unseal_from_storage(binary(Map.get(row,
      "sealed_quote_key"))?,
    wrapping,
    issuer_quote_key_context(service_key, quote.issuer_key_id)?) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_quote_key_unavailable")
  end
  let authenticated = sign_credit_quote(quote_private, quote)?
  if !verify_credit_quote(authenticated, issuer_key_from_row(row)?)? do
    return Err("issuer_quote_key_mismatch")
  end
  let signed_quote = encode_signed_credit_quote(authenticated)?
  Pg.execute_values(conn,
    "INSERT INTO issuer_quotes (quote_id, quote, key_id, deposit_owner, sealed_deposit_key, price_observed_at, batch_hash, signed_quote,policy_version,policy_hash) VALUES ($1, $2, $3, $4, $5, $6::numeric, $7, $8,$9::smallint,$10) ON CONFLICT (quote_id) DO NOTHING",
    [
      Binary(quote.quote_id),
      Binary(encoded),
      Binary(quote.issuer_key_id),
      Binary(quote.deposit_owner),
      Binary(sealed),
      Text(U64.to_string(price_observed_at)),
      Binary(quote.batch_hash),
      Binary(signed_quote),
      Text(Int.to_string(version)),
      Binary(policy_hash)
    ])?
  let previous = Pg.query_values(conn,
    "SELECT quote, signed_quote, price_observed_at::text,policy_version::text,policy_hash FROM issuer_quotes WHERE quote_id = $1 FOR UPDATE",
    [Binary(quote.quote_id)])?
  if List.length(previous) != 1
    || text(Map.get(List.head(previous), "policy_version"))? != Int.to_string(version)
    || binary(Map.get(List.head(previous), "policy_hash"))? != policy_hash
    || !Bytes.secure_equals(binary(Map.get(List.head(previous), "quote"))?, encoded)
    || !Bytes.secure_equals(binary(Map.get(List.head(previous), "signed_quote"))?, signed_quote)
    || text(Map.get(List.head(previous),
      "price_observed_at"))? != U64.to_string(price_observed_at) do
    return Err("credit_quote_conflict")
  end
  Ok(nil)
end

pub fn load_quote(conn :: borrow PgConn, quote_id :: Bytes) -> CreditQuote!String do
  let rows = Pg.query_values(conn,
    "SELECT quote FROM issuer_quotes WHERE quote_id = $1",
    [Binary(quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  decode_credit_quote(binary(Map.get(List.head(rows), "quote"))?)
end

pub struct PreparedIssue do
  quote :: CreditQuote
  price_observed_at :: U64
  cached :: Option<CreditIssueResponse>
end

# Release the database connection before any RPC operation. Immutable quote
# bytes and the final issuance row lock make this read safe to retry/race.
pub fn prepare_issue_on_connection(conn :: borrow PgConn,
  request :: CreditIssueRequest) -> PreparedIssue!String do
  let rows = Pg.query_values(conn,
    "SELECT quote, price_observed_at::text, payment_signature, issued_response FROM issuer_quotes WHERE quote_id = $1",
    [Binary(request.quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  let row = List.head(rows)
  let quote = decode_credit_quote(binary(Map.get(row, "quote"))?)?
  validate_issue_for_quote(quote, request)?
  let cached = case Map.get(row, "issued_response") do
    Binary(response) -> do
      if !Bytes.secure_equals(binary(Map.get(row, "payment_signature"))?,
        request.transaction_signature) do
        return Err("credit_payment_conflict")
      end
      Some(decode_credit_issue_response(response)?)
    end
    Null -> None
    _ -> return Err("invalid_issuer_row")
  end
  Ok(PreparedIssue {
    quote: quote,
    price_observed_at: U64.parse(text(Map.get(row, "price_observed_at"))?)?,
    cached: cached
  })
end

# A verified payment is supplied only by Payment.Verify. This function is the
# final transaction boundary: no signature may leave the server before commit.
pub fn issue_paid_on_connection(conn :: borrow PgConn,
  request :: CreditIssueRequest,
  payment :: PaymentReceipt,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  now :: U64) -> CreditIssueResponse!String do
  let rows = Pg.query_values(conn,
    "SELECT quote, payment_signature, issued_response FROM issuer_quotes WHERE quote_id = $1 FOR UPDATE",
    [Binary(request.quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  let row = List.head(rows)
  let quote = decode_credit_quote(binary(Map.get(row, "quote"))?)?
  validate_issue_for_quote(quote, request)?
  case Map.get(row, "issued_response") do
    Binary(response) -> do
      if !Bytes.secure_equals(binary(Map.get(row, "payment_signature"))?,
        request.transaction_signature) do
        return Err("credit_payment_conflict")
      end
      return decode_credit_issue_response(response)
    end
    Null -> nil
    _ -> return Err("invalid_issuer_row")
  end
  if !Bytes.secure_equals(payment.transaction_signature, request.transaction_signature)
    || Bytes.length(payment.payer) != 32
    || Bytes.to_hex(payment.payer) == String.repeat("00", 32)
    || payment.slot == U64.parse("0")?
    || U64.compare(payment.block_time, quote.issued_at) < 0
    || U64.compare(payment.block_time, quote.expires_at) >= 0
    || U64.compare(payment.block_time, now) > 0
    || U64.compare(payment.received_amount, quote.amount) < 0
    || U128.compare(U128.multiply(U128.parse(U64.to_string(payment.received_amount))?,
        U128.parse("100")?)?,
      U128.multiply(U128.parse(U64.to_string(quote.amount))?, U128.parse("101")?)?) > 0 do
    return Err("credit_payment_mismatch")
  end
  let keys = issuer_key_rows(conn, quote.issuer_key_id)?
  if List.length(keys) != 1 do
    return Err("unknown_issuer_key")
  end
  let key_row = List.head(keys)
  binary(Map.get(key_row, "admitted_evidence"))?
  let key = issuer_key_from_row(key_row)?
  if !issuer_epoch_accepted(key.epoch, now)? do
    return Err("inactive_credit_issuer")
  end
  let private = case BlindRsaSecretKey.unseal_from_storage(binary(Map.get(key_row,
      "sealed_private_key"))?,
    wrapping,
    issuer_key_context(service_key, quote.issuer_key_id, 18)?) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_key_unavailable")
  end
  let signatures = for blinded in request.requests do
    sign_credit_request(private, key, blinded)?
  end
  let response = CreditIssueResponse {
    quote_id: quote.quote_id,
    batch_hash: quote.batch_hash,
    signatures: signatures
  }
  Pg.execute_values(conn,
    "UPDATE issuer_quotes SET payment_signature = $2, payment_payer = $3, payment_slot = $4::numeric, payment_time = $5::numeric, payment_amount = $6::numeric, issued_response = $7 WHERE quote_id = $1",
    [
      Binary(quote.quote_id),
      Binary(payment.transaction_signature),
      Binary(payment.payer),
      Text(U64.to_string(payment.slot)),
      Text(U64.to_string(payment.block_time)),
      Text(U64.to_string(payment.received_amount)),
      Binary(encode_credit_issue_response(response)?)
    ])?
  record_issued_credit_revenue(conn, quote.quote_id)?
  Ok(response)
end

pub fn load_signed_quote(conn :: borrow PgConn, quote_id :: Bytes) -> SignedCreditQuote!String do
  let rows = Pg.query_values(conn,
    "SELECT quote, signed_quote FROM issuer_quotes WHERE quote_id = $1",
    [Binary(quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  let row = List.head(rows)
  let signed = decode_signed_credit_quote(binary(Map.get(row, "signed_quote"))?)?
  let keys = issuer_key_rows(conn, signed.quote.issuer_key_id)?
  if List.length(keys) != 1
    || !Bytes.secure_equals(encode_credit_quote(signed.quote)?, binary(Map.get(row, "quote"))?)
    || !verify_credit_quote(signed, issuer_key_from_row(List.head(keys))?)? do
    return Err("invalid_signed_credit_quote")
  end
  Ok(signed)
end

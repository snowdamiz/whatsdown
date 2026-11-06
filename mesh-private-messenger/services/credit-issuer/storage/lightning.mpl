from Payment.RevenuePolicy import credit_revenue_policy_hash
from Credits.LightningCancellation import (
  LightningCancellation,
  sign_lightning_cancellation,
  encode_lightning_cancellation,
  decode_lightning_cancellation,
  verify_lightning_cancellation
)
from Credits.Lightning import (
  LightningQuote,
  LightningIssueRequest,
  sign_lightning_quote,
  verify_lightning_quote,
  encode_signed_lightning_quote,
  validate_lightning_quote_response,
  validate_lightning_issue
)
from Credits.Issuance import encode_credit_issue_response
from Credits.Policy import issuer_epoch_accepted
from Credits.Token import sign_credit_request
from Storage.KeyMaterial import (
  issuer_key_context,
  issuer_quote_key_context,
  issuer_key_rows,
  issuer_key_from_row
)
from Payment.LightningBackend import LndInvoice
from Payment.LightningPolicy import lightning_settlement_decision
from Credits.Lightning import (
  LightningQuoteRequest,
  SignedLightningQuote,
  encode_lightning_quote_request,
  decode_lightning_quote_request,
  decode_signed_lightning_quote
)
from Credits.Issuance import CreditIssueResponse, decode_credit_issue_response
from Credits.Policy import issuer_epoch
from Payment.LightningBackend import LndConfig, validate_lnd_config
from Payment.LightningPolicy import lightning_amount

pub struct LightningRecord do
  quote_id :: Bytes
  policy_version :: Int
  policy_hash :: Bytes
  service_key :: Bytes
  request :: LightningQuoteRequest
  payment_hash :: Bytes
  amount_msat :: U64
  reserved_at :: U64
  price_observed_at :: U64
  state :: Int
  signed :: Option<SignedLightningQuote>
  response :: Option<CreditIssueResponse>
  cancellation :: Option<LightningCancellation>
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_lightning_row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_lightning_row")
  end
end

pub fn lightning_backend_hash(config :: LndConfig) -> Bytes!String do
  validate_lnd_config(config)?
  Ok(Crypto.sha256(Bytes.from_utf8("morse-lightning-backend-v1\n"
    <> config.origin
    <> "\n"
    <> Int.to_string(config.purpose)
    <> "\n"
    <> Int.to_string(config.network)
    <> "\n"
    <> Bytes.to_hex(config.payee))))
end

fn context(service_key :: Bytes, id :: Bytes) -> Bytes!String do
  if Bytes.length(service_key) != 32 || Bytes.length(id) != 32 do
    return Err("invalid_lightning_context")
  end
  Bytes.from_hex("01"
    <> Bytes.to_hex(service_key)
    <> String.repeat("00", 48)
    <> Bytes.to_hex(Crypto.sha256(Bytes.concat(Bytes.from_utf8("morse-lightning-preimage-v1"),
      id)?))
    <> "00140000000000000001")
end

fn rows(conn :: borrow PgConn, id :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT quote_id,request,key_id,batch_hash,backend_hash,service_key,payment_hash,sealed_preimage,amount_msat::text,reserved_at::text,price_observed_at::text,state::text,signed_quote,prepared_response,prepared_signature,cancellation,policy_version::text,policy_hash FROM issuer_lightning_quotes WHERE quote_id=$1 FOR UPDATE",
    [Binary(id)])
end

fn from_row(row :: Map<String, DbValue>, config :: LndConfig) -> LightningRecord!String do
  if !Bytes.secure_equals(binary(Map.get(row, "backend_hash"))?, lightning_backend_hash(config)?) do
    return Err("lightning_backend_change_refused")
  end
  let request = decode_lightning_quote_request(binary(Map.get(row, "request"))?)?
  if request.network != config.network
    || request.purpose != config.purpose
    || !Bytes.secure_equals(request.issuer_key_id, binary(Map.get(row, "key_id"))?)
    || !Bytes.secure_equals(request.batch_hash, binary(Map.get(row, "batch_hash"))?) do
    return Err("invalid_lightning_row")
  end
  let state = case String.to_int(text(Map.get(row, "state"))?) do
    Some(value) -> value
    None -> return Err("invalid_lightning_row")
  end
  Ok(LightningRecord {
    quote_id: binary(Map.get(row, "quote_id"))?,
    policy_version: case String.to_int(text(Map.get(row, "policy_version"))?) do
      Some(value) -> value
      None -> return Err("invalid_lightning_row")
    end,
    policy_hash: binary(Map.get(row, "policy_hash"))?,
    service_key: binary(Map.get(row, "service_key"))?,
    request: request,
    payment_hash: binary(Map.get(row, "payment_hash"))?,
    amount_msat: U64.parse(text(Map.get(row, "amount_msat"))?)?,
    reserved_at: U64.parse(text(Map.get(row, "reserved_at"))?)?,
    price_observed_at: U64.parse(text(Map.get(row, "price_observed_at"))?)?,
    state: state,
    signed: case Map.get(row, "signed_quote") do
      Null -> None
      Binary(value) -> Some(decode_signed_lightning_quote(value)?)
      _ -> return Err("invalid_lightning_row")
    end,
    cancellation: case Map.get(row, "cancellation") do
      Null -> None
      Binary(value) -> Some(decode_lightning_cancellation(value)?)
      _ -> return Err("invalid_lightning_row")
    end,
    response: case Map.get(row, "prepared_response") do
      Null -> None
      Binary(value) -> Some(decode_credit_issue_response(value)?)
      _ -> return Err("invalid_lightning_row")
    end
  })
end

pub fn load_lightning_record(conn :: borrow PgConn,
  id :: Bytes,
  config :: LndConfig) -> LightningRecord!String do
  let found = rows(conn, id)?
  if List.length(found) != 1 do
    return Err("unknown_lightning_quote")
  end
  let row = List.head(found)
  let record = from_row(row, config)?
  case record.signed do
    None -> if Option.is_some(record.cancellation) do
      return Err("invalid_lightning_row")
    end
    Some(signed) -> do
      let key = issuer_key_from_row(List.head(issuer_key_rows(conn,
        record.request.issuer_key_id)?))?
      if !verify_lightning_quote(signed, key)?
        || !Bytes.secure_equals(signed.quote.quote_id, record.quote_id)
        || !Bytes.secure_equals(signed.quote.payment_hash, record.payment_hash)
        || signed.quote.amount_msat != record.amount_msat do
        return Err("invalid_lightning_row")
      end
      validate_lightning_quote_response(record.request, signed.quote, key, signed.quote.issued_at)?
      case record.cancellation do
        None -> nil
        Some(canceled) -> if record.state != 4
          || !verify_lightning_cancellation(canceled, signed.quote, key)? do
          return Err("invalid_lightning_cancellation_signature")
        end
      end
      case record.response do
        None -> nil
        Some(response) -> do
          if !Bytes.secure_equals(response.quote_id, record.quote_id)
            || !Bytes.secure_equals(response.batch_hash, record.request.batch_hash)
            || List.length(response.signatures) != record.request.credits do
            return Err("invalid_lightning_row")
          end
          let valid = case Crypto.verify(SigningPublicKey { bytes: key.quote_public_key },
            prepared_bytes(response)?,
            Signature { bytes: binary(Map.get(row, "prepared_signature"))? }) do
            Ok(value) -> value
            Err(_) -> false
          end
          if !valid do
            return Err("invalid_lightning_prepared_signature")
          end
        end
      end
    end
  end
  Ok(record)
end

pub fn existing_lightning_quote(conn :: borrow PgConn,
  request :: LightningQuoteRequest,
  config :: LndConfig,
  service_key :: Bytes) -> Option<LightningRecord>!String do
  let encoded = encode_lightning_quote_request(request)?
  let found = Pg.query_values(conn,
    "SELECT quote_id FROM issuer_lightning_quotes WHERE key_id=$1 AND batch_hash=$2",
    [Binary(request.issuer_key_id), Binary(request.batch_hash)])?
  if List.length(found) == 0 do
    return Ok(None)
  end
  let record_rows = rows(conn, binary(Map.get(List.head(found), "quote_id"))?)?
  let row = List.head(record_rows)
  if !Bytes.secure_equals(encoded, binary(Map.get(row, "request"))?)
    || !Bytes.secure_equals(service_key, binary(Map.get(row, "service_key"))?) do
    return Err("lightning_quote_conflict")
  end
  Ok(Some(load_lightning_record(conn, binary(Map.get(row, "quote_id"))?, config)?))
end

# The shared Solana/LN creation lock fences one batch across payment rails.
# Return an existing reservation before checking a new oracle or key epoch.
pub fn reserve_lightning_quote(conn :: borrow PgConn,
  request :: LightningQuoteRequest,
  config :: LndConfig,
  btc_usd_micros :: U64,
  price_observed_at :: U64,
  now :: U64,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> LightningRecord!String do
  reserve_lightning_quote_with_revenue_policy(conn,
    request,
    config,
    btc_usd_micros,
    price_observed_at,
    now,
    wrapping,
    service_key,
    1)
end

pub fn reserve_lightning_quote_with_revenue_policy(conn :: borrow PgConn,
  request :: LightningQuoteRequest,
  config :: LndConfig,
  btc_usd_micros :: U64,
  price_observed_at :: U64,
  now :: U64,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  version :: Int) -> LightningRecord!String do
  let policy_hash = credit_revenue_policy_hash(version)?
  let encoded = encode_lightning_quote_request(request)?
  let backend = lightning_backend_hash(config)?
  if request.network != config.network || request.purpose != config.purpose do
    return Err("lightning_quote_policy_mismatch")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365491)", [])?
  case existing_lightning_quote(conn, request, config, service_key)? do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let other = Pg.query_values(conn,
    "SELECT quote_id FROM issuer_quotes WHERE key_id=$1 AND batch_hash=$2",
    [Binary(request.issuer_key_id), Binary(request.batch_hash)])?
  if List.length(other) != 0 do
    return Err("lightning_quote_conflict")
  end
  let keys = Pg.query_values(conn,
    "SELECT epoch::text,purpose::text,admitted_evidence FROM issuer_keys WHERE key_id=$1 FOR SHARE",
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
  if U64.compare(price_observed_at, now) > 0
    || U64.compare(U64.subtract(now, price_observed_at)?, U64.parse("60")?) > 0 do
    return Err("stale_payment_price")
  end
  let amount = lightning_amount(request.credits, btc_usd_micros)?
  let id = case Crypto.random_bytes(32) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_entropy_unavailable")
  end
  let preimage = case HashPreimage.generate() do
    Ok(value) -> value
    Err(_) -> return Err("issuer_entropy_unavailable")
  end
  let hash = case HashPreimage.commitment(preimage) do
    Ok(value) -> value
    Err(_) -> return Err("lightning_preimage_unavailable")
  end
  let sealed = case HashPreimage.seal_for_storage(preimage, wrapping, context(service_key, id)?) do
    Ok(value) -> value
    Err(_) -> return Err("lightning_preimage_seal_failed")
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_quotes(quote_id,request,key_id,batch_hash,backend_hash,service_key,payment_hash,sealed_preimage,amount_msat,reserved_at,price_observed_at,policy_version,policy_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9::numeric,$10::numeric,$11::numeric,$12::smallint,$13)",
    [
      Binary(id),
      Binary(encoded),
      Binary(request.issuer_key_id),
      Binary(request.batch_hash),
      Binary(backend),
      Binary(service_key),
      Binary(hash),
      Binary(sealed),
      Text(U64.to_string(amount)),
      Text(U64.to_string(now)),
      Text(U64.to_string(price_observed_at)),
      Text(Int.to_string(version)),
      Binary(policy_hash)
    ])?
  load_lightning_record(conn, id, config)
end

# No preimage can leave storage before the exact response has committed. The
# controller calls this in a later transaction, after preparation returned.
pub fn restore_lightning_preimage(conn :: borrow PgConn,
  id :: Bytes,
  config :: LndConfig,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> HashPreimage!String do
  let found = rows(conn, id)?
  if List.length(found) != 1 do
    return Err("unknown_lightning_quote")
  end
  let row = List.head(found)
  let record = load_lightning_record(conn, id, config)?
  if record.state != 2 || !Bytes.secure_equals(binary(Map.get(row, "service_key"))?, service_key) do
    return Err("lightning_settlement_not_prepared")
  end
  let value = case HashPreimage.unseal_from_storage(binary(Map.get(row, "sealed_preimage"))?,
    wrapping,
    context(service_key, id)?) do
    Ok(secret) -> secret
    Err(_) -> return Err("lightning_preimage_unavailable")
  end
  let hash = case HashPreimage.commitment(value) do
    Ok(bytes) -> bytes
    Err(_) -> return Err("lightning_preimage_unavailable")
  end
  if !Bytes.secure_equals(hash, record.payment_hash) do
    return Err("lightning_preimage_mismatch")
  end
  Ok(value)
end

fn prepared_bytes(response :: CreditIssueResponse) -> Bytes!String do
  Bytes.concat(Bytes.from_utf8("morse-lightning-prepared-response-v1"),
    Crypto.sha256(encode_credit_issue_response(response)?))
end

fn signing_key(conn :: borrow PgConn,
  id :: Bytes,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> SigningPrivateKey!String do
  let found = issuer_key_rows(conn, id)?
  if List.length(found) != 1 do
    return Err("unknown_issuer_key")
  end
  let row = List.head(found)
  binary(Map.get(row, "admitted_evidence"))?
  case SigningPrivateKey.unseal_from_storage(binary(Map.get(row, "sealed_quote_key"))?,
    wrapping,
    issuer_quote_key_context(service_key, id)?) do
    Ok(value)
    Err(_) -> Err("issuer_quote_key_unavailable")
  end
end

fn bound_invoice(record :: LightningRecord, observed :: LndInvoice) -> Result<(), String> do
  let signed = case record.signed do
    Some(value) -> value
    None -> return Err("lightning_quote_not_ready")
  end
  if !Bytes.secure_equals(record.payment_hash, observed.payment_hash)
    || observed.amount_msat != record.amount_msat
    || signed.quote.invoice != observed.invoice
    || signed.quote.issued_at != observed.created_at
    || signed.quote.expires_at != observed.expires_at do
    return Err("lightning_receipt_mismatch")
  end
  Ok(nil)
end

pub fn store_lightning_invoice(conn :: borrow PgConn,
  id :: Bytes,
  observed :: LndInvoice,
  config :: LndConfig,
  wrapping :: borrow StorageKey,
  service_key :: Bytes) -> LightningRecord!String do
  let record = load_lightning_record(conn, id, config)?
  if !Bytes.secure_equals(record.service_key, service_key) do
    return Err("lightning_quote_conflict")
  end
  if record.state != 0 do
    bound_invoice(record, observed)?
    return Ok(record)
  end
  if !Bytes.secure_equals(record.payment_hash, observed.payment_hash)
    || record.amount_msat != observed.amount_msat
    || U64.compare(observed.created_at, record.reserved_at) < 0
    || U64.compare(observed.created_at, record.price_observed_at) < 0
    || U64.compare(U64.subtract(observed.created_at, record.price_observed_at)?,
      U64.parse("60")?) > 0
    || (observed.state != "OPEN" && observed.state != "ACCEPTED" && observed.state != "CANCELED") do
    return Err("lightning_reservation_invoice_mismatch")
  end
  let quote = LightningQuote {
    quote_id: id,
    network: record.request.network,
    purpose: record.request.purpose,
    credits: record.request.credits,
    amount_msat: record.amount_msat,
    issued_at: observed.created_at,
    expires_at: observed.expires_at,
    issuer_key_id: record.request.issuer_key_id,
    batch_hash: record.request.batch_hash,
    payment_hash: record.payment_hash,
    payee: config.payee,
    invoice: observed.invoice
  }
  let key = issuer_key_from_row(List.head(issuer_key_rows(conn, quote.issuer_key_id)?))?
  validate_lightning_quote_response(record.request, quote, key, quote.issued_at)?
  let signer = signing_key(conn, quote.issuer_key_id, wrapping, service_key)?
  let signed = sign_lightning_quote(signer, quote)?
  if !verify_lightning_quote(signed, key)? do
    return Err("issuer_quote_key_mismatch")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_lightning_quotes SET state=1,signed_quote=$2 WHERE quote_id=$1",
    [Binary(id), Binary(encode_signed_lightning_quote(signed)?)])?
  load_lightning_record(conn, id, config)
end

pub fn prepare_lightning_settlement(conn :: borrow PgConn,
  request :: LightningIssueRequest,
  observed :: LndInvoice,
  config :: LndConfig,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  now :: U64) -> Result<(), String> do
  let record = load_lightning_record(conn, request.quote_id, config)?
  let signed = case record.signed do
    Some(value) -> value
    None -> return Err("lightning_quote_not_ready")
  end
  validate_lightning_issue(signed.quote, request)?
  bound_invoice(record, observed)?
  if !Bytes.secure_equals(record.service_key, service_key)
    || U64.compare(observed.created_at, now) > 0 do
    return Err("lightning_quote_conflict")
  end
  if record.state == 2 || record.state == 3 do
    return Ok(nil)
  end
  if record.state != 1
    || lightning_settlement_decision(observed.state,
      record.amount_msat,
      observed.amount_msat,
      observed.paid_msat)? != "settle" do
    return Err("lightning_payment_not_accepted")
  end
  let key_row = List.head(issuer_key_rows(conn, record.request.issuer_key_id)?)
  binary(Map.get(key_row, "admitted_evidence"))?
  let key = issuer_key_from_row(key_row)?
  if !issuer_epoch_accepted(key.epoch, now)? do
    return Err("inactive_credit_issuer")
  end
  let private = case BlindRsaSecretKey.unseal_from_storage(binary(Map.get(key_row,
      "sealed_private_key"))?,
    wrapping,
    issuer_key_context(service_key, record.request.issuer_key_id, 18)?) do
    Ok(value) -> value
    Err(_) -> return Err("issuer_key_unavailable")
  end
  let signatures = for request in request.requests do
    sign_credit_request(private, key, request)?
  end
  let response = CreditIssueResponse {
    quote_id: record.quote_id,
    batch_hash: record.request.batch_hash,
    signatures: signatures
  }
  let signer = signing_key(conn,
    key_row
      |> Map.get("key_id")
      |> binary()?,
    wrapping,
    service_key)?
  let authentication = case Crypto.sign(signer, prepared_bytes(response)?) do
    Ok(value) -> value.bytes
    Err(_) -> return Err("lightning_prepared_signature_failed")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_lightning_quotes SET state=2,prepared_response=$2,prepared_signature=$3 WHERE quote_id=$1",
    [
      Binary(record.quote_id),
      Binary(encode_credit_issue_response(response)?),
      Binary(authentication)
    ])?
  Ok(nil)
end

pub fn finish_lightning_settlement(conn :: borrow PgConn,
  id :: Bytes,
  observed :: LndInvoice,
  config :: LndConfig,
  now :: U64) -> CreditIssueResponse!String do
  let record = load_lightning_record(conn, id, config)?
  bound_invoice(record, observed)?
  if lightning_settlement_decision(observed.state,
    record.amount_msat,
    observed.amount_msat,
    observed.paid_msat)? != "issue"
    || observed.settle_index == U64.parse("0")?
    || U64.compare(observed.settled_at, observed.created_at) < 0
    || U64.compare(observed.settled_at, now) > 0
    || (record.state != 2 && record.state != 3) do
    return Err("lightning_settlement_not_confirmed")
  end
  let response = case record.response do
    Some(value) -> value
    None -> return Err("lightning_settlement_not_prepared")
  end
  if record.state == 3 do
    return Ok(response)
  end
  Pg.execute_values(conn,
    "UPDATE issuer_lightning_quotes SET state=3,settled_amount=$2::numeric,settled_at=$3::numeric,settle_index=$4::numeric WHERE quote_id=$1",
    [
      Binary(id),
      Text(U64.to_string(observed.paid_msat)),
      Text(U64.to_string(observed.settled_at)),
      Text(U64.to_string(observed.settle_index))
    ])?
  Pg.execute_values(conn,
    "INSERT INTO issuer_lightning_revenue(quote_id,backend_hash,received_msat,settled_at,policy_version,policy_hash) VALUES($1,$2,$3::numeric,$4::numeric,$5::smallint,$6)",
    [
      Binary(id),
      Binary(lightning_backend_hash(config)?),
      Text(U64.to_string(observed.paid_msat)),
      Text(U64.to_string(observed.settled_at)),
      Text(Int.to_string(record.policy_version)),
      Binary(record.policy_hash)
    ])?
  Ok(response)
end

pub fn record_lightning_cancellation(conn :: borrow PgConn,
  id :: Bytes,
  observed :: LndInvoice,
  config :: LndConfig) -> Result<(), String> do
  let record = load_lightning_record(conn, id, config)?
  bound_invoice(record, observed)?
  if observed.state != "CANCELED" || record.state == 3 do
    return Err("lightning_cancellation_not_confirmed")
  end
  Pg.execute_values(conn,
    "UPDATE issuer_lightning_quotes SET state=4 WHERE quote_id=$1",
    [Binary(id)])?
  Ok(nil)
end

# Only a fresh authenticated CANCELED observation authorizes first signing.
# The same certificate is replayed after restart, even if new purchases are off.
pub fn certify_lightning_cancellation(conn :: borrow PgConn,
  id :: Bytes,
  observed :: LndInvoice,
  config :: LndConfig,
  wrapping :: borrow StorageKey,
  service_key :: Bytes,
  now :: U64) -> LightningCancellation!String do
  let record = load_lightning_record(conn, id, config)?
  bound_invoice(record, observed)?
  if observed.state != "CANCELED"
    || record.state == 3
    || !Bytes.secure_equals(record.service_key, service_key) do
    return Err("lightning_cancellation_not_confirmed")
  end
  case record.cancellation do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let signed = case record.signed do
    Some(value) -> value
    None -> return Err("lightning_quote_not_ready")
  end
  let private = signing_key(conn, record.request.issuer_key_id, wrapping, service_key)?
  let canceled = sign_lightning_cancellation(private, signed.quote, now)?
  Pg.execute_values(conn,
    "UPDATE issuer_lightning_quotes SET state=4,cancellation=$2 WHERE quote_id=$1",
    [Binary(id), Binary(encode_lightning_cancellation(canceled)?)])?
  Ok(canceled)
end

# Claims are bounded and expire after a crash. Network access starts only after
# this transaction commits; malformed records cannot starve the next page.
pub fn claim_lightning_settlements(conn :: borrow PgConn,
  config :: LndConfig,
  service_key :: Bytes,
  now :: U64) -> List<Bytes>!String do
  if Bytes.length(service_key) != 32 do
    return Err("invalid_lightning_context")
  end
  let due = U64.add(now, U64.parse("60")?)?
  let found = Pg.query_values(conn,
    "SELECT quote_id FROM issuer_lightning_quotes WHERE backend_hash=$1 AND service_key=$2 AND state=2 AND next_attempt<=$3::numeric ORDER BY next_attempt,quote_id LIMIT 8 FOR UPDATE SKIP LOCKED",
    [Binary(lightning_backend_hash(config)?), Binary(service_key), Text(U64.to_string(now))])?
  Ok(for row in found do
    let id = binary(Map.get(row, "quote_id"))?
    Pg.execute_values(conn,
      "UPDATE issuer_lightning_quotes SET next_attempt=$2::numeric WHERE quote_id=$1",
      [Binary(id), Text(U64.to_string(due))])?
    id
  end)
end

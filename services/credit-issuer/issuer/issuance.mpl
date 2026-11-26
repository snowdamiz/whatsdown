##! Issuance (plan §6.10 steps 3–4): verify the quote's payment, then
##! blind-sign the whole batch with this epoch's key.
##!
##! - One payment (Solana transaction or Lightning invoice) pays one quote.
##! - USDC and Lightning must pay the quoted amount; SOL may be up to 1% short
##!   (the oracle tolerance). Less, or paid after the quote expired, issues
##!   nothing and is refundable on request (Issuer.Refunds).
##! - A resubmission with the same blinded batch returns the stored
##!   signatures; a different batch is refused. After a key revocation, a quote
##!   signed with the revoked key is signed again for a batch blinded for the
##!   current key (re-issue against the purchase).
##! - An operator's re-issue (Issuer.Reissues) opens an issued quote for one
##!   more batch, once, for a client that lost its blinding states.
##! - MORSE_CREDITS_MODE=off signs nothing, but still answers resubmissions
##!   from the signatures it stored.
##! - The issuer never sees a token, so it cannot record a redemption.

from Credits.CreditFrames import (
  CreditIssueRequest,
  CreditIssueResponse,
  credits_blinded_hash
)
from Issuer.Chain import ChainLookup, ChainPayment, issuer_deposit_signatures, issuer_solana_payment
from Issuer.KeyStore import IssuerKeyRow, issuer_key_revoked, issuer_open_key, issuer_signing_key
from Issuer.Lightning import issuer_lnd_settled
from Issuer.Reissues import issuer_reissue_open, issuer_take_reissue
from Issuer.Settings import IssuerSettings, issuer_purpose

pub type IssueOutcome do
  Issued(response :: CreditIssueResponse)
  IssuePending
  IssueUnpaid
  IssueExpired
  IssueUnknown
  IssueConflict
  IssueStaleKey
  IssueClosed
end

struct QuoteRow do
  quote_id :: Bytes
  batch :: Int
  asset :: String
  amount :: Int
  deposit_address :: String
  invoice_hash :: Bytes
  expires_at_ms :: Int
  state :: String
  batch_hash :: Bytes
  signing_key_id :: Bytes
  signatures :: Bytes
end

fn text(value :: DbValue) -> String do
  case value do
    Text(output) -> output
    _ -> ""
  end
end

fn binary(value :: DbValue) -> Bytes do
  case value do
    Binary(output) -> output
    _ -> Bytes.empty()
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)) do
    Some(output) -> Ok(output)
    None -> Err("invalid quote row")
  end
end

fn quote_row(pool :: PoolHandle, quote_id :: Bytes) -> Option<QuoteRow>!String do
  let rows = Pool.query_values(pool,
    "SELECT quote_id, batch::text AS batch, asset, amount::text AS amount, deposit_address, invoice_hash, floor(extract(epoch FROM expires_at) * 1000)::bigint::text AS expires_at_ms, state, batch_hash, signing_key_id, blind_signatures FROM quotes WHERE quote_id = $1",
    [Binary(quote_id)])?
  case rows do
    [row] -> Ok(Some(QuoteRow {
      quote_id: binary(Map.get(row, "quote_id")),
      batch: integer(Map.get(row, "batch"))?,
      asset: text(Map.get(row, "asset")),
      amount: integer(Map.get(row, "amount"))?,
      deposit_address: text(Map.get(row, "deposit_address")),
      invoice_hash: binary(Map.get(row, "invoice_hash")),
      expires_at_ms: integer(Map.get(row, "expires_at_ms"))?,
      state: text(Map.get(row, "state")),
      batch_hash: binary(Map.get(row, "batch_hash")),
      signing_key_id: binary(Map.get(row, "signing_key_id")),
      signatures: binary(Map.get(row, "blind_signatures"))
    }))
    _ -> Ok(None)
  end
end

fn blocks(value :: Bytes, count :: Int) -> List<Bytes>!String do
  let values = for index in 0..count do
    case Bytes.slice(value, index * 256, 256) do
      Err(_) -> Err("stored signatures truncated")
      Ok(block)
    end?
  end
  Ok(values)
end

fn stored(row :: QuoteRow) -> IssueOutcome!String do
  Ok(Issued(CreditIssueResponse {
    quote_id: row.quote_id,
    token_key_id: row.signing_key_id,
    signatures: blocks(row.signatures, row.batch)?
  }))
end

# The smallest amount that pays: SOL may be 1% short of its quote.

fn required(row :: QuoteRow) -> Int do
  if row.asset == "sol" do
    row.amount - row.amount / 100
  else
    row.amount
  end
end

fn optional(value :: String) -> DbValue do
  if value == "" do
    Null
  else
    Text(value)
  end
end

# Records the payment and moves the quote on: paid, underpaid or late. Err
# "payment_used" when the transaction already paid another quote.

fn record_on_connection(conn :: borrow PgConn,
  row :: QuoteRow,
  payment :: ChainPayment) -> String!String do
  let locked = Pg.query_values(conn,
    "SELECT state FROM quotes WHERE quote_id = $1 FOR UPDATE",
    [Binary(row.quote_id)])?
  let state = case locked do
    [found] -> text(Map.get(found, "state"))
    _ -> ""
  end
  if state != "open" do
    return Ok(state)
  end
  let inserted = Pg.execute_values(conn,
    "INSERT INTO payments (tx_reference, quote_id, received, payer, payer_account, deposit_account, paid_at) VALUES ($1, $2, $3::bigint, $4, $5, $6, to_timestamp($7::bigint)) ON CONFLICT DO NOTHING",
    [
      Text(payment.signature),
      Binary(row.quote_id),
      Text(Int.to_string(payment.received)),
      optional(payment.payer),
      optional(payment.payer_account),
      optional(payment.deposit_account),
      Text(Int.to_string(payment.paid_at_s))
    ])?
  if inserted != 1 do
    return Err("payment_used")
  end
  let next = if payment.paid_at_s * 1000 > row.expires_at_ms do
    "late"
  else if payment.received < required(row) do
    "underpaid"
  else
    "paid"
  end
  Pg.execute_values(conn,
    "UPDATE quotes SET state = $2 WHERE quote_id = $1",
    [Binary(row.quote_id), Text(next)])?
  Ok(next)
end

fn record(pool :: PoolHandle, row :: QuoteRow, payment :: ChainPayment) -> String!String do
  Repo.transaction(pool, fn(conn :: borrow PgConn) -> record_on_connection(conn, row, payment) end)
end

fn known_payment(pool :: PoolHandle, signature :: String) -> Bool!String do
  let rows = Pool.query_values(pool,
    "SELECT 1 FROM payments WHERE tx_reference = $1",
    [Text(signature)])?
  Ok(List.length(rows) > 0)
end

# The first unclaimed finalized transaction that paid the deposit.

fn found_payment(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  signatures :: List<String>,
  index :: Int) -> ChainLookup!String do
  if index >= List.length(signatures) do
    Ok(ChainPending)
  else
    let signature = List.get(signatures, index)
    let lookup = if known_payment(pool, signature)? do
      ChainNotPayment
    else
      issuer_solana_payment(settings.rpc_url,
        settings.usdc_mint,
        row.deposit_address,
        row.asset,
        signature)?
    end
    case lookup do
      ChainPaid(_) -> Ok(lookup)
      _ -> found_payment(pool, settings, row, signatures, index + 1)
    end
  end
end

fn chain_payment(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  reference :: String) -> ChainLookup!String do
  if row.asset == "btc" do
    case issuer_lnd_settled(settings.lnd_url, settings.lnd_macaroon, row.invoice_hash)? do
      None -> Ok(ChainPending)
      Some((sats, settled_at)) -> Ok(ChainPaid(ChainPayment {
        signature: "ln:" <> Bytes.to_hex(row.invoice_hash),
        received: sats,
        payer: "",
        payer_account: "",
        deposit_account: "",
        paid_at_s: settled_at
      }))
    end
  else if reference != "" do
    issuer_solana_payment(settings.rpc_url,
      settings.usdc_mint,
      row.deposit_address,
      row.asset,
      reference)
  else
    found_payment(pool,
      settings,
      row,
      issuer_deposit_signatures(settings.rpc_url, row.deposit_address)?,
      0)
  end
end

fn unpaid_state(row :: QuoteRow, now_ms :: Int) -> IssueOutcome do
  if now_ms > row.expires_at_ms do
    IssueExpired
  else
    IssuePending
  end
end

# An open quote: find and record its payment; "paid" when it may be signed.

fn settle(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  reference :: String,
  now_ms :: Int) -> Result<String, IssueOutcome>!String do
  let lookup = chain_payment(pool, settings, row, reference)?
  case lookup do
    ChainPending -> Ok(Err(unpaid_state(row, now_ms)))
    ChainNotPayment -> Ok(Err(IssueUnpaid))
    ChainPaid(payment) -> case record(pool, row, payment) do
      Err(error) -> if String.contains(error, "payment_used") do
        Ok(Err(IssueConflict))
      else
        Err(error)
      end
      Ok(state) -> Ok(Ok(state))
    end
  end
end

fn sign_all(key :: borrow BlindRsaSecretKey,
  blinded :: List<Bytes>,
  index :: Int,
  output :: Bytes) -> Bytes!String do
  if index >= List.length(blinded) do
    Ok(output)
  else
    let signature = case Crypto.blind_rsa_sign(key, List.get(blinded, index)) do
      Err(_) -> Err("a blinded message was refused")
      Ok(value)
    end?
    let next = case Bytes.concat(output, signature) do
      Err(_) -> Err("signature allocation failed")
      Ok(value)
    end?
    sign_all(key, blinded, index + 1, next)
  end
end

fn random_delay(settings :: IssuerSettings) -> Int!String do
  let span = settings.sweep_max_delay_s - settings.sweep_min_delay_s
  if span <= 0 do
    Ok(settings.sweep_min_delay_s)
  else
    let bytes = case Crypto.random_bytes(4) do
      Err(_) -> Err("randomness unavailable")
      Ok(value)
    end?
    let wide = case Bytes.read_u32_be(bytes, 0) do
      Err(_) -> Err("randomness unavailable")
      Ok(value)
    end?
    Ok(settings.sweep_min_delay_s + U64.to_int(wide)? % (span + 1))
  end
end

# Stores the signatures if nobody else did first: from "paid", or, to
# re-issue, from "issued" under a revoked key or an operator's open re-issue.

fn store(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  key :: IssuerKeyRow,
  batch_hash :: Bytes,
  signatures :: Bytes,
  reissue :: Bool) -> Int!String do
  if reissue do
    return issuer_take_reissue(pool, row.quote_id, key.key_id, batch_hash, signatures)
  end
  let delay = if row.asset == "btc" do
    -1
  else
    random_delay(settings)?
  end
  Pool.execute_values(pool,
    "UPDATE quotes SET state = 'issued', batch_hash = $2, signing_key_id = $3, blind_signatures = $4, issued_at = now(), sweep_after = CASE WHEN $5::integer < 0 THEN NULL ELSE now() + $5::integer * interval '1 second' END WHERE quote_id = $1 AND (state = 'paid' OR (state = 'issued' AND signing_key_id IN (SELECT key_id FROM issuer_keys WHERE revoked_at IS NOT NULL)))",
    [
      Binary(row.quote_id),
      Binary(batch_hash),
      Binary(key.key_id),
      Binary(signatures),
      Text(Int.to_string(delay))
    ])
end

fn after_store(pool :: PoolHandle, quote_id :: Bytes, batch_hash :: Bytes) -> IssueOutcome!String do
  case quote_row(pool, quote_id)? do
    Some(latest) -> if latest.state == "issued"
      && Bytes.secure_equals(latest.batch_hash, batch_hash) do
      stored(latest)
    else
      Ok(IssueConflict)
    end
    None -> Ok(IssueUnknown)
  end
end

fn sign(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  request :: CreditIssueRequest,
  wrapping :: borrow X25519PrivateKey,
  now_ms :: Int,
  reissue :: Bool) -> IssueOutcome!String do
  if settings.mode == "off" do
    return Ok(IssueClosed)
  end
  let key = case issuer_signing_key(pool, issuer_purpose(settings), now_ms)? do
    None -> return Ok(IssueClosed)
    Some(value) -> value
  end
  if !Bytes.secure_equals(key.key_id, request.token_key_id) do
    return Ok(IssueStaleKey)
  end
  let batch_hash = credits_blinded_hash(request)?
  let secret = issuer_open_key(key.sealed_key, wrapping, key.purpose, key.epoch)?
  let signatures = sign_all(secret, request.blinded, 0, Bytes.empty())?
  store(pool, settings, row, key, batch_hash, signatures, reissue)?
  after_store(pool, row.quote_id, batch_hash)
end

fn issued(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  request :: CreditIssueRequest,
  wrapping :: borrow X25519PrivateKey,
  now_ms :: Int) -> IssueOutcome!String do
  if Bytes.secure_equals(row.batch_hash, credits_blinded_hash(request)?) do
    stored(row)
  else if issuer_key_revoked(pool, row.signing_key_id)? do
    sign(pool, settings, row, request, wrapping, now_ms, false)
  else if issuer_reissue_open(pool, row.quote_id)? do
    sign(pool, settings, row, request, wrapping, now_ms, true)
  else
    Ok(IssueConflict)
  end
end

fn signable(pool :: PoolHandle,
  settings :: IssuerSettings,
  row :: QuoteRow,
  request :: CreditIssueRequest,
  wrapping :: borrow X25519PrivateKey,
  now_ms :: Int) -> IssueOutcome!String do
  let state = if row.state == "open" do
    case settle(pool, settings, row, request.payment, now_ms)? do
      Err(outcome) -> return Ok(outcome)
      Ok(next) -> next
    end
  else
    row.state
  end
  if state == "paid" do
    sign(pool, settings, row, request, wrapping, now_ms, false)
  else if state == "issued" do
    after_store(pool, row.quote_id, credits_blinded_hash(request)?)
  else
    Ok(IssueUnpaid)
  end
end

## Issues the batch of `request` for its quote. `wrapping` opens the sealed
## signing key.

pub fn issuer_issue(pool :: PoolHandle,
  settings :: IssuerSettings,
  request :: CreditIssueRequest,
  wrapping :: borrow X25519PrivateKey,
  now_ms :: Int) -> IssueOutcome!String do
  let row = case quote_row(pool, request.quote_id)? do
    None -> return Ok(IssueUnknown)
    Some(value) -> value
  end
  if List.length(request.blinded) != row.batch do
    Ok(IssueConflict)
  else if row.state == "issued" do
    issued(pool, settings, row, request, wrapping, now_ms)
  else
    signable(pool, settings, row, request, wrapping, now_ms)
  end
end

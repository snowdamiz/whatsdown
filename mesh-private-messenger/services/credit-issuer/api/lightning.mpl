from Credits.LightningCancellation import encode_lightning_cancellation
from Api.Purchases import IssuerResult
from Credits.Lightning import (
  decode_lightning_quote_request,
  decode_lightning_issue_request,
  encode_signed_lightning_quote,
  validate_lightning_issue
)
from Credits.Issuance import encode_credit_issue_response
from Payment.BitcoinOracle import read_btc_price
from Payment.LightningBackend import (
  LndConfig,
  LndInvoice,
  lookup_lnd_invoice,
  create_lnd_hold,
  settle_lnd_hold,
  cancel_lnd_hold
)
from Payment.LightningPolicy import lightning_settlement_decision
from Solana.Read import pubkey
from Storage.Lightning import (
  LightningRecord,
  existing_lightning_quote,
  reserve_lightning_quote_with_revenue_policy,
  store_lightning_invoice,
  load_lightning_record,
  prepare_lightning_settlement,
  restore_lightning_preimage,
  finish_lightning_settlement,
  certify_lightning_cancellation
)

pub struct LightningPolicy do
  enabled :: Bool
  revenue_policy :: Int
  service_key :: Bytes
  backend :: LndConfig
  rpc_url :: String
  oracle_account :: String
end

fn empty(status :: Int) -> IssuerResult do
  IssuerResult { status: status, body: Bytes.empty() }
end

fn failure(error :: String) -> IssuerResult do
  if error == "invalid_lightning_request" do
    empty(400)
  else if List.contains([
      "lightning_quote_conflict",
      "lightning_quote_batch_mismatch",
      "lightning_quote_policy_mismatch",
      "lightning_canceled"
    ],
    error) do
    empty(409)
  else
    empty(503)
  end
end

fn quote_result(record :: LightningRecord) -> IssuerResult!String do
  case record.signed do
    None -> Err("lightning_quote_not_ready")
    Some(value) -> Ok(IssuerResult { status: 200, body: encode_signed_lightning_quote(value)? })
  end
end

fn quote(pool :: PoolHandle,
  policy :: LightningPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult!String do
  if !policy.enabled do
    return Ok(empty(503))
  end
  let request = case decode_lightning_quote_request(body) do
    Ok(value) -> value
    Err(_) -> return Err("invalid_lightning_request")
  end
  if request.purpose != policy.backend.purpose || request.network != policy.backend.network do
    return Err("invalid_lightning_request")
  end
  let previous = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do existing_lightning_quote(conn,
      request,
      policy.backend,
      policy.service_key) end)?
  let record = case previous do
    Some(value) -> value
    None -> do
      let client = Http.client()
      let result = read_btc_price(client, policy.rpc_url, pubkey(policy.oracle_account)?, 1, now)
      Http.client_close(client)
      let price = result?
      Repo.transaction(pool,
        fn(conn :: borrow PgConn) do
          let wrapping = open_key()?
          reserve_lightning_quote_with_revenue_policy(conn,
            request,
            policy.backend,
            price.usd_micros,
            price.observed_at,
            now,
            wrapping,
            policy.service_key,
            policy.revenue_policy)
        end)?
    end
  end
  if record.state != 0 do
    if record.state == 4 do
      return Err("lightning_canceled")
    end
    return quote_result(record)
  end
  # Lookup precedes the age check: a lost creation response must recover the
  # original invoice even when its original oracle window has since elapsed.
  let existing = lookup_lnd_invoice(policy.backend, record.payment_hash)?
  let observed = case existing do
    Some(value) -> value
    None -> do
      if U64.compare(now, record.price_observed_at) < 0
        || U64.compare(U64.subtract(now, record.price_observed_at)?, U64.parse("60")?) > 0 do
        return Err("stale_lightning_reservation")
      end
      # An error is an unknown outcome, not authorization for another bill.
      create_lnd_hold(policy.backend, record.payment_hash, record.amount_msat)
      case lookup_lnd_invoice(policy.backend, record.payment_hash)? do
        Some(value) -> value
        None -> return Err("lightning_hold_creation_unknown")
      end
    end
  end
  let stored = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = open_key()?
      store_lightning_invoice(conn,
        record.quote_id,
        observed,
        policy.backend,
        wrapping,
        policy.service_key)
    end)?
  quote_result(stored)
end

pub fn lightning_quote_response(pool :: PoolHandle,
  policy :: LightningPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult do
  case quote(pool, policy, body, open_key, now) do
    Ok(value) -> value
    Err(error) -> failure(error)
  end
end

fn receipt_result(pool :: PoolHandle,
  policy :: LightningPolicy,
  id :: Bytes,
  observed :: LndInvoice,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult!String do
  if observed.state == "CANCELED" do
    let canceled = Repo.transaction(pool,
      fn(conn :: borrow PgConn) do
        let wrapping = open_key()?
        certify_lightning_cancellation(conn,
          id,
          observed,
          policy.backend,
          wrapping,
          policy.service_key,
          now)
      end)?
    return Ok(IssuerResult { status: 200, body: encode_lightning_cancellation(canceled)? })
  end
  if observed.state != "SETTLED" do
    return Ok(empty(425))
  end
  let response = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do finish_lightning_settlement(conn,
      id,
      observed,
      policy.backend,
      now) end)?
  Ok(IssuerResult { status: 200, body: encode_credit_issue_response(response)? })
end

fn issue(pool :: PoolHandle,
  policy :: LightningPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult!String do
  let request = case decode_lightning_issue_request(body) do
    Ok(value) -> value
    Err(_) -> return Err("invalid_lightning_request")
  end
  let record = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_lightning_record(conn, request.quote_id, policy.backend) end)?
  if !Bytes.secure_equals(record.service_key, policy.service_key) do
    return Err("invalid_lightning_request")
  end
  let signed = case record.signed do
    Some(value) -> value
    None -> return Ok(empty(425))
  end
  validate_lightning_issue(signed.quote, request)?
  if record.state == 3 do
    return case record.response do
      Some(value) -> Ok(IssuerResult { status: 200, body: encode_credit_issue_response(value)? })
      None -> Err("invalid_lightning_row")
    end
  end
  if record.state == 4 do
    case record.cancellation do
      Some(value) -> return Ok(IssuerResult {
        status: 200,
        body: encode_lightning_cancellation(value)?
      })
      None -> nil
    end
  end
  let observed = case lookup_lnd_invoice(policy.backend, record.payment_hash)? do
    Some(value) -> value
    None -> return Ok(empty(425))
  end
  # Cancellation recovery never authorizes settlement or new issuance.
  if observed.state == "CANCELED" do
    return receipt_result(pool, policy, record.quote_id, observed, open_key, now)
  end
  # Preparation already committed authorizes only completion of that same
  # settlement. Disabling purchases cannot strand a terminal cancellation.
  if !policy.enabled && record.state != 2 do
    return Ok(empty(503))
  end
  let decision = lightning_settlement_decision(observed.state,
    record.amount_msat,
    observed.amount_msat,
    observed.paid_msat)?
  if decision == "wait" do
    return Ok(empty(425))
  end
  if decision == "cancel" do
    cancel_lnd_hold(policy.backend, record.payment_hash)
    let canceled = case lookup_lnd_invoice(policy.backend, record.payment_hash)? do
      Some(value) -> value
      None -> return Ok(empty(425))
    end
    return receipt_result(pool, policy, record.quote_id, canceled, open_key, now)
  end
  if decision == "canceled" || decision == "issue" do
    return receipt_result(pool, policy, record.quote_id, observed, open_key, now)
  end
  if decision != "settle" do
    return Err("lightning_payment_reconciliation_required")
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = open_key()?
      prepare_lightning_settlement(conn,
        request,
        observed,
        policy.backend,
        wrapping,
        policy.service_key,
        now)
    end)?
  resume_lightning_settlement(pool, policy, record.quote_id, open_key, now)
end

# This path can only complete an already committed blind batch. It is shared
# by retries and the background worker, including when new purchases are off.
pub fn resume_lightning_settlement(pool :: PoolHandle,
  policy :: LightningPolicy,
  id :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult!String do
  let record = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_lightning_record(conn, id, policy.backend) end)?
  if !Bytes.secure_equals(record.service_key, policy.service_key) do
    return Err("lightning_quote_conflict")
  end
  if record.state == 3 do
    return case record.response do
      Some(value) -> Ok(IssuerResult { status: 200, body: encode_credit_issue_response(value)? })
      None -> Err("invalid_lightning_row")
    end
  end
  if record.state != 2 do
    return Err("lightning_settlement_not_prepared")
  end
  let observed = case lookup_lnd_invoice(policy.backend, record.payment_hash)? do
    Some(value) -> value
    None -> return Ok(empty(425))
  end
  let decision = lightning_settlement_decision(observed.state,
    record.amount_msat,
    observed.amount_msat,
    observed.paid_msat)?
  if decision == "issue" || decision == "canceled" do
    return receipt_result(pool, policy, id, observed, open_key, now)
  end
  if decision == "wait" do
    return Ok(empty(425))
  end
  if decision == "cancel" do
    cancel_lnd_hold(policy.backend, record.payment_hash)
    let canceled = case lookup_lnd_invoice(policy.backend, record.payment_hash)? do
      Some(value) -> value
      None -> return Ok(empty(425))
    end
    return receipt_result(pool, policy, id, canceled, open_key, now)
  end
  if decision != "settle" do
    return Err("lightning_payment_reconciliation_required")
  end
  # No network call or preimage disclosure occurs inside the transaction above.
  # Reload the authenticated response and sealed preimage only after commit.
  let preimage = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = open_key()?
      restore_lightning_preimage(conn,
        record.quote_id,
        policy.backend,
        wrapping,
        policy.service_key)
    end)?
  settle_lnd_hold(policy.backend, preimage)
  let outcome = case lookup_lnd_invoice(policy.backend, record.payment_hash)? do
    Some(value) -> value
    None -> return Ok(empty(425))
  end
  # Use a fresh clock after network settlement; it may cross a UTC second.
  let checked_now = U64.parse(Int.to_string(DateTime.to_unix_ms(DateTime.utc_now()) / 1000))?
  receipt_result(pool, policy, record.quote_id, outcome, open_key, checked_now)
end

pub fn lightning_issue_response(pool :: PoolHandle,
  policy :: LightningPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult do
  case issue(pool, policy, body, open_key, now) do
    Ok(value) -> value
    Err(error) -> failure(error)
  end
end

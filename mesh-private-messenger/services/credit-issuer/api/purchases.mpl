from Credits.QuoteAuth import encode_signed_credit_quote
from Credits.Issuance import (
  decode_credit_quote_request,
  decode_credit_issue_request,
  encode_credit_issue_response
)
from Payment.Oracle import SolPrice, read_sol_price
from Payment.Verify import verify_credit_payment
from Solana.Read import pubkey
from Storage.Quotes import existing_quote_on_connection, create_quote_with_revenue_policy
from Storage.Issuance import (
  prepare_issue_on_connection,
  issue_paid_on_connection,
  load_signed_quote
)

pub struct IssuerPolicy do
  enabled :: Bool
  revenue_policy :: Int
  purpose :: Int
  service_key :: Bytes
  mint :: Bytes
  rpc_url :: String
  oracle_account :: String
end

pub struct IssuerResult do
  status :: Int
  body :: Bytes
end

fn empty(status :: Int) -> IssuerResult do
  IssuerResult { status: status, body: Bytes.empty() }
end

fn failure(error :: String) -> IssuerResult do
  if List.contains([
      "credit_quote_conflict",
      "credit_payment_conflict",
      "credit_quote_batch_mismatch"
    ],
    error) do
    empty(409)
  else if error == "invalid_credit_request" do
    empty(400)
  else
    empty(503)
  end
end

fn quote(pool :: PoolHandle,
  policy :: IssuerPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult!String do
  if !policy.enabled do
    return Ok(empty(503))
  end
  let request = case decode_credit_quote_request(body) do
    Err(_) -> return Err("invalid_credit_request")
    Ok(value) -> value
  end
  if request.purpose != policy.purpose do
    return Err("invalid_credit_request")
  end
  # Lost response recovery does not need a new price or a fresh key epoch.
  case Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      case existing_quote_on_connection(conn, request, policy.mint)? do
        Some(value) -> Ok(Some(load_signed_quote(conn, value.quote_id)?))
        None -> Ok(None)
      end
    end)? do
    Some(value) -> return Ok(IssuerResult { status: 200, body: encode_signed_credit_quote(value)? })
    None -> nil
  end
  let price = if request.asset == 1 do
    let address = pubkey(policy.oracle_account)?
    let client = Http.client()
    let result = read_sol_price(client, policy.rpc_url, address, 1, now)
    Http.client_close(client)
    result?
  else
    SolPrice { usd_micros: U64.parse("0")?, observed_at: now, slot: U64.parse("0")? }
  end
  let value = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = open_key()?
      let created = create_quote_with_revenue_policy(conn,
        request,
        policy.mint,
        price.usd_micros,
        price.observed_at,
        now,
        wrapping,
        policy.service_key,
        policy.revenue_policy)?
      load_signed_quote(conn, created.quote_id)
    end)?
  Ok(IssuerResult { status: 200, body: encode_signed_credit_quote(value)? })
end

pub fn quote_response(pool :: PoolHandle,
  policy :: IssuerPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult do
  case quote(pool, policy, body, open_key, now) do
    Ok(value) -> value
    Err(error) -> failure(error)
  end
end

fn issue(pool :: PoolHandle,
  policy :: IssuerPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult!String do
  let request = case decode_credit_issue_request(body) do
    Err(_) -> return Err("invalid_credit_request")
    Ok(value) -> value
  end
  let prepared = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_issue_on_connection(conn, request) end)?
  if prepared.quote.purpose != policy.purpose do
    return Err("invalid_credit_request")
  end
  case prepared.cached do
    Some(value) -> return Ok(IssuerResult {
      status: 200,
      body: encode_credit_issue_response(value)?
    })
    None -> nil
  end
  if !policy.enabled do
    return Ok(empty(503))
  end
  let client = Http.client()
  let checked = verify_credit_payment(client,
    policy.rpc_url,
    request.transaction_signature,
    2,
    prepared.quote,
    policy.mint,
    prepared.price_observed_at,
    now)
  Http.client_close(client)
  let payment = case checked? do
    None -> return Ok(empty(425))
    Some(value) -> value
  end
  # Blind signatures are only returned after Repo has committed both payment
  # ownership and the canonical response. Concurrent calls recheck the row.
  let response = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let wrapping = open_key()?
      issue_paid_on_connection(conn, request, payment, wrapping, policy.service_key, now)
    end)?
  Ok(IssuerResult { status: 200, body: encode_credit_issue_response(response)? })
end

pub fn issue_response(pool :: PoolHandle,
  policy :: IssuerPolicy,
  body :: Bytes,
  open_key :: Fun() -> Result<StorageKey, String>,
  now :: U64) -> IssuerResult do
  case issue(pool, policy, body, open_key, now) do
    Ok(value) -> value
    Err(error) -> failure(error)
  end
end

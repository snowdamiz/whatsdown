##! Re-issue (protocol/credits-v1.md "Issuance"). A client killed mid-exchange
##! keeps its purchase reference (the quote ID) but not its blinding states, so
##! it cannot open the signatures stored for its quote, and a new batch gets
##! 409. `credit-issuer reissue <quote>` shows the quote; `--confirm <quote>`
##! re-opens it once: the next batch for it (same count, blinded for the current
##! key) is signed, and the quote closes again. At most one re-issue per quote,
##! ever, recorded in `reissues` with its time and the operator's note, never
##! who asked. The operator asks for the payment proof first.

pub struct ReissuePlan do
  quote_id :: Bytes
  state :: String
  asset :: String
  payment :: String
  issued_at :: String
  reissued :: Bool
end

fn text(value :: DbValue) -> String do
  case value do
    Text(output) -> output
    _ -> ""
  end
end

## The quote as a re-issue would find it; `payment` is the transaction (or
## "ln:" invoice hash) that paid it, to compare with the payer's proof.

pub fn issuer_reissue_plan(pool :: PoolHandle, quote_id :: Bytes) -> ReissuePlan!String do
  let rows = Pool.query_values(pool,
    "SELECT quote.state, quote.asset, coalesce(payment.tx_reference, '') AS payment, coalesce(quote.issued_at::text, '') AS issued_at, (reissue.quote_id IS NOT NULL)::text AS reissued FROM quotes AS quote LEFT JOIN payments AS payment ON payment.quote_id = quote.quote_id LEFT JOIN reissues AS reissue ON reissue.quote_id = quote.quote_id WHERE quote.quote_id = $1",
    [Binary(quote_id)])?
  case rows do
    [row] -> Ok(ReissuePlan {
      quote_id: quote_id,
      state: text(Map.get(row, "state")),
      asset: text(Map.get(row, "asset")),
      payment: text(Map.get(row, "payment")),
      issued_at: text(Map.get(row, "issued_at")),
      reissued: text(Map.get(row, "reissued")) == "true"
    })
    _ -> Err("unknown quote")
  end
end

pub fn issuer_reissue_plan_json(plan :: ReissuePlan) -> String do
  let reissued = if plan.reissued do
    "true"
  else
    "false"
  end
  "{\"quote_id\":"
    <> Json.encode_string(Bytes.to_hex(plan.quote_id))
    <> ",\"state\":"
    <> Json.encode_string(plan.state)
    <> ",\"asset\":"
    <> Json.encode_string(plan.asset)
    <> ",\"payment\":"
    <> Json.encode_string(plan.payment)
    <> ",\"issued_at\":"
    <> Json.encode_string(plan.issued_at)
    <> ",\"reissued\":"
    <> reissued
    <> "}"
end

## Re-opens an issued, paid quote for one more batch when `confirmation`
## repeats its ID. Refused for any other state, and for a quote re-issued
## before.

pub fn issuer_reissue(pool :: PoolHandle,
  quote_id :: Bytes,
  confirmation :: String,
  note :: String) -> Result<(), String> do
  if confirmation != Bytes.to_hex(quote_id) do
    return Err("confirm the re-issue with --confirm #{Bytes.to_hex(quote_id)}")
  end
  if Bytes.length(Bytes.from_utf8(note)) > 500 do
    return Err("the note is at most 500 bytes")
  end
  let plan = issuer_reissue_plan(pool, quote_id)?
  if plan.state != "issued" || plan.payment == "" do
    return Err("only an issued, paid quote is re-issued (this one is #{plan.state})")
  end
  let inserted = Pool.execute_values(pool,
    "INSERT INTO reissues (quote_id, note) SELECT quote_id, $2 FROM quotes WHERE quote_id = $1 AND state = 'issued' ON CONFLICT DO NOTHING",
    [Binary(quote_id), Text(note)])?
  if inserted != 1 do
    Err("this quote was already re-issued once")
  else
    Ok(nil)
  end
end

## Whether an operator re-opened `quote_id` and no batch has used it yet.

pub fn issuer_reissue_open(pool :: PoolHandle, quote_id :: Bytes) -> Bool!String do
  let rows = Pool.query_values(pool,
    "SELECT 1 FROM reissues WHERE quote_id = $1 AND signed_at IS NULL",
    [Binary(quote_id)])?
  Ok(List.length(rows) > 0)
end

fn take_on_connection(conn :: borrow PgConn,
  quote_id :: Bytes,
  key_id :: Bytes,
  batch_hash :: Bytes,
  signatures :: Bytes) -> Int!String do
  let taken = Pg.execute_values(conn,
    "UPDATE reissues SET signed_at = now() WHERE quote_id = $1 AND signed_at IS NULL",
    [Binary(quote_id)])?
  if taken != 1 do
    return Ok(0)
  end
  Pg.execute_values(conn,
    "UPDATE quotes SET signing_key_id = $2, batch_hash = $3, blind_signatures = $4 WHERE quote_id = $1 AND state = 'issued'",
    [Binary(quote_id), Binary(key_id), Binary(batch_hash), Binary(signatures)])
end

## Closes the open re-issue of `quote_id` and stores the batch it signed, in
## one transaction; 0 when another batch closed it first. The quote keeps its
## issue time (the settlement week) and sweep schedule.

pub fn issuer_take_reissue(pool :: PoolHandle,
  quote_id :: Bytes,
  key_id :: Bytes,
  batch_hash :: Bytes,
  signatures :: Bytes) -> Int!String do
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> take_on_connection(conn,
      quote_id,
      key_id,
      batch_hash,
      signatures) end)
end

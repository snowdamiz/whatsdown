from Payment.RevenuePolicy import credit_revenue_policy_hash, split_credit_revenue
from Credits.Issuance import CreditQuote, decode_credit_quote, encode_credit_quote
from Payment.Observation import CreditDepositObservation
from Payment.Verify import PaymentReceipt, payment_token_address

pub struct TreasuryMovement do
  movement_id :: Bytes
  batch_id :: Bytes
  quote :: CreditQuote
  payment_signature :: Bytes
  kind :: Int
  config_hash :: Bytes
  source :: Bytes
  destination :: Bytes
  destination_owner :: Bytes
  amount :: U64
  ready_at :: U64
  state :: Int
  message :: Bytes
  packet :: Bytes
  transaction_signature :: Bytes
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    Some(output) -> Ok(output)
    None -> Err("invalid_treasury_row")
  end
end

fn optional_binary(value :: DbValue) -> Bytes!String do
  case value do
    Null -> Ok(Bytes.empty())
    Binary(output) -> Ok(output)
    _ -> Err("invalid_treasury_row")
  end
end

fn key(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

# The quote row is the first lock in every observation/allocation/issuance path.
# This storage boundary accepts only the internal verifier's typed observation.
# Public HTTP routes must fetch Payment.Observation themselves.
pub fn record_credit_deposit(conn :: borrow PgConn,
  value :: CreditDepositObservation) -> Result<(), String> do
  let rows = Pg.query_values(conn,
    "SELECT quote FROM issuer_quotes WHERE quote_id = $1 FOR UPDATE",
    [Binary(value.quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  let quote = decode_credit_quote(binary(Map.get(List.head(rows), "quote"))?)?
  let amount = value.payment.received_amount
  let maximum = U128.divide(U128.multiply(U128.parse(U64.to_string(quote.amount))?,
      U128.parse("101")?)?,
    U128.parse("100")?)?
  let disposition = if U64.compare(amount, quote.amount) < 0 do
    1
  else if U128.compare(U128.parse(U64.to_string(amount))?, maximum) > 0 do
    2
  else
    0
  end
  if !Bytes.secure_equals(value.quote_id, quote.quote_id)
    || value.asset != quote.asset
    || !Bytes.secure_equals(value.mint, quote.mint)
    || !Bytes.secure_equals(value.deposit_owner, quote.deposit_owner)
    || !Bytes.secure_equals(value.destination, quote.destination)
    || value.disposition != disposition
    || !key(value.wire_sha256)
    || Bytes.length(value.payment.transaction_signature) != 64
    || !key(value.payment.payer)
    || value.payment.slot == U64.parse("0")?
    || amount == U64.parse("0")?
    || U64.compare(value.payment.block_time, quote.issued_at) < 0
    || U64.compare(value.payment.block_time, quote.expires_at) >= 0 do
    return Err("credit_deposit_mismatch")
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_payment_observations (payment_signature, quote_id, payer, slot, payment_time, amount, wire_sha256, disposition) VALUES ($1,$2,$3,$4::numeric,$5::numeric,$6::numeric,$7,$8::smallint) ON CONFLICT (payment_signature) DO NOTHING",
    [
      Binary(value.payment.transaction_signature),
      Binary(value.quote_id),
      Binary(value.payment.payer),
      Text(U64.to_string(value.payment.slot)),
      Text(U64.to_string(value.payment.block_time)),
      Text(U64.to_string(amount)),
      Binary(value.wire_sha256),
      Text(Int.to_string(disposition))
    ])?
  let stored = Pg.query_values(conn,
    "SELECT quote_id, payer, slot::text, payment_time::text, amount::text, wire_sha256, disposition::text FROM issuer_payment_observations WHERE payment_signature = $1",
    [Binary(value.payment.transaction_signature)])?
  if List.length(stored) != 1 do
    return Err("invalid_treasury_row")
  end
  let row = List.head(stored)
  if !Bytes.secure_equals(binary(Map.get(row, "quote_id"))?, value.quote_id)
    || !Bytes.secure_equals(binary(Map.get(row, "payer"))?, value.payment.payer)
    || text(Map.get(row, "slot"))? != U64.to_string(value.payment.slot)
    || text(Map.get(row, "payment_time"))? != U64.to_string(value.payment.block_time)
    || text(Map.get(row, "amount"))? != U64.to_string(amount)
    || !Bytes.secure_equals(binary(Map.get(row, "wire_sha256"))?, value.wire_sha256)
    || integer(Map.get(row, "disposition"))? != disposition do
    return Err("credit_deposit_conflict")
  end
  Ok(nil)
end

# Called after issuance's paid-row update, within that same transaction.
# Also permits explicit historical backfill only from a fully issued row.
pub fn record_issued_credit_revenue(conn :: borrow PgConn,
  quote_id :: Bytes) -> Result<(), String> do
  let rows = Pg.query_values(conn,
    "SELECT quote, payment_signature, payment_time::text, payment_amount::text,policy_version::text,policy_hash FROM issuer_quotes WHERE quote_id = $1 AND issued_response IS NOT NULL FOR UPDATE",
    [Binary(quote_id)])?
  if List.length(rows) != 1 do
    return Err("credit_revenue_not_issued")
  end
  let row = List.head(rows)
  let quote = decode_credit_quote(binary(Map.get(row, "quote"))?)?
  let inserted = Pg.query_values(conn,
    "INSERT INTO issuer_credit_revenue (quote_id,payment_signature,asset,mint,amount,payment_time,policy_version,policy_hash) VALUES ($1,$2,$3::smallint,$4,$5::numeric,$6::numeric,$7::smallint,$8) ON CONFLICT (quote_id) DO UPDATE SET quote_id=EXCLUDED.quote_id WHERE issuer_credit_revenue.payment_signature=EXCLUDED.payment_signature AND issuer_credit_revenue.asset=EXCLUDED.asset AND issuer_credit_revenue.mint=EXCLUDED.mint AND issuer_credit_revenue.amount=EXCLUDED.amount AND issuer_credit_revenue.payment_time=EXCLUDED.payment_time AND issuer_credit_revenue.policy_version=EXCLUDED.policy_version AND issuer_credit_revenue.policy_hash=EXCLUDED.policy_hash RETURNING event_id::text",
    [
      Binary(quote_id),
      Binary(binary(Map.get(row, "payment_signature"))?),
      Text(Int.to_string(quote.asset)),
      Binary(quote.mint),
      Text(text(Map.get(row, "payment_amount"))?),
      Text(text(Map.get(row, "payment_time"))?),
      Text(text(Map.get(row, "policy_version"))?),
      Binary(binary(Map.get(row, "policy_hash"))?)
    ])?
  if List.length(inserted) != 1 do
    return Err("credit_revenue_conflict")
  end
  Ok(nil)
end

fn movement_from_row(row :: Map<String, DbValue>) -> TreasuryMovement!String do
  Ok(TreasuryMovement {
    movement_id: binary(Map.get(row, "movement_id"))?,
    batch_id: optional_binary(Map.get(row, "batch_id"))?,
    quote: decode_credit_quote(binary(Map.get(row, "quote"))?)?,
    payment_signature: binary(Map.get(row, "payment_signature"))?,
    kind: integer(Map.get(row, "kind"))?,
    config_hash: binary(Map.get(row, "config_hash"))?,
    source: binary(Map.get(row, "source"))?,
    destination: binary(Map.get(row, "destination"))?,
    destination_owner: binary(Map.get(row, "destination_owner"))?,
    amount: U64.parse(text(Map.get(row, "amount"))?)?,
    ready_at: U64.parse(text(Map.get(row, "ready_at"))?)?,
    state: integer(Map.get(row, "state"))?,
    message: optional_binary(Map.get(row, "message"))?,
    packet: optional_binary(Map.get(row, "packet"))?,
    transaction_signature: optional_binary(Map.get(row, "transaction_signature"))?
  })
end

pub fn load_treasury_movement(conn :: borrow PgConn, id :: Bytes) -> TreasuryMovement!String do
  let rows = Pg.query_values(conn,
    "SELECT m.*,m.kind::text,m.amount::text,m.ready_at::text,m.state::text,q.quote FROM issuer_treasury_movements m JOIN issuer_payment_observations p USING(payment_signature) JOIN issuer_quotes q ON q.quote_id=p.quote_id WHERE m.movement_id=$1",
    [Binary(id)])?
  if List.length(rows) != 1 do
    return Err("unknown_treasury_movement")
  end
  movement_from_row(List.head(rows))
end

# Reserve the exact observed payment once. No balance read or caller-selected
# refund address can increase the amount. Delay is sampled once by the caller.
pub fn reserve_treasury_movement(conn :: borrow PgConn,
  quote_id :: Bytes,
  signature :: Bytes,
  kind :: Int,
  treasury_owner :: Bytes,
  config_hash :: Bytes,
  now :: U64,
  delay_seconds :: U64) -> TreasuryMovement!String do
  if (kind != 0 && kind != 1)
    || !key(config_hash)
    || !key(treasury_owner)
    || U64.compare(delay_seconds, U64.parse("86400")?) > 0
    || (kind == 1 && delay_seconds != U64.parse("0")?) do
    return Err("invalid_treasury_intent")
  end
  let rows = Pg.query_values(conn,
    "SELECT quote,payment_signature,issued_response FROM issuer_quotes WHERE quote_id=$1 FOR UPDATE",
    [Binary(quote_id)])?
  if List.length(rows) != 1 do
    return Err("unknown_credit_quote")
  end
  let row = List.head(rows)
  let quote = decode_credit_quote(binary(Map.get(row, "quote"))?)?
  let payments = Pg.query_values(conn,
    "SELECT payer,amount::text,disposition::text FROM issuer_payment_observations WHERE payment_signature=$1 AND quote_id=$2 FOR UPDATE",
    [Binary(signature), Binary(quote_id)])?
  if List.length(payments) != 1 do
    return Err("unobserved_credit_payment")
  end
  let payment = List.head(payments)
  let issued = case Map.get(row, "issued_response") do
    Binary(_) -> true
    Null -> false
    _ -> return Err("invalid_treasury_row")
  end
  if (kind == 0
    && (!issued
      || !Bytes.secure_equals(binary(Map.get(row, "payment_signature"))?, signature)
      || integer(Map.get(payment, "disposition"))? != 0))
    || (kind == 1 && integer(Map.get(payment, "disposition"))? != 1) do
    return Err("credit_payment_not_allocatable")
  end
  let destination_owner = if kind == 0 do
    treasury_owner
  else
    binary(Map.get(payment, "payer"))?
  end
  let destination = if quote.asset == 0 do
    payment_token_address(destination_owner, quote.mint)?
  else
    destination_owner
  end
  if Bytes.secure_equals(destination, quote.destination)
    || Bytes.secure_equals(destination_owner, quote.deposit_owner) do
    return Err("invalid_treasury_destination")
  end
  let id = Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-credit-movement-v1"))
    <> Bytes.to_hex(signature)
    <> Int.to_string(kind)
    <> "0"
    <> Bytes.to_hex(config_hash))?)
  let existing = Pg.query_values(conn,
    "SELECT movement_id FROM issuer_treasury_movements WHERE payment_signature=$1",
    [Binary(signature)])?
  if List.length(existing) != 0 do
    let previous = load_treasury_movement(conn,
      binary(Map.get(List.head(existing), "movement_id"))?)?
    if !Bytes.secure_equals(previous.movement_id, id)
      || !Bytes.secure_equals(previous.destination, destination) do
      return Err("credit_movement_conflict")
    end
    return Ok(previous)
  end
  Pg.execute_values(conn,
    "INSERT INTO issuer_treasury_movements (movement_id,payment_signature,kind,config_hash,source,destination,destination_owner,amount,ready_at) VALUES ($1,$2,$3::smallint,$4,$5,$6,$7,$8::numeric,$9::numeric)",
    [
      Binary(id),
      Binary(signature),
      Text(Int.to_string(kind)),
      Binary(config_hash),
      Binary(quote.destination),
      Binary(destination),
      Binary(destination_owner),
      Text(text(Map.get(payment, "amount"))?),
      Text(U64.to_string(U64.add(now, delay_seconds)?))
    ])?
  load_treasury_movement(conn, id)
end

pub struct TreasuryWeeklyBatch do
  batch_id :: U64
  week :: U64
  asset :: Int
  mint :: Bytes
  config_hash :: Bytes
  amount :: U64
  witness :: U64
  operations :: U64
  carry_before :: Int
  carry_after :: Int
  membership_hash :: Bytes
  policy_version :: Int
  policy_hash :: Bytes
  burn :: U64
  burn_carry_before :: Int
  burn_carry_after :: Int
  operations_carry_before :: Int
  operations_carry_after :: Int
  reserve_before :: Int
  reserve_after :: Int
end

fn weekly_from_row(row :: Map<String, DbValue>) -> TreasuryWeeklyBatch!String do
  let batch = TreasuryWeeklyBatch {
    batch_id: U64.parse(text(Map.get(row, "batch_id"))?)?,
    week: U64.parse(text(Map.get(row, "week"))?)?,
    asset: integer(Map.get(row, "asset"))?,
    mint: binary(Map.get(row, "mint"))?,
    config_hash: binary(Map.get(row, "config_hash"))?,
    amount: U64.parse(text(Map.get(row, "amount"))?)?,
    witness: U64.parse(text(Map.get(row, "witness"))?)?,
    operations: U64.parse(text(Map.get(row, "operations"))?)?,
    carry_before: integer(Map.get(row, "carry_before"))?,
    carry_after: integer(Map.get(row, "carry_after"))?,
    membership_hash: binary(Map.get(row, "membership_hash"))?,
    policy_version: integer(Map.get(row, "policy_version"))?,
    policy_hash: binary(Map.get(row, "policy_hash"))?,
    burn: U64.parse(text(Map.get(row, "burn"))?)?,
    burn_carry_before: integer(Map.get(row, "burn_carry_before"))?,
    burn_carry_after: integer(Map.get(row, "burn_carry_after"))?,
    operations_carry_before: integer(Map.get(row, "operations_carry_before"))?,
    operations_carry_after: integer(Map.get(row, "operations_carry_after"))?,
    reserve_before: integer(Map.get(row, "reserve_before"))?,
    reserve_after: integer(Map.get(row, "reserve_after"))?
  }
  let expected = split_credit_revenue(batch.policy_version,
    batch.amount,
    batch.carry_before,
    batch.burn_carry_before,
    batch.operations_carry_before)?
  if batch.policy_hash != expected.policy_hash
    || batch.witness != expected.witness
    || batch.burn != expected.burn
    || batch.operations != expected.operations
    || batch.carry_after != expected.carry_witness
    || batch.burn_carry_after != expected.carry_burn
    || batch.operations_carry_after != expected.carry_operations
    || batch.reserve_before != expected.reserve_before
    || batch.reserve_after != expected.reserve_after do
    return Err("invalid_treasury_policy_math")
  end
  Ok(batch)
end

# Compatibility entry point: historical callers always retain v1 interpretation.
pub fn freeze_treasury_week(conn :: borrow PgConn,
  week :: U64,
  asset :: Int,
  mint :: Bytes,
  config_hash :: Bytes,
  now :: U64) -> TreasuryWeeklyBatch!String do
  freeze_treasury_week_for_policy(conn, week, asset, mint, config_hash, 1, now)
end

# Only issued events whose exact deposits have finalized successful sweeps enter
# a batch. Version/custody lanes never share remainder reserves. SQL snapshots
# immutable ordered membership and creates burn liability in the same statement.
pub fn freeze_treasury_week_for_policy(conn :: borrow PgConn,
  week :: U64,
  asset :: Int,
  mint :: Bytes,
  config_hash :: Bytes,
  version :: Int,
  now :: U64) -> TreasuryWeeklyBatch!String do
  let policy_hash = credit_revenue_policy_hash(version)?
  if (asset != 0 && asset != 1)
    || !key(config_hash)
    || Bytes.length(mint) != 32
    || (asset == 0 && !key(mint))
    || (asset == 1 && Bytes.to_hex(mint) != String.repeat("00", 32))
    || U64.compare(week, U64.divide(now, U64.parse("604800")?)?) >= 0 do
    return Err("treasury_week_not_closed")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365491)", [])?
  let existing = Pg.query_values(conn,
    "SELECT batch_id::text,week::text,asset::text,mint,config_hash,amount::text,witness::text,operations::text,carry_before::text,carry_after::text,membership_hash,policy_version::text,policy_hash,burn::text,burn_carry_before::text,burn_carry_after::text,operations_carry_before::text,operations_carry_after::text,reserve_before::text,reserve_after::text FROM issuer_treasury_weekly WHERE week=$1::numeric AND asset=$2::smallint AND policy_version=$3::smallint",
    [Text(U64.to_string(week)), Text(Int.to_string(asset)), Text(Int.to_string(version))])?
  if List.length(existing) == 1 do
    let batch = weekly_from_row(List.head(existing))?
    if batch.mint != mint || batch.config_hash != config_hash do
      return Err("treasury_week_config_conflict")
    end
    return Ok(batch)
  end
  let previous = Pg.query_values(conn,
    "SELECT week::text,carry_after::text,burn_carry_after::text,operations_carry_after::text,config_hash,mint FROM issuer_treasury_weekly WHERE asset=$1::smallint AND policy_version=$2::smallint ORDER BY week DESC LIMIT 1",
    [Text(Int.to_string(asset)), Text(Int.to_string(version))])?
  let carries = if List.length(previous) == 0 do
    [0, 0, 0]
  else
    let row = List.head(previous)
    if U64.compare(U64.parse(text(Map.get(row, "week"))?)?, week) >= 0 do
      return Err("treasury_week_out_of_order")
    end
    if binary(Map.get(row, "config_hash"))? != config_hash
      || binary(Map.get(row, "mint"))? != mint do
      return Err("treasury_week_config_conflict")
    end
    [
      integer(Map.get(row, "carry_after"))?,
      integer(Map.get(row, "burn_carry_after"))?,
      integer(Map.get(row, "operations_carry_after"))?
    ]
  end
  let domain = Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8(if version == 1 do
    "morse-credit-week-members-v1"
  else
    "morse-credit-week-members-v2"
  end))
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(week), 8)?)
    <> Bytes.to_hex(Bytes.write_uint_le(Int.to_string(asset), 1)?)
    <> Bytes.to_hex(mint)
    <> Bytes.to_hex(config_hash)
    <> if version == 2 do
      Bytes.to_hex(policy_hash)
    else
      ""
    end)?
  let inserted = Pg.query_values(conn,
    "WITH candidates AS MATERIALIZED (SELECT e.event_id,e.quote_id,e.payment_signature,e.amount,e.payment_time,e.mint FROM issuer_credit_revenue e JOIN issuer_treasury_movements m ON m.payment_signature=e.payment_signature LEFT JOIN issuer_treasury_weekly_events a ON a.event_id=e.event_id WHERE e.asset=$2::smallint AND e.policy_version=$8::smallint AND e.policy_hash=$9 AND m.kind=0 AND m.state=2 AND m.config_hash=$6 AND a.event_id IS NULL AND e.payment_time<$3::numeric), totals AS (SELECT COALESCE(SUM(amount),0) AS amount,COALESCE(MAX(event_id),0) AS cutoff,COALESCE(bool_and(mint=$5),true) AS valid_mint,sha256($7::bytea || COALESCE(string_agg(quote_id || payment_signature || convert_to(lpad(amount::text,20,'0') || lpad(payment_time::text,20,'0'),'UTF8'),''::bytea ORDER BY event_id),''::bytea)) AS hash FROM candidates), shares AS (SELECT *,trunc((amount*(CASE WHEN $8::smallint=1 THEN 1 ELSE 2 END)+$4::numeric)/(CASE WHEN $8::smallint=1 THEN 5 ELSE 10 END)) AS w,CASE WHEN $8::smallint=1 THEN 0 ELSE trunc((amount*3+$10::numeric)/10) END AS b,CASE WHEN $8::smallint=1 THEN amount-trunc((amount+$4::numeric)/5) ELSE trunc((amount*5+$11::numeric)/10) END AS o,mod(amount*(CASE WHEN $8::smallint=1 THEN 1 ELSE 2 END)+$4::numeric,CASE WHEN $8::smallint=1 THEN 5 ELSE 10 END) AS cw,CASE WHEN $8::smallint=1 THEN 0 ELSE mod(amount*3+$10::numeric,10) END AS cb,CASE WHEN $8::smallint=1 THEN 0 ELSE mod(amount*5+$11::numeric,10) END AS co FROM totals), batch AS (INSERT INTO issuer_treasury_weekly(week,asset,cutoff,mint,config_hash,amount,witness,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash,burn,burn_carry_before,burn_carry_after,operations_carry_before,operations_carry_after,reserve_before,reserve_after) SELECT $1::numeric,$2::smallint,cutoff,$5,$6,amount,w,o,$4::smallint,cw::smallint,hash,$8::smallint,$9,b,$10::smallint,cb::smallint,$11::smallint,co::smallint,CASE WHEN $8::smallint=1 THEN 0 ELSE ($4::smallint+$10::smallint+$11::smallint)/10 END,(cw+cb+co)::smallint/10 FROM shares WHERE valid_mint RETURNING *), members AS (INSERT INTO issuer_treasury_weekly_events(event_id,batch_id) SELECT c.event_id,b.batch_id FROM candidates c CROSS JOIN batch b RETURNING event_id), liabilities AS (INSERT INTO issuer_treasury_burn_liabilities(batch_id,amount) SELECT batch_id,burn FROM batch WHERE burn>0 RETURNING batch_id) SELECT b.batch_id::text,b.week::text,b.asset::text,b.mint,b.config_hash,b.amount::text,b.witness::text,b.operations::text,b.carry_before::text,b.carry_after::text,b.membership_hash,b.policy_version::text,b.policy_hash,b.burn::text,b.burn_carry_before::text,b.burn_carry_after::text,b.operations_carry_before::text,b.operations_carry_after::text,b.reserve_before::text,b.reserve_after::text,(SELECT COUNT(*) FROM members)::text AS member_count,(SELECT COUNT(*) FROM liabilities)::text AS liability_count FROM batch b",
    [
      Text(U64.to_string(week)),
      Text(Int.to_string(asset)),
      Text(U64.to_string(U64.multiply(U64.add(week, U64.parse("1")?)?, U64.parse("604800")?)?)),
      Text(Int.to_string(List.get(carries, 0))),
      Binary(mint),
      Binary(config_hash),
      Binary(domain),
      Text(Int.to_string(version)),
      Binary(policy_hash),
      Text(Int.to_string(List.get(carries, 1))),
      Text(Int.to_string(List.get(carries, 2)))
    ])?
  if List.length(inserted) != 1 do
    return Err("treasury_week_mint_conflict")
  end
  weekly_from_row(List.head(inserted))
end

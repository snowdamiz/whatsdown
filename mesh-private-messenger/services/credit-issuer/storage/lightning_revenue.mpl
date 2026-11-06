from Payment.RevenuePolicy import (
  CreditRevenueSplit,
  credit_revenue_policy_hash,
  split_credit_revenue
)

pub struct LightningRevenueWeek do
  batch_id :: U64
  week :: U64
  backend_hash :: Bytes
  amount :: U64
  allocation :: CreditRevenueSplit
  membership_hash :: Bytes
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_lightning_revenue_row")
  end
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(output) -> Ok(output)
    _ -> Err("invalid_lightning_revenue_row")
  end
end

fn number(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    Some(output) -> Ok(output)
    None -> Err("invalid_lightning_revenue_row")
  end
end

fn from_row(row :: Map<String, DbValue>) -> LightningRevenueWeek!String do
  let version = number(Map.get(row, "policy_version"))?
  let amount = U64.parse(text(Map.get(row, "amount"))?)?
  let split = split_credit_revenue(version,
    amount,
    number(Map.get(row, "carry_before"))?,
    number(Map.get(row, "burn_carry_before"))?,
    number(Map.get(row, "operations_carry_before"))?)?
  if split.policy_hash != binary(Map.get(row, "policy_hash"))?
    || U64.to_string(split.witness) != text(Map.get(row, "witness"))?
    || U64.to_string(split.burn) != text(Map.get(row, "burn"))?
    || U64.to_string(split.operations) != text(Map.get(row, "operations"))?
    || split.carry_witness != number(Map.get(row, "carry_after"))?
    || split.carry_burn != number(Map.get(row, "burn_carry_after"))?
    || split.carry_operations != number(Map.get(row, "operations_carry_after"))?
    || split.reserve_before != number(Map.get(row, "reserve_before"))?
    || split.reserve_after != number(Map.get(row, "reserve_after"))? do
    return Err("invalid_lightning_revenue_math")
  end
  Ok(LightningRevenueWeek {
    batch_id: U64.parse(text(Map.get(row, "batch_id"))?)?,
    week: U64.parse(text(Map.get(row, "week"))?)?,
    backend_hash: binary(Map.get(row, "backend_hash"))?,
    amount: amount,
    allocation: split,
    membership_hash: binary(Map.get(row, "membership_hash"))?
  })
end

# BTC millisatoshis remain conversion-pending. No Solana funding or operations
# withdrawal is implied by this immutable original-unit allocation.
pub fn freeze_lightning_revenue_week(conn :: borrow PgConn,
  week :: U64,
  backend_hash :: Bytes,
  version :: Int,
  now :: U64) -> LightningRevenueWeek!String do
  let hash = credit_revenue_policy_hash(version)?
  if Bytes.length(backend_hash) != 32
    || Bytes.to_hex(backend_hash) == String.repeat("00", 32)
    || U64.compare(week, U64.divide(now, U64.parse("604800")?)?) >= 0 do
    return Err("lightning_revenue_week_not_closed")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365494)", [])?
  let existing = Pg.query_values(conn,
    "SELECT batch_id::text,week::text,backend_hash,policy_version::text,policy_hash,amount::text,witness::text,burn::text,operations::text,carry_before::text,carry_after::text,burn_carry_before::text,burn_carry_after::text,operations_carry_before::text,operations_carry_after::text,reserve_before::text,reserve_after::text,membership_hash FROM issuer_lightning_weekly WHERE week=$1::numeric AND backend_hash=$2 AND policy_version=$3::smallint",
    [Text(U64.to_string(week)), Binary(backend_hash), Text(Int.to_string(version))])?
  if List.length(existing) == 1 do
    return from_row(List.head(existing))
  end
  let previous = Pg.query_values(conn,
    "SELECT week::text,carry_after::text,burn_carry_after::text,operations_carry_after::text FROM issuer_lightning_weekly WHERE backend_hash=$1 AND policy_version=$2::smallint ORDER BY week DESC LIMIT 1",
    [Binary(backend_hash), Text(Int.to_string(version))])?
  let carry = if List.length(previous) == 0 do
    [0, 0, 0]
  else
    let row = List.head(previous)
    if U64.compare(U64.parse(text(Map.get(row, "week"))?)?, week) >= 0 do
      return Err("lightning_revenue_week_out_of_order")
    end
    [
      number(Map.get(row, "carry_after"))?,
      number(Map.get(row, "burn_carry_after"))?,
      number(Map.get(row, "operations_carry_after"))?
    ]
  end
  let domain = Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-lightning-week-members-v1"))
    <> Bytes.to_hex(backend_hash)
    <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(week), 8)?)
    <> Bytes.to_hex(hash))?
  let rows = Pg.query_values(conn,
    "WITH candidates AS MATERIALIZED (SELECT e.quote_id,e.received_msat AS amount,e.settled_at FROM issuer_lightning_revenue e LEFT JOIN issuer_lightning_weekly_events m USING(quote_id) WHERE e.backend_hash=$2 AND e.policy_version=$4::smallint AND e.policy_hash=$5 AND e.settled_at<$3::numeric AND m.quote_id IS NULL), totals AS (SELECT COALESCE(SUM(amount),0) AS amount,sha256($9::bytea || COALESCE(string_agg(quote_id || convert_to(lpad(amount::text,20,'0') || lpad(settled_at::text,20,'0'),'UTF8'),''::bytea ORDER BY quote_id),''::bytea)) AS hash FROM candidates), shares AS (SELECT *,trunc((amount*(CASE WHEN $4::smallint=1 THEN 1 ELSE 2 END)+$6::numeric)/(CASE WHEN $4::smallint=1 THEN 5 ELSE 10 END)) AS w,CASE WHEN $4::smallint=1 THEN 0 ELSE trunc((amount*3+$7::numeric)/10) END AS b,CASE WHEN $4::smallint=1 THEN amount-trunc((amount+$6::numeric)/5) ELSE trunc((amount*5+$8::numeric)/10) END AS o,mod(amount*(CASE WHEN $4::smallint=1 THEN 1 ELSE 2 END)+$6::numeric,CASE WHEN $4::smallint=1 THEN 5 ELSE 10 END) AS cw,CASE WHEN $4::smallint=1 THEN 0 ELSE mod(amount*3+$7::numeric,10) END AS cb,CASE WHEN $4::smallint=1 THEN 0 ELSE mod(amount*5+$8::numeric,10) END AS co FROM totals), batch AS (INSERT INTO issuer_lightning_weekly(week,backend_hash,policy_version,policy_hash,amount,witness,burn,operations,carry_before,carry_after,burn_carry_before,burn_carry_after,operations_carry_before,operations_carry_after,reserve_before,reserve_after,membership_hash) SELECT $1::numeric,$2,$4::smallint,$5,amount,w,b,o,$6::smallint,cw::smallint,$7::smallint,cb::smallint,$8::smallint,co::smallint,CASE WHEN $4::smallint=1 THEN 0 ELSE ($6::smallint+$7::smallint+$8::smallint)/10 END,(cw+cb+co)::smallint/10,hash FROM shares RETURNING *), members AS (INSERT INTO issuer_lightning_weekly_events(quote_id,batch_id) SELECT c.quote_id,b.batch_id FROM candidates c CROSS JOIN batch b RETURNING quote_id) SELECT b.batch_id::text,b.week::text,b.backend_hash,b.policy_version::text,b.policy_hash,b.amount::text,b.witness::text,b.burn::text,b.operations::text,b.carry_before::text,b.carry_after::text,b.burn_carry_before::text,b.burn_carry_after::text,b.operations_carry_before::text,b.operations_carry_after::text,b.reserve_before::text,b.reserve_after::text,b.membership_hash,(SELECT COUNT(*) FROM members)::text AS member_count FROM batch b",
    [
      Text(U64.to_string(week)),
      Binary(backend_hash),
      Text(U64.to_string(U64.multiply(U64.add(week, U64.parse("1")?)?, U64.parse("604800")?)?)),
      Text(Int.to_string(version)),
      Binary(hash),
      Text(Int.to_string(List.get(carry, 0))),
      Text(Int.to_string(List.get(carry, 1))),
      Text(Int.to_string(List.get(carry, 2))),
      Binary(domain)
    ])?
  if List.length(rows) != 1 do
    return Err("invalid_lightning_revenue_row")
  end
  from_row(List.head(rows))
end

pub fn lightning_revenue_versions(conn :: borrow PgConn,
  backend_hash :: Bytes) -> List<Int>!String do
  let rows = Pg.query_values(conn,
    "SELECT 1::text AS version UNION ALL SELECT 2::text WHERE EXISTS(SELECT 1 FROM issuer_lightning_weekly WHERE backend_hash=$1 AND policy_version=2) OR EXISTS(SELECT 1 FROM issuer_lightning_revenue WHERE backend_hash=$1 AND policy_version=2)",
    [Binary(backend_hash)])?
  let versions = for row in rows do
    case text(Map.get(row, "version"))? do
      "1" -> 1
      "2" -> 2
      _ -> return Err("invalid_credit_revenue_policy")
    end
  end
  Ok(versions)
end

pub fn load_lightning_revenue_week(conn :: borrow PgConn,batch :: U64) -> LightningRevenueWeek!String do
  let rows=Pg.query_values(conn,"SELECT *,batch_id::text,week::text,policy_version::text,amount::text,witness::text,burn::text,operations::text,carry_before::text,carry_after::text,burn_carry_before::text,burn_carry_after::text,operations_carry_before::text,operations_carry_after::text,reserve_before::text,reserve_after::text FROM issuer_lightning_weekly WHERE batch_id=$1::bigint",[Text(U64.to_string(batch))])?
  if List.length(rows)!=1 do return Err("unknown_lightning_revenue_week") end
  from_row(List.head(rows))
end

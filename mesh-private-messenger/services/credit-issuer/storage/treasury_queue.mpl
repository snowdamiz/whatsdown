from Credits.Issuance import decode_credit_quote
from Storage.Treasury import load_treasury_movement, record_issued_credit_revenue

pub struct TreasuryObservationJob do
  quote_id :: Bytes
  payment_signature :: Bytes
end

fn binary(value :: DbValue) -> Bytes!String do
  case value do
    Binary(bytes) -> Ok(bytes)
    _ -> Err("invalid_treasury_queue_row")
  end
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid_treasury_queue_row")
  end
end

pub fn claim_treasury_funding(conn :: borrow PgConn,
  config_hash :: Bytes,
  now :: U64) -> List<U64>!String do
  valid_scope(config_hash)?
  let due = U64.add(now, U64.parse("60")?)?
  let rows = Pg.query_values(conn,
    "SELECT b.batch_id::text FROM issuer_treasury_weekly b LEFT JOIN issuer_treasury_funding_jobs j USING(batch_id) WHERE b.config_hash=$1 AND b.asset=0 AND b.witness>0 AND NOT EXISTS(SELECT 1 FROM issuer_treasury_rewards_intents i WHERE i.batch_id=b.batch_id AND i.state=1) AND (j.next_attempt IS NULL OR j.next_attempt<=$2::numeric) ORDER BY COALESCE(j.next_attempt,0),b.batch_id LIMIT 8 FOR UPDATE OF b SKIP LOCKED",
    [Binary(config_hash), Text(U64.to_string(now))])?
  Ok(for row in rows do
    let id = U64.parse(text(Map.get(row, "batch_id"))?)?
    Pg.execute_values(conn,
      "INSERT INTO issuer_treasury_funding_jobs(batch_id,next_attempt) VALUES($1::bigint,$2::numeric) ON CONFLICT(batch_id) DO UPDATE SET next_attempt=GREATEST(issuer_treasury_funding_jobs.next_attempt,EXCLUDED.next_attempt)",
      [Text(U64.to_string(id)), Text(U64.to_string(due))])?
    id
  end)
end

pub fn treasury_queue_status(conn :: borrow PgConn, config_hash :: Bytes) -> String!String do
  valid_scope(config_hash)?
  let rows = Pg.query_values(conn,
    "SELECT state::text,COUNT(*)::text AS count FROM issuer_treasury_movements WHERE config_hash=$1 GROUP BY state ORDER BY state",
    [Binary(config_hash)])?
  let fields = for row in rows do
    Json.encode_string(text(Map.get(row, "state"))?)
      <> ":"
      <> Json.encode_string(text(Map.get(row, "count"))?)
  end
  Ok("{" <> String.join(fields, ",") <> "}")
end

fn valid_scope(config_hash :: Bytes) -> Result<(), String> do
  if Bytes.length(config_hash) != 32 || Bytes.to_hex(config_hash) == String.repeat("00", 32) do
    return Err("invalid_treasury_queue_scope")
  end
  Ok(nil)
end

# Claims expire; RPC happens only after this transaction commits. A failed or
# missing observation cannot occupy the bounded first page on every cycle.
pub fn claim_treasury_observations(conn :: borrow PgConn,
  purpose :: Int,
  config_hash :: Bytes,
  now :: U64) -> List<TreasuryObservationJob>!String do
  valid_scope(config_hash)?
  if purpose != 0 && purpose != 1 do
    return Err("invalid_treasury_queue_purpose")
  end
  let due = U64.add(now, U64.parse("60")?)?
  let rows = Pg.query_values(conn,
    "SELECT q.quote_id,q.quote,q.payment_signature FROM issuer_quotes q JOIN issuer_keys k ON k.key_id=q.key_id LEFT JOIN issuer_treasury_movements m ON m.payment_signature=q.payment_signature LEFT JOIN issuer_treasury_observation_jobs j ON j.quote_id=q.quote_id AND j.config_hash=$1 WHERE k.purpose=$2::smallint AND q.issued_response IS NOT NULL AND m.movement_id IS NULL AND (j.next_attempt IS NULL OR j.next_attempt<=$3::numeric) ORDER BY COALESCE(j.next_attempt,0),q.quote_id LIMIT 8 FOR UPDATE OF q SKIP LOCKED",
    [Binary(config_hash), Text(Int.to_string(purpose)), Text(U64.to_string(now))])?
  let jobs = for row in rows do
    let quote_id = binary(Map.get(row, "quote_id"))?
    let quote = decode_credit_quote(binary(Map.get(row, "quote"))?)?
    if quote.purpose != purpose || !Bytes.secure_equals(quote.quote_id, quote_id) do
      return Err("treasury_queue_quote_mismatch")
    end
    # Backfill an issued quote from a pre-treasury deployment transactionally.
    record_issued_credit_revenue(conn, quote_id)?
    Pg.execute_values(conn,
      "INSERT INTO issuer_treasury_observation_jobs(config_hash,quote_id,next_attempt) VALUES($1,$2,$3::numeric) ON CONFLICT(config_hash,quote_id) DO UPDATE SET next_attempt=GREATEST(issuer_treasury_observation_jobs.next_attempt,EXCLUDED.next_attempt)",
      [Binary(config_hash), Binary(quote_id), Text(U64.to_string(due))])?
    TreasuryObservationJob {
      quote_id: quote_id,
      payment_signature: binary(Map.get(row, "payment_signature"))?
    }
  end
  Ok(jobs)
end

pub fn complete_treasury_observation(conn :: borrow PgConn,
  config_hash :: Bytes,
  quote_id :: Bytes) -> Result<(), String> do
  Pg.execute_values(conn,
    "DELETE FROM issuer_treasury_observation_jobs WHERE config_hash=$1 AND quote_id=$2",
    [Binary(config_hash), Binary(quote_id)])?
  Ok(nil)
end

pub fn pending_treasury_batches(conn :: borrow PgConn,
  config_hash :: Bytes) -> List<Bytes>!String do
  valid_scope(config_hash)?
  let rows = Pg.query_values(conn,
    "SELECT batch_id FROM issuer_treasury_batches WHERE config_hash=$1 AND state IN(0,1,4) ORDER BY batch_id LIMIT 8",
    [Binary(config_hash)])?
  Ok(for row in rows do
    binary(Map.get(row, "batch_id"))?
  end)
end

pub fn pending_treasury_singles(conn :: borrow PgConn,
  config_hash :: Bytes) -> List<Bytes>!String do
  valid_scope(config_hash)?
  let rows = Pg.query_values(conn,
    "SELECT movement_id FROM issuer_treasury_movements WHERE config_hash=$1 AND batch_id IS NULL AND state IN(0,1,4) AND message IS NOT NULL ORDER BY movement_id LIMIT 8",
    [Binary(config_hash)])?
  Ok(for row in rows do
    binary(Map.get(row, "movement_id"))?
  end)
end

# Advisory selection only. prepare_treasury_batch atomically rechecks readiness,
# exact membership and the shared nonce lane before it reserves a message.
pub fn ready_treasury_batch_members(conn :: borrow PgConn,
  config_hash :: Bytes,
  now :: U64) -> List<Bytes>!String do
  valid_scope(config_hash)?
  let rows = Pg.query_values(conn,
    "SELECT movement_id FROM issuer_treasury_movements WHERE config_hash=$1 AND state=0 AND batch_id IS NULL AND message IS NULL AND ready_at<=$2::numeric ORDER BY ready_at,movement_id LIMIT 32",
    [Binary(config_hash), Text(U64.to_string(now))])?
  if List.length(rows) == 0 do
    return Ok([])
  end
  let candidates = for row in rows do
    load_treasury_movement(conn, binary(Map.get(row, "movement_id"))?)?
  end
  let first = List.head(candidates)
  let matching = List.filter(candidates,
    fn(value) do value.kind == first.kind
      && value.quote.asset == first.quote.asset
      && Bytes.secure_equals(value.quote.mint, first.quote.mint) end)
  let count = if List.length(matching) < 4 do
    List.length(matching)
  else
    4
  end
  Ok(for index in 0..count do
    List.get(matching, index).movement_id
  end)
end

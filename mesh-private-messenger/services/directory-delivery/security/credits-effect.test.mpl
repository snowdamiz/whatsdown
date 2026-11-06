from Storage.TransparencyRecords import (
  entry_bytes_on_connection,
  backfill_records_on_connection,
  store_entry_records
)
from Transparency.Merkle import leaf_hash_for
from Credits.Action import decode_credit_action
from Storage.Credits import consume_credit_hold_on_connection, CreditHoldUse

fn apply(conn :: borrow PgConn,
  action :: Bytes,
  effect :: Bytes,
  fail_action :: Bool) -> Bool!String do
  case consume_credit_hold_on_connection(conn, decode_credit_action(action)?, effect)? do
    HoldAlreadyApplied -> Ok(false)
    HoldApplied -> do
      if fail_action do
        return Err("simulated_action_failure")
      end
      Pg.execute_values(conn,
        "INSERT INTO credit_test_effects (effect_id) VALUES ($1)",
        [Binary(effect)])?
      Ok(true)
    end
  end
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL", "")
  if url == "" do
    return Err("credits database proof requires its isolated test harness")
  end
  let action = Bytes.from_hex(Env.get("CREDIT_TEST_ACTION", ""))?
  let effect = Bytes.from_hex(String.repeat("ab", 32))?
  let pool = Pool.open(url, 1, 2, 5000)?
  assert(Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> apply(conn,
      action,
      effect,
      true) end) == Err("simulated_action_failure"))
  assert(Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> apply(conn, action, effect, false) end) == Ok(true))
  assert(Repo.transaction(pool,
    fn(conn :: borrow PgConn) -> apply(conn, action, effect, false) end) == Ok(false))
  assert(Result.is_err(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do consume_credit_hold_on_connection(conn,
      decode_credit_action(action)?,
      Bytes.from_hex(String.repeat("cd", 32))?) end)))
  let rows = Pool.query(pool, "SELECT count(*)::text AS count FROM credit_test_effects", [])?
  assert(Map.get(List.head(rows), "count") == "1")
  # Canonical issuer leaves stay as public raw records. Device-record backfill
  # must not repeatedly select them or lose the bytes used by public proofs.
  let records = Pool.query(pool,
    "SELECT entry_sequence::text FROM credit_issuer_announcements LIMIT 1",
    [])?
  let sequence = case String.to_int(Map.get(List.head(records), "entry_sequence")) do
    None -> return Err("missing issuer fixture")
    Some(value) -> value
  end
  assert(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let leaf = entry_bytes_on_connection(conn, sequence)?
      if Bytes.length(leaf) != 387 do
        return Err("issuer leaf was lost")
      end
      store_entry_records(conn, sequence, leaf, leaf_hash_for(2, leaf)?)?
      if backfill_records_on_connection(conn, 100)? != 0 do
        return Err("issuer leaf starved device backfill")
      end
      Ok(true)
    end) == Ok(true))
  Pool.close(pool)
  Ok(true)
end

test("a hold is consumed with an atomic durable effect and retry recovers the same result") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

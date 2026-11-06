# A transaction may yield while holding PostgreSQL locks. A competing actor
# on the same worker must wait without blocking the lock owner from resuming.
fn locked_increment(conn :: borrow PgConn) -> Bool!String do
  Pg.execute(conn, "SET LOCAL statement_timeout = '1000ms'", [])?
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365488)", [])?
  Timer.sleep(50)
  Pg.execute(conn, "UPDATE credit_test_actor_lock SET value = value + 1", [])?
  Ok(true)
end

fn proof() -> Bool!String do
  let url = Env.get("MESSENGER_TEST_DATABASE_URL", "")
  if !String.contains(url, "/credits_test?") do
    return Err("actor PostgreSQL proof requires its disposable local harness")
  end
  let pool = Pool.open(url, 2, 2, 5000)?
  Pool.execute(pool, "CREATE TABLE credit_test_actor_lock (value integer NOT NULL)", [])?
  Pool.execute(pool, "INSERT INTO credit_test_actor_lock VALUES (0)", [])?
  let results = Job.map([0, 1],
    fn(_index) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do locked_increment(conn) end) end)
  for result in results do
    case result do
      Ok(Ok(true)) -> nil
      _ -> return Err("same-worker lock waiter blocked its suspended transaction owner")
    end
  end
  let rows = Pool.query(pool, "SELECT value::text FROM credit_test_actor_lock", [])?
  assert(Map.get(List.head(rows), "value") == "2")
  Pool.execute(pool, "DROP TABLE credit_test_actor_lock", [])?
  Pool.close(pool)
  Ok(true)
end

test("same-worker PostgreSQL lock contention lets both transactions commit") do
  case proof() do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

from Storage.SolConversion import (
  reserve_sol_conversion,
  prepare_sol_conversion,
  load_sol_conversion,
  commit_sol_conversion,
  reconcile_sol_conversion,
  sol_conversion_ready_packet
)
from Tests.SolConversionFixture import (
  conversion_fixture_profile,
  conversion_fixture_text,
  conversion_fixture_bank,
  conversion_fixture_outcome
)

fn db_text(value :: DbValue) -> String!String do
  case value do
    Text(v) -> Ok(v)
    _ -> Err("fixture_row")
  end
end

fn exercise(pool :: PoolHandle) -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let executed = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_EXECUTION", ""))?)?
  let profile = conversion_fixture_profile(root)?
  let id = Bytes.from_hex(conversion_fixture_text(root, "id")?)?
  let bank = conversion_fixture_bank(root, profile, id)?
  let hash = Bytes.from_base58(conversion_fixture_text(root, "blockhash")?)?
  let wire = Bytes.from_base64(conversion_fixture_text(executed, "wire")?)?
  let signature = Bytes.from_base58(conversion_fixture_text(executed, "signature")?)?
  let outcome = conversion_fixture_outcome(executed, wire, signature)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      Pg.execute_values(conn,
        "INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(1,1,1,1,$1,$2,5000000000,1000000000,1500000000,2500000000,0,0,$3,2,$4)",
        [
          Binary(Bytes.from_hex(String.repeat("00", 32))?),
          Binary(profile.treasury_config),
          Binary(Bytes.from_hex(conversion_fixture_text(root, "membership_hash")?)?),
          Binary(Bytes.from_hex(conversion_fixture_text(root, "policy_hash")?)?)
        ])?
      assert(reserve_sol_conversion(conn, profile, U64.parse("1")?, 0)? == id)
      Ok(nil)
    end)?
  let first = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_sol_conversion(conn,
      profile,
      id,
      bank,
      hash,
      U64.parse("1100")?) end)?
  assert(first.plan.lamports == U64.parse("1000000000")?)
  assert(first.plan.minimum == U64.parse("148500000")?)
  assert(first.state == 0)
  let later = %{bank | now: U64.add(bank.now, U64.parse("61")?)?}
  assert(Result.is_err(sol_conversion_ready_packet(profile,
    first,
    bank,
    bank.now,
    U64.parse("1000")?)))
  let commits = Job.map([0, 1, 2, 3],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do commit_sol_conversion(conn,
        profile,
        id,
        first.ordinal,
        wire,
        bank,
        bank.now) end) end)
  for committed in commits do
    assert(committed??.packet == wire)
  end
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, profile, id) end)?
  assert(saved.state == 1 && saved.packet == wire)
  assert(sol_conversion_ready_packet(profile, saved, bank, bank.now, U64.parse("1000")?)? == wire)
  assert(Result.is_err(sol_conversion_ready_packet(profile,
    saved,
    later,
    later.now,
    U64.parse("1000")?)))
  assert(Result.is_err(sol_conversion_ready_packet(profile,
    saved,
    bank,
    bank.now,
    U64.parse("1101")?)))
  assert(Result.is_err(sol_conversion_ready_packet(%{profile | maximum_fee: U64.parse("100001")?},
    saved,
    bank,
    bank.now,
    U64.parse("1000")?)))
  let unknown = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prepare_sol_conversion(conn,
      profile,
      id,
      later,
      Crypto.sha256(Bytes.from_utf8("new hash")),
      U64.parse("2000")?) end)?
  assert(unknown.packet == wire && unknown.ordinal == saved.ordinal)
  let results = Job.map([0, 1, 2, 3],
    fn(_) do Repo.transaction(pool,
      fn(conn :: borrow PgConn) do reconcile_sol_conversion(conn,
        profile,
        id,
        first.ordinal,
        outcome) end) end)
  for result in results do
    assert(result??.state == 2)
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do
      let rows = Pg.query_values(conn,
        "SELECT amount::text FROM issuer_sol_conversion_outputs WHERE intent_id=$1",
        [Binary(id)])?
      assert(List.length(rows) == 1)
      assert(db_text(Map.get(List.head(rows), "amount"))? == conversion_fixture_text(executed,
          "received_usdc")?)
      let source = List.head(Pg.query_values(conn,
        "SELECT amount::text,witness::text,burn::text,operations::text FROM issuer_treasury_weekly WHERE batch_id=1",
        [])?)
      assert(db_text(Map.get(source, "amount"))? == "5000000000"
        && db_text(Map.get(source, "witness"))? == "1000000000"
        && db_text(Map.get(source, "burn"))? == "1500000000"
        && db_text(Map.get(source, "operations"))? == "2500000000")
      assert(Result.is_err(reconcile_sol_conversion(conn,
        profile,
        id,
        first.ordinal,
        %{outcome | transaction: %{outcome.transaction | fee: U64.parse("10001")?}})))
      Ok(nil)
    end)?
  Ok(true)
end

test("actual swap output is durably reconciled once across workers; original SOL liabilities never become quoted USDC") do
  let pool = case Pool.open(Env.get("MESSENGER_ISSUER_TEST_DATABASE_URL", ""), 1, 8, 5000) do
    Ok(value) -> value
    Err(error) -> do
      println(error)
      assert(false)
      return
    end
  end
  let result = exercise(pool)
  Pool.close(pool)
  case result do
    Ok(value) -> assert(value)
    Err(error) -> do
      println(error)
      assert(false)
    end
  end
end

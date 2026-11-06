from Tests.SolConversionFixture import conversion_fixture_config, conversion_fixture_text
from Runtime.SolConversionNetwork import (
  prepare_weekly_sol_conversion,
  refresh_unsigned_weekly_sol_conversion,
  commit_weekly_sol_conversion
)
from Storage.SolConversion import load_sol_conversion

fn exercise(pool :: PoolHandle) -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let executed = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_EXECUTION", ""))?)?
  let config = conversion_fixture_config(root)?
  let mode = Env.get("MORSE_SOL_CONVERSION_MODE", "")
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do Pg.execute_values(conn,
      "INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(1,1,1,1,$1,$2,5000000000,1000000000,1500000000,2500000000,0,0,$3,2,$4)",
      [
        Binary(Bytes.from_hex(String.repeat("00", 32))?),
        Binary(config.profile.treasury_config),
        Binary(Bytes.from_hex(conversion_fixture_text(root, "membership_hash")?)?),
        Binary(Bytes.from_hex(conversion_fixture_text(root, "policy_hash")?)?)
      ]) end)?
  File.write(mode, "normal")?
  let first = prepare_weekly_sol_conversion(pool, config, U64.parse("1")?, 0)?
  File.write(mode, "oldvalidheight")?
  # A too-small stored lifetime or elapsed wall time cannot prove hash expiry.
  assert(Result.is_err(refresh_unsigned_weekly_sol_conversion(pool, config, first.plan.intent_id)))
  assert(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn,
      config.profile,
      first.plan.intent_id) end)?.ordinal == 0)
  File.write(mode, "olddead")?
  let fresh = refresh_unsigned_weekly_sol_conversion(pool, config, first.plan.intent_id)?
  assert(fresh.ordinal == 1
    && fresh.state == 0
    && fresh.plan.intent_id == first.plan.intent_id
    && fresh.plan.message != first.plan.message)
  assert(Result.is_err(commit_weekly_sol_conversion(pool,
    config,
    first.plan.intent_id,
    0,
    Bytes.from_base64(conversion_fixture_text(executed, "wire")?)?)))
  let again = prepare_weekly_sol_conversion(pool, config, U64.parse("1")?, 0)?
  assert(again.plan.message == fresh.plan.message && again.ordinal == 1)
  Ok(true)
end

test("unsigned refresh requires exact finalized old-hash invalidity, archives intent and rejects stale signer callback") do
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

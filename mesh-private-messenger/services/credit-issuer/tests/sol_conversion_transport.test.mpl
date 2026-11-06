from Tests.SolConversionFixture import conversion_fixture_config, conversion_fixture_text
from Runtime.SolConversionNetwork import (
  prepare_weekly_sol_conversion,
  commit_weekly_sol_conversion,
  submit_weekly_sol_conversion,
  reconcile_weekly_sol_conversion
)
from Storage.SolConversion import load_sol_conversion

fn sends() -> Int!String do
  Ok(List.length(String.split(File.read(Env.get("MORSE_SOL_CONVERSION_TRACE", ""))?,
    "sendTransaction")) - 1)
end

fn exercise(pool :: PoolHandle) -> Bool!String do
  let root = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_BANK", ""))?)?
  let executed = Json.parse(File.read(Env.get("MORSE_SOL_CONVERSION_EXECUTION", ""))?)?
  let config = conversion_fixture_config(root)?
  let profile = config.profile
  let id = Bytes.from_hex(conversion_fixture_text(root, "id")?)?
  let mode = Env.get("MORSE_SOL_CONVERSION_MODE", "")
  let wire = Bytes.from_base64(conversion_fixture_text(executed, "wire")?)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do Pg.execute_values(conn,
      "INSERT INTO issuer_treasury_weekly(batch_id,week,asset,cutoff,mint,config_hash,amount,witness,burn,operations,carry_before,carry_after,membership_hash,policy_version,policy_hash) VALUES(1,1,1,1,$1,$2,5000000000,1000000000,1500000000,2500000000,0,0,$3,2,$4)",
      [
        Binary(Bytes.from_hex(String.repeat("00", 32))?),
        Binary(profile.treasury_config),
        Binary(Bytes.from_hex(conversion_fixture_text(root, "membership_hash")?)?),
        Binary(Bytes.from_hex(conversion_fixture_text(root, "policy_hash")?)?)
      ]) end)?
  File.write(mode, "normal")?
  let plan = prepare_weekly_sol_conversion(pool, config, U64.parse("1")?, 0)?
  assert(plan.plan.message == Bytes.from_base64(conversion_fixture_text(executed, "message")?)?)
  for invalid in ["stale", "code", "expired"] do
    File.write(mode, invalid)?
    assert(Result.is_err(commit_weekly_sol_conversion(pool, config, id, plan.ordinal, wire)))
  end
  assert(Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, profile, id) end)?.state == 0)
  File.write(mode, "normal")?
  let saved = commit_weekly_sol_conversion(pool, config, id, plan.ordinal, wire)?
  assert(saved.packet == wire && saved.state == 1)
  let count = sends()?
  for invalid in ["stale", "code", "expired"] do
    File.write(mode, invalid)?
    assert(Result.is_err(submit_weekly_sol_conversion(pool, config, id)))
    assert(sends()? == count)
  end
  File.write(mode, "normal")?
  let unknown = submit_weekly_sol_conversion(pool, config, id)?
  assert(unknown.state == 1 && unknown.packet == wire)
  assert(sends()? == count + 2)
  let pending = prepare_weekly_sol_conversion(pool, config, U64.parse("1")?, 0)?
  assert(pending.plan.message == saved.plan.message
    && pending.packet == wire
    && pending.ordinal == saved.ordinal)
  # Oracle is unavailable in this historical-execution response. Both actual SBF
  # transaction deltas and pinned current code, rather than a quote, are authority.
  File.write(mode, "executed")?
  let terminal = reconcile_weekly_sol_conversion(pool, config, id)?
  assert(terminal.state == 2 && Bytes.length(terminal.receipt) == 197)
  let trace = File.read(Env.get("MORSE_SOL_CONVERSION_TRACE", ""))?
  assert(submit_weekly_sol_conversion(pool, config, id)?.state == 2)
  assert(File.read(Env.get("MORSE_SOL_CONVERSION_TRACE", ""))? == trace)
  Ok(true)
end

test("owned HTTP preserves externally signed unknown packet, blocks stale submission and reconciles actual SBF custody without quote feed") do
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

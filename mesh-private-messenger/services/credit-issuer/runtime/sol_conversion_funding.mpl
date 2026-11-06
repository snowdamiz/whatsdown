from Runtime.SolConversionNetwork import SolConversionConfig, validate_sol_conversion_config
from Runtime.Treasury import TreasuryWorkerConfig
from Storage.SolConversion import load_sol_conversion
from Storage.SolConversionFunding import (
  reserve_sol_witness_funding,
  active_sol_witness_funding,
  load_sol_witness_funding,
  reconcile_sol_witness_funding
)
from Storage.TreasuryFunding import TreasuryFundingIntent
from Payment.TreasuryRewards import read_treasury_funding

# One explicitly requested conversion accounting handoff. This does not schedule,
# sign, submit, claim or operate the separately scoped rewards protocol.
pub fn prepare_sol_witness_output(pool :: PoolHandle,
  config :: SolConversionConfig,
  conversion :: Bytes) -> TreasuryFundingIntent!String do
  validate_sol_conversion_config(config)?
  let actual = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_conversion(conn, config.profile, conversion) end)?
  if actual.state != 2 do
    return Err("sol_conversion_output_not_finalized")
  end
  let worker = TreasuryWorkerConfig {
    chain: config.chain,
    providers: config.providers,
    test_mode: config.test_mode
  }
  let active = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do active_sol_witness_funding(conn,
      config.profile,
      config.chain,
      conversion) end)?
  let reserved = case active do
    Some(value) -> if value.state == 1 do
      return Ok(value)
    else
      value
    end
    None -> do
      let current = read_treasury_funding(worker,
        Crypto.sha256(Bytes.concat(Bytes.from_utf8("sol-output-clock-v1"), conversion)?))?
      Repo.transaction(pool,
        fn(conn :: borrow PgConn) do reserve_sol_witness_funding(conn,
          config.profile,
          config.chain,
          conversion,
          current.current_epoch) end)?
    end
  end
  let proof = read_treasury_funding(worker, reserved.intent_id)?
  let checked = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reconcile_sol_witness_funding(conn,
      config.profile,
      config.chain,
      reserved.intent_id,
      proof) end)?
  if checked.state == 2 do
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do reserve_sol_witness_funding(conn,
        config.profile,
        config.chain,
        conversion,
        proof.current_epoch) end)
  else
    Ok(checked)
  end
end

pub fn reconcile_sol_witness_output(pool :: PoolHandle,
  config :: SolConversionConfig,
  id :: Bytes) -> TreasuryFundingIntent!String do
  validate_sol_conversion_config(config)?
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_sol_witness_funding(conn,
      config.profile,
      config.chain,
      id) end)?
  if saved.state != 0 do
    return Ok(saved)
  end
  let proof = read_treasury_funding(TreasuryWorkerConfig {
      chain: config.chain,
      providers: config.providers,
      test_mode: config.test_mode
    },
    id)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reconcile_sol_witness_funding(conn,
      config.profile,
      config.chain,
      id,
      proof) end)
end

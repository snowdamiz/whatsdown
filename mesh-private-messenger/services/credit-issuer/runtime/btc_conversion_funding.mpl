from Payment.BtcConversionConfig import BtcConversionConfig, validate_btc_conversion_config
from Runtime.Treasury import TreasuryWorkerConfig, validate_worker
from Storage.BtcConversionFunding import (
  btc_witness_funding_binding,
  active_btc_witness_funding,
  load_btc_witness_funding,
  reserve_btc_witness_funding,
  reconcile_btc_witness_funding
)
from Storage.TreasuryFunding import TreasuryFundingIntent
from Payment.TreasuryRewards import read_treasury_funding

pub struct BtcWitnessFundingConfig do
  conversion :: BtcConversionConfig
  treasury :: TreasuryWorkerConfig
end

pub fn validate_btc_witness_funding(config :: BtcWitnessFundingConfig) -> Result<(), String> do
  validate_btc_conversion_config(config.conversion)?
  validate_worker(config.treasury)?
  btc_witness_funding_binding(config.conversion, config.treasury.chain)
end

# One explicit accounting handoff. No scheduler, signer or transaction submission.
# The existing reader authenticates program identity and two pinned sources;
# this does not add current Pool or executable release authentication.
pub fn prepare_btc_witness_output(pool :: PoolHandle,
  config :: BtcWitnessFundingConfig,
  conversion :: Bytes) -> TreasuryFundingIntent!String do
  validate_btc_witness_funding(config)?
  let active = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do active_btc_witness_funding(conn,
      config.conversion,
      config.treasury.chain,
      conversion) end)?
  let reserved = case active do
    Some(value) -> if value.state == 1 do
      return Ok(value)
    else
      value
    end
    None -> do
      let current = read_treasury_funding(config.treasury,
        Crypto.sha256(Bytes.concat(Bytes.from_utf8("btc-witness-output-clock-v1"), conversion)?))?
      Repo.transaction(pool,
        fn(conn :: borrow PgConn) do reserve_btc_witness_funding(conn,
          config.conversion,
          config.treasury.chain,
          conversion,
          current.current_epoch) end)?
    end
  end
  let proof = read_treasury_funding(config.treasury, reserved.intent_id)?
  let checked = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reconcile_btc_witness_funding(conn,
      config.conversion,
      config.treasury.chain,
      reserved.intent_id,
      proof) end)?
  if checked.state == 2 do
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) do reserve_btc_witness_funding(conn,
        config.conversion,
        config.treasury.chain,
        conversion,
        proof.current_epoch) end)
  else
    Ok(checked)
  end
end

pub fn reconcile_btc_witness_output(pool :: PoolHandle,
  config :: BtcWitnessFundingConfig,
  id :: Bytes) -> TreasuryFundingIntent!String do
  validate_btc_witness_funding(config)?
  let saved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_btc_witness_funding(conn,
      config.conversion,
      config.treasury.chain,
      id) end)?
  if saved.state != 0 do
    return Ok(saved)
  end
  let proof = read_treasury_funding(config.treasury, id)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reconcile_btc_witness_funding(conn,
      config.conversion,
      config.treasury.chain,
      id,
      proof) end)
end

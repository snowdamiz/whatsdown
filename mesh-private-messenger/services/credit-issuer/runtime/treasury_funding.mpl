from Runtime.Treasury import TreasuryWorkerConfig
from Payment.Treasury import treasury_config_hash
from Payment.TreasuryRewards import read_treasury_funding
from Storage.TreasuryFunding import (
  TreasuryFundingIntent,
  active_treasury_funding,
  load_treasury_funding,
  reserve_treasury_funding,
  reconcile_treasury_funding
)

pub fn reconcile_weekly_treasury_funding(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  id :: Bytes) -> TreasuryFundingIntent!String do
  let intent = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do load_treasury_funding(conn, id) end)?
  if !Bytes.secure_equals(intent.pool, config.chain.rewards_pool)
    || !Bytes.secure_equals(intent.funder, config.chain.treasury_owner)
    || !Bytes.secure_equals(intent.mint, config.chain.mint) do
    return Err("treasury_funding_config_changed")
  end
  let proof = read_treasury_funding(config, id)?
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reconcile_treasury_funding(conn, id, proof) end)
end

# The returned intent is handed to the existing permanent-receipt rewards
# operator. This function never calls a raw fund instruction or assumes success
# from an acknowledgment. Rollover keeps the original weekly liability reserved.
pub fn prepare_weekly_treasury_funding(pool :: PoolHandle,
  config :: TreasuryWorkerConfig,
  batch_id :: U64) -> Option<TreasuryFundingIntent>!String do
  let active = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do active_treasury_funding(conn, batch_id) end)?
  let current_epoch = case active do
    Some(intent) -> do
      let checked = reconcile_weekly_treasury_funding(pool, config, intent.intent_id)?
      if checked.state == 1 || checked.state == 0 do
        return Ok(Some(checked))
      end
      let proof = read_treasury_funding(config, intent.intent_id)?
      proof.current_epoch
    end
    None -> do
      let probe = Crypto.sha256(Bytes.from_hex(Bytes.to_hex(Bytes.from_utf8("morse-credit-treasury-clock-probe-v1"))
        <> Bytes.to_hex(treasury_config_hash(config.chain)?)
        <> Bytes.to_hex(Bytes.write_uint_le(U64.to_string(batch_id), 8)?))?)
      read_treasury_funding(config, probe)?.current_epoch
    end
  end
  let reserved = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do reserve_treasury_funding(conn,
      batch_id,
      config.chain,
      current_epoch) end)?
  case reserved do
    None -> Ok(None)
    Some(intent) -> Ok(Some(reconcile_weekly_treasury_funding(pool, config, intent.intent_id)?))
  end
end

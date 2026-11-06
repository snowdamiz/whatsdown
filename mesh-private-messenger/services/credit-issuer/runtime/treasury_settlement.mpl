from Storage.RevenuePolicy import treasury_revenue_versions
from Runtime.Treasury import TreasuryWorkerConfig
from Runtime.TreasuryFunding import prepare_weekly_treasury_funding
from Payment.Treasury import treasury_config_hash
from Storage.Treasury import TreasuryWeeklyBatch, freeze_treasury_week_for_policy
from Storage.TreasuryQueue import claim_treasury_funding

pub fn settle_treasury_week(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  week :: U64,
  asset :: Int,
  now :: U64) -> TreasuryWeeklyBatch!String do
  settle_policy_treasury_week(pool, worker, week, asset, 1, now)
end

pub fn settle_policy_treasury_week(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  week :: U64,
  asset :: Int,
  version :: Int,
  now :: U64) -> TreasuryWeeklyBatch!String do
  let mint = if asset == 0 do
    worker.chain.mint
  else
    Bytes.from_hex(String.repeat("00", 32))?
  end
  Repo.transaction(pool,
    fn(conn :: borrow PgConn) do freeze_treasury_week_for_policy(conn,
      week,
      asset,
      mint,
      treasury_config_hash(worker.chain)?,
      version,
      now) end)
end

pub fn treasury_week_json(value :: TreasuryWeeklyBatch) -> String do
  "{\"batch_id\":"
    <> Json.encode_string(U64.to_string(value.batch_id))
    <> ",\"week\":"
    <> Json.encode_string(U64.to_string(value.week))
    <> ",\"asset\":"
    <> Json.encode_string(if value.asset == 0 do
      "usdc"
    else
      "sol"
    end)
    <> ",\"amount\":"
    <> Json.encode_string(U64.to_string(value.amount))
    <> ",\"witness\":"
    <> Json.encode_string(U64.to_string(value.witness))
    <> ",\"burn\":"
    <> Json.encode_string(U64.to_string(value.burn))
    <> ",\"policy_version\":"
    <> Int.to_string(value.policy_version)
    <> ",\"policy_hash\":"
    <> Json.encode_string(Bytes.to_hex(value.policy_hash))
    <> ",\"reserve_before\":"
    <> Int.to_string(value.reserve_before)
    <> ",\"reserve_after\":"
    <> Int.to_string(value.reserve_after)
    <> ",\"operations\":"
    <> Json.encode_string(U64.to_string(value.operations))
    <> ",\"membership_hash\":"
    <> Json.encode_string(Bytes.to_hex(value.membership_hash))
    <> "}"
end

# Late successful sweeps remain for the next week's adjustment. Funding stays
# pending until its permanent receipt is authenticated. The separately held
# treasury owner executes the reviewed funding request with the rewards operator.
pub fn treasury_settlement_cycle(pool :: PoolHandle,
  worker :: TreasuryWorkerConfig,
  now :: U64) -> Int!String do
  let current = U64.divide(now, U64.parse("604800")?)?
  if current == U64.parse("0")? do
    return Ok(0)
  end
  let week = U64.subtract(current, U64.parse("1")?)?
  let versions = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do treasury_revenue_versions(conn,
      treasury_config_hash(worker.chain)?) end)?
  let frozen = List.flatten(for asset in [0, 1] do
    for version in versions do
      case settle_policy_treasury_week(pool, worker, week, asset, version, now) do
        Ok(_) -> 0
        Err(_) -> 1
      end
    end
  end)
  let ids = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do claim_treasury_funding(conn,
      treasury_config_hash(worker.chain)?,
      now) end)?
  let checked = for id in ids do
    case prepare_weekly_treasury_funding(pool, worker, id) do
      Ok(_) -> 0
      Err(_) -> 1
    end
  end
  Ok(List.length(List.filter(List.concat(frozen, checked), fn(value) do value == 1 end)))
end

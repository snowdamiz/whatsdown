from Storage.Treasury import TreasuryWeeklyBatch, freeze_treasury_week_for_policy

pub fn freeze_policy_treasury_week(conn :: borrow PgConn,
  week :: U64,
  asset :: Int,
  mint :: Bytes,
  config_hash :: Bytes,
  version :: Int,
  now :: U64) -> TreasuryWeeklyBatch!String do
  freeze_treasury_week_for_policy(conn, week, asset, mint, config_hash, version, now)
end

# Legacy empty-week behavior remains unchanged. A v2 lane begins only when its
# own finalized revenue exists, then continues carrying its reserved dust.
pub fn treasury_revenue_versions(conn :: borrow PgConn, config_hash :: Bytes) -> List<Int>!String do
  let rows = Pg.query_values(conn,
    "SELECT 1::text AS version UNION ALL SELECT 2::text WHERE EXISTS(SELECT 1 FROM issuer_treasury_weekly WHERE config_hash=$1 AND policy_version=2) OR EXISTS(SELECT 1 FROM issuer_credit_revenue e JOIN issuer_treasury_movements m USING(payment_signature) WHERE e.policy_version=2 AND m.config_hash=$1 AND m.kind=0 AND m.state=2)",
    [Binary(config_hash)])?
  let versions = for row in rows do
    case Map.get(row, "version") do
      Text("1") -> 1
      Text("2") -> 2
      _ -> return Err("invalid_credit_revenue_policy")
    end
  end
  Ok(versions)
end

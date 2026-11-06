# Transaction-only bridge from verified BTC conversion outputs to the existing
# burn intent. Lightning batch IDs never enter the Solana liability foreign key.
# The output-use row reserves actual USDC; it does not discharge residual BTC.

pub fn available_btc_burn_rows(conn :: borrow PgConn,
  config :: Bytes,
  mint :: Bytes,
  owner :: Bytes,
  custody :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT i.batch_id::text,b.week::text,i.policy_hash,i.treasury_config_hash AS config_hash,o.mint,o.amount::text,i.intent_id AS conversion_id FROM issuer_btc_conversion_intents i JOIN issuer_lightning_weekly b USING(batch_id) JOIN issuer_btc_conversion_outputs o USING(intent_id) LEFT JOIN issuer_btc_conversion_output_uses u ON u.intent_id=i.intent_id AND NOT u.released WHERE i.bucket=1 AND i.stage='arrived' AND i.policy_version=2 AND b.policy_version=i.policy_version AND b.policy_hash=i.policy_hash AND b.membership_hash=i.membership_hash AND b.backend_hash=i.backend_hash AND b.burn=i.source_msat AND i.treasury_config_hash=$1 AND o.mint=$2 AND o.owner=$3 AND o.custody=$4 AND u.intent_id IS NULL ORDER BY b.week,i.batch_id LIMIT 64 FOR UPDATE OF i,b",
    [Binary(config), Binary(mint), Binary(owner), Binary(custody)])
end

# Include released history: old intents must still reconstruct byte-for-byte
# after a proven-unfunded expiry permits a different epoch to reserve output.
pub fn load_btc_burn_rows(conn :: borrow PgConn,
  id :: Bytes,
  config :: Bytes,
  mint :: Bytes,
  owner :: Bytes,
  custody :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT i.batch_id::text,b.week::text,i.policy_hash,i.treasury_config_hash AS config_hash,o.mint,o.amount::text,i.intent_id AS conversion_id FROM issuer_btc_conversion_output_uses u JOIN issuer_btc_conversion_intents i USING(intent_id) JOIN issuer_lightning_weekly b USING(batch_id) JOIN issuer_btc_conversion_outputs o USING(intent_id) WHERE u.operation_id=$1 AND u.bucket=1 AND i.bucket=1 AND i.policy_version=2 AND b.policy_version=i.policy_version AND b.policy_hash=i.policy_hash AND b.membership_hash=i.membership_hash AND b.backend_hash=i.backend_hash AND b.burn=i.source_msat AND i.treasury_config_hash=$2 AND o.mint=$3 AND o.owner=$4 AND o.custody=$5 AND u.receipt_hash=sha256(o.receipt) ORDER BY i.batch_id",
    [Binary(id), Binary(config), Binary(mint), Binary(owner), Binary(custody)])
end

pub fn reserve_btc_burn_row(conn :: borrow PgConn,
  conversion :: Bytes,
  operation :: Bytes) -> Result<(), String> do
  # The caller holds the shared burn lock and the selected conversion row lock.
  # Migration 014 independently binds the reservation to this pending intent's
  # treasury, mint and config. The stage CAS serializes other output consumers.
  let inserted = Pg.query_values(conn,
    "INSERT INTO issuer_btc_conversion_output_uses(intent_id,bucket,operation_id,receipt_hash) SELECT i.intent_id,1,$2,sha256(o.receipt) FROM issuer_btc_conversion_intents i JOIN issuer_btc_conversion_outputs o USING(intent_id) WHERE i.intent_id=$1 AND i.bucket=1 AND i.stage='arrived' RETURNING intent_id",
    [Binary(conversion), Binary(operation)])?
  if List.length(inserted) != 1 do
    return Err("credit_burn_btc_reservation_conflict")
  end
  let changed = Pg.query_values(conn,
    "UPDATE issuer_btc_conversion_intents SET stage='output-reserved',revision=revision+1 WHERE intent_id=$1 AND bucket=1 AND stage='arrived' RETURNING intent_id",
    [Binary(conversion)])?
  if List.length(changed) != 1 do
    return Err("credit_burn_btc_reservation_conflict")
  end
  Ok(nil)
end

pub fn active_btc_burn_rows(conn :: borrow PgConn,
  operation :: Bytes) -> List<Map<String, DbValue>>!String do
  Pg.query_values(conn,
    "SELECT i.intent_id FROM issuer_btc_conversion_output_uses u JOIN issuer_btc_conversion_intents i USING(intent_id) JOIN issuer_btc_conversion_outputs o USING(intent_id) WHERE u.operation_id=$1 AND u.bucket=1 AND NOT u.released AND i.bucket=1 AND i.stage='output-reserved' AND u.receipt_hash=sha256(o.receipt) FOR UPDATE OF i",
    [Binary(operation)])
end

# The shared intent must already contain the authenticated permanent tombstone.
# Database guards refuse all other releases, including funded or timed-out work.
pub fn release_btc_burn_rows(conn :: borrow PgConn,
  operation :: Bytes,
  receipt :: Bytes) -> Int!String do
  let released = Pg.query_values(conn,
    "UPDATE issuer_btc_conversion_output_uses SET released=true,expiry_receipt=$2 WHERE operation_id=$1 AND bucket=1 AND NOT released RETURNING intent_id",
    [Binary(operation), Binary(receipt)])?
  for row in released do
    let changed = Pg.query_values(conn,
      "UPDATE issuer_btc_conversion_intents i SET stage='arrived',revision=revision+1 WHERE i.intent_id=$1 AND i.bucket=1 AND i.stage='output-reserved' AND NOT EXISTS(SELECT 1 FROM issuer_btc_conversion_output_uses u WHERE u.intent_id=i.intent_id AND NOT u.released) RETURNING i.intent_id",
      [Map.get(row, "intent_id")])?
    if List.length(changed) != 1 do
      return Err("credit_burn_btc_release_conflict")
    end
  end
  Ok(List.length(released))
end

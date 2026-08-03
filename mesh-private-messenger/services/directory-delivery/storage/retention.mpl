pub fn purge_envelopes(pool :: PoolHandle, acknowledged_retention_seconds :: Int, limit :: Int) -> Int ! String do
  if acknowledged_retention_seconds < 0 || acknowledged_retention_seconds > 2592000 || limit <= 0 || limit > 1000 do
    Err("invalid retention policy")
  else
    Pool.execute_values(pool,
    "WITH doomed AS (SELECT sequence FROM messenger_envelopes WHERE expiration_ms <= floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint OR (acknowledged_at IS NOT NULL AND acknowledged_at <= clock_timestamp() - ($1::integer * interval '1 second')) ORDER BY sequence FOR UPDATE SKIP LOCKED LIMIT $2::integer) DELETE FROM messenger_envelopes AS envelope USING doomed WHERE envelope.sequence = doomed.sequence",
    [Text(Int.to_string(acknowledged_retention_seconds)), Text(Int.to_string(limit))])
  end
end

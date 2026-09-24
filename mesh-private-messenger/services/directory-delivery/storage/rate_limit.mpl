fn valid_policy(key :: Bytes, limit :: Int, window_seconds :: Int) -> Result<(), String> do
  if Bytes.length(key) != 32 || limit <= 0 || limit > 1000000 || window_seconds <= 0 || window_seconds > 86400 do
    Err("invalid rate-limit policy")
  else
    Ok(nil)
  end
end

pub fn allow_request_on_connection(conn :: borrow PgConn,
  key :: Bytes,
  limit :: Int,
  window_seconds :: Int) -> Bool!String do
  valid_policy(key, limit, window_seconds)?
  let rows = Pg.query_values(conn,
    "INSERT INTO messenger_rate_limits (bucket_key, window_started_at, request_count) VALUES ($1, clock_timestamp(), 1) ON CONFLICT (bucket_key) DO UPDATE SET window_started_at = CASE WHEN messenger_rate_limits.window_started_at <= clock_timestamp() - ($3::integer * interval '1 second') THEN clock_timestamp() ELSE messenger_rate_limits.window_started_at END, request_count = CASE WHEN messenger_rate_limits.window_started_at <= clock_timestamp() - ($3::integer * interval '1 second') THEN 1 ELSE messenger_rate_limits.request_count + 1 END WHERE messenger_rate_limits.window_started_at <= clock_timestamp() - ($3::integer * interval '1 second') OR messenger_rate_limits.request_count < $2::integer RETURNING request_count::text",
    [Binary(key), Text(Int.to_string(limit)), Text(Int.to_string(window_seconds))])?
  Ok(List.length(rows) == 1)
end

pub fn allow_request(pool :: PoolHandle, key :: Bytes, limit :: Int, window_seconds :: Int) -> Bool!String do
  valid_policy(key, limit, window_seconds)?
  Repo.transaction(pool,
    fn (conn :: borrow PgConn) -> allow_request_on_connection(conn, key, limit, window_seconds) end)
end

# No policy keeps a window longer than a day, so an older row can never affect
# a decision again. Buckets also record spent request stamps, one per request,
# so without this the table grows without bound.

pub fn purge_rate_limits(pool :: PoolHandle, limit :: Int) -> Int!String do
  if limit <= 0 || limit > 1000 do
    Err("invalid rate-limit purge")
  else
    Pool.execute_values(pool,
      "WITH doomed AS (SELECT bucket_key FROM messenger_rate_limits WHERE window_started_at <= clock_timestamp() - interval '1 day' ORDER BY window_started_at FOR UPDATE SKIP LOCKED LIMIT $1::integer) DELETE FROM messenger_rate_limits AS bucket USING doomed WHERE bucket.bucket_key = doomed.bucket_key",
      [Text(Int.to_string(limit))])
  end
end

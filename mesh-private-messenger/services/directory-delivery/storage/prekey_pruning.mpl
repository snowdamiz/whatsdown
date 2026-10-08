##! Deleting consumed one-time prekeys once their claims can no longer be retried.
##!
##! A consumed row keeps the claim's hashes and its exact answer (migration 009)
##! so a retried claim gets the same bundle. After a day it is only a record of
##! when a session started, so the scheduled job deletes it. The device's
##! `pruned_prekey_id` keeps the highest identifier deleted so far; publication
##! skips identifiers at or below it (migration 021).

fn text_value(rows :: List<Map<String, DbValue>>, key :: String) -> String!String do
  case rows do
    [row] -> case Map.get(row, key) do
      Text(value) -> Ok(value)
      _ -> Err("invalid prekey pruning row")
    end
    _ -> Err("invalid prekey pruning result")
  end
end

fn integer_value(rows :: List<Map<String, DbValue>>, key :: String) -> Int!String do
  case String.to_int(text_value(rows, key)?) do
    Some(value) -> Ok(value)
    None -> Err("invalid prekey pruning count")
  end
end

## Deletes up to `limit` one-time prekeys consumed more than a day ago, with
## their claim hashes and answers, and returns how many went.

pub fn prekeys_prune_consumed(pool :: PoolHandle, limit :: Int) -> Int!String do
  if limit <= 0 || limit > 1000 do
    Err("invalid prekey pruning limit")
  else
    integer_value(Pool.query_values(pool,
        "WITH doomed AS (SELECT account_id, device_id, prekey_id FROM messenger_one_time_prekeys WHERE consumed_at IS NOT NULL AND NOT last_resort AND consumed_at <= clock_timestamp() - interval '1 day' ORDER BY consumed_at FOR UPDATE SKIP LOCKED LIMIT $1::integer), removed AS (DELETE FROM messenger_one_time_prekeys AS prekey USING doomed WHERE prekey.account_id = doomed.account_id AND prekey.device_id = doomed.device_id AND prekey.prekey_id = doomed.prekey_id RETURNING prekey.account_id, prekey.device_id, prekey.prekey_id), marked AS (UPDATE messenger_devices AS device SET pruned_prekey_id = GREATEST(device.pruned_prekey_id, highest.prekey_id) FROM (SELECT account_id, device_id, max(prekey_id) AS prekey_id FROM removed GROUP BY account_id, device_id) AS highest WHERE device.account_id = highest.account_id AND device.device_id = highest.device_id RETURNING 1) SELECT (SELECT count(*) FROM removed)::text AS removed",
        [Text(Int.to_string(limit))])?,
      "removed")
  end
end

## When the oldest consumed one-time prekey becomes deletable, in Unix
## milliseconds (0: none waits).

pub fn prekeys_pruning_due(pool :: PoolHandle) -> Int!String do
  integer_value(Pool.query_values(pool,
      "SELECT COALESCE(floor(extract(epoch FROM min(consumed_at) + interval '1 day') * 1000)::bigint, 0)::text AS due FROM messenger_one_time_prekeys WHERE consumed_at IS NOT NULL AND NOT last_resort",
      [])?,
    "due")
end

##! Pruning what the log keeps around its hashes (plan §6.15 G2 and G4).
##!
##! - An entry's bytes go once the account's next entry has existed for 90
##!   days: never an account's current entry, never anything younger than 90
##!   days, and never a hash. Device records no remaining entry refers to go
##!   with them, so superseded device keys are then kept only as hashes.
##! - Checkpoints older than 35 days go, with their witness signatures, except
##!   the newest one and every anchored one.
##!
##! It runs at most once a UTC day, up to a daily cap per kind, under the log's
##! append lock. In dry-run mode it only counts what it would remove.

pub struct PruningRun do
  ran :: Bool
  mode :: String
  entries :: Int
  records :: Int
  checkpoints :: Int
end

fn text(value :: DbValue) -> String!String do
  case value do
    Text(output) -> Ok(output)
    _ -> Err("invalid pruning row")
  end
end

fn integer(value :: DbValue) -> Int!String do
  case String.to_int(text(value)?) do
    None -> Err("invalid pruning integer")
    Some(output) -> Ok(output)
  end
end

## MESSENGER_TRANSPARENCY_PRUNING: on (the default), dry-run or off.

pub fn transparency_pruning_mode() -> String!String do
  let mode = Env.get("MESSENGER_TRANSPARENCY_PRUNING", "on")
  if mode == "off" || mode == "dry-run" || mode == "on" do
    Ok(mode)
  else
    Err("MESSENGER_TRANSPARENCY_PRUNING must be off, dry-run or on")
  end
end

## MESSENGER_TRANSPARENCY_PRUNING_DAILY_CAP: rows of each kind per day, 1 to
## 1,000,000 (default 10,000).

pub fn transparency_pruning_cap() -> Int!String do
  let cap = Env.get_int("MESSENGER_TRANSPARENCY_PRUNING_DAILY_CAP", 10000)
  if cap < 1 || cap > 1000000 do
    Err("MESSENGER_TRANSPARENCY_PRUNING_DAILY_CAP must be between 1 and 1000000")
  else
    Ok(cap)
  end
end

# Entries superseded for 90 days, oldest first, up to the cap.

fn superseded() -> String do
  "SELECT entry.sequence, entry.record_hashes FROM transparency_entries AS entry WHERE entry.pruned_at IS NULL AND (entry.record_hashes IS NOT NULL OR entry.entry_bytes IS NOT NULL) AND EXISTS (SELECT 1 FROM transparency_entries AS newer WHERE newer.account_commitment = entry.account_commitment AND newer.sequence > entry.sequence AND newer.created_at <= now() - interval '90 days') ORDER BY entry.sequence LIMIT $1::integer"
end

# Records that only doomed entries refer to.

fn orphaned() -> String do
  "SELECT DISTINCT listed.record_hash FROM doomed, unnest(doomed.record_hashes) AS listed (record_hash) WHERE NOT EXISTS (SELECT 1 FROM transparency_entries AS kept WHERE kept.record_hashes @> ARRAY[listed.record_hash] AND kept.sequence NOT IN (SELECT sequence FROM doomed))"
end

fn expired_checkpoints() -> String do
  "SELECT checkpoint.sequence FROM transparency_checkpoints AS checkpoint WHERE checkpoint.created_at <= now() - interval '35 days' AND checkpoint.sequence < (SELECT max(sequence) FROM transparency_checkpoints) AND NOT EXISTS (SELECT 1 FROM transparency_anchors AS anchor WHERE anchor.checkpoint_sequence = checkpoint.sequence) ORDER BY checkpoint.sequence LIMIT $1::integer"
end

fn counted(rows :: List<Map<String, DbValue>>, key :: String) -> Int!String do
  case rows do
    [row] -> integer(Map.get(row, key))
    _ -> Err("pruning count failed")
  end
end

fn prune_entries(conn :: borrow PgConn, cap :: DbValue) -> (Int, Int)!String do
  let rows = Pg.query_values(conn,
    "WITH doomed AS ("
      <> superseded()
      <> " FOR UPDATE OF entry), orphans AS ("
      <> orphaned()
      <> "), pruned AS (UPDATE transparency_entries AS entry SET entry_header = NULL, record_hashes = NULL, entry_trailer = NULL, entry_bytes = NULL, pruned_at = now() FROM doomed WHERE entry.sequence = doomed.sequence RETURNING entry.sequence), removed AS (DELETE FROM transparency_device_records AS record USING orphans WHERE record.record_hash = orphans.record_hash RETURNING record.record_hash) SELECT (SELECT count(*) FROM pruned)::text AS entries, (SELECT count(*) FROM removed)::text AS records",
    [cap])?
  Ok((counted(rows, "entries")?, counted(rows, "records")?))
end

fn count_entries(conn :: borrow PgConn, cap :: DbValue) -> (Int, Int)!String do
  let rows = Pg.query_values(conn,
    "WITH doomed AS ("
      <> superseded()
      <> "), orphans AS ("
      <> orphaned()
      <> ") SELECT (SELECT count(*) FROM doomed)::text AS entries, (SELECT count(*) FROM orphans)::text AS records",
    [cap])?
  Ok((counted(rows, "entries")?, counted(rows, "records")?))
end

fn prune_checkpoints(conn :: borrow PgConn, cap :: DbValue, dry_run :: Bool) -> Int!String do
  if dry_run do
    counted(Pg.query_values(conn,
        "SELECT count(*)::text AS checkpoints FROM (" <> expired_checkpoints() <> ") AS doomed",
        [cap])?,
      "checkpoints")
  else
    Pg.execute_values(conn,
      "DELETE FROM transparency_checkpoints AS checkpoint USING ("
        <> expired_checkpoints()
        <> ") AS doomed WHERE checkpoint.sequence = doomed.sequence",
      [cap])
  end
end

fn prune_on_connection(conn :: borrow PgConn, mode :: String, cap :: Int) -> PruningRun!String do
  Pg.query_values(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let claimed = Pg.query_values(conn,
    "INSERT INTO transparency_pruning_runs (run_day, mode) VALUES ((now() AT TIME ZONE 'UTC')::date, $1) ON CONFLICT DO NOTHING RETURNING run_day::text AS run_day",
    [Text(mode)])?
  if List.length(claimed) == 0 do
    return Ok(PruningRun { ran: false, mode: mode, entries: 0, records: 0, checkpoints: 0 })
  end
  let limit = Text(Int.to_string(cap))
  let dry_run = mode != "on"
  let (entries, records) = if dry_run do
    count_entries(conn, limit)?
  else
    prune_entries(conn, limit)?
  end
  let checkpoints = prune_checkpoints(conn, limit, dry_run)?
  Pg.execute_values(conn,
    "UPDATE transparency_pruning_runs SET entries = $1::integer, records = $2::integer, checkpoints = $3::integer WHERE run_day = (now() AT TIME ZONE 'UTC')::date",
    [Text(Int.to_string(entries)), Text(Int.to_string(records)), Text(Int.to_string(checkpoints))])?
  Ok(PruningRun {
    ran: true,
    mode: mode,
    entries: entries,
    records: records,
    checkpoints: checkpoints
  })
end

## Runs today's pruning, unless it already ran today or mode is off.

pub fn transparency_prune(pool :: PoolHandle, mode :: String, cap :: Int) -> PruningRun!String do
  if mode == "off" do
    Ok(PruningRun { ran: false, mode: mode, entries: 0, records: 0, checkpoints: 0 })
  else if mode != "dry-run" && mode != "on" || cap < 1 do
    Err("invalid pruning configuration")
  else
    Repo.transaction(pool, fn(conn :: borrow PgConn) -> prune_on_connection(conn, mode, cap) end)
  end
end

## The scheduled job's entry point, configured from the environment.

pub fn transparency_prune_scheduled(pool :: PoolHandle) -> PruningRun!String do
  transparency_prune(pool, transparency_pruning_mode()?, transparency_pruning_cap()?)
end

## When pruning is next due, in Unix milliseconds: now if today's run has not
## happened, else the next UTC midnight; 0 (never) when pruning is off.

pub fn transparency_pruning_due(pool :: PoolHandle) -> Int!String do
  if transparency_pruning_mode()? == "off" do
    Ok(0)
  else
    counted(Pool.query_values(pool,
        "SELECT (CASE WHEN EXISTS (SELECT 1 FROM transparency_pruning_runs WHERE run_day = (now() AT TIME ZONE 'UTC')::date) THEN floor(extract(epoch FROM (date_trunc('day', now() AT TIME ZONE 'UTC') + interval '1 day') AT TIME ZONE 'UTC') * 1000) ELSE floor(extract(epoch FROM now()) * 1000) END)::bigint::text AS due",
        [])?,
      "due")
  end
end

## The UTC day of the last pruning run, or "" before the first.

pub fn transparency_last_pruning(pool :: PoolHandle) -> String!String do
  let rows = Pool.query_values(pool,
    "SELECT COALESCE(max(run_day)::text, '') AS run_day FROM transparency_pruning_runs",
    [])?
  case rows do
    [row] -> text(Map.get(row, "run_day"))
    _ -> Err("pruning run lookup failed")
  end
end

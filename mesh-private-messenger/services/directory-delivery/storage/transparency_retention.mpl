##! Bounded daily retention. Hashes and tree nodes are never candidates.
from Storage.TransparencyRecords import backfill_records_on_connection, delete_orphan_records
from Storage.TransparencyLog import checkpoint_table, anchor_table

pub struct TransparencyPruneResult do
  entries :: Int
  checkpoints :: Int
end

fn integer(value :: String) -> Int!String do
  case String.to_int(value) do
    None -> Err("invalid transparency maintenance row")
    Some(value) -> Ok(value)
  end
end

fn minimum(left :: Int, right :: Int) -> Int do
  if left < right do
    left
  else
    right
  end
end

fn remaining(used :: Int, limit :: Int, daily_cap :: Int) -> Int do
  if used >= daily_cap do
    0
  else
    minimum(limit, daily_cap - used)
  end
end

fn allowance(conn :: borrow PgConn,
  limit :: Int,
  daily_cap :: Int) -> TransparencyPruneResult!String do
  let rows = Pg.query(conn,
    "SELECT entries_pruned::text, checkpoints_pruned::text FROM transparency_maintenance WHERE day = (now() AT TIME ZONE 'UTC')::date",
    [])?
  if List.length(rows) == 0 do
    Ok(TransparencyPruneResult {
      entries: minimum(limit, daily_cap),
      checkpoints: minimum(limit, daily_cap)
    })
  else
    let row = List.head(rows)
    Ok(TransparencyPruneResult {
      entries: remaining(integer(Map.get(row, "entries_pruned"))?, limit, daily_cap),
      checkpoints: remaining(integer(Map.get(row, "checkpoints_pruned"))?, limit, daily_cap)
    })
  end
end

fn prune_entries(conn :: borrow PgConn, dry_run :: Bool, limit :: Int) -> Int!String do
  let rows = Pg.query(conn,
    "SELECT e.sequence::text FROM transparency_entries e WHERE e.pruned_at IS NULL AND (e.entry_bytes IS NOT NULL OR e.entry_header IS NOT NULL) AND e.created_at < now() - interval '90 days' AND EXISTS (SELECT 1 FROM transparency_entries newer WHERE newer.account_commitment = e.account_commitment AND newer.sequence > e.sequence) ORDER BY e.created_at, e.sequence LIMIT $1::integer FOR UPDATE OF e",
    [Int.to_string(limit)])?
  if !dry_run do
    for row in rows do
      let sequence = Map.get(row, "sequence")
      Pg.execute(conn,
        "DELETE FROM transparency_entry_devices WHERE entry_sequence = $1::bigint",
        [sequence])?
      Pg.execute(conn,
        "UPDATE transparency_entries SET entry_bytes = NULL, entry_header = NULL, entry_suffix = NULL, pruned_at = now() WHERE sequence = $1::bigint",
        [sequence])?
    end
    delete_orphan_records(conn, limit * 8)?
    nil
  else
    nil
  end
  Ok(List.length(rows))
end

fn prune_checkpoint_version(conn :: borrow PgConn,
  version :: Int,
  dry_run :: Bool,
  limit :: Int) -> Int!String do
  let checkpoints = checkpoint_table(version)?
  let anchors = anchor_table(version)?
  let rows = Pg.query(conn,
    "SELECT c.sequence::text FROM "
      <> checkpoints
      <> " c WHERE c.created_at < now() - interval '35 days' AND c.sequence < (SELECT max(sequence) FROM "
      <> checkpoints
      <> ") AND NOT EXISTS (SELECT 1 FROM "
      <> anchors
      <> " a WHERE a.checkpoint_sequence = c.sequence) ORDER BY c.sequence LIMIT $1::integer FOR UPDATE OF c",
    [Int.to_string(limit)])?
  if !dry_run do
    for row in rows do
      Pg.execute(conn,
        "DELETE FROM " <> checkpoints <> " WHERE sequence = $1::bigint",
        [Map.get(row, "sequence")])?
    end
    nil
  else
    nil
  end
  Ok(List.length(rows))
end

fn prune_checkpoints(conn :: borrow PgConn, dry_run :: Bool, limit :: Int) -> Int!String do
  let legacy = prune_checkpoint_version(conn, 1, dry_run, limit)?
  let rfc = prune_checkpoint_version(conn, 2, dry_run, limit - legacy)?
  Ok(legacy + rfc)
end

pub fn prune_on_connection(conn :: borrow PgConn,
  dry_run :: Bool,
  limit :: Int,
  daily_cap :: Int) -> TransparencyPruneResult!String do
  if limit < 1 || limit > 1000 || daily_cap < 1 || daily_cap > 100000 do
    return Err("invalid transparency retention limits")
  end
  Pg.query(conn, "SELECT pg_advisory_xact_lock(1835365485)", [])?
  let quota = allowance(conn, limit, daily_cap)?
  let result = TransparencyPruneResult {
    entries: prune_entries(conn, dry_run, quota.entries)?,
    checkpoints: prune_checkpoints(conn, dry_run, quota.checkpoints)?
  }
  if !dry_run do
    Pg.execute(conn,
      "INSERT INTO transparency_maintenance (day, entries_pruned, checkpoints_pruned) VALUES ((now() AT TIME ZONE 'UTC')::date, $1::integer, $2::integer) ON CONFLICT (day) DO UPDATE SET entries_pruned = transparency_maintenance.entries_pruned + EXCLUDED.entries_pruned, checkpoints_pruned = transparency_maintenance.checkpoints_pruned + EXCLUDED.checkpoints_pruned",
      [Int.to_string(result.entries), Int.to_string(result.checkpoints)])?
    Pg.execute(conn,
      "DELETE FROM transparency_maintenance WHERE day < (now() AT TIME ZONE 'UTC')::date - 35",
      [])?
    nil
  else
    nil
  end
  Ok(result)
end

pub fn transparency_maintenance_enabled() -> Bool do
  Env.get("MORSE_TRANSPARENCY_RETENTION", "off") != "off"
end

pub fn validate_retention_config() -> Result<(), String> do
  let mode = Env.get("MORSE_TRANSPARENCY_RETENTION", "off")
  let cap = Env.get_int("MORSE_TRANSPARENCY_PRUNE_DAILY_CAP", 1000)
  if (mode != "off" && mode != "dry-run" && mode != "on") || cap < 1 || cap > 100000 do
    Err("invalid transparency retention configuration")
  else
    Ok(nil)
  end
end

pub fn run_transparency_maintenance(pool :: PoolHandle) -> Result<(), String> do
  let mode = Env.get("MORSE_TRANSPARENCY_RETENTION", "off")
  if mode == "off" do
    return Ok(nil)
  end
  if mode != "on" && mode != "dry-run" do
    return Err("invalid transparency retention mode")
  end
  let cap = Env.get_int("MORSE_TRANSPARENCY_PRUNE_DAILY_CAP", 1000)
  let result = Repo.transaction(pool,
    fn(conn :: borrow PgConn) do prune_on_connection(conn, mode == "dry-run", 100, cap) end)?
  if result.entries > 0 || result.checkpoints > 0 do
    println("transparency retention #{mode}: #{result.entries} entries, #{result.checkpoints} checkpoints")
  else
    nil
  end
  # Backfill is separately committed: a damaged legacy record must not undo
  # retention work. Dry runs never replace any bytes.
  if mode == "on" do
    Repo.transaction(pool,
      fn(conn :: borrow PgConn) -> backfill_records_on_connection(conn, 100) end)?
    nil
  else
    nil
  end
  Ok(nil)
end

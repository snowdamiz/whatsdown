##! One monitoring cycle, as main runs it every --interval seconds. Each step
##! commits its own progress; a step that cannot finish (a provider or the
##! directory not answering) leaves a note on the status page and is retried
##! next cycle. Nothing here files evidence except a verified FRK.

from Monitor.Chain import ChainLog, RingHeader
from Monitor.Flags import MonitorConfig
from Monitor.Report import Context
from Monitor.Ring import (
  ChainView,
  monitor_check_entries,
  monitor_follow_copy,
  monitor_follow_ring,
  monitor_prev,
  monitor_read_chain
)
from Monitor.Status import monitor_status_json
from Monitor.Store import (
  monitor_entries_prune,
  monitor_findings,
  monitor_kv_put,
  monitor_observed_prune,
  monitor_store_open
)
from Monitor.Watch import (
  monitor_check_cosigns,
  monitor_check_registry,
  monitor_check_sets,
  monitor_check_view,
  monitor_file_proofs
)

fn note(result :: String!String, label :: String) -> List<String> do
  case result do
    Err(reason) -> ["#{label}: #{reason}"]
    Ok("") -> List.new()
    Ok(text) -> [text]
  end
end

fn done(result :: Result<(), String>, label :: String) -> List<String> do
  case result do
    Err(reason) -> ["#{label}: #{reason}"]
    Ok(_) -> List.new()
  end
end

fn follow_copy(ctx :: Context) -> Result<(), String> do
  case monitor_prev(ctx)? do
    None -> Ok(nil)
    Some(tip) -> monitor_follow_copy(ctx, tip)
  end
end

fn ring_notes(ctx :: Context, header :: RingHeader) -> List<String> do
  let read = case monitor_follow_ring(ctx, header) do
    Err(reason) -> ["ring: #{reason}"]
    Ok(_) -> List.new()
  end
  read
    ++ note(monitor_check_entries(ctx), "anchor pairs")
    ++ done(follow_copy(ctx), "leaf copy")
    ++ note(monitor_check_view(ctx), "directory view")
    ++ done(monitor_check_cosigns(ctx), "cosignatures")
    ++ done(monitor_check_sets(ctx), "witness sets")
end

fn housekeeping(ctx :: Context) -> Result<(), String> do
  monitor_entries_prune(ctx.db, ctx.now_ms / 1000 / 604800)?
  monitor_observed_prune(ctx.db, ctx.now_ms)
end

fn unread_log() -> ChainLog do
  ChainLog {
    log_id: Bytes.empty(),
    service_key: Bytes.empty(),
    ring: "",
    service_slashed: false,
    witnesses: List.new()
  }
end

fn run(config :: MonitorConfig, db :: SqliteConn, now_ms :: Int) -> Result<(), String> do
  let chain = monitor_read_chain(config)
  let ctx = Context {
    config: config,
    db: db,
    log: case chain do
      Ok(view) -> view.log
      Err(_) -> unread_log()
    end,
    now_ms: now_ms,
    slot: case chain do
      Ok(view) -> view.slot
      Err(_) -> 0
    end
  }
  let chain_notes = case chain do
    Err(reason) -> ["chain (no verdicts this cycle): #{reason}"]
    Ok(view) -> ring_notes(ctx, view.header)
  end
  let notes = chain_notes
    ++ note(monitor_check_registry(ctx), "registry")
    ++ done(monitor_file_proofs(ctx), "relays")
    ++ done(housekeeping(ctx), "housekeeping")
  let header = case chain do
    Ok(view) -> Some(view.header)
    Err(_) -> None
  end
  monitor_kv_put(db, "status", monitor_status_json(ctx, header, notes)?)
end

pub fn monitor_cycle(config :: MonitorConfig, now_ms :: Int) -> Result<(), String> do
  let db = monitor_store_open(config.state_path)?
  let result = run(config, db, now_ms)
  Sqlite.close(db)
  result
end

# The number of unresolved P0 findings in the state (exit status of --once).

pub fn monitor_p0_count(config :: MonitorConfig) -> Int!String do
  let db = monitor_store_open(config.state_path)?
  let findings = monitor_findings(db)
  Sqlite.close(db)
  Ok(List.length(List.filter(findings?, fn value -> value.severity == "P0" end)))
end

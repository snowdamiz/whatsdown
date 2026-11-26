##! What one cycle works with, and how findings are recorded: once per key in
##! the state, a log line (P0 lines are what operators alert on), and for a
##! fork proof the FRK itself beside the state file, ready for
##! `morse-relay submit`.

from Monitor.Chain import ChainLog, RingEntry
from Monitor.Flags import MonitorConfig
from Monitor.Evidence import Side
from Monitor.Store import Finding, monitor_finding_add

pub struct Context do
  config :: MonitorConfig
  db :: SqliteConn
  log :: ChainLog
  now_ms :: Int
  slot :: Int
end

pub fn monitor_frk_path(config :: MonitorConfig, proof_hash :: String) -> String do
  "#{config.state_path}.#{proof_hash}.frk"
end

pub fn monitor_report(ctx :: Context, value :: Finding) -> Result<(), String> do
  let fresh = monitor_finding_add(ctx.db, value)?
  if fresh do
    let proof = if value.proof_hash == "" do
      ""
    else
      File.write_bytes(monitor_frk_path(ctx.config, value.proof_hash), 0, value.frk, true)?
      " proof_hash=#{value.proof_hash} frk=#{monitor_frk_path(ctx.config, value.proof_hash)}"
    end
    println("#{value.severity} morse-monitor #{ctx.config.log_name} #{value.kind}: #{value.detail}#{proof}")
  end
  Ok(nil)
end

pub fn monitor_finding(ctx :: Context,
  key :: String,
  severity :: String,
  kind :: String,
  detail :: String,
  evidence :: String) -> Finding do
  Finding {
    key: key,
    found_at: ctx.now_ms,
    severity: severity,
    kind: kind,
    detail: detail,
    evidence: evidence,
    frk: Bytes.empty(),
    proof_hash: ""
  }
end

fn hex_or_null(value :: Option<Bytes>) -> String do
  case value do
    None -> "null"
    Some(bytes) -> Json.encode_string(Bytes.to_hex(bytes))
  end
end

pub fn monitor_side_json(side :: Side, checkpoint :: Option<Bytes>) -> String do
  let ring = case side.entry do
    None -> "null"
    Some(entry) -> Int.to_string(entry.index)
  end
  "{\"sequence\":#{side.sequence},\"tree_size\":#{side.tree_size},\"root\":#{Json.encode_string(Bytes.to_hex(side.root))},\"checkpoint_hash\":#{Json.encode_string(Bytes.to_hex(side.hash))},\"ring_index\":#{ring},\"checkpoint\":#{hex_or_null(checkpoint)}}"
end

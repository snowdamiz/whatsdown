from Monitor.Config import MonitorConfig
from Monitor.Status import monitor_status, monitor_evidence
from Monitor.State import MonitorState, load_monitor_state, save_monitor_state
from Transparency.Config import decode_security_config
from Transparency.AnchorChain import AnchorPins, anchor_addresses
from Transparency.RpcTransport import webpki_rpc_transport
from Solana.Read import pubkey

fn proof() -> Result<(), String> do
  let program = pubkey("11111111111111111111111111111111")?
  let addresses = anchor_addresses(program, "morse-main")?
  let primary = decode_security_config(Bytes.from_utf8(String.join([
      "1",
      String.repeat("11", 32),
      String.repeat("01", 32),
      String.repeat("02", 32),
      String.repeat("22", 32),
      "8"
    ],
    "\n")))?
  let path = Env.get("TMPDIR", "/tmp") <> "/morse-monitor-status-" <> Crypto.uuid4() <> ".sqlite"
  let config = MonitorConfig {
    primary: primary,
    log_version: 1,
    policies: [],
    path: path,
    origin: "not-a-network-address",
    identity: Crypto.sha256(Bytes.from_utf8("status")),
    pins: AnchorPins {
      program: program,
      ring: addresses.ring,
      log_name: "morse-main",
      log_id: addresses.log_id,
      rpc: webpki_rpc_transport([])?
    }
  }
  let (missing, _) = monitor_status(config, 1000)
  assert(missing == 503 && !File.exists(path))
  let state = load_monitor_state(path, config.identity)?
  let (starting, _) = monitor_status(config, 1000)
  assert(starting == 503)
  save_monitor_state(path,
    config.identity,
    state.revision,
    %{state | report: "{\"checked_at_ms\":1000,\"healthy\":true,\"issues\":[]}"})?
  let (live, report) = monitor_status(config, 121000)
  assert(live == 200 && String.contains(report, "\"healthy\":true"))
  let (stale, report) = monitor_status(config, 121001)
  assert(stale == 503 && String.contains(report, "\"stale\":true"))
  let (backward, _) = monitor_status(config, 999)
  assert(backward == 503)
  let (absent, bytes) = monitor_evidence(config, false)
  assert(absent == 404 && Bytes.length(bytes) == 0)
  File.delete(path)?
  Ok(nil)
end

test("status only reads the durable cache and never reports an expired or future result as healthy") do
  case proof() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(_) -> nil
  end
end

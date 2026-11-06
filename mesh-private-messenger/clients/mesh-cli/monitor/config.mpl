from Monitor.Policy import MonitorPolicy
from Transparency.Config import SecurityConfig, decode_security_config
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.AnchorHttp import anchor_proof_origin
from Solana.Read import Pubkey

pub struct MonitorConfig do
  primary :: SecurityConfig
  log_version :: Int
  pins :: AnchorPins
  policies :: List<MonitorPolicy>
  origin :: String
  path :: String
  identity :: Bytes
end

pub fn monitor_configuration(log_name :: String,
  origin :: String,
  path :: String,
  frames :: List<Bytes>) -> MonitorConfig!String do
  monitor_configuration_for(log_name, origin, path, frames, 2)
end

# A v4 release frame carries both current and legacy witness policies. A
# separate legacy-log monitor uses the latter without rewriting that frame.
pub fn monitor_configuration_for(log_name :: String,
  origin :: String,
  path :: String,
  frames :: List<Bytes>,
  log_version :: Int) -> MonitorConfig!String do
  if log_version != 1 && log_version != 2 do
    return Err("invalid_monitor_log_version")
  end
  if List.length(frames) < 1
    || List.length(frames) > 16
    || String.length(path) < 1
    || String.length(path) > 4096 do
    return Err("invalid_monitor_configuration")
  end
  let primary = decode_security_config(List.head(frames))?
  let pins = case configured_anchor_pins(primary, webpki_rpc_transport(primary.rpc_urls)?)? do
    None -> return Err("monitor_requires_anchor_pins")
    Some(value) -> value
  end
  if pins.log_name != log_name do
    return Err("monitor_log_mismatch")
  end
  let origin = anchor_proof_origin(origin)?
  let policies = for frame in frames do
    let config = decode_security_config(frame)?
    if config.version != 4 && config.version != 5
      || config.anchor_program != primary.anchor_program
      || config.anchor_address != primary.anchor_address
      || config.anchor_log_name != primary.anchor_log_name
      || config.log_version != primary.log_version
      || !Bytes.secure_equals(config.service_public_key, primary.service_public_key) do
      return Err("monitor_policy_identity_mismatch")
    end
    if log_version == 1 do
      MonitorPolicy { witnesses: config.legacy_witnesses, threshold: config.legacy_threshold }
    else
      MonitorPolicy { witnesses: config.witnesses, threshold: config.threshold }
    end
  end
  # Policy and RPC rotation can preserve history. Changing the public log,
  # service identity or directory origin cannot silently reuse another cursor.
  let identity = Crypto.sha256(Bytes.from_utf8(String.join([
      "morse-monitor-v1",
      Bytes.to_hex(pins.program.bytes),
      Bytes.to_hex(pins.ring.bytes),
      Bytes.to_hex(pins.log_id),
      Bytes.to_hex(primary.service_public_key),
      Int.to_string(log_version),
      origin
    ],
    "\n")))
  Ok(MonitorConfig {
    primary: primary,
    log_version: log_version,
    pins: pins,
    policies: policies,
    origin: origin,
    path: path,
    identity: identity
  })
end

pub fn configured_monitor(log_name :: String) -> MonitorConfig!String do
  let frame = Env.get("MESSENGER_SECURITY_CONFIG", "")
  if frame == "" do
    return Err("MESSENGER_SECURITY_CONFIG is required for monitor")
  end
  let files = Env.get("MORSE_MONITOR_POLICY_FILES", "")
  let paths = if files == "" do
    []
  else
    String.split(files, "\n")
  end
  if List.length(paths) > 15 do
    return Err("too_many_monitor_policies")
  end
  let extra = for path in paths do
    if path == "" || File.size(path)? > 8192 do
      return Err("invalid_monitor_policy_file")
    end
    Bytes.from_utf8(File.read(path)?)
  end
  let version = case Env.get("MORSE_MONITOR_LOG_VERSION", "2") do
    "1" -> 1
    "2" -> 2
    _ -> return Err("MORSE_MONITOR_LOG_VERSION must be 1 or 2")
  end
  monitor_configuration_for(log_name,
    Env.get("MESSENGER_BASE_URL", ""),
    Env.get("MORSE_MONITOR_STATE_PATH", "morse-monitor-#{log_name}.sqlite"),
    [Bytes.from_utf8(frame)] ++ extra,
    version)
end

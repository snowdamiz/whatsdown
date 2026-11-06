from Transparency.Config import SecurityConfig, decode_security_config
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Transparency.RpcTransport import webpki_rpc_transport
from Transparency.RewardsOperator import (
  RewardOperatorIntent,
  decode_reward_intent,
  plan_reward_operation,
  read_reward_effect
)

fn run() -> Result<(), String> do
  let args = Env.args()
  if (List.length(args) != 3 && List.length(args) != 5)
    || List.get(args, 1) != "--input"
    || (List.length(args) == 5 && List.get(args, 3) != "--effect") do
    return Err("usage: morse-rewards-operator --input request.json [--effect previous-plan.json]")
  end
  let path = List.get(args, 2)
  let size = File.size(path)?
  if size > 4096 do
    return Err("rewards_intent_too_large")
  end
  let intent = decode_reward_intent(Bytes.to_utf8(File.read_bytes(path, 0, size)?)?)?
  let config = decode_security_config(Bytes.from_utf8(Env.get("MESSENGER_SECURITY_CONFIG", "")))?
  let pins = case configured_anchor_pins(config, webpki_rpc_transport(config.rpc_urls)?)? do
    None -> return Err("rewards_requires_anchor_pins")
    Some(value) -> value
  end
  let version = case Env.get("MORSE_REWARDS_LOG_VERSION", "2") do
    "1" -> 1
    "2" -> 2
    _ -> return Err("invalid_rewards_log_version")
  end
  let floor = Env.get("MORSE_REWARDS_MIN_CONTEXT_SLOT", "0")
  let minimum = U64.parse(floor)?
  if U64.to_string(minimum) != floor do
    return Err("invalid_rewards_context")
  end
  if List.length(args) == 5 do
    let previous_path = List.get(args, 4)
    let previous_size = File.size(previous_path)?
    if previous_size > 16384 do
      return Err("rewards_effect_too_large")
    end
    let previous = Bytes.to_utf8(File.read_bytes(previous_path, 0, previous_size)?)?
    println(read_reward_effect(pins,
      config.service_public_key,
      version,
      intent,
      previous,
      minimum)?)
  else
    println(plan_reward_operation(pins, config.service_public_key, version, intent, minimum)?)
  end
  Ok(nil)
end

fn main() do
  case run() do
    Err(error) -> do
      io_eprintln(error)
      Process.exit(1)
    end
    Ok(_) -> nil
  end
end

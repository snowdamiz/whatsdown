from RewardOperator import (
  decode_reward_v2_config,
  decode_reward_v2_intent,
  plan_reward_v2,
  read_reward_v2_effect
)

fn bounded_file(path :: String, limit :: Int) -> String!String do
  let size = File.size(path)?
  if size < 0 || size > limit do
    return Err("rewards_v2_input_bound")
  end
  Bytes.to_utf8(File.read_bytes(path, 0, size)?)
end

fn run() -> String!String do
  let args = Env.args()
  if (List.length(args) != 3 && List.length(args) != 5)
    || List.get(args, 1) != "--input"
    || (List.length(args) == 5 && List.get(args, 3) != "--effect") do
    return Err("usage: rewards-v2-operator --input request.json [--effect previous-plan.json]")
  end
  let config = decode_reward_v2_config(Env.get("MORSE_REWARDS_V2_CONFIG", ""))?
  let intent = decode_reward_v2_intent(config, bounded_file(List.get(args, 2), 4096)?)?
  let floor = Env.get("MORSE_REWARDS_MIN_CONTEXT_SLOT", "0")
  let minimum = U64.parse(floor)?
  if U64.to_string(minimum) != floor do
    return Err("rewards_v2_context")
  end
  let previous = if List.length(args) == 5 do
    Some(bounded_file(List.get(args, 4), 16384)?)
  else
    None
  end
  let client = Http.client()
  let result = case previous do
    None -> plan_reward_v2(client, config, intent, minimum)
    Some(value) -> read_reward_v2_effect(client, config, intent, value, minimum)
  end
  Http.client_close(client)
  result
end

fn main() do
  case run() do
    Ok(value) -> println(value)
    Err(error) -> do
      io_eprintln(error)
      Process.exit(1)
    end
  end
end

# Test-only adapter. Caller-owned local SBF banks replace public providers.
# Production tools/rewards-operator accepts only native SecurityConfig pins.
# All parsing, authenticated reads, policy and plans remain the public operator.
from Solana.Read import pubkey
from Transparency.AnchorChain import AnchorPins, AnchorAddresses, anchor_addresses
from Transparency.RewardsOperator import (
  RewardOperatorIntent,
  decode_reward_intent,
  plan_reward_operation,
  read_reward_effect
)

fn text(value :: Json, key :: String) -> String!String do
  Json.as_string(Json.object_get(value, key)?)
end

fn run() -> String!String do
  let args = Env.args()
  if (List.length(args) != 3 && List.length(args) != 5)
    || List.get(args, 1) != "--input"
    || (List.length(args) == 5 && List.get(args, 3) != "--effect") do
    return Err("expected --input disposable reward request")
  end
  let input = File.read(List.get(args, 2))?
  let request = Json.parse(input)?
  let fixture = Json.object_get(request, "configuration")?
  let program = pubkey(text(fixture, "judge")?)?
  let name = text(fixture, "log_name")?
  let derived = anchor_addresses(program, name)?
  let sources = Json.object_get(fixture, "endpoints")?
  let pins = AnchorPins {
    program: program,
    log_name: name,
    log_id: derived.log_id,
    ring: derived.ring,
    endpoints: for index in 0..Json.array_length(sources)? do
      Json.as_string(Json.array_get(sources, index)?)?
    end
  }
  let intent = decode_reward_intent(input)?
  let floor = Env.get("MORSE_REWARDS_MIN_CONTEXT_SLOT", "0")
  let minimum = U64.parse(floor)?
  if U64.to_string(minimum) != floor do
    return Err("invalid_reward_fixture_context")
  end
  let service_key = Bytes.from_hex(text(fixture, "service_key")?)?
  let version = Json.as_int(Json.object_get(fixture, "version")?)?
  if List.length(args) == 5 do
    read_reward_effect(pins, service_key, version, intent, File.read(List.get(args, 4))?, minimum)
  else
    plan_reward_operation(pins, service_key, version, intent, minimum)
  end
end

fn main() do
  case run() do
    Err(error) -> do
      io_eprintln(error)
      Process.exit(1)
    end
    Ok(value) -> println(value)
  end
end

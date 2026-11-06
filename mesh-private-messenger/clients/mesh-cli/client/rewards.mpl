from Solana.Read import Pubkey, pubkey, pubkey_string
from Transparency.Config import SecurityConfig, decode_security_config, valid_witness_id
from Transparency.AnchorChain import AnchorPins, configured_anchor_pins
from Transparency.RewardsRead import RewardsState, read_rewards, rewards_report

pub struct RewardsQuery do
  program :: Pubkey
  mint :: Pubkey
  log_name :: String
  epoch :: U64
end

fn selected_key(value :: String) -> Pubkey!String do
  let key = pubkey(value)?
  if Bytes.to_hex(key.bytes) == String.repeat("00", 32) || pubkey_string(key) != value do
    return Err("invalid_rewards_key")
  end
  Ok(key)
end

pub fn parse_rewards_command(args :: List<String>) -> RewardsQuery!String do
  let usage = "usage: morse rewards --program PROGRAM --mint MINT --log LOG_NAME --epoch EPOCH"
  if List.length(args) != 10
    || List.get(args, 1) != "rewards"
    || List.get(args, 2) != "--program"
    || List.get(args, 4) != "--mint"
    || List.get(args, 6) != "--log"
    || List.get(args, 8) != "--epoch"
    || !valid_witness_id(List.get(args, 7))
    || String.length(List.get(args, 7)) > 32 do
    return Err(usage)
  end
  let program = case selected_key(List.get(args, 3)) do
    Err(_) -> return Err(usage)
    Ok(value) -> value
  end
  let mint = case selected_key(List.get(args, 5)) do
    Err(_) -> return Err(usage)
    Ok(value) -> value
  end
  let epoch = case U64.parse(List.get(args, 9)) do
    Err(_) -> return Err(usage)
    Ok(value) -> value
  end
  if U64.to_string(epoch) != List.get(args, 9) do
    return Err(usage)
  end
  Ok(RewardsQuery { program: program, mint: mint, log_name: List.get(args, 7), epoch: epoch })
end

pub fn run_rewards_command(args :: List<String>) -> Int!String do
  let query = parse_rewards_command(args)?
  let frame = Env.get("MESSENGER_SECURITY_CONFIG", "")
  if frame == "" do
    return Err("MESSENGER_SECURITY_CONFIG is required for rewards")
  end
  let config = decode_security_config(Bytes.from_utf8(frame))?
  let pins = case configured_anchor_pins(config)? do
    None -> return Err("rewards_requires_anchor_pins")
    Some(value) -> value
  end
  if pins.log_name != query.log_name do
    return Err("rewards_log_mismatch")
  end
  let minimum = Env.get("MORSE_REWARDS_MIN_CONTEXT_SLOT", "0")
  let slot = U64.parse(minimum)?
  if U64.to_string(slot) != minimum do
    return Err("invalid_rewards_minimum_slot")
  end
  println(rewards_report(read_rewards(pins,
    config.service_public_key,
    config.log_version,
    query.program,
    query.mint,
    query.epoch,
    slot)?))
  Ok(0)
end

from RewardRead import (
  TokenRewardReadPins,
  TokenRewardReadState,
  read_token_reward_quorum,
  token_reward_rpc_sources,
  token_reward_read_keys
)
from RewardIdentities import read_token_reward_append_quorum
from RewardKeeper import TokenRewardKeeperStep, plan_token_reward_step, plan_token_reward_claim
from Transparency.TokenWrite import TokenRewardWriteContext, token_reward_write_addresses
from Transparency.TokenRewards import TokenRewardEpochAccount
from Transparency.AnchorRpc import validate_anchor_sources
from Solana.Read import Pubkey, pubkey, pubkey_string
from Solana.Tx import Instruction, instruction_report_json, compute_unit_limit_instruction

pub type RewardV2Operation do
  SettleRewards
  ClaimRewards(Int, Int)
end

pub struct RewardV2Intent do
  operation :: RewardV2Operation
  payer :: Pubkey
  epoch :: U64
  hash :: Bytes
end

pub struct RewardV2Config do
  pins :: TokenRewardReadPins
  sources :: List<String>
  allow_loopback :: Bool
  hash :: Bytes
end

fn text(value :: Json, field :: String) -> String!String do
  Json.as_string(Json.object_get(value, field)?)
end

fn wide(value :: Json, field :: String) -> U64!String do
  let encoded = text(value, field)?
  let number = U64.parse(encoded)?
  if U64.to_string(number) != encoded do
    return Err("rewards_v2_noncanonical_integer")
  end
  Ok(number)
end

fn bytes(value :: Json, field :: String) -> Bytes!String do
  let encoded = text(value, field)?
  let raw = Bytes.from_hex(encoded)?
  if Bytes.length(raw) != 32 || Bytes.to_hex(raw) != encoded do
    return Err("rewards_v2_invalid_bytes")
  end
  Ok(raw)
end

fn source_host(origin :: String) -> String do
  let authority = List.get(String.split(origin, "://"), 1)
  if String.starts_with(authority, "[") do
    List.head(String.split(authority, "]")) <> "]"
  else
    List.head(String.split(authority, ":"))
  end
end

pub fn decode_reward_v2_config(input :: String) -> RewardV2Config!String do
  if String.length(input) > 65536 do
    return Err("rewards_v2_config_bound")
  end
  let value = Json.parse(input)?
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 2 do
    return Err("rewards_v2_config_version")
  end
  let pins = TokenRewardReadPins {
    context: TokenRewardWriteContext {
      program: pubkey(text(value, "program")?)?,
      judge: pubkey(text(value, "judge")?)?,
      token: pubkey(text(value, "token")?)?,
      log_name: text(value, "log_name")?,
      usdc_mint: pubkey(text(value, "usdc_mint")?)?
    },
    governance: pubkey(text(value, "governance")?)?,
    token_governance: pubkey(text(value, "token_governance")?)?,
    service_key: bytes(value, "service_key")?,
    log_version: Json.as_int(Json.object_get(value, "log_version")?)?,
    network_started: wide(value, "network_started")?,
    token_slot: wide(value, "token_slot")?,
    judge_slot: wide(value, "judge_slot")?,
    rewards_slot: wide(value, "rewards_slot")?,
    source_program: pubkey(text(value, "source_program")?)?,
    source: pubkey(text(value, "source")?)?,
    feed: bytes(value, "feed")?,
    source_revision: wide(value, "source_revision")?
  }
  let raw = Json.object_get(value, "endpoints")?
  if Json.array_length(raw)? != 3 do
    return Err("rewards_v2_sources")
  end
  let sources = for index in 0..3 do
    Json.as_string(Json.array_get(raw, index)?)?
  end
  let allow_loopback = case Json.object_get(value, "allow_loopback") do
    Err(_) -> false
    Ok(flag) -> Json.as_bool(flag)?
  end
  token_reward_rpc_sources(sources, allow_loopback)?
  validate_anchor_sources(sources)?
  for index in 0..3 do
    let origin = Http.url_origin(List.get(sources, index))?
    for other in 0..index do
      let previous = Http.url_origin(List.get(sources, other))?
      let local = allow_loopback
        && String.starts_with(origin, "http://127.0.0.1:")
        && String.starts_with(previous, "http://127.0.0.1:")
      if !local && source_host(origin) == source_host(previous) do
        return Err("rewards_v2_source_hosts")
      end
    end
  end
  token_reward_read_keys(pins, U64.parse("0")?)?
  Ok(RewardV2Config {
    pins: pins,
    sources: sources,
    allow_loopback: allow_loopback,
    hash: Crypto.sha256(Bytes.from_utf8(input))
  })
end

pub fn decode_reward_v2_intent(config :: RewardV2Config,
  input :: String) -> RewardV2Intent!String do
  if String.length(input) > 4096 do
    return Err("rewards_v2_intent_bound")
  end
  let value = Json.parse(input)?
  let c = config.pins.context
  if Json.as_int(Json.object_get(value, "schema_version")?)? != 2
    || pubkey(text(value, "program")?)? != c.program
    || pubkey(text(value, "mint")?)? != c.usdc_mint
    || text(value, "log")? != c.log_name do
    return Err("rewards_v2_intent_pins")
  end
  let payer = pubkey(text(value, "payer")?)?
  if Bytes.to_hex(payer.bytes) == String.repeat("00", 32) do
    return Err("rewards_v2_payer")
  end
  let epoch = wide(value, "epoch")?
  let action = text(value, "action")?
  let operation = if action == "settle" do
    SettleRewards
  else if action == "claim" do
    let row = Json.as_int(Json.object_get(value, "row")?)?
    let asset = Json.as_int(Json.object_get(value, "asset")?)?
    if row < 0 || row > 63 || asset < 0 || asset > 1 do
      return Err("rewards_v2_claim")
    end
    ClaimRewards(row, asset)
  else
    return Err("rewards_v2_action")
  end
  let selection = case operation do
    SettleRewards -> "settle"
    ClaimRewards(row, asset) -> "claim\n" <> Int.to_string(row) <> "\n" <> Int.to_string(asset)
  end
  let canonical = String.join([
      "morse-rewards-intent-v2",
      Bytes.to_hex(config.hash),
      pubkey_string(payer),
      U64.to_string(epoch),
      selection
    ],
    "\n")
  Ok(RewardV2Intent {
    operation: operation,
    payer: payer,
    epoch: epoch,
    hash: Crypto.sha256(Bytes.from_utf8(canonical))
  })
end

fn stage_hash(record :: TokenRewardEpochAccount) -> String do
  Bytes.to_hex(Crypto.sha256(Bytes.from_utf8(String.join([
      U64.to_string(record.snapshot_at),
      U64.to_string(record.eligibility_revision),
      U64.to_string(record.source_revision),
      U64.to_string(record.twap),
      Bytes.to_hex(record.attendance_hash),
      Int.to_string(record.expected)
    ],
    "\n"))))
end

fn address(key :: Pubkey) -> String do
  Json.encode_string(pubkey_string(key))
end

fn allocation(key :: Pubkey, space :: Int) -> String do
  """{"address":#{address(key)},"space":#{space}}"""
end

fn report(config :: RewardV2Config,
  intent :: RewardV2Intent,
  state :: TokenRewardReadState,
  step :: TokenRewardKeeperStep) -> String!String do
  let c = config.pins.context
  let a = token_reward_write_addresses(c, intent.epoch)?
  let status = if step.status == "complete" do
    "complete"
  else if String.starts_with(step.status, "waiting:") do
    "waiting"
  else
    "ready"
  end
  let instructions = if status == "ready" do
    [compute_unit_limit_instruction(1400000)?] ++ step.instructions
  else
    []
  end
  let rent = case step.status do
    "open" -> [allocation(a.base.epoch, 8416), allocation(a.token_epoch, 1280)]
    "attendance-open" -> [allocation(a.base.attendance_epoch, 2640)]
    "finalize" -> [allocation(a.reserve_receipt, 256)]
    "claim-usdc" -> [allocation(List.get(List.get(step.instructions, 1).accounts, 3).pubkey, 165)]
    "claim-morse" -> [allocation(List.get(List.get(step.instructions, 1).accounts, 5).pubkey, 165)]
    _ -> []
  end
  let count = case state.record do
    None -> 0
    Some(record) -> List.length(record.rows)
  end
  let stage = case state.record do
    None -> ""
    Some(record) -> stage_hash(record)
  end
  let reports = String.join(for instruction in instructions do
      instruction_report_json(instruction)
    end,
    ",")
  Ok("""{"schema_version":2,"status":#{Json.encode_string(status)},"action":#{Json.encode_string(step.status)},"program":#{address(c.program)},"judge":#{address(c.judge)},"token":#{address(c.token)},"log":#{address(a.base.log)},"mint":#{address(c.usdc_mint)},"morse":#{address(a.morse)},"payer":#{address(intent.payer)},"epoch":"#{U64.to_string(intent.epoch)}","context_slot":"#{U64.to_string(state.context_slot)}","configuration_hash":"#{Bytes.to_hex(config.hash)}","intent_hash":"#{Bytes.to_hex(intent.hash)}","stage_hash":"#{stage}","staged_count":#{count},"signer_keys":[#{address(intent.payer)}],"instructions":[#{reports}],"rent_allocations":[#{String.join(rent,
    ",")}]}""")
end

pub fn plan_reward_v2(client :: Int,
  config :: RewardV2Config,
  intent :: RewardV2Intent,
  minimum :: U64) -> String!String do
  let state = read_token_reward_quorum(client,
    config.sources,
    config.allow_loopback,
    config.pins,
    intent.epoch,
    minimum)?
  let c = config.pins.context
  let step = case intent.operation do
    SettleRewards -> case plan_token_reward_step(c, intent.payer, intent.epoch, state, []) do
      Ok(step) -> step
      Err(error) -> if error == "token_rewards_next_rows_missing" do
        let identities = read_token_reward_append_quorum(client,
          config.sources,
          config.allow_loopback,
          c,
          state)?
        plan_token_reward_step(c, intent.payer, intent.epoch, state, identities)?
      else
        return Err(error)
      end
    end
    ClaimRewards(row, asset) -> do
      let record = case state.record do
        None -> return Err("rewards_v2_claim_epoch_missing")
        Some(value) -> value
      end
      if record.status != 2 || row >= List.length(record.rows) do
        return Err("rewards_v2_claim_not_finalized")
      end
      let selected = List.get(record.rows, row)
      let complete = if asset == 0 do
        selected.claimed_usd || selected.amount_usd == U64.parse("0")?
      else
        selected.claimed_morse || selected.amount_morse == U64.parse("0")?
      end
      if complete do
        TokenRewardKeeperStep { status: "complete", instructions: [] }
      else
        plan_token_reward_claim(c, intent.payer, intent.epoch, state, row, asset)?
      end
    end
  end
  report(config, intent, state, step)
end

fn effect_report(present :: Bool, slot :: U64) -> String do
  let state = if present do
    "present"
  else
    "absent"
  end
  """{"schema_version":2,"state":"#{state}","slot":"#{U64.to_string(slot)}"}"""
end

# A stage can be cancelled and replaced while a packet is unresolved. Mutable
# stage evidence must refer to its snapshot/revisions, not just its row count.
# The writer only uses this effect after its finalized expiry barrier; missing
# history plus absent evidence keeps the existing packet and budget reserved.
pub fn read_reward_v2_effect(client :: Int,
  config :: RewardV2Config,
  intent :: RewardV2Intent,
  input :: String,
  minimum :: U64) -> String!String do
  if String.length(input) > 16384 do
    return Err("rewards_v2_effect_bound")
  end
  let previous = Json.parse(input)?
  let c = config.pins.context
  if Json.as_int(Json.object_get(previous, "schema_version")?)? != 2
    || text(previous, "status")? != "ready"
    || text(previous, "intent_hash")? != Bytes.to_hex(intent.hash)
    || text(previous, "configuration_hash")? != Bytes.to_hex(config.hash)
    || text(previous, "program")? != pubkey_string(c.program)
    || text(previous, "payer")? != pubkey_string(intent.payer)
    || wide(previous, "epoch")? != intent.epoch
    || U64.compare(minimum, wide(previous, "context_slot")?) < 0 do
    return Err("rewards_v2_effect_intent")
  end
  let action = text(previous, "action")?
  case intent.operation do
    SettleRewards -> if action == "claim-usdc" || action == "claim-morse" do
      return Err("rewards_v2_effect_action")
    end
    ClaimRewards(_, asset) -> if action != (if asset == 0 do
        "claim-usdc"
      else
        "claim-morse"
      end) do
      return Err("rewards_v2_effect_action")
    end
  end
  let state = read_token_reward_quorum(client,
    config.sources,
    config.allow_loopback,
    config.pins,
    intent.epoch,
    minimum)?
  let present = case action do
    "attendance-open" -> case state.attendance do
      None -> false
      Some(_) -> true
    end
    "seal" -> case state.attendance do
      None -> false
      Some(value) -> value.sealed
    end
    _ -> do
      let record = case state.record do
        None -> return Ok(effect_report(false, state.context_slot))
        Some(value) -> value
      end
      case action do
        "open" -> true
        "begin" -> record.status > 0
        "finalize" -> record.status == 2
        "cancel" -> record.status != 1 || stage_hash(record) != text(previous, "stage_hash")?
        "claim-usdc" -> case intent.operation do
          ClaimRewards(row, _) -> record.status == 2
            && row < List.length(record.rows)
            && List.get(record.rows, row).claimed_usd
          _ -> false
        end
        "claim-morse" -> case intent.operation do
          ClaimRewards(row, _) -> record.status == 2
            && row < List.length(record.rows)
            && List.get(record.rows, row).claimed_morse
          _ -> false
        end
        "append" -> do
          let count = Json.as_int(Json.object_get(previous, "staged_count")?)?
          let instructions = Json.object_get(previous, "instructions")?
          let last = Json.array_get(instructions, Json.array_length(instructions)? - 1)?
          let keys = Json.object_get(last, "accountKeys")?
          let length = Json.array_length(keys)?
          if count < 0 || count > 63 || length < 23 || length > 31 || (length - 19) % 4 != 0 do
            return Err("rewards_v2_effect_append")
          end
          let number = (length - 19) / 4
          if record.status == 0
            || stage_hash(record) != text(previous, "stage_hash")?
            || List.length(record.rows) < count + number do
            return Ok(effect_report(false, state.context_slot))
          end
          for index in 0..number do
            let expected = pubkey(Json.as_string(Json.array_get(keys, 19 + index * 4)?)?)?
            if List.get(record.rows, count + index).witness != expected.bytes do
              return Err("rewards_v2_effect_append_identity")
            end
          end
          true
        end
        _ -> return Err("rewards_v2_effect_action")
      end
    end
  end
  Ok(effect_report(present, state.context_slot))
end

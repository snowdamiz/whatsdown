from Solana.Read import Pubkey, AccountSlice, pubkey, pubkey_equal, pubkey_string
from Solana.Tx import (
  Instruction,
  AccountMeta,
  instruction_report_json,
  compute_unit_limit_instruction
)
from Transparency.AnchorChain import AnchorPins
from Transparency.AnchorRpc import read_anchor_time_quorum
from Transparency.Merkle import WitnessKey
from Transparency.Attendance import AttendanceEpoch, AttendanceRow
from Transparency.RewardsChain import (
  RewardEpochAccount,
  RewardFundingReceipt,
  reward_funding_address
)
from Transparency.RewardsRead import (
  RewardsState,
  RewardsReadAddresses,
  RewardFundingState,
  read_rewards,
  read_rewards_account_slices,
  read_reward_funding
)
from Transparency.RewardsWrite import (
  RewardWriteContext,
  RewardAppendWitness,
  reward_witness_address,
  reward_open_instruction,
  reward_fund_instruction,
  reward_begin_instruction,
  reward_append_instruction,
  reward_finalize_instruction,
  reward_cancel_instruction,
  reward_claim_instruction,
  reward_claim_setup_instruction
)

pub struct RewardOperatorIntent do
  action :: String
  program :: Pubkey
  mint :: Pubkey
  log_name :: String
  payer :: Pubkey
  epoch :: U64
  funder :: Pubkey
  kind :: Int
  amount :: U64
  operation_id :: Bytes
  row :: Int
  intent_hash :: Bytes
end

fn text(input :: String, field :: String) -> String!String do
  Json.as_string(Json.object_get(Json.parse(input)?, field)?)
end

fn wide(input :: String, field :: String) -> U64!String do
  let encoded = text(input, field)?
  let value = U64.parse(encoded)?
  if U64.to_string(value) != encoded do
    return Err("noncanonical_rewards_intent")
  end
  Ok(value)
end

fn key(input :: String, field :: String) -> Pubkey!String do
  let value = pubkey(text(input, field)?)?
  if Bytes.to_hex(value.bytes) == String.repeat("00", 32) do
    return Err("invalid_rewards_intent_key")
  end
  Ok(value)
end

pub fn decode_reward_intent(input :: String) -> RewardOperatorIntent!String do
  if String.length(input) > 4096 do
    return Err("rewards_intent_too_large")
  end
  let action = text(input, "action")?
  if action != "settle" && action != "fund" && action != "claim" do
    return Err("invalid_rewards_intent_action")
  end
  let program = key(input, "program")?
  let mint = key(input, "mint")?
  let payer = key(input, "payer")?
  let epoch = wide(input, "epoch")?
  let name = text(input, "log")?
  let funder = if action == "fund" do
    key(input, "funder")?
  else
    payer
  end
  let kind = if action == "fund" do
    Json.as_int(Json.object_get(Json.parse(input)?, "kind")?)?
  else
    0
  end
  let amount = if action == "fund" do
    wide(input, "amount")?
  else
    U64.parse("0")?
  end
  let operation = if action == "fund" do
    let encoded = text(input, "operation_id")?
    let bytes = Bytes.from_hex(encoded)?
    if Bytes.length(bytes) != 32
      || Bytes.to_hex(bytes) != encoded
      || encoded == String.repeat("00", 32) do
      return Err("invalid_rewards_operation_id")
    end
    bytes
  else
    Bytes.from_hex(String.repeat("00", 32))?
  end
  let row = if action == "claim" do
    Json.as_int(Json.object_get(Json.parse(input)?, "row")?)?
  else
    0
  end
  if row < 0
    || row > 63
    || kind < 0
    || kind > 1
    || (action == "fund" && amount == U64.parse("0")?) do
    return Err("invalid_rewards_intent")
  end
  let canonical = String.join([
      action,
      pubkey_string(program),
      pubkey_string(mint),
      Json.encode_string(name),
      pubkey_string(payer),
      U64.to_string(epoch),
      pubkey_string(funder),
      Int.to_string(kind),
      U64.to_string(amount),
      Bytes.to_hex(operation),
      Int.to_string(row)
    ],
    "\n")
  Ok(RewardOperatorIntent {
    action: action,
    program: program,
    mint: mint,
    log_name: name,
    payer: payer,
    epoch: epoch,
    funder: funder,
    kind: kind,
    amount: amount,
    operation_id: operation,
    row: row,
    intent_hash: Crypto.sha256(Bytes.from_utf8("morse-rewards-intent-v1\n" <> canonical))
  })
end

# Chain time is the quorum-authenticated block time at the account snapshot's
# finalized context, never local wall time. The program rechecks it at execution.
pub fn select_reward_step(intent :: RewardOperatorIntent,
  state :: RewardsState,
  chain_time :: U64) -> String!String do
  if intent.epoch != state.epoch_number
    || !pubkey_equal(intent.program, state.program)
    || !pubkey_equal(intent.mint, state.mint)
    || intent.log_name != state.log_name do
    return Err("rewards_intent_snapshot_mismatch")
  end
  let pool = case state.pool do
    None -> return Ok("waiting:pool")
    Some(value) -> value
  end
  if intent.action == "claim" do
    let record = case state.record do
      None -> return Ok("waiting:settlement")
      Some(value) -> value
    end
    if record.status != 2 do
      return Ok("waiting:settlement")
    end
    if intent.row >= List.length(record.rows) do
      return Err("invalid_rewards_claim_row")
    end
    if List.get(record.rows, intent.row).claimed do
      return Ok("complete")
    end
    if List.get(record.rows, intent.row).amount == U64.parse("0")? do
      return Ok("complete")
    end
    return Ok("claim")
  end
  let current = U64.divide(chain_time, U64.parse("604800")?)?
  if intent.action == "fund" do
    if U64.compare(intent.epoch, pool.first_full_epoch) < 0 do
      return Ok("waiting:first-full-epoch")
    end
    if current != intent.epoch do
      return Ok("waiting:funding-week")
    end
    let record = case state.record do
      None -> return Ok("open")
      Some(value) -> value
    end
    if record.status != 0 do
      return Ok("waiting:open-ledger")
    end
    return Ok("fund")
  end
  case state.record do
    Some(value) when value.status == 2 -> return Ok("complete")
    _ -> nil
  end
  if intent.epoch != pool.next_epoch do
    return Ok("waiting:previous-epoch")
  end
  if U64.compare(intent.epoch, current) >= 0 do
    return Ok("waiting:week-end")
  end
  let record = case state.record do
    None -> return Ok("open")
    Some(value) -> value
  end
  case state.economics do
    None -> return Ok("waiting:economics")
    Some(_) -> nil
  end
  case pool.active_epoch do
    Some(value) when value != intent.epoch -> return Ok("waiting:active-epoch")
    _ -> nil
  end
  if record.status == 1 do
    if state.revision_matches == Some(false)
      || U64.compare(chain_time, U64.add(record.started_at, U64.parse("3600")?)?) >= 0 do
      return Ok("cancel")
    end
  end
  let attendance = case state.attendance do
    None -> return Ok("attendance-open")
    Some(value) -> value
  end
  if !attendance.sealed do
    if attendance.posts != U64.parse("0")?
      && U64.compare(state.context_slot,
        U64.add(attendance.max_post_slot, U64.parse("1500")?)?) <= 0 do
      return Ok("waiting:cosign-window")
    end
    return Ok("seal")
  end
  if record.status == 0 do
    return Ok("begin")
  end
  if List.length(record.rows) < record.expected do
    return Ok("append")
  end
  if U64.compare(record.floor_required, U64.add(record.available, pool.subsidy)?) > 0 do
    return Ok("waiting:floor-funding")
  end
  Ok("finalize")
end

fn zeroes(bytes :: Bytes, start :: Int, length :: Int) -> Bool!String do
  Ok(Bytes.to_hex(Bytes.slice(bytes, start, length)?) == String.repeat("00", length))
end

# Only identities are needed to construct the next append. Current bond/member
# eligibility is checked atomically by the program, including its revision fence.
fn append_keys(pins :: AnchorPins,
  context :: RewardWriteContext,
  state :: RewardsState) -> List<RewardAppendWitness>!String do
  let attendance = case state.attendance do
    None -> return Err("attendance_missing")
    Some(value) -> value
  end
  let record = case state.record do
    None -> return Err("rewards_epoch_missing")
    Some(value) -> value
  end
  let start = List.length(record.rows)
  let stop = if start + 4 > List.length(attendance.rows) do
    List.length(attendance.rows)
  else
    start + 4
  end
  let addresses = for index in start..stop do
    Pubkey { bytes: List.get(attendance.rows, index).witness }
  end
  let snapshot = read_rewards_account_slices(pins, addresses, 320, state.context_slot)?
  let result = for index in 0..List.length(addresses) do
    let slice = case List.get(snapshot.accounts, index) do
      None -> return Err("rewards_witness_missing")
      Some(value) -> value
    end
    let bytes = slice.info.data
    if slice.info.executable
      || !pubkey_equal(slice.info.owner, pins.program)
      || slice.info.lamports == U64.parse("0")?
      || slice.space != U64.parse("320")?
      || Bytes.length(bytes) != 320
      || Bytes.to_hex(Bytes.slice(bytes, 0, 4)?) != "4d574901" do
      return Err("invalid_rewards_witness")
    end
    let length = Bytes.get(bytes, 4)?
    if length < 1
      || length > 64
      || Bytes.get(bytes, 5)? > 4
      || Bytes.get(bytes, 6)? > 1
      || Bytes.get(bytes, 7)? != 0
      || !zeroes(bytes, 8 + length, 64 - length)?
      || !Bytes.secure_equals(Bytes.slice(bytes, 200, 32)?, pins.log_id)
      || !zeroes(bytes, 272, 48)? do
      return Err("invalid_rewards_witness")
    end
    let witness_key = WitnessKey {
      witness_id: Bytes.to_utf8(Bytes.slice(bytes, 8, length)?)?,
      public_key: Bytes.slice(bytes, 72, 32)?
    }
    let address = List.get(addresses, index)
    if !pubkey_equal(reward_witness_address(context, witness_key)?, address) do
      return Err("rewards_witness_identity_mismatch")
    end
    RewardAppendWitness { witness: address, key: witness_key }
  end
  Ok(result)
end

fn meta(address :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: address, signer: signer, writable: writable }
end

fn attendance_instruction(intent :: RewardOperatorIntent,
  state :: RewardsState,
  step :: String) -> Instruction!String do
  if step == "seal" do
    return Ok(Instruction {
      program_id: state.judge,
      accounts: [
        meta(state.addresses.log, false, false),
        meta(state.addresses.attendance, false, true)
      ],
      data: Bytes.from_hex("1d")?
    })
  end
  Ok(Instruction {
    program_id: state.judge,
    accounts: [
      meta(intent.payer, true, true),
      meta(state.addresses.log, false, false),
      meta(state.addresses.clock, false, false),
      meta(state.addresses.attendance, false, true),
      meta(pubkey("11111111111111111111111111111111")?, false, false)
    ],
    data: Bytes.concat(Bytes.from_hex("1c")?, Bytes.write_uint_le(U64.to_string(intent.epoch), 8)?)?
  })
end

fn address(value :: Pubkey) -> String do
  Json.encode_string(pubkey_string(value))
end

fn allocation(value :: Pubkey, space :: Int) -> String do
  """{"address":#{address(value)},"space":#{space}}"""
end

fn report(intent :: RewardOperatorIntent,
  state :: RewardsState,
  step :: String,
  instructions :: List<Instruction>,
  rent :: List<String>) -> String do
  let status = if step == "complete" do
    "complete"
  else if String.starts_with(step, "waiting:") do
    "waiting"
  else
    "ready"
  end
  let signers = if step == "fund" && !pubkey_equal(intent.funder, intent.payer) do
    [address(intent.payer), address(intent.funder)]
  else
    [address(intent.payer)]
  end
  let reports = String.join(for instruction in instructions do
      instruction_report_json(instruction)
    end,
    ",")
  let staged_count = case state.record do
    None -> 0
    Some(value) -> List.length(value.rows)
  end
  let stage_started = case state.record do
    None -> "0"
    Some(value) -> U64.to_string(value.started_at)
  end
  let stage_revision = case state.record do
    None -> "0"
    Some(value) -> U64.to_string(value.eligibility_revision)
  end
  """{"schema_version":1,"status":#{Json.encode_string(status)},"action":#{Json.encode_string(step)},"program":#{address(intent.program)},"judge":#{address(state.judge)},"log":#{address(state.addresses.log)},"log_name":#{Json.encode_string(state.log_name)},"mint":#{address(intent.mint)},"payer":#{address(intent.payer)},"epoch":"#{U64.to_string(intent.epoch)}","context_slot":"#{U64.to_string(state.context_slot)}","intent_hash":"#{Bytes.to_hex(intent.intent_hash)}","staged_count":#{staged_count},"stage_started":"#{stage_started}","stage_revision":"#{stage_revision}","signer_keys":[#{String.join(signers,
    ",")}],"instructions":[#{reports}],"rent_allocations":[#{String.join(rent, ",")}]}"""
end

fn effect_report(present :: Bool, slot :: U64) -> String do
  let state = if present do
    "present"
  else
    "absent"
  end
  """{"schema_version":1,"state":"#{state}","slot":"#{U64.to_string(slot)}"}"""
end

# Recovery reads effects only after the writer has crossed a finalized expiry
# barrier. Absence alone cannot prove that a pruned transaction paid no fees.
pub fn read_reward_effect(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  intent :: RewardOperatorIntent,
  previous :: String,
  minimum_slot :: U64) -> String!String do
  if intent.log_name != pins.log_name
    || text(previous, "intent_hash")? != Bytes.to_hex(intent.intent_hash)
    || text(previous, "program")? != pubkey_string(intent.program)
    || text(previous, "mint")? != pubkey_string(intent.mint)
    || wide(previous, "epoch")? != intent.epoch do
    return Err("rewards_effect_intent_mismatch")
  end
  let action = text(previous, "action")?
  if action == "fund" do
    if intent.action != "fund" do
      return Err("rewards_effect_intent_mismatch")
    end
    let funding = read_reward_funding(pins,
      service_key,
      version,
      intent.program,
      intent.mint,
      intent.epoch,
      intent.funder,
      intent.operation_id,
      minimum_slot)?
    let present = case funding.receipt do
      None -> false
      Some(receipt) -> do
        if receipt.kind != intent.kind || receipt.amount != intent.amount do
          return Err("rewards_funding_intent_collision")
        end
        true
      end
    end
    return Ok(effect_report(present, funding.context_slot))
  end
  let state = read_rewards(pins,
    service_key,
    version,
    intent.program,
    intent.mint,
    intent.epoch,
    minimum_slot)?
  let present = case action do
    "open" -> case state.record do
      None -> false
      Some(_) -> true
    end
    "attendance-open" -> case state.attendance do
      None -> false
      Some(_) -> true
    end
    "seal" -> case state.attendance do
      None -> false
      Some(value) -> value.sealed
    end
    "begin" -> case state.record do
      None -> false
      Some(value) -> value.status > 0
    end
    "finalize" -> case state.record do
      None -> false
      Some(value) -> value.status == 2
    end
    "claim" -> case state.record do
      Some(value) when value.status == 2
        && intent.row < List.length(value.rows) -> List.get(value.rows, intent.row).claimed
      _ -> false
    end
    "cancel" -> case state.record do
      None -> false
      Some(value) -> value.status != 1
        || value.started_at != wide(previous, "stage_started")?
        || value.eligibility_revision != wide(previous, "stage_revision")?
    end
    "append" -> do
      let count = Json.as_int(Json.object_get(Json.parse(previous)?, "staged_count")?)?
      let instructions = Json.object_get(Json.parse(previous)?, "instructions")?
      let last = Json.array_get(instructions, Json.array_length(instructions)? - 1)?
      let keys = Json.object_get(last, "accountKeys")?
      let length = Json.array_length(keys)?
      if count < 0 || count > 63 || length < 9 || length > 18 || (length - 6) % 3 != 0 do
        return Err("invalid_rewards_append_effect")
      end
      let record = case state.record do
        None -> return Ok(effect_report(false, state.context_slot))
        Some(value) -> value
      end
      let number = (length - 6) / 3
      if record.status == 0 || List.length(record.rows) < count + number do
        return Ok(effect_report(false, state.context_slot))
      end
      for index in 0..number do
        let expected = pubkey(Json.as_string(Json.array_get(keys, 6 + index * 3)?)?)?
        if !Bytes.secure_equals(List.get(record.rows, count + index).witness, expected.bytes) do
          return Err("rewards_append_effect_mismatch")
        end
      end
      true
    end
    _ -> return Err("invalid_rewards_effect_action")
  end
  Ok(effect_report(present, state.context_slot))
end

pub fn plan_reward_operation(pins :: AnchorPins,
  service_key :: Bytes,
  version :: Int,
  intent :: RewardOperatorIntent,
  minimum_slot :: U64) -> String!String do
  if intent.log_name != pins.log_name do
    return Err("rewards_log_pin_mismatch")
  end
  let state = if intent.action == "fund" do
    let funding = read_reward_funding(pins,
      service_key,
      version,
      intent.program,
      intent.mint,
      intent.epoch,
      intent.funder,
      intent.operation_id,
      minimum_slot)?
    case funding.receipt do
      Some(receipt) -> do
        if receipt.kind != intent.kind || receipt.amount != intent.amount do
          return Err("rewards_funding_intent_collision")
        end
        return Ok(report(intent, funding.rewards, "complete", [], []))
      end
      None -> nil
    end
    funding.rewards
  else
    read_rewards(pins,
      service_key,
      version,
      intent.program,
      intent.mint,
      intent.epoch,
      minimum_slot)?
  end
  let chain_time = read_anchor_time_quorum(pins.endpoints, state.context_slot)?
  let step = select_reward_step(intent, state, U64.parse(Int.to_string(chain_time))?)?
  if step == "complete" || String.starts_with(step, "waiting:") do
    return Ok(report(intent, state, step, [], []))
  end
  let context = RewardWriteContext {
    program: intent.program,
    judge: pins.program,
    log_name: pins.log_name,
    mint: intent.mint
  }
  let instruction = case step do
    "open" -> reward_open_instruction(context, intent.payer, intent.epoch)?
    "fund" -> reward_fund_instruction(context,
      intent.funder,
      intent.payer,
      intent.epoch,
      intent.kind,
      intent.amount,
      intent.operation_id)?
    "begin" -> reward_begin_instruction(context, intent.epoch)?
    "append" -> reward_append_instruction(context,
      intent.epoch,
      append_keys(pins, context, state)?)?
    "finalize" -> reward_finalize_instruction(context, intent.epoch)?
    "cancel" -> reward_cancel_instruction(context, intent.epoch)?
    "claim" -> do
      let record = case state.record do
        None -> return Err("rewards_epoch_missing")
        Some(value) -> value
      end
      reward_claim_instruction(context, record, intent.row)?
    end
    _ -> attendance_instruction(intent, state, step)?
  end
  let rent = case step do
    "open" -> [allocation(state.addresses.epoch, 8416)]
    "fund" -> [
      allocation(reward_funding_address(intent.program, intent.funder, intent.operation_id)?, 192)
    ]
    "attendance-open" -> [allocation(state.addresses.attendance, 2640)]
    "claim" -> [allocation(List.get(instruction.accounts, 3).pubkey, 165)]
    _ -> []
  end
  let setup = if step == "claim" do
    let record = case state.record do
      None -> return Err("rewards_epoch_missing")
      Some(value) -> value
    end
    [reward_claim_setup_instruction(context, intent.payer, record, intent.row)?]
  else
    []
  end
  Ok(report(intent,
    state,
    step,
    [compute_unit_limit_instruction(1400000)?] ++ setup ++ [instruction],
    rent))
end

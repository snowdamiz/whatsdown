from Solana.Read import Pubkey, Hash, pubkey, pubkey_string
from Solana.Tx import (
  Instruction,
  AccountMeta,
  LegacyMessage,
  compile_legacy_message,
  serialize_unsigned_legacy_transaction
)
from Transparency.Merkle import WitnessKey
from Transparency.RewardsChain import (
  RewardEpochAccount,
  RewardClaimRow,
  reward_funding_address,
  reward_member_address,
  reward_pool_address,
  reward_epoch_address
)
from Transparency.RewardsWrite import (
  RewardWriteContext,
  RewardWriteAddresses,
  RewardAppendWitness,
  reward_write_addresses,
  reward_witness_address,
  reward_bond_address,
  reward_initialize_instruction,
  reward_open_instruction,
  reward_fund_instruction,
  reward_propose_member_instruction,
  reward_apply_member_instruction,
  reward_begin_instruction,
  reward_append_instruction,
  reward_finalize_instruction,
  reward_claim_instruction,
  reward_claim_setup_instruction,
  reward_propose_governance_instruction,
  reward_apply_governance_instruction,
  reward_cancel_instruction,
  reward_instruction_report
)

fn key(value :: String) -> Pubkey!String do
  Ok(Pubkey { bytes: Bytes.from_hex(String.repeat(value, 32))? })
end

fn context() -> RewardWriteContext!String do
  Ok(RewardWriteContext {
    program: key("66")?,
    judge: key("33")?,
    log_name: "morse-main",
    mint: key("77")?
  })
end

fn zero() -> U64!String do
  U64.parse("0")
end

fn witness(index :: Int) -> WitnessKey!String do
  Ok(WitnessKey { witness_id: "outside-#{index}", public_key: key("51")?.bytes })
end

fn instruction_meta(value :: Instruction,
  index :: Int,
  address :: Pubkey,
  signer :: Bool,
  writable :: Bool) -> Bool do
  let account = List.get(value.accounts, index)
  account.pubkey == address && account.signer == signer && account.writable == writable
end

fn claim_record(ctx :: RewardWriteContext) -> RewardEpochAccount!String do
  let z = zero()?
  Ok(RewardEpochAccount {
    pool: reward_pool_address(ctx.program)?.bytes,
    epoch: U64.parse("2813")?,
    revenue: U64.parse("100")?,
    status: 2,
    expected: 1,
    attendance_hash: key("11")?.bytes,
    posts: U64.parse("100")?,
    total_weight: U128.parse("300")?,
    floor_required: z,
    base_floor: z,
    available: U64.parse("100")?,
    subsidy_used: z,
    allocated: U64.parse("100")?,
    carry: z,
    claimed_mask: z,
    started_at: U64.parse("1701907200")?,
    eligibility_revision: z,
    rows: [
      RewardClaimRow {
        witness: key("12")?.bytes,
        payout: key("13")?.bytes,
        bond: key("14")?.bytes,
        weight: U128.parse("300")?,
        floor: z,
        amount: U64.parse("100")?,
        claimed: false
      }
    ]
  })
end

fn funding_case() -> Bool!String do
  let ctx = context()?
  let funder = key("88")?
  let payer = key("89")?
  let operation = key("99")?.bytes
  let maximum = U64.parse("18446744073709551615")?
  let instruction = reward_fund_instruction(ctx, funder, payer, maximum, 1, maximum, operation)?
  assert(Bytes.to_hex(instruction.data) == "0c01ffffffffffffffff" <> String.repeat("99", 32))
  assert(List.length(instruction.accounts) == 10 && instruction.program_id == ctx.program)
  assert(instruction_meta(instruction, 0, funder, true, false))
  assert(instruction_meta(instruction, 1, payer, true, true))
  assert(instruction_meta(instruction, 2, reward_pool_address(ctx.program)?, false, true))
  assert(instruction_meta(instruction, 3, reward_epoch_address(ctx.program, maximum)?, false, true))
  assert(instruction_meta(instruction,
    8,
    reward_funding_address(ctx.program, funder, operation)?,
    false,
    true))
  assert(instruction_meta(instruction,
    9,
    pubkey("11111111111111111111111111111111")?,
    false,
    false))
  let report = Json.parse(reward_instruction_report(instruction))?
  assert(Json.as_int(Json.object_get(report, "schemaVersion")?)? == 1)
  assert(Json.as_string(Json.object_get(report,
    "dataBase64")?)? == Bytes.to_base64(instruction.data))
  for (kind, amount, id) in [
    (2, maximum, operation),
    (1, zero()?, operation),
    (1, maximum, Bytes.from_hex(String.repeat("00", 32))?)
  ] do
    case reward_fund_instruction(ctx, funder, payer, maximum, kind, amount, id) do
      Ok(_) -> return Err("prepared invalid durable funding")
      Err(_) -> nil
    end
  end
  Ok(true)
end

fn builders_case() -> Bool!String do
  let ctx = context()?
  let payer = key("88")?
  let governance = key("89")?
  let epoch = U64.parse("2813")?
  let key = witness(0)?
  let addresses = reward_write_addresses(ctx, epoch)?
  let initialize = reward_initialize_instruction(ctx,
    payer,
    payer,
    governance,
    U64.parse("1700000000")?,
    key)?
  assert(Bytes.get(initialize.data, 0)? == 0 && Bytes.length(initialize.data) == 73)
  assert(List.length(initialize.accounts) == 13)
  assert(instruction_meta(initialize, 0, payer, true, false))
  assert(instruction_meta(initialize, 1, payer, true, true))
  assert(instruction_meta(initialize, 5, addresses.program_data, false, false))
  let open = reward_open_instruction(ctx, payer, epoch)?
  assert(Bytes.to_hex(open.data) == "01fd0a000000000000")
  assert(List.length(open.accounts) == 4 && instruction_meta(open, 1, addresses.pool, false, false))
  let proposal = reward_propose_member_instruction(ctx, governance, payer, key, 1)?
  assert(Bytes.to_hex(proposal.data) == "0301")
  assert(instruction_meta(proposal, 3, reward_witness_address(ctx, key)?, false, false))
  let apply = reward_apply_member_instruction(ctx, key)?
  assert(Bytes.to_hex(apply.data) == "04" && List.length(apply.accounts) == 2)
  assert(instruction_meta(apply,
    1,
    reward_member_address(ctx.program, reward_witness_address(ctx, key)?)?,
    false,
    true))
  for (tag, instruction) in [
    (5, reward_begin_instruction(ctx, epoch)?),
    (7, reward_finalize_instruction(ctx, epoch)?),
    (9, reward_propose_governance_instruction(ctx, governance, payer)?),
    (10, reward_apply_governance_instruction(ctx)?),
    (11, reward_cancel_instruction(ctx, epoch)?)
  ] do
    assert(Bytes.get(instruction.data, 0)? == tag)
    assert(instruction_meta(instruction,
      if tag == 9 do
        1
      else
        0
      end,
      addresses.pool,
      false,
      true))
  end
  case reward_propose_member_instruction(ctx, governance, payer, key, 3) do
    Ok(_) -> return Err("prepared unsupported membership status")
    Err(_) -> nil
  end
  Ok(true)
end

fn packets_case() -> Bool!String do
  let ctx = context()?
  let payer = key("88")?
  let epoch = U64.parse("2813")?
  let candidates = for index in 0..4 do
    let key = witness(index)?
    RewardAppendWitness { witness: reward_witness_address(ctx, key)?, key: key }
  end
  # Sort the canonical PDA keys, just as authenticated attendance rows are sorted.
  let ordered = List.sort(candidates,
    fn(a, b) do
      if Bytes.to_hex(a.witness.bytes) < Bytes.to_hex(b.witness.bytes) do
        -1
      else if Bytes.to_hex(a.witness.bytes) > Bytes.to_hex(b.witness.bytes) do
        1
      else
        0
      end
    end)
  let hash = Hash { bytes: key("aa")?.bytes }
  for count in 1..5 do
    let instruction = reward_append_instruction(ctx, epoch, List.take(ordered, count))?
    assert(Bytes.to_hex(instruction.data) == "06")
    assert(List.length(instruction.accounts) == 6 + count * 3)
    let packet = serialize_unsigned_legacy_transaction(compile_legacy_message(payer,
      hash,
      [instruction])?)?
    assert(Bytes.length(packet) <= 1232)
  end
  let record = claim_record(ctx)?
  let setup = reward_claim_setup_instruction(ctx, payer, record, 0)?
  let claim = reward_claim_instruction(ctx, record, 0)?
  assert(Bytes.to_hex(claim.data) == "0800")
  assert(List.length(claim.accounts) == 6)
  let packet = serialize_unsigned_legacy_transaction(compile_legacy_message(payer,
    hash,
    [setup, claim])?)?
  assert(Bytes.length(packet) <= 1232)
  case reward_append_instruction(ctx, epoch, []) do
    Ok(_) -> return Err("prepared empty append")
    Err(_) -> nil
  end
  case reward_append_instruction(ctx, epoch, List.append(ordered, List.head(ordered))) do
    Ok(_) -> return Err("prepared append larger than four witnesses")
    Err(_) -> nil
  end
  case reward_append_instruction(ctx, epoch, List.reverse(ordered)) do
    Ok(_) -> return Err("prepared out-of-order append")
    Err(_) -> nil
  end
  case reward_append_instruction(ctx, epoch, [List.head(ordered), List.head(ordered)]) do
    Ok(_) -> return Err("prepared duplicate append")
    Err(_) -> nil
  end
  let bad = %{List.head(ordered) | witness: key("ff")?}
  case reward_append_instruction(ctx, epoch, [bad]) do
    Ok(_) -> return Err("prepared noncanonical witness selector")
    Err(_) -> nil
  end
  case reward_claim_instruction(ctx,
    %{record | rows: [%{List.head(record.rows) | claimed: true}]},
    0) do
    Ok(_) -> return Err("prepared already-claimed row")
    Err(_) -> nil
  end
  case reward_claim_instruction(ctx, %{record | pool: key("fe")?.bytes}, 0) do
    Ok(_) -> return Err("prepared claim from a different pool")
    Err(_) -> nil
  end
  case reward_claim_instruction(ctx, record, 64) do
    Ok(_) -> return Err("prepared claim outside the fixed row set")
    Err(_) -> nil
  end
  Ok(true)
end

test("reward funding uses permanent intent receipts and exact wide payloads") do
  case funding_case() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("reward builders derive canonical account roles for initialization and governance") do
  case builders_case() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

test("reward append and claim with ATA setup fit real Solana packet serialization") do
  case packets_case() do
    Err(error) -> do
      println(error)
      assert(false)
    end
    Ok(value) -> assert(value)
  end
end

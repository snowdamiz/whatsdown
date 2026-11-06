from RewardRead import TokenRewardReadState
from Transparency.TokenWrite import (
  TokenRewardWriteContext,
  token_reward_write_addresses,
  token_reward_open_instruction,
  token_reward_begin_instruction,
  token_reward_append_instruction,
  token_reward_finalize_instruction,
  token_reward_cancel_instruction,
  token_reward_claim_instruction,
  token_reward_claim_setup_instruction,
  token_reward_claim_usdc_instruction,
  token_reward_claim_usdc_setup_instruction
)
from Transparency.RewardsWrite import RewardAppendWitness
from Solana.Read import Pubkey, pubkey
from Solana.Tx import Instruction, AccountMeta
from RewardsPolicy import TokenFloorInput, plan_token_floor

pub struct TokenRewardKeeperStep do
  status :: String
  instructions :: List<Instruction>
end

fn step(status :: String, instructions :: List<Instruction>) -> TokenRewardKeeperStep do
  TokenRewardKeeperStep { status: status, instructions: instructions }
end

fn checked(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: U64,
  state :: TokenRewardReadState) -> Bool!String do
  let a = token_reward_write_addresses(context, epoch)?
  if Bytes.length(payer.bytes) != 32
    || Bytes.to_hex(payer.bytes) == String.repeat("00", 32)
    || state.pool.judge != context.judge.bytes
    || state.pool.log != a.base.log.bytes
    || state.pool.log_id != a.base.log_id
    || state.pool.mint != context.usdc_mint.bytes
    || state.token_pool.pool != a.base.pool.bytes
    || state.token_pool.binding != a.binding.bytes
    || state.token_pool.token_program != context.token.bytes
    || state.token_pool.config != a.token_config.bytes
    || state.token_pool.mint != a.morse.bytes
    || state.token_pool.oracle != a.oracle.bytes
    || state.token_pool.profile != a.reserve_profile.bytes
    || state.token_pool.vault != a.morse_vault.bytes do
    return Err("token_rewards_keeper_context_mismatch")
  end
  case state.record do
    None -> nil
    Some(record) -> if record.epoch != epoch
      || record.pool != a.base.pool.bytes
      || record.token_pool != a.token_pool.bytes
      || record.ledger != a.base.epoch.bytes do
      return Err("token_rewards_keeper_epoch_mismatch")
    end
  end
  Ok(true)
end

fn meta(key :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: key, signer: signer, writable: writable }
end

fn attendance(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: U64,
  seal :: Bool) -> Instruction!String do
  let a = token_reward_write_addresses(context, epoch)?
  if seal do
    Ok(Instruction {
      program_id: context.judge,
      accounts: [meta(a.base.log, false, false), meta(a.base.attendance_epoch, false, true)],
      data: Bytes.from_hex("1d")?
    })
  else
    Ok(Instruction {
      program_id: context.judge,
      accounts: [
        meta(payer, true, true),
        meta(a.base.log, false, false),
        meta(a.base.clock, false, false),
        meta(a.base.attendance_epoch, false, true),
        meta(pubkey("11111111111111111111111111111111")?, false, false)
      ],
      data: Bytes.concat(Bytes.from_hex("1c")?, Bytes.write_uint_le(U64.to_string(epoch), 8)?)?
    })
  end
end

# One bounded next instruction. Identities only select the next mandatory rows;
# actual custody/admission eligibility is rechecked atomically onchain. This
# preparation function neither authenticates a caller-made state nor broadcasts.
pub fn plan_token_reward_step(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: U64,
  state :: TokenRewardReadState,
  identities :: List<RewardAppendWitness>) -> TokenRewardKeeperStep!String do
  checked(context, payer, epoch, state)?
  if !state.code_current do
    return Ok(step("waiting:code-pins", []))
  end
  case state.record do
    None -> nil
    Some(value) -> if value.status == 2 do
      return Ok(step("complete", []))
    end
  end
  let record = state.record
  if epoch != state.pool.next_epoch do
    return Ok(step("waiting:previous-epoch", []))
  end
  if U64.compare(epoch, U64.divide(state.timestamp, U64.parse("604800")?)?) >= 0 do
    return Ok(step("waiting:week-end", []))
  end
  case state.pool.active_epoch do
    Some(value) when value != epoch -> return Ok(step("waiting:active-epoch", []))
    _ -> nil
  end
  case record do
    Some(value) -> if value.status == 1 && (!state.revision_matches || state.stage_expired) do
      return Ok(step("cancel", [token_reward_cancel_instruction(context, epoch)?]))
    end
    None -> nil
  end
  if !state.source_current do
    return Ok(step("waiting:source-pins", []))
  end
  let record = case record do
    None -> return Ok(step("open", [token_reward_open_instruction(context, payer, epoch)?]))
    Some(value) -> value
  end
  let week = case state.attendance do
    None -> return Ok(step("attendance-open", [attendance(context, payer, epoch, false)?]))
    Some(value) -> value
  end
  if !week.sealed do
    if week.posts != U64.parse("0")?
      && U64.compare(state.context_slot, U64.add(week.max_post_slot, U64.parse("1500")?)?) <= 0 do
      return Ok(step("waiting:cosign-window", []))
    end
    return Ok(step("seal", [attendance(context, payer, epoch, true)?]))
  end
  if record.status == 0 do
    return Ok(step("begin", [token_reward_begin_instruction(context, epoch)?]))
  end
  let start = List.length(record.rows)
  if start < record.expected do
    let stop = if start + 3 < record.expected do
      start + 3
    else
      record.expected
    end
    if List.length(identities) != stop - start do
      return Err("token_rewards_next_rows_missing")
    end
    for index in start..stop do
      if List.get(identities, index - start).witness.bytes != List.get(week.rows, index).witness do
        return Err("token_rewards_next_rows_mismatch")
      end
    end
    return Ok(step("append", [token_reward_append_instruction(context, epoch, identities)?]))
  end
  let floor = plan_token_floor(record.available_usd,
    state.pool.subsidy,
    for row in record.rows do
      TokenFloorInput { weight: row.weight, floor: row.floor_usd }
    end,
    record.twap,
    state.reserve_remaining)
  case floor do
    Err(error) -> if error == "token_reserve_cap"
      || error == "token_reserve_underfunded"
      || error == "token_reserve_unavailable" do
      return Ok(step("waiting:" <> error, []))
    else
      return Err(error)
    end
    Ok(_) -> nil
  end
  Ok(step("finalize", [token_reward_finalize_instruction(context, payer, epoch)?]))
end

# Claims use the immutable finalized entitlement, even after an unrelated later
# unbond, exclusion, source rotation or price gap. Code changes still pause signing.
pub fn plan_token_reward_claim(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: U64,
  state :: TokenRewardReadState,
  row :: Int,
  asset :: Int) -> TokenRewardKeeperStep!String do
  checked(context, payer, epoch, state)?
  if !state.code_current do
    return Ok(step("waiting:code-pins", []))
  end
  let record = case state.record do
    None -> return Err("token_rewards_epoch_missing")
    Some(value) -> value
  end
  if asset == 0 do
    Ok(step("claim-usdc",
      [
        token_reward_claim_usdc_setup_instruction(context, payer, record, row)?,
        token_reward_claim_usdc_instruction(context, record, row)?
      ]))
  else if asset == 1 do
    Ok(step("claim-morse",
      [
        token_reward_claim_setup_instruction(context, payer, record, row)?,
        token_reward_claim_instruction(context, record, row)?
      ]))
  else
    Err("invalid_token_rewards_claim_asset")
  end
end

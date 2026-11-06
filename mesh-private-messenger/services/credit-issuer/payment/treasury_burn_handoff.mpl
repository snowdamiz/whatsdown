from Payment.RevenuePolicy import credit_revenue_policy_hash
from Transparency.TokenBurnWrite import token_burn_addresses
from Transparency.TokenBurnCarryWrite import (
  token_burn_fund_v2_instruction,
  token_burn_carry_addresses
)
from Transparency.TokenBurnCarry import (
  decode_token_burn_carry_frame,
  decode_token_burn_close_receipt
)
from Transparency.TokenPolicy import token_burn_chunks
from Solana.Read import Pubkey
from Solana.Tx import Instruction
from Transparency.TokenBurn import TokenBurnProfile

pub struct CreditBurnAllocation do
  batch_id :: U64
  policy_hash :: Bytes
  config_hash :: Bytes
  mint :: Pubkey
  amount :: U64
end

pub struct CreditBurnHandoff do
  intent_id :: Bytes
  membership_hash :: Bytes
  funding_hash :: Bytes
  config_hash :: Bytes
  program :: Pubkey
  payer :: Pubkey
  profile :: TokenBurnProfile
  epoch :: U64
  cash :: U64
  carry :: U64
  weights :: List<U64>
  entropy :: List<U64>
  allocations :: List<CreditBurnAllocation>
  instruction :: Instruction
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn key(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

fn wide(value :: U64) -> Bytes!String do
  Bytes.write_uint_le(U64.to_string(value), 8)
end

fn profile_hash(profile :: TokenBurnProfile) -> Bytes!String do
  Ok(Crypto.sha256(cat([
    Bytes.from_utf8("morse-credit-burn-profile-v1"),
    profile.config.bytes,
    profile.usdc.bytes,
    profile.treasury.bytes,
    profile.pool.bytes,
    profile.factory.bytes,
    profile.vault0.bytes,
    profile.vault1.bytes,
    profile.observation.bytes,
    wide(profile.jupiter_slot)?,
    wide(profile.raydium_slot)?,
    wide(profile.ready_at)?,
    profile.factory_hash
  ])?))
end

# Prepared external-owner handoff only. The caller must authenticate the profile
# bank/configuration and reserve the exact ordered liabilities transactionally.
pub fn prepare_credit_burn_handoff(config_hash :: Bytes,
  program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64,
  allocations :: List<CreditBurnAllocation>,
  carry :: U64,
  weights :: List<U64>,
  entropy :: List<U64>) -> CreditBurnHandoff!String do
  if !key(config_hash) || List.length(allocations) == 0 || List.length(allocations) > 64 do
    return Err("invalid_credit_burn_members")
  end
  let policy = credit_revenue_policy_hash(2)?
  let members = for index in 0..List.length(allocations) do
    let member = List.get(allocations, index)
    if member.batch_id == U64.parse("0")?
      || member.policy_hash != policy
      || member.config_hash != config_hash
      || member.mint != profile.usdc
      || member.amount == U64.parse("0")?
      || (index > 0
        && U64.compare(List.get(allocations, index - 1).batch_id, member.batch_id) >= 0) do
      return Err("invalid_credit_burn_members")
    end
    cat([wide(member.batch_id)?, member.policy_hash, member.mint.bytes, wide(member.amount)?])?
  end
  let cash = List.reduce(allocations,
    Ok(U64.parse("0")?),
    fn(total, member) do U64.add(total?, member.amount) end)?
  let instruction = token_burn_fund_v2_instruction(program,
    payer,
    profile,
    epoch,
    cash,
    carry,
    weights,
    entropy)?
  let a = token_burn_addresses(program, profile, epoch, 0)?
  let funding_hash = Crypto.sha256(cat([
    Bytes.from_utf8("morse-burn-week-v2"),
    a.profile.bytes,
    Bytes.slice(instruction.data, 1, 312)?
  ])?)
  let membership_hash = Crypto.sha256(cat([
    Bytes.from_utf8("morse-credit-burn-members-v1"),
    config_hash
  ]
    ++ members)?)
  let id = Crypto.sha256(cat([
    Bytes.from_utf8("morse-credit-burn-handoff-v1"),
    config_hash,
    program.bytes,
    payer.bytes,
    profile_hash(profile)?,
    wide(epoch)?,
    membership_hash,
    funding_hash
  ])?)
  Ok(CreditBurnHandoff {
    intent_id: id,
    membership_hash: membership_hash,
    funding_hash: funding_hash,
    config_hash: config_hash,
    program: program,
    payer: payer,
    profile: profile,
    epoch: epoch,
    cash: cash,
    carry: carry,
    weights: weights,
    entropy: entropy,
    allocations: allocations,
    instruction: instruction
  })
end

# Pure frame/intent consistency only: raw bytes are NOT a chain proof. Production
# reconciliation must additionally authenticate canonical owner/PDA/finalized-bank
# context and pinned code before calling this internal matching boundary.
pub fn match_credit_burn_handoff_frame(intent :: CreditBurnHandoff,
  raw :: Bytes,
  receipt :: Option<Bytes>) -> Bool!String do
  let canonical = prepare_credit_burn_handoff(intent.config_hash,
    intent.program,
    intent.payer,
    intent.profile,
    intent.epoch,
    intent.allocations,
    intent.carry,
    intent.weights,
    intent.entropy)?
  if canonical.intent_id != intent.intent_id
    || canonical.membership_hash != intent.membership_hash
    || canonical.funding_hash != intent.funding_hash
    || canonical.cash != intent.cash do
    return Err("credit_burn_intent_conflict")
  end
  let frame = decode_token_burn_carry_frame(raw)?
  let week = frame.week
  let a = token_burn_addresses(intent.program, intent.profile, intent.epoch, 0)?
  let c = token_burn_carry_addresses(intent.program, intent.profile.usdc, intent.epoch)?
  if frame.version != 2
    || week.profile != a.profile
    || week.epoch != intent.epoch
    || week.usdc != intent.profile.usdc
    || week.treasury != intent.profile.treasury
    || week.vault != a.week_vault
    || week.source != a.treasury_source
    || week.funding_hash != intent.funding_hash
    || frame.cash_budget != intent.cash
    || frame.carry_budget != intent.carry
    || frame.carry != Some(c.carry) do
    return Err("credit_burn_funding_mismatch")
  end
  let rows = token_burn_chunks(U64.add(intent.cash, intent.carry)?,
    U64.multiply(intent.epoch, U64.parse("604800")?)?,
    intent.weights,
    intent.entropy)?
  for index in 0..24 do
    let expected = List.get(rows, index)
    let actual = List.get(week.rows, index)
    if expected.amount != actual.amount
      || expected.window_start != actual.window_start
      || expected.window_end != actual.window_end
      || expected.execute_at != actual.execute_at do
      return Err("credit_burn_schedule_mismatch")
    end
  end
  if frame.closed do
    let proof = case receipt do
      None -> return Err("credit_burn_close_receipt_missing")
      Some(value) -> decode_token_burn_close_receipt(value)?
    end
    if proof.profile != a.profile
      || proof.week != a.week
      || proof.source != a.week_vault
      || proof.epoch != intent.epoch
      || proof.budget != week.budget
      || proof.spent != week.spent
      || proof.burned != week.burned
      || proof.carried != U64.subtract(week.budget, week.spent)?
      || proof.carry != c.carry
      || proof.funding_hash != intent.funding_hash
      || proof.active_frame_hash != frame.active_frame_hash
      || proof.version != 2 do
      return Err("credit_burn_close_receipt_mismatch")
    end
  else if receipt != None do
    return Err("credit_burn_unexpected_close_receipt")
  end
  Ok(true)
end

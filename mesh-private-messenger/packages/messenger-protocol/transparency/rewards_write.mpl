from Solana.Read import Pubkey, pubkey
from Solana.Address import ProgramDerivedAddress, find_program_address
from Solana.Tx import (
  Instruction,
  AccountMeta,
  instruction_report_json,
  create_associated_token_idempotent_instruction
)
from Transparency.Merkle import WitnessKey
from Transparency.AnchorChain import AnchorAddresses, anchor_addresses
from Transparency.Attendance import AttendanceAddresses, attendance_addresses
from Transparency.AnchorBond import bond_witness_identity
from Transparency.RelayDestinations import relay_destination_address
from Transparency.RewardsChain import (
  RewardEpochAccount,
  RewardClaimRow,
  reward_pool_address,
  reward_epoch_address,
  reward_member_address,
  reward_pool_vault,
  reward_funding_address
)

# Prepare only. Callers must authenticate program/judge/mint pins and chain
# reads; these builders confer no ownership, finality, eligibility or balance trust.
pub struct RewardWriteContext do
  program :: Pubkey
  judge :: Pubkey
  log_name :: String
  mint :: Pubkey
end

pub struct RewardAppendWitness do
  witness :: Pubkey
  key :: WitnessKey
end

pub struct RewardWriteAddresses do
  pool :: Pubkey
  epoch :: Pubkey
  vault :: Pubkey
  log :: Pubkey
  log_id :: Bytes
  clock :: Pubkey
  attendance_epoch :: Pubkey
  economics :: Pubkey
  program_data :: Pubkey
end

fn wallet(value :: Pubkey) -> Pubkey!String do
  if Bytes.length(value.bytes) != 32 || Bytes.to_hex(value.bytes) == String.repeat("00", 32) do
    Err("invalid_rewards_write")
  else
    Ok(value)
  end
end

fn wide(value :: U64) -> Bytes!String do
  Bytes.write_uint_le(U64.to_string(value), 8)
end

fn byte(value :: Int) -> Bytes!String do
  Bytes.write_uint_le(Int.to_string(value), 1)
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn meta(address :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: address, signer: signer, writable: writable }
end

fn token() -> Pubkey!String do
  pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
end

fn system() -> Pubkey!String do
  pubkey("11111111111111111111111111111111")
end

fn prepared(context :: RewardWriteContext,
  tag :: Int,
  payload :: Bytes,
  accounts :: List<AccountMeta>) -> Instruction!String do
  for account in accounts do
    if Bytes.length(account.pubkey.bytes) != 32 do
      return Err("invalid_rewards_write")
    end
  end
  Ok(Instruction {
    program_id: context.program,
    accounts: accounts,
    data: cat([byte(tag)?, payload])?
  })
end

fn settlement_accounts(addresses :: RewardWriteAddresses) -> List<AccountMeta> do
  [
    meta(addresses.pool, false, true),
    meta(addresses.epoch, false, true),
    meta(addresses.log, false, false),
    meta(addresses.clock, false, false),
    meta(addresses.attendance_epoch, false, false),
    meta(addresses.economics, false, false)
  ]
end

pub fn reward_write_addresses(context :: RewardWriteContext,
  epoch :: U64) -> RewardWriteAddresses!String do
  wallet(context.program)?
  wallet(context.judge)?
  wallet(context.mint)?
  if context.program == context.judge do
    return Err("invalid_rewards_write")
  end
  let anchor = anchor_addresses(context.judge, context.log_name)?
  let attendance = attendance_addresses(context.judge, anchor.log_id, epoch)?
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  Ok(RewardWriteAddresses {
    pool: reward_pool_address(context.program)?,
    epoch: reward_epoch_address(context.program, epoch)?,
    vault: reward_pool_vault(context.program, context.mint)?,
    log: anchor.log,
    log_id: anchor.log_id,
    clock: attendance.clock,
    attendance_epoch: attendance.epoch,
    economics: find_program_address(context.judge,
      [Bytes.from_utf8("economics"), anchor.log_id])?.address,
    program_data: find_program_address(loader, [context.program.bytes])?.address
  })
end

pub fn reward_witness_address(context :: RewardWriteContext, key :: WitnessKey) -> Pubkey!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  Ok(find_program_address(context.judge,
    [
      Bytes.from_utf8("witness"),
      addresses.log_id,
      bond_witness_identity(key.witness_id, key.public_key)?
    ])?.address)
end

pub fn reward_bond_address(context :: RewardWriteContext, key :: WitnessKey) -> Pubkey!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  Ok(find_program_address(context.judge,
    [
      Bytes.from_utf8("bond"),
      addresses.log_id,
      bond_witness_identity(key.witness_id, key.public_key)?
    ])?.address)
end

pub fn reward_initialize_instruction(context :: RewardWriteContext,
  upgrade_authority :: Pubkey,
  payer :: Pubkey,
  governance :: Pubkey,
  started :: U64,
  morse :: WitnessKey) -> Instruction!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  if started == U64.parse("0")? || U64.compare(started, U64.parse("9223372036854775807")?) > 0 do
    return Err("invalid_rewards_write")
  end
  let morse_address = reward_witness_address(context, morse)?
  prepared(context,
    0,
    cat([wallet(governance)?.bytes, wide(started)?, morse_address.bytes])?,
    [
      meta(wallet(upgrade_authority)?, true, false),
      meta(wallet(payer)?, true, true),
      meta(addresses.pool, false, true),
      meta(addresses.vault, false, true),
      meta(context.program, false, false),
      meta(addresses.program_data, false, false),
      meta(context.judge, false, false),
      meta(addresses.log, false, false),
      meta(addresses.clock, false, false),
      meta(context.mint, false, false),
      meta(token()?, false, false),
      meta(pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?, false, false),
      meta(system()?, false, false)
    ])
end

pub fn reward_open_instruction(context :: RewardWriteContext,
  payer :: Pubkey,
  epoch :: U64) -> Instruction!String do
  let addresses = reward_write_addresses(context, epoch)?
  prepared(context,
    1,
    wide(epoch)?,
    [
      meta(wallet(payer)?, true, true),
      meta(addresses.pool, false, false),
      meta(addresses.epoch, false, true),
      meta(system()?, false, false)
    ])
end

pub fn reward_fund_instruction(context :: RewardWriteContext,
  funder :: Pubkey,
  payer :: Pubkey,
  epoch :: U64,
  kind :: Int,
  amount :: U64,
  operation_id :: Bytes) -> Instruction!String do
  let addresses = reward_write_addresses(context, epoch)?
  if kind < 0 || kind > 1 || amount == U64.parse("0")? do
    return Err("invalid_rewards_write")
  end
  let funder = wallet(funder)?
  let receipt = reward_funding_address(context.program, funder, operation_id)?
  let source = relay_destination_address(funder, context.mint)?
  prepared(context,
    12,
    cat([byte(kind)?, wide(amount)?, operation_id])?,
    [
      meta(funder, true, false),
      meta(wallet(payer)?, true, true),
      meta(addresses.pool, false, true),
      meta(addresses.epoch, false, true),
      meta(addresses.vault, false, true),
      meta(source, false, true),
      meta(context.mint, false, false),
      meta(token()?, false, false),
      meta(receipt, false, true),
      meta(system()?, false, false)
    ])
end

pub fn reward_propose_member_instruction(context :: RewardWriteContext,
  governance :: Pubkey,
  payer :: Pubkey,
  key :: WitnessKey,
  status :: Int) -> Instruction!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  if status < 0 || status > 2 do
    return Err("invalid_rewards_write")
  end
  let witness = reward_witness_address(context, key)?
  prepared(context,
    3,
    byte(status)?,
    [
      meta(wallet(governance)?, true, false),
      meta(wallet(payer)?, true, true),
      meta(addresses.pool, false, false),
      meta(witness, false, false),
      meta(reward_member_address(context.program, witness)?, false, true),
      meta(system()?, false, false)
    ])
end

pub fn reward_apply_member_instruction(context :: RewardWriteContext,
  key :: WitnessKey) -> Instruction!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  let witness = reward_witness_address(context, key)?
  prepared(context,
    4,
    Bytes.empty(),
    [
      meta(addresses.pool, false, false),
      meta(reward_member_address(context.program, witness)?, false, true)
    ])
end

pub fn reward_begin_instruction(context :: RewardWriteContext,
  epoch :: U64) -> Instruction!String do
  prepared(context, 5, Bytes.empty(), settlement_accounts(reward_write_addresses(context, epoch)?))
end

pub fn reward_append_instruction(context :: RewardWriteContext,
  epoch :: U64,
  witnesses :: List<RewardAppendWitness>) -> Instruction!String do
  let addresses = reward_write_addresses(context, epoch)?
  if List.length(witnesses) < 1 || List.length(witnesses) > 4 do
    return Err("invalid_rewards_write")
  end
  let triples = for index in 0..List.length(witnesses) do
    let selector = List.get(witnesses, index)
    let witness = reward_witness_address(context, selector.key)?
    if witness != selector.witness
      || (index > 0
        && Bytes.to_hex(List.get(witnesses,
          index - 1).witness.bytes) >= Bytes.to_hex(witness.bytes)) do
      return Err("invalid_rewards_write")
    end
    [
      meta(witness, false, false),
      meta(reward_bond_address(context, selector.key)?, false, false),
      meta(reward_member_address(context.program, witness)?, false, false)
    ]
  end
  prepared(context,
    6,
    Bytes.empty(),
    List.concat(settlement_accounts(addresses), List.flat_map(triples, fn(values) -> values end)))
end

pub fn reward_finalize_instruction(context :: RewardWriteContext,
  epoch :: U64) -> Instruction!String do
  prepared(context, 7, Bytes.empty(), settlement_accounts(reward_write_addresses(context, epoch)?))
end

fn claim_row(context :: RewardWriteContext,
  record :: RewardEpochAccount,
  row :: Int) -> RewardClaimRow!String do
  let addresses = reward_write_addresses(context, record.epoch)?
  if !Bytes.secure_equals(record.pool, addresses.pool.bytes)
    || record.status != 2
    || row < 0
    || row >= List.length(record.rows)
    || row >= 64 do
    return Err("invalid_rewards_write")
  end
  let value = List.get(record.rows, row)
  if value.claimed
    || value.amount == U64.parse("0")?
    || wallet(Pubkey { bytes: value.payout })? == addresses.pool do
    return Err("invalid_rewards_write")
  end
  Ok(value)
end

pub fn reward_claim_instruction(context :: RewardWriteContext,
  record :: RewardEpochAccount,
  row :: Int) -> Instruction!String do
  let addresses = reward_write_addresses(context, record.epoch)?
  let value = claim_row(context, record, row)?
  let destination = relay_destination_address(Pubkey { bytes: value.payout }, context.mint)?
  prepared(context,
    8,
    byte(row)?,
    [
      meta(addresses.pool, false, true),
      meta(addresses.epoch, false, true),
      meta(addresses.vault, false, true),
      meta(destination, false, true),
      meta(context.mint, false, false),
      meta(token()?, false, false)
    ])
end

pub fn reward_claim_setup_instruction(context :: RewardWriteContext,
  payer :: Pubkey,
  record :: RewardEpochAccount,
  row :: Int) -> Instruction!String do
  let value = claim_row(context, record, row)?
  let payout = Pubkey { bytes: value.payout }
  create_associated_token_idempotent_instruction(wallet(payer)?,
    relay_destination_address(payout, context.mint)?,
    payout,
    context.mint)
end

pub fn reward_propose_governance_instruction(context :: RewardWriteContext,
  governance :: Pubkey,
  next :: Pubkey) -> Instruction!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  prepared(context,
    9,
    wallet(next)?.bytes,
    [meta(wallet(governance)?, true, false), meta(addresses.pool, false, true)])
end

pub fn reward_apply_governance_instruction(context :: RewardWriteContext) -> Instruction!String do
  let addresses = reward_write_addresses(context, U64.parse("0")?)?
  prepared(context, 10, Bytes.empty(), [meta(addresses.pool, false, true)])
end

pub fn reward_cancel_instruction(context :: RewardWriteContext,
  epoch :: U64) -> Instruction!String do
  let addresses = reward_write_addresses(context, epoch)?
  prepared(context,
    11,
    Bytes.empty(),
    [
      meta(addresses.pool, false, true),
      meta(addresses.epoch, false, true),
      meta(addresses.economics, false, false)
    ])
end

pub fn reward_instruction_report(instruction :: Instruction) -> String do
  instruction_report_json(instruction)
end

from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Solana.Tx import Instruction, AccountMeta, create_associated_token_idempotent_instruction
from Transparency.Merkle import WitnessKey
from Transparency.RewardsWrite import (
  RewardWriteContext,
  RewardWriteAddresses,
  RewardAppendWitness,
  reward_write_addresses,
  reward_witness_address,
  reward_bond_address
)
from Transparency.RewardsChain import reward_member_address, reward_pool_vault
from Transparency.TokenCustody import token_binding_address, token_pending_address
from Transparency.TokenRewards import (
  TokenRewardEpochAccount,
  token_reward_pool_address,
  token_reward_epoch_address,
  token_reserve_profile_address,
  token_reserve_receipt_address
)

# Prepare only. The onchain programs authenticate all owners, pins and balances;
# neither these constructors nor caller-supplied structs prove chain state.
pub struct TokenRewardWriteContext do
  program :: Pubkey
  judge :: Pubkey
  token :: Pubkey
  log_name :: String
  usdc_mint :: Pubkey
end

pub struct TokenRewardWriteAddresses do
  base :: RewardWriteAddresses
  token_config :: Pubkey
  morse :: Pubkey
  oracle :: Pubkey
  binding :: Pubkey
  token_pool :: Pubkey
  token_epoch :: Pubkey
  morse_vault :: Pubkey
  reserve_profile :: Pubkey
  reserve_receipt :: Pubkey
  reserve_allocation :: Pubkey
  reserve_vault :: Pubkey
  token_data :: Pubkey
  judge_data :: Pubkey
end

fn base(context :: TokenRewardWriteContext) -> RewardWriteContext do
  RewardWriteContext {
    program: context.program,
    judge: context.judge,
    log_name: context.log_name,
    mint: context.usdc_mint
  }
end

fn wallet(value :: Pubkey) -> Pubkey!String do
  if Bytes.length(value.bytes) != 32 || Bytes.to_hex(value.bytes) == String.repeat("00", 32) do
    Err("invalid_token_reward_write")
  else
    Ok(value)
  end
end

fn classic_token() -> Pubkey!String do
  pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
end

fn ata_program() -> Pubkey!String do
  pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
end

fn system() -> Pubkey!String do
  pubkey("11111111111111111111111111111111")
end

fn meta(value :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: value, signer: signer, writable: writable }
end

fn encoded(value :: U64) -> Bytes!String do
  Bytes.write_uint_le(U64.to_string(value), 8)
end

fn derived(program :: Pubkey, seed :: String) -> Pubkey!String do
  Ok(find_program_address(program, [Bytes.from_utf8(seed)])?.address)
end

fn program_data(program :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?,
    [program.bytes])?.address)
end

fn vault(owner :: Pubkey, mint :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(ata_program()?,
    [owner.bytes, classic_token()?.bytes, mint.bytes])?.address)
end

fn prepared(program :: Pubkey,
  tag :: Int,
  payload :: Bytes,
  accounts :: List<AccountMeta>) -> Instruction!String do
  wallet(program)?
  for account in accounts do
    if Bytes.length(account.pubkey.bytes) != 32 do
      return Err("invalid_token_reward_write")
    end
  end
  Ok(Instruction {
    program_id: program,
    accounts: accounts,
    data: Bytes.concat(Bytes.write_uint_le(Int.to_string(tag), 1)?, payload)?
  })
end

pub fn token_reward_write_addresses(context :: TokenRewardWriteContext,
  epoch :: U64) -> TokenRewardWriteAddresses!String do
  wallet(context.token)?
  if context.token == context.program || context.token == context.judge do
    return Err("invalid_token_reward_write")
  end
  let addresses = reward_write_addresses(base(context), epoch)?
  let morse = derived(context.token, "mint")?
  if morse == context.usdc_mint do
    return Err("invalid_token_reward_write")
  end
  let allocation = find_program_address(context.token,
    [Bytes.from_utf8("allocation"), Bytes.from_hex("04")?])?.address
  Ok(TokenRewardWriteAddresses {
    base: addresses,
    token_config: derived(context.token, "token")?,
    morse: morse,
    oracle: derived(context.token, "oracle")?,
    binding: token_binding_address(context.judge, addresses.log_id)?,
    token_pool: token_reward_pool_address(context.program)?,
    token_epoch: token_reward_epoch_address(context.program, epoch)?,
    morse_vault: reward_pool_vault(context.program, morse)?,
    reserve_profile: token_reserve_profile_address(context.token)?,
    reserve_receipt: token_reserve_receipt_address(context.token, epoch)?,
    reserve_allocation: allocation,
    reserve_vault: vault(allocation, morse)?,
    token_data: program_data(context.token)?,
    judge_data: program_data(context.judge)?
  })
end

fn stage(context :: TokenRewardWriteContext,
  a :: TokenRewardWriteAddresses,
  finalizing :: Bool) -> List<AccountMeta> do
  [
    meta(a.base.pool, false, true),
    meta(a.token_pool, false, finalizing),
    meta(a.base.epoch, false, true),
    meta(a.token_epoch, false, true),
    meta(a.base.log, false, false),
    meta(a.base.clock, false, false),
    meta(a.base.attendance_epoch, false, false),
    meta(a.base.economics, false, false),
    meta(a.binding, false, false),
    meta(context.token, false, false),
    meta(a.token_data, false, false),
    meta(a.token_config, false, false),
    meta(a.morse, false, false),
    meta(a.oracle, false, false),
    meta(context.program, false, false),
    meta(a.base.program_data, false, false),
    meta(context.judge, false, false),
    meta(a.judge_data, false, false),
    meta(a.reserve_profile, false, false)
  ]
end

pub fn token_reserve_configure_instruction(context :: TokenRewardWriteContext,
  governance :: Pubkey,
  payer :: Pubkey) -> Instruction!String do
  let a = token_reward_write_addresses(context, U64.parse("0")?)?
  prepared(context.token,
    11,
    Bytes.empty(),
    [
      meta(wallet(governance)?, true, false),
      meta(wallet(payer)?, true, true),
      meta(a.token_config, false, false),
      meta(a.morse, false, false),
      meta(a.reserve_profile, false, true),
      meta(context.judge, false, false),
      meta(a.judge_data, false, false),
      meta(a.base.log, false, false),
      meta(a.base.economics, false, false),
      meta(a.binding, false, false),
      meta(context.program, false, false),
      meta(a.base.program_data, false, false),
      meta(a.base.pool, false, false),
      meta(context.usdc_mint, false, false),
      meta(a.oracle, false, false),
      meta(context.token, false, false),
      meta(a.token_data, false, false),
      meta(system()?, false, false)
    ])
end

pub fn token_reward_activate_instruction(context :: TokenRewardWriteContext,
  governance :: Pubkey,
  payer :: Pubkey) -> Instruction!String do
  let a = token_reward_write_addresses(context, U64.parse("0")?)?
  prepared(context.program,
    13,
    Bytes.empty(),
    [
      meta(wallet(governance)?, true, false),
      meta(wallet(payer)?, true, true),
      meta(a.base.pool, false, true),
      meta(a.token_pool, false, true),
      meta(a.morse_vault, false, true),
      meta(context.judge, false, false),
      meta(a.judge_data, false, false),
      meta(a.base.log, false, false),
      meta(a.base.economics, false, false),
      meta(a.binding, false, false),
      meta(context.token, false, false),
      meta(a.token_data, false, false),
      meta(a.token_config, false, false),
      meta(a.morse, false, false),
      meta(a.oracle, false, false),
      meta(a.reserve_profile, false, false),
      meta(context.program, false, false),
      meta(a.base.program_data, false, false),
      meta(classic_token()?, false, false),
      meta(ata_program()?, false, false),
      meta(system()?, false, false)
    ])
end

pub fn token_reward_open_instruction(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: U64) -> Instruction!String do
  let a = token_reward_write_addresses(context, epoch)?
  prepared(context.program,
    14,
    encoded(epoch)?,
    [
      meta(wallet(payer)?, true, true),
      meta(a.base.pool, false, false),
      meta(a.token_pool, false, false),
      meta(a.base.epoch, false, true),
      meta(a.token_epoch, false, true),
      meta(system()?, false, false)
    ])
end

pub fn token_reward_begin_instruction(context :: TokenRewardWriteContext,
  epoch :: U64) -> Instruction!String do
  prepared(context.program,
    15,
    Bytes.empty(),
    stage(context, token_reward_write_addresses(context, epoch)?, false))
end

pub fn token_reward_append_instruction(context :: TokenRewardWriteContext,
  epoch :: U64,
  witnesses :: List<RewardAppendWitness>) -> Instruction!String do
  if List.length(witnesses) < 1 || List.length(witnesses) > 3 do
    return Err("invalid_token_reward_write")
  end
  let a = token_reward_write_addresses(context, epoch)?
  let groups = for index in 0..List.length(witnesses) do
    let subject = List.get(witnesses, index)
    let witness = reward_witness_address(base(context), subject.key)?
    if witness != subject.witness
      || (index > 0
        && Bytes.to_hex(List.get(witnesses,
          index - 1).witness.bytes) >= Bytes.to_hex(witness.bytes)) do
      return Err("invalid_token_reward_write")
    end
    let bond = reward_bond_address(base(context), subject.key)?
    [
      meta(witness, false, false),
      meta(bond, false, false),
      meta(token_pending_address(context.judge, bond)?, false, false),
      meta(reward_member_address(context.program, witness)?, false, false)
    ]
  end
  prepared(context.program, 16, Bytes.empty(), stage(context, a, false) ++ List.flatten(groups))
end

pub fn token_reward_finalize_instruction(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: U64) -> Instruction!String do
  let a = token_reward_write_addresses(context, epoch)?
  prepared(context.program,
    17,
    Bytes.empty(),
    stage(context, a, true)
      ++ [
        meta(a.reserve_allocation, false, true),
        meta(a.reserve_vault, false, true),
        meta(a.morse_vault, false, true),
        meta(a.reserve_receipt, false, true),
        meta(wallet(payer)?, true, true),
        meta(classic_token()?, false, false),
        meta(system()?, false, false)
      ])
end

pub fn token_reward_claim_instruction(context :: TokenRewardWriteContext,
  epoch :: TokenRewardEpochAccount,
  row :: Int) -> Instruction!String do
  let a = token_reward_write_addresses(context, epoch.epoch)?
  if epoch.status != 2
    || epoch.pool != a.base.pool.bytes
    || epoch.token_pool != a.token_pool.bytes
    || epoch.ledger != a.base.epoch.bytes
    || row < 0
    || row >= 64
    || row >= List.length(epoch.rows) do
    return Err("invalid_token_reward_write")
  end
  let selected = List.get(epoch.rows, row)
  if selected.amount_morse == U64.parse("0")? || selected.claimed_morse do
    return Err("invalid_token_reward_write")
  end
  let payout = Pubkey { bytes: selected.payout }
  prepared(context.program,
    18,
    Bytes.write_uint_le(Int.to_string(row), 1)?,
    [
      meta(a.base.pool, false, false),
      meta(a.token_pool, false, true),
      meta(a.base.epoch, false, false),
      meta(a.token_epoch, false, true),
      meta(a.morse_vault, false, true),
      meta(vault(wallet(payout)?, a.morse)?, false, true),
      meta(a.morse, false, false),
      meta(classic_token()?, false, false)
    ])
end

pub fn token_reward_cancel_instruction(context :: TokenRewardWriteContext,
  epoch :: U64) -> Instruction!String do
  prepared(context.program,
    19,
    Bytes.empty(),
    stage(context, token_reward_write_addresses(context, epoch)?, false))
end

pub fn token_reward_claim_setup_instruction(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: TokenRewardEpochAccount,
  row :: Int) -> Instruction!String do
  let claim = token_reward_claim_instruction(context, epoch, row)?
  let a = token_reward_write_addresses(context, epoch.epoch)?
  create_associated_token_idempotent_instruction(wallet(payer)?,
    List.get(claim.accounts, 5).pubkey,
    Pubkey { bytes: List.get(epoch.rows, row).payout },
    a.morse)
end

pub fn token_reward_claim_usdc_instruction(context :: TokenRewardWriteContext,
  epoch :: TokenRewardEpochAccount,
  row :: Int) -> Instruction!String do
  let a = token_reward_write_addresses(context, epoch.epoch)?
  if epoch.status != 2
    || epoch.pool != a.base.pool.bytes
    || epoch.token_pool != a.token_pool.bytes
    || epoch.ledger != a.base.epoch.bytes
    || row < 0
    || row >= 64
    || row >= List.length(epoch.rows) do
    return Err("invalid_token_reward_write")
  end
  let selected = List.get(epoch.rows, row)
  if selected.amount_usd == U64.parse("0")? || selected.claimed_usd do
    return Err("invalid_token_reward_write")
  end
  let payout = wallet(Pubkey { bytes: selected.payout })?
  prepared(context.program,
    8,
    Bytes.write_uint_le(Int.to_string(row), 1)?,
    [
      meta(a.base.pool, false, true),
      meta(a.base.epoch, false, true),
      meta(a.base.vault, false, true),
      meta(vault(payout, context.usdc_mint)?, false, true),
      meta(context.usdc_mint, false, false),
      meta(classic_token()?, false, false)
    ])
end

pub fn token_reward_claim_usdc_setup_instruction(context :: TokenRewardWriteContext,
  payer :: Pubkey,
  epoch :: TokenRewardEpochAccount,
  row :: Int) -> Instruction!String do
  let claim = token_reward_claim_usdc_instruction(context, epoch, row)?
  create_associated_token_idempotent_instruction(wallet(payer)?,
    List.get(claim.accounts, 3).pubkey,
    Pubkey { bytes: List.get(epoch.rows, row).payout },
    context.usdc_mint)
end

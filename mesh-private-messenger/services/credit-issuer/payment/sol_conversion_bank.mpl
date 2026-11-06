from Payment.SolConversionPacket import (
  SolConversionProfile,
  sol_conversion_profile_hash,
  conversion_native_mint,
  conversion_raydium_program,
  conversion_token_program,
  conversion_destination,
  conversion_escrow
)
from Payment.Oracle import sol_price_from_account
from Solana.Read import (
  Pubkey,
  AccountInfo,
  AccountAtSlot,
  OptionalAccountsAtSlot,
  TokenAccount,
  pubkey,
  token_account,
  mint,
  clock_sysvar,
  clock_sysvar_address
)
from Solana.Address import find_program_address

pub struct SolConversionBank do
  profile_hash :: Bytes
  bank_hash :: Bytes
  slot :: U64
  now :: U64
  usd_micros :: U64
  published :: U64
  payer_lamports :: U64
  owner_lamports :: U64
end

fn cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(total, value) do Bytes.concat(total?, value) end)
end

fn code_address(program :: Pubkey) -> Pubkey!String do
  Ok(find_program_address(pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?,
    [program.bytes])?.address)
end

# Full code data is bounded and hashed, never accepted from a caller's Boolean or
# a provider-reported hash. An immutable BPF-loader image needs no ProgramData.
fn program_code(program :: AccountInfo,
  metadata :: Option<AccountInfo>,
  address :: Pubkey,
  pinned :: Bytes) -> Result<(), String> do
  if !program.executable
    || Bytes.length(program.data) == 0
    || Bytes.length(program.data) > 1048576 do
    return Err("sol_conversion_program_mismatch")
  end
  if program.owner == pubkey("BPFLoader2111111111111111111111111111111111")? do
    if metadata != None || Crypto.sha256(program.data) != pinned do
      return Err("sol_conversion_code_mismatch")
    end
  else
    let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
    let image = case metadata do
      None -> return Err("sol_conversion_code_missing")
      Some(value) -> value
    end
    if program.owner != loader
      || Bytes.length(program.data) != 36
      || Bytes.read_uint_le(program.data, 0, 4)? != "2"
      || Bytes.slice(program.data, 4, 32)? != code_address(address)?.bytes
      || image.owner != loader
      || image.executable
      || Bytes.length(image.data) < 45
      || Bytes.length(image.data) > 1048576
      || Bytes.read_uint_le(image.data, 0, 4)? != "3"
      || Crypto.sha256(image.data) != pinned do
      return Err("sol_conversion_code_mismatch")
    end
  end
  Ok(nil)
end

pub fn sol_conversion_bank_keys(profile :: SolConversionProfile,
  id :: Bytes) -> List<Pubkey>!String do
  sol_conversion_profile_hash(profile)?
  Ok([
    profile.owner,
    profile.payer,
    conversion_native_mint()?,
    profile.usdc,
    conversion_raydium_program()?,
    code_address(conversion_raydium_program()?)?,
    conversion_token_program()?,
    code_address(conversion_token_program()?)?,
    profile.pool,
    profile.amm_config,
    profile.input_vault,
    profile.output_vault,
    profile.observation,
    conversion_destination(profile)?,
    conversion_escrow(profile, id)?,
    clock_sysvar_address()?,
    profile.oracle
  ])
end

fn required(bank :: OptionalAccountsAtSlot, index :: Int) -> AccountInfo!String do
  case List.get(bank.accounts, index) do
    None -> Err("sol_conversion_account_missing")
    Some(value) -> Ok(value)
  end
end

fn owned(account :: AccountInfo, owner :: Pubkey) -> Result<(), String> do
  if account.owner != owner || account.executable || account.lamports == U64.parse("0")? do
    return Err("sol_conversion_account_owner")
  end
  Ok(nil)
end

fn token(account :: AccountInfo,
  owner :: Pubkey,
  asset :: Pubkey,
  native :: Bool) -> TokenAccount!String do
  owned(account, conversion_token_program()?)?
  let value = token_account(account)?
  if value.owner != owner
    || value.mint != asset
    || value.state != 1
    || value.delegate != None
    || value.close_authority != None
    || value.delegated_amount != U64.parse("0")?
    || (native && value.native_reserve == None)
    || (!native && value.native_reserve != None) do
    return Err("sol_conversion_token_custody")
  end
  if native do
    let rent = case value.native_reserve do
      Some(amount) -> amount
      None -> return Err("sol_conversion_native_rent")
    end
    if account.lamports != U64.add(value.amount, rent)? do
      return Err("sol_conversion_native_rent")
    end
  end
  Ok(value)
end

fn field(data :: Bytes, offset :: Int, value :: Bytes) -> Result<(), String> do
  if Bytes.slice(data, offset, Bytes.length(value))? != value do
    return Err("sol_conversion_pool_mismatch")
  end
  Ok(nil)
end

pub fn admit_sol_conversion_bank(profile :: SolConversionProfile,
  id :: Bytes,
  bank :: OptionalAccountsAtSlot) -> SolConversionBank!String do
  let profile_hash = sol_conversion_profile_hash(profile)?
  let keys = sol_conversion_bank_keys(profile, id)?
  if List.length(bank.accounts) != List.length(keys) || bank.slot == U64.parse("0")? do
    return Err("sol_conversion_bank_shape")
  end
  let system = pubkey("11111111111111111111111111111111")?
  let owner = required(bank, 0)?
  owned(owner, system)?
  let payer = required(bank, 1)?
  owned(payer, system)?
  if Bytes.length(owner.data) != 0 || Bytes.length(payer.data) != 0 do
    return Err("sol_conversion_system_account_data")
  end
  let native = conversion_native_mint()?
  let ray = conversion_raydium_program()?
  let token_program = conversion_token_program()?
  owned(required(bank, 2)?, token_program)?
  owned(required(bank, 3)?, token_program)?
  let native_mint = mint(required(bank, 2)?)?
  let usdc = mint(required(bank, 3)?)?
  if !native_mint.initialized
    || native_mint.decimals != 9
    || !usdc.initialized
    || usdc.decimals != 6 do
    return Err("sol_conversion_mint_mismatch")
  end
  program_code(required(bank, 4)?, List.get(bank.accounts, 5), ray, profile.raydium_code)?
  program_code(required(bank, 6)?, List.get(bank.accounts, 7), token_program, profile.token_code)?
  let pool = required(bank, 8)?
  let amm = required(bank, 9)?
  let observation = required(bank, 12)?
  for account in [pool, amm, observation] do
    owned(account, ray)?
  end
  if Bytes.length(pool.data) != 637
    || Bytes.length(amm.data) != 236
    || Bytes.length(observation.data) != 4075
    || Crypto.sha256(amm.data) != profile.amm_hash
    || Bytes.slice(pool.data,
      0,
      8)? != Bytes.slice(Crypto.sha256(Bytes.from_utf8("account:PoolState")), 0, 8)?
    || Bytes.slice(amm.data,
      0,
      8)? != Bytes.slice(Crypto.sha256(Bytes.from_utf8("account:AmmConfig")), 0, 8)?
    || Bytes.slice(observation.data,
      0,
      8)? != Bytes.slice(Crypto.sha256(Bytes.from_utf8("account:ObservationState")), 0, 8)?
    || (Bytes.get(pool.data, 329)? / 4) % 2 != 0 do
    return Err("sol_conversion_pool_mismatch")
  end
  field(pool.data, 8, profile.amm_config.bytes)?
  field(pool.data, 232, token_program.bytes)?
  field(pool.data, 264, token_program.bytes)?
  field(pool.data, 296, profile.observation.bytes)?
  let native_first = Bytes.slice(pool.data, 168, 32)? == native.bytes
  field(pool.data,
    if native_first do
      168
    else
      200
    end,
    native.bytes)?
  field(pool.data,
    if native_first do
      200
    else
      168
    end,
    profile.usdc.bytes)?
  field(pool.data,
    if native_first do
      72
    else
      104
    end,
    profile.input_vault.bytes)?
  field(pool.data,
    if native_first do
      104
    else
      72
    end,
    profile.output_vault.bytes)?
  if Bytes.get(pool.data,
    if native_first do
      331
    else
      332
    end)? != 9
    || Bytes.get(pool.data,
      if native_first do
        332
      else
        331
      end)? != 6 do
    return Err("sol_conversion_mint_mismatch")
  end
  token(required(bank, 10)?, profile.authority, native, true)?
  token(required(bank, 11)?, profile.authority, profile.usdc, false)?
  token(required(bank, 13)?, profile.owner, profile.usdc, false)?
  # Never adopt an old or donated escrow, even if its decoded amount looks right.
  if List.get(bank.accounts, 14) != None do
    return Err("sol_conversion_escrow_occupied")
  end
  let clock = clock_sysvar(required(bank, 15)?)?
  if clock.slot != bank.slot || clock.unix_timestamp <= 0 do
    return Err("sol_conversion_clock_mismatch")
  end
  let now = U64.parse(Int.to_string(clock.unix_timestamp))?
  let price = sol_price_from_account(AccountAtSlot {
      slot: bank.slot,
      account: required(bank, 16)?
    },
    now)?
  let hashes = for index in 0..List.length(keys) do
    let key = List.get(keys, index).bytes
    case List.get(bank.accounts, index) do
      None -> cat([key, Bytes.from_hex("00")?])?
      Some(value) -> cat([
        key,
        Bytes.from_hex("01")?,
        value.owner.bytes,
        Bytes.write_uint_le(U64.to_string(value.lamports), 8)?,
        Bytes.write_uint_le(U64.to_string(value.rent_epoch), 8)?,
        Bytes.from_hex(if value.executable do
          "01"
        else
          "00"
        end)?,
        Crypto.sha256(value.data)
      ])?
    end
  end
  Ok(SolConversionBank {
    profile_hash: profile_hash,
    bank_hash: Crypto.sha256(cat([
      profile_hash,
      Bytes.write_uint_le(U64.to_string(bank.slot), 8)?,
      cat(hashes)?
    ])?),
    slot: bank.slot,
    now: now,
    usd_micros: price.usd_micros,
    published: price.observed_at,
    payer_lamports: required(bank, 1)?.lamports,
    owner_lamports: owner.lamports
  })
end

# Reconciliation authenticates pinned code at a bank no earlier than execution.
# It deliberately does not require a fresh quote oracle or an enabled pool:
# neither condition can erase a finalized historical execution or its custody.
pub fn sol_conversion_reconciliation_bank(profile :: SolConversionProfile,
  bank :: OptionalAccountsAtSlot,
  execution_slot :: U64) -> U64!String do
  sol_conversion_profile_hash(profile)?
  if List.length(bank.accounts) != 17
    || bank.slot == U64.parse("0")?
    || U64.compare(bank.slot, execution_slot) < 0 do
    return Err("sol_conversion_reconcile_bank")
  end
  program_code(required(bank, 4)?,
    List.get(bank.accounts, 5),
    conversion_raydium_program()?,
    profile.raydium_code)?
  program_code(required(bank, 6)?,
    List.get(bank.accounts, 7),
    conversion_token_program()?,
    profile.token_code)?
  let clock = clock_sysvar(required(bank, 15)?)?
  if clock.slot != bank.slot || clock.unix_timestamp <= 0 do
    return Err("sol_conversion_clock_mismatch")
  end
  Ok(bank.slot)
end

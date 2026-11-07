# These builders derive every CPI role. Decoded bytes alone do not authenticate an RPC account.
from Transparency.TokenBurn import TokenBurnProfile, TokenBurnWeek, token_burn_route_minimum
from Transparency.TokenChain import TokenConfig, token_addresses, token_payout_address
from Transparency.TokenPolicy import token_burn_chunks
from Solana.Read import Pubkey, pubkey
from Solana.Address import find_program_address
from Solana.Tx import Instruction, AccountMeta

pub struct TokenBurnAddresses do
  profile :: Pubkey
  week :: Pubkey
  week_vault :: Pubkey
  chunk :: Pubkey
  chunk_input :: Pubkey
  chunk_output :: Pubkey
  treasury_source :: Pubkey
  jupiter_data :: Pubkey
  raydium_data :: Pubkey
  raydium_authority :: Pubkey
  jupiter_event :: Pubkey
end

fn burn_cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

fn burn_write_key(key :: Pubkey) -> Pubkey!String do
  if Bytes.length(key.bytes) != 32 || Bytes.to_hex(key.bytes) == String.repeat("00", 32) do
    Err("invalid_token_burn_key")
  else
    Ok(key)
  end
end

fn burn_meta(key :: Pubkey, signer :: Bool, writable :: Bool) -> AccountMeta do
  AccountMeta { pubkey: key, signer: signer, writable: writable }
end

fn burn_token_program() -> Pubkey!String do
  pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")
end

fn burn_ata_program() -> Pubkey!String do
  pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")
end

pub fn token_burn_jupiter_program() -> Pubkey!String do
  pubkey("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4")
end

pub fn token_burn_raydium_program() -> Pubkey!String do
  pubkey("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C")
end

fn burn_pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

fn burn_profile_roles(program :: Pubkey, profile :: TokenBurnProfile) -> Bool!String do
  let token = token_addresses(program)?
  burn_write_key(profile.usdc)?
  burn_write_key(profile.treasury)?
  burn_write_key(profile.factory)?
  if profile.config != token.config || profile.usdc == token.mint do
    return Err("invalid_token_burn_roles")
  end
  let usdc_first = Bytes.to_hex(profile.usdc.bytes) < Bytes.to_hex(token.mint.bytes)
  let mint0 = if usdc_first do
    profile.usdc
  else
    token.mint
  end
  let mint1 = if usdc_first do
    token.mint
  else
    profile.usdc
  end
  let raydium = token_burn_raydium_program()?
  let pool = burn_pda(raydium,
    [Bytes.from_utf8("pool"), profile.factory.bytes, mint0.bytes, mint1.bytes])?
  if profile.pool != pool
    || profile.vault0 != burn_pda(raydium,
        [Bytes.from_utf8("pool_vault"), pool.bytes, mint0.bytes])?
    || profile.vault1 != burn_pda(raydium,
        [Bytes.from_utf8("pool_vault"), pool.bytes, mint1.bytes])?
    || profile.observation != burn_pda(raydium, [Bytes.from_utf8("observation"), pool.bytes])? do
    Err("invalid_token_burn_roles")
  else
    Ok(true)
  end
end

pub fn token_burn_addresses(program :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64,
  index :: Int) -> TokenBurnAddresses!String do
  burn_profile_roles(program, profile)?
  if index < 0 || index >= 24 do
    return Err("invalid_token_burn_index")
  end
  let token = token_addresses(program)?
  let jupiter = token_burn_jupiter_program()?
  let raydium = token_burn_raydium_program()?
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let week = burn_pda(program,
    [Bytes.from_utf8("burn-week"), Bytes.write_uint_le(U64.to_string(epoch), 8)?])?
  let chunk = burn_pda(program,
    [Bytes.from_utf8("burn-chunk"), week.bytes, Bytes.write_uint_le(Int.to_string(index), 1)?])?
  Ok(TokenBurnAddresses {
    profile: burn_pda(program, [Bytes.from_utf8("swap")])?,
    week: week,
    week_vault: token_payout_address(week, profile.usdc)?,
    chunk: chunk,
    chunk_input: token_payout_address(chunk, profile.usdc)?,
    chunk_output: token_payout_address(chunk, token.mint)?,
    treasury_source: token_payout_address(profile.treasury, profile.usdc)?,
    jupiter_data: burn_pda(loader, [jupiter.bytes])?,
    raydium_data: burn_pda(loader, [raydium.bytes])?,
    raydium_authority: burn_pda(raydium, [Bytes.from_utf8("vault_and_lp_mint_auth_seed")])?,
    jupiter_event: burn_pda(jupiter, [Bytes.from_utf8("__event_authority")])?
  })
end

pub fn token_burn_configure_instruction(program :: Pubkey,
  payer :: Pubkey,
  config :: TokenConfig,
  profile :: TokenBurnProfile) -> Instruction!String do
  burn_write_key(payer)?
  burn_write_key(config.governance)?
  let token = token_addresses(program)?
  let a = token_burn_addresses(program, profile, U64.parse("0")?, 0)?
  if config.mint != token.mint do
    return Err("invalid_token_burn_roles")
  end
  Ok(Instruction {
    program_id: program,
    data: Bytes.from_hex("08")?,
    accounts: [
      burn_meta(config.governance, true, false),
      burn_meta(payer, true, true),
      burn_meta(token.config, false, false),
      burn_meta(token.mint, false, false),
      burn_meta(a.profile, false, true),
      burn_meta(profile.usdc, false, false),
      burn_meta(profile.treasury, false, false),
      burn_meta(profile.pool, false, false),
      burn_meta(profile.factory, false, false),
      burn_meta(profile.vault0, false, false),
      burn_meta(profile.vault1, false, false),
      burn_meta(profile.observation, false, false),
      burn_meta(token_burn_jupiter_program()?, false, false),
      burn_meta(a.jupiter_data, false, false),
      burn_meta(token_burn_raydium_program()?, false, false),
      burn_meta(a.raydium_data, false, false),
      burn_meta(pubkey("11111111111111111111111111111111")?, false, false)
    ]
  })
end

pub fn token_burn_fund_instruction(program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  epoch :: U64,
  budget :: U64,
  weights :: List<U64>,
  entropy :: List<U64>) -> Instruction!String do
  burn_write_key(payer)?
  if List.length(weights) != 24 || List.length(entropy) != 24 do
    return Err("invalid_token_burn_schedule")
  end
  token_burn_chunks(budget, U64.multiply(epoch, U64.parse("604800")?)?, weights, entropy)?
  let schedule = for index in 0..24 do
    burn_cat([
      Bytes.write_uint_le(U64.to_string(List.get(weights, index)), 4)?,
      Bytes.write_uint_le(U64.to_string(List.get(entropy, index)), 8)?
    ])?
  end
  let token = token_addresses(program)?
  let a = token_burn_addresses(program, profile, epoch, 0)?
  let payload = burn_cat([
    Bytes.from_hex("09")?,
    Bytes.write_uint_le(U64.to_string(epoch), 8)?,
    Bytes.write_uint_le(U64.to_string(budget), 8)?
  ]
    ++ schedule)?
  Ok(Instruction {
    program_id: program,
    data: payload,
    accounts: [
      burn_meta(profile.treasury, true, false),
      burn_meta(payer, true, true),
      burn_meta(token.config, false, false),
      burn_meta(token.mint, false, false),
      burn_meta(a.profile, false, false),
      burn_meta(profile.usdc, false, false),
      burn_meta(a.week, false, true),
      burn_meta(a.week_vault, false, true),
      burn_meta(a.treasury_source, false, true),
      burn_meta(burn_token_program()?, false, false),
      burn_meta(burn_ata_program()?, false, false),
      burn_meta(pubkey("11111111111111111111111111111111")?, false, false),
      burn_meta(token_burn_jupiter_program()?, false, false),
      burn_meta(a.jupiter_data, false, false),
      burn_meta(token_burn_raydium_program()?, false, false),
      burn_meta(a.raydium_data, false, false),
      burn_meta(token.oracle, false, false)
    ]
  })
end

pub fn token_burn_execute_instruction(program :: Pubkey,
  payer :: Pubkey,
  profile :: TokenBurnProfile,
  week :: TokenBurnWeek,
  index :: Int,
  route :: Bytes,
  spot :: U64) -> Instruction!String do
  burn_write_key(payer)?
  let token = token_addresses(program)?
  let a = token_burn_addresses(program, profile, week.epoch, index)?
  if week.profile != a.profile
    || week.usdc != profile.usdc
    || week.treasury != profile.treasury
    || week.vault != a.week_vault
    || week.source != a.treasury_source
    || List.length(week.rows) != 24 do
    return Err("invalid_token_burn_roles")
  end
  token_burn_route_minimum(route, List.get(week.rows, index).amount, spot)?
  let usdc_first = Bytes.to_hex(profile.usdc.bytes) < Bytes.to_hex(token.mint.bytes)
  let input_vault = if usdc_first do
    profile.vault0
  else
    profile.vault1
  end
  let output_vault = if usdc_first do
    profile.vault1
  else
    profile.vault0
  end
  Ok(Instruction {
    program_id: program,
    data: burn_cat([Bytes.from_hex("0a")?, Bytes.write_uint_le(Int.to_string(index), 1)?, route])?,
    accounts: [
      burn_meta(payer, true, true),
      burn_meta(token.config, false, false),
      burn_meta(token.mint, false, true),
      burn_meta(a.profile, false, false),
      burn_meta(profile.usdc, false, false),
      burn_meta(a.week, false, true),
      burn_meta(a.week_vault, false, true),
      burn_meta(a.chunk, false, false),
      burn_meta(a.chunk_input, false, true),
      burn_meta(a.chunk_output, false, true),
      burn_meta(token.oracle, false, false),
      burn_meta(burn_token_program()?, false, false),
      burn_meta(burn_ata_program()?, false, false),
      burn_meta(pubkey("11111111111111111111111111111111")?, false, false),
      burn_meta(token_burn_jupiter_program()?, false, false),
      burn_meta(a.jupiter_data, false, false),
      burn_meta(token_burn_raydium_program()?, false, false),
      burn_meta(a.raydium_data, false, false),
      burn_meta(profile.pool, false, true),
      burn_meta(profile.factory, false, false),
      burn_meta(input_vault, false, true),
      burn_meta(output_vault, false, true),
      burn_meta(profile.observation, false, true),
      burn_meta(a.raydium_authority, false, false),
      burn_meta(a.jupiter_event, false, false)
    ]
  })
end

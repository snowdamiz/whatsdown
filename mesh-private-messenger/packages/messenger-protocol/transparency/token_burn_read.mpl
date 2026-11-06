from Transparency.AnchorRpc import validate_anchor_sources
from Transparency.TokenBurn import (
  TokenBurnProfile,
  TokenBurnWeek,
  decode_token_burn_profile
)
from Transparency.TokenBurnCarry import decode_token_burn_carry_frame
from Transparency.TokenBurnWrite import (
  token_burn_addresses,
  token_burn_jupiter_program,
  token_burn_raydium_program
)
from Transparency.TokenChain import (
  token_addresses,
  decode_token_config,
  decode_token_oracle,
  token_oracle_spot,
  token_oracle_twap
)
from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  mint,
  token_account,
  clock_sysvar,
  get_multiple_accounts_slice_request,
  optional_accounts_slice_from_response,
  rpc_send
)
from Solana.Address import find_program_address

pub struct TokenBurnReadPins do
  program :: Pubkey
  governance :: Pubkey
  program_slot :: U64
  usdc :: Pubkey
  treasury :: Pubkey
  factory :: Pubkey
end

pub struct TokenBurnState do
  context_slot :: U64
  timestamp :: Int
  profile :: TokenBurnProfile
  week :: Option<TokenBurnWeek>
  supply :: U64
  remaining :: U64
  vault_surplus :: U64
  code_current :: Bool
  spot :: Option<U64>
  twap :: Option<U64>
  digest :: Bytes
end

# Raw active-frame decoding only; callers still authenticate account owner, address and space.
# Closed frames remain reconciliation inputs for the custody-only carry reader.
pub fn decode_token_burn_active_week(data :: Bytes) -> TokenBurnWeek!String do
  let frame = decode_token_burn_carry_frame(data)?
  if frame.closed do
    Err("token_burn_week_closed")
  else
    Ok(frame.week)
  end
end

fn read_burn_part(data :: Bytes, at :: Int, length :: Int) -> Bytes!String do
  Bytes.slice(data, at, length)
end

fn read_burn_wide(data :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, at, 8)?)
end

fn read_burn_pda(program :: Pubkey, seeds :: List<Bytes>) -> Pubkey!String do
  Ok(find_program_address(program, seeds)?.address)
end

fn read_burn_profile(pins :: TokenBurnReadPins) -> TokenBurnProfile!String do
  let token = token_addresses(pins.program)?
  for key in [pins.governance, pins.usdc, pins.treasury, pins.factory] do
    if Bytes.length(key.bytes) != 32 || Bytes.to_hex(key.bytes) == String.repeat("00", 32) do
      return Err("invalid_token_burn_pins")
    end
  end
  if pins.usdc == token.mint do
    return Err("invalid_token_burn_pins")
  end
  let usdc_first = Bytes.to_hex(pins.usdc.bytes) < Bytes.to_hex(token.mint.bytes)
  let mint0 = if usdc_first do
    pins.usdc
  else
    token.mint
  end
  let mint1 = if usdc_first do
    token.mint
  else
    pins.usdc
  end
  let ray = token_burn_raydium_program()?
  let pool = read_burn_pda(ray,
    [Bytes.from_utf8("pool"), pins.factory.bytes, mint0.bytes, mint1.bytes])?
  Ok(TokenBurnProfile {
    config: token.config,
    usdc: pins.usdc,
    treasury: pins.treasury,
    factory: pins.factory,
    pool: pool,
    vault0: read_burn_pda(ray, [Bytes.from_utf8("pool_vault"), pool.bytes, mint0.bytes])?,
    vault1: read_burn_pda(ray, [Bytes.from_utf8("pool_vault"), pool.bytes, mint1.bytes])?,
    observation: read_burn_pda(ray, [Bytes.from_utf8("observation"), pool.bytes])?,
    jupiter_slot: U64.parse("0")?,
    raydium_slot: U64.parse("0")?,
    ready_at: U64.parse("1")?,
    factory_hash: Bytes.from_hex(String.repeat("00", 32))?
  })
end

pub fn token_burn_read_keys(pins :: TokenBurnReadPins, epoch :: U64) -> List<Pubkey>!String do
  let p = read_burn_profile(pins)?
  let token = token_addresses(pins.program)?
  let a = token_burn_addresses(pins.program, p, epoch, 0)?
  Ok([
    token.config,
    token.mint,
    a.profile,
    pins.usdc,
    token.oracle,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    token_burn_jupiter_program()?,
    a.jupiter_data,
    token_burn_raydium_program()?,
    a.raydium_data,
    p.pool,
    p.factory,
    p.vault0,
    p.vault1,
    p.observation,
    a.week,
    a.week_vault,
    pins.program,
    token.program_data
  ])
end

fn read_burn_required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  length :: Int,
  executable :: Bool) -> AccountSlice!String do
  let value = case List.get(snapshot.accounts, index) do
    None -> return Err("token_burn_account_missing")
    Some(value) -> value
  end
  if value.info.owner != owner
    || value.info.executable != executable
    || value.info.lamports == U64.parse("0")?
    || value.space != space
    || Bytes.length(value.info.data) != length do
    Err("token_burn_account_mismatch")
  else
    Ok(value)
  end
end

fn read_burn_owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  size :: Int) -> AccountSlice!String do
  read_burn_required(snapshot, index, owner, U64.parse(Int.to_string(size))?, size, false)
end

fn read_burn_code(snapshot :: OptionalAccountSlicesAtSlot,
  program :: Pubkey,
  image_index :: Int,
  data_index :: Int) -> U64!String do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = read_burn_required(snapshot,
    image_index,
    loader,
    U64.parse("36")?,
    36,
    true)?.info.data
  let pd = read_burn_pda(loader, [program.bytes])?
  if Bytes.to_hex(read_burn_part(image, 0, 4)?) != "02000000"
    || read_burn_part(image, 4, 32)? != pd.bytes do
    return Err("token_burn_executable_mismatch")
  end
  let value = case List.get(snapshot.accounts, data_index) do
    None -> return Err("token_burn_program_data_missing")
    Some(value) -> value
  end
  if U64.compare(value.space, U64.parse("45")?) < 0
    || U64.compare(value.space, U64.parse("10485760")?) > 0 do
    return Err("token_burn_program_data_mismatch")
  end
  let length = if U64.compare(value.space, U64.parse("5728")?) > 0 do
    5728
  else
    case String.to_int(U64.to_string(value.space)) do
      None -> return Err("token_burn_program_data_mismatch")
      Some(value) -> value
    end
  end
  let data = read_burn_required(snapshot, data_index, loader, value.space, length, false)?.info.data
  let slot = read_burn_wide(data, 4)?
  if Bytes.to_hex(read_burn_part(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || U64.compare(slot, snapshot.slot) > 0 do
    Err("token_burn_program_data_mismatch")
  else
    Ok(slot)
  end
end

fn read_burn_vault(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  mint_key :: Pubkey,
  owner :: Pubkey) -> U64!String do
  let value = token_account(read_burn_owned(snapshot,
    index,
    pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?,
    165)?.info)?
  if value.mint != mint_key
    || value.owner != owner
    || value.state != 1
    || value.delegate != None
    || value.native_reserve != None
    || value.close_authority != None
    || value.delegated_amount != U64.parse("0")? do
    Err("token_burn_vault_mismatch")
  else
    Ok(value.amount)
  end
end

fn read_burn_absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(value) -> !value.info.executable
      && Bytes.length(value.info.data) == 0
      && Bytes.to_hex(value.info.owner.bytes) == String.repeat("00", 32)
      && U64.to_string(value.space) == "0"
  end
end

fn read_burn_digest(snapshot :: OptionalAccountSlicesAtSlot) -> Bytes!String do
  let pieces = for value in snapshot.accounts do
    case value do
      None -> Bytes.from_hex("00")?
      Some(value) ->
        Bytes.concat(Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex(if value.info.executable do
                  "0101"
                else
                  "0100"
                end)?,
                value.info.owner.bytes)?,
              Bytes.write_uint_le(U64.to_string(value.space), 8)?)?,
            Bytes.write_uint_le(U64.to_string(value.info.lamports), 8)?)?,
          value.info.data)?
    end
  end
  let data = List.reduce(pieces,
    Ok(Bytes.from_utf8("morse-burn-account-snapshot-v1")),
    fn(result, value) do Bytes.concat(result?, value) end)?
  Ok(Crypto.sha256(data))
end

pub fn decode_token_burn_snapshot(pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> TokenBurnState!String do
  if List.length(snapshot.accounts) != 19 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("invalid_token_burn_snapshot")
  end
  let expected = read_burn_profile(pins)?
  let token = token_addresses(pins.program)?
  let a = token_burn_addresses(pins.program, expected, epoch, 0)?
  let config = decode_token_config(read_burn_owned(snapshot, 0, pins.program, 320)?.info.data)?
  if config.governance != pins.governance || config.mint != token.mint do
    return Err("token_burn_config_mismatch")
  end
  let token_program = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let morse = mint(read_burn_owned(snapshot, 1, token_program, 82)?.info)?
  let usdc = mint(read_burn_owned(snapshot, 3, token_program, 82)?.info)?
  if !morse.initialized
    || morse.decimals != 6
    || morse.mint_authority != None
    || morse.freeze_authority != None
    || U64.compare(morse.supply, U64.parse("1000000000000000")?) > 0
    || !usdc.initialized
    || usdc.decimals != 6 do
    return Err("token_burn_mint_mismatch")
  end
  let profile = decode_token_burn_profile(read_burn_owned(snapshot,
    2,
    pins.program,
    320)?.info.data)?
  if profile.config != expected.config
    || profile.usdc != expected.usdc
    || profile.treasury != expected.treasury
    || profile.pool != expected.pool
    || profile.factory != expected.factory
    || profile.vault0 != expected.vault0
    || profile.vault1 != expected.vault1
    || profile.observation != expected.observation do
    return Err("token_burn_profile_mismatch")
  end
  let clock = clock_sysvar(read_burn_owned(snapshot,
    5,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    40)?.info)?
  if clock.unix_timestamp <= 0 || clock.slot != snapshot.slot do
    return Err("token_burn_clock_mismatch")
  end
  let oracle_data = read_burn_owned(snapshot, 4, pins.program, 5728)?.info.data
  let oracle = decode_token_oracle(oracle_data)?
  if oracle.config != token.config
    || oracle.mint != token.mint
    || U64.compare(oracle.last_slot, snapshot.slot) > 0 do
    return Err("token_burn_oracle_mismatch")
  end
  let now = U64.parse(Int.to_string(clock.unix_timestamp))?
  let spot = case token_oracle_spot(oracle_data, now) do
    Ok(value) -> Some(value)
    Err(_) -> None
  end
  let twap = case token_oracle_twap(oracle_data, now) do
    Ok(value) -> Some(value)
    Err(_) -> None
  end
  let jupiter_slot = read_burn_code(snapshot, token_burn_jupiter_program()?, 6, 7)?
  let raydium_slot = read_burn_code(snapshot, token_burn_raydium_program()?, 8, 9)?
  let program_slot = read_burn_code(snapshot, pins.program, 17, 18)?
  let raydium = token_burn_raydium_program()?
  let pool = read_burn_owned(snapshot, 10, raydium, 637)?.info.data
  let factory = read_burn_owned(snapshot, 11, raydium, 236)?.info.data
  let observation = read_burn_owned(snapshot, 14, raydium, 4075)?.info.data
  let usdc_first = Bytes.to_hex(pins.usdc.bytes) < Bytes.to_hex(token.mint.bytes)
  let mint0 = if usdc_first do
    pins.usdc
  else
    token.mint
  end
  let mint1 = if usdc_first do
    token.mint
  else
    pins.usdc
  end
  let factory_index = Bytes.concat(Bytes.slice(factory, 11, 1)?, Bytes.slice(factory, 10, 1)?)?
  if Bytes.to_hex(Bytes.slice(pool, 0, 8)?) != "f7ede3f5d7c3de46"
    || Bytes.to_hex(Bytes.slice(factory, 0, 8)?) != "daf42168cbcb2b6f"
    || Bytes.to_hex(Bytes.slice(observation, 0, 8)?) != "7aaec5358109a584"
    || read_burn_pda(raydium, [Bytes.from_utf8("amm_config"), factory_index])? != pins.factory
    || Bytes.slice(pool, 8, 32)? != pins.factory.bytes
    || Bytes.slice(pool, 72, 32)? != profile.vault0.bytes
    || Bytes.slice(pool, 104, 32)? != profile.vault1.bytes
    || Bytes.slice(pool, 168, 32)? != mint0.bytes
    || Bytes.slice(pool, 200, 32)? != mint1.bytes
    || Bytes.slice(pool, 232, 32)? != token_program.bytes
    || Bytes.slice(pool, 264, 32)? != token_program.bytes
    || Bytes.slice(pool, 296, 32)? != profile.observation.bytes
    || Bytes.get(pool, 331)? != 6
    || Bytes.get(pool, 332)? != 6 do
    return Err("token_burn_pool_mismatch")
  end
  read_burn_vault(snapshot, 12, mint0, a.raydium_authority)?
  read_burn_vault(snapshot, 13, mint1, a.raydium_authority)?
  let week = if read_burn_absent(List.get(snapshot.accounts, 15)) do
    None
  else
    let account = case List.get(snapshot.accounts, 15) do
      None -> return Err("token_burn_account_missing")
      Some(value) -> value
    end
    let length = if account.space == U64.parse("2176")? do
      2176
    else if account.space == U64.parse("2240")? do
      2240
    else
      return Err("token_burn_account_mismatch")
    end
    let frame = decode_token_burn_carry_frame(read_burn_owned(snapshot,
      15,
      pins.program,
      length)?.info.data)?
    if frame.closed do
      return Err("token_burn_week_closed")
    end
    if frame.version == 2
      && frame.carry != Some(read_burn_pda(pins.program, [Bytes.from_utf8("burn-carry")])?) do
      return Err("token_burn_week_mismatch")
    end
    let value = frame.week
    if value.epoch != epoch
      || value.profile != a.profile
      || value.usdc != pins.usdc
      || value.treasury != pins.treasury
      || value.vault != a.week_vault
      || value.source != a.treasury_source do
      return Err("token_burn_week_mismatch")
    end
    Some(value)
  end
  let remaining = case week do
    None -> U64.parse("0")?
    Some(value) -> U64.subtract(value.budget, value.spent)?
  end
  let balance = if read_burn_absent(List.get(snapshot.accounts, 16)) do
    case week do
      None -> U64.parse("0")?
      Some(_) -> return Err("token_burn_account_missing")
    end
  else
    read_burn_vault(snapshot, 16, pins.usdc, a.week)?
  end
  let surplus = U64.subtract(balance, remaining)?
  let pool_enabled = (Bytes.get(pool, 329)? / 4) % 2 == 0
  Ok(TokenBurnState {
    context_slot: snapshot.slot,
    timestamp: clock.unix_timestamp,
    profile: profile,
    week: week,
    supply: morse.supply,
    remaining: remaining,
    vault_surplus: surplus,
    code_current: jupiter_slot == profile.jupiter_slot
      && raydium_slot == profile.raydium_slot
      && program_slot == pins.program_slot
      && Crypto.sha256(factory) == profile.factory_hash
      && pool_enabled,
    spot: spot,
    twap: twap,
    digest: read_burn_digest(snapshot)?
  })
end

# One finalized bank, bounded to 19 accounts and 5728 bytes per account. This establishes
# schema/owner/address pins, not independent provider agreement or a live price feed.
pub fn read_token_burn_from(client :: Int,
  url :: String,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenBurnState!String do
  let request = get_multiple_accounts_slice_request(1,
    token_burn_read_keys(pins, epoch)?,
    "finalized",
    0,
    5728,
    Some(minimum))?
  let response = rpc_send(client, url, request, 5000, 262144)?
  decode_token_burn_snapshot(pins, epoch, minimum, optional_accounts_slice_from_response(response)?)
end

fn read_burn_agree(first :: TokenBurnState!String,
  second :: TokenBurnState!String) -> Option<TokenBurnState> do
  case first do
    Err(_) -> None
    Ok(first) -> case second do
      Err(_) -> None
      Ok(second) -> if first.digest != second.digest do
        None
      else
        Some(if U64.compare(first.context_slot, second.context_slot) >= 0 do
          first
        else
          second
        end)
      end
    end
  end
end

# Configured operators must be independent; different URL strings cannot prove ownership.
# No redirects, three bounded attempts, and two identical authenticated account snapshots.
pub fn read_token_burn_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenBurnState!String do
  token_burn_rpc_sources(urls, test_mode)?
  let first = read_token_burn_from(client, List.get(urls, 0), pins, epoch, minimum)
  let second = read_token_burn_from(client, List.get(urls, 1), pins, epoch, minimum)
  case read_burn_agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_token_burn_from(client, List.get(urls, 2), pins, epoch, minimum)
  case read_burn_agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case read_burn_agree(second, third) do
    Some(value) -> Ok(value)
    None -> Err("token_burn_rpc_no_agreement")
  end
end

pub fn token_burn_rpc_sources(urls :: List<String>, test_mode :: Bool) -> Bool!String do
  if List.length(urls) != 3 do
    return Err("invalid_token_burn_rpc_sources")
  end
  for url in urls do
    if String.length(url) > 2048 || String.contains(url, "\n") || String.contains(url, "\r") do
      return Err("invalid_token_burn_rpc_sources")
    end
  end
  # Qualified normalization rejects credentials, fragments, backslashes and
  # duplicate origins even when paths/default ports/host spelling differ.
  case validate_anchor_sources(urls) do
    Err(_) -> return Err("invalid_token_burn_rpc_sources")
    Ok(_) -> nil
  end
  for url in urls do
    let origin = Http.url_origin(url)?
    if !String.starts_with(origin, "https://")
      && !(test_mode && String.starts_with(origin, "http://127.0.0.1:")) do
      return Err("invalid_token_burn_rpc_sources")
    end
  end
  Ok(true)
end

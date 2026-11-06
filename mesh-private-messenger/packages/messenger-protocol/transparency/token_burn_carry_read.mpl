# Custody-only bank authentication: no oracle, route or external DEX availability dependency.
from Transparency.TokenBurn import TokenBurnProfile, decode_token_burn_profile
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnCarry import (
  TokenBurnCarryFrame,
  TokenBurnCarryAccount,
  TokenBurnCloseReceipt,
  decode_token_burn_carry_frame,
  decode_token_burn_carry_account,
  decode_token_burn_close_receipt
)
from Transparency.TokenBurnCarryWrite import (
  token_burn_carry_addresses,
  token_burn_close_instruction
)
from Transparency.TokenBurnWrite import token_burn_addresses
from Transparency.TokenChain import token_addresses, decode_token_config
from Transparency.TokenBurnRead import token_burn_rpc_sources
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
from Solana.Tx import Instruction

pub struct TokenBurnCarryState do
  context_slot :: U64
  timestamp :: Int
  profile :: TokenBurnProfile
  frame :: Option<TokenBurnCarryFrame>
  carry :: Option<TokenBurnCarryAccount>
  receipt :: Option<TokenBurnCloseReceipt>
  remaining :: U64
  week_surplus :: U64
  carry_surplus :: U64
  code_current :: Bool
  digest :: Bytes
end

fn carry_read_key(program :: Pubkey, seed :: String) -> Pubkey!String do
  Ok(find_program_address(program, [Bytes.from_utf8(seed)])?.address)
end

pub fn token_burn_carry_read_keys(pins :: TokenBurnReadPins, epoch :: U64) -> List<Pubkey>!String do
  for key in [pins.program, pins.governance, pins.usdc, pins.treasury, pins.factory] do
    if Bytes.length(key.bytes) != 32 || Bytes.to_hex(key.bytes) == String.repeat("00", 32) do
      return Err("invalid_burn_carry_pins")
    end
  end
  let token = token_addresses(pins.program)?
  let a = token_burn_carry_addresses(pins.program, pins.usdc, epoch)?
  let week = find_program_address(pins.program,
    [Bytes.from_utf8("burn-week"), Bytes.write_uint_le(U64.to_string(epoch), 8)?])?.address
  let ata = pubkey("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL")?
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let vault = find_program_address(ata, [week.bytes, spl.bytes, pins.usdc.bytes])?.address
  Ok([
    token.config,
    token.mint,
    carry_read_key(pins.program, "swap")?,
    pins.usdc,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    week,
    vault,
    a.carry,
    a.carry_vault,
    a.receipt,
    pins.program,
    token.program_data
  ])
end

fn carry_read_required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  length :: Int,
  executable :: Bool) -> AccountSlice!String do
  let a = case List.get(snapshot.accounts, index) do
    None -> return Err("burn_carry_account_missing")
    Some(value) -> value
  end
  if a.info.owner != owner
    || a.space != space
    || Bytes.length(a.info.data) != length
    || a.info.executable != executable
    || a.info.lamports == U64.parse("0")? do
    Err("burn_carry_account_mismatch")
  else
    Ok(a)
  end
end

fn carry_read_owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  length :: Int) -> AccountSlice!String do
  carry_read_required(snapshot, index, owner, U64.parse(Int.to_string(length))?, length, false)
end

fn carry_read_absent(value :: Option<AccountSlice>) -> Bool do
  case value do
    None -> true
    Some(a) -> !a.info.executable
      && Bytes.length(a.info.data) == 0
      && Bytes.to_hex(a.info.owner.bytes) == String.repeat("00", 32)
      && U64.to_string(a.space) == "0"
  end
end

fn carry_read_vault(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  usdc :: Pubkey,
  owner :: Pubkey) -> U64!String do
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let value = token_account(carry_read_owned(snapshot, index, spl, 165)?.info)?
  if value.mint != usdc
    || value.owner != owner
    || value.state != 1
    || value.delegate != None
    || value.native_reserve != None
    || value.close_authority != None
    || value.delegated_amount != U64.parse("0")? do
    Err("burn_carry_vault_mismatch")
  else
    Ok(value.amount)
  end
end

fn carry_read_code(snapshot :: OptionalAccountSlicesAtSlot,
  pins :: TokenBurnReadPins) -> U64!String do
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = carry_read_required(snapshot, 10, loader, U64.parse("36")?, 36, true)?.info.data
  let token = token_addresses(pins.program)?
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != token.program_data.bytes do
    return Err("burn_carry_executable_mismatch")
  end
  let pd = case List.get(snapshot.accounts, 11) do
    None -> return Err("burn_carry_program_missing")
    Some(value) -> value
  end
  if U64.compare(pd.space, U64.parse("45")?) < 0
    || U64.compare(pd.space, U64.parse("10485760")?) > 0 do
    return Err("burn_carry_program_mismatch")
  end
  let length = if U64.compare(pd.space, U64.parse("2240")?) > 0 do
    2240
  else
    case String.to_int(U64.to_string(pd.space)) do
      None -> return Err("burn_carry_program_mismatch")
      Some(value) -> value
    end
  end
  let data = carry_read_required(snapshot, 11, loader, pd.space, length, false)?.info.data
  let slot = U64.parse(Bytes.read_uint_le(data, 4, 8)?)?
  if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || U64.compare(slot, snapshot.slot) > 0 do
    Err("burn_carry_program_mismatch")
  else
    Ok(slot)
  end
end

fn carry_read_digest(keys :: List<Pubkey>,
  snapshot :: OptionalAccountSlicesAtSlot) -> Bytes!String do
  let parts = for index in 0..List.length(keys) do
    let body = case List.get(snapshot.accounts, index) do
      None -> Bytes.from_hex("00")?
      Some(a) ->
        let head = Bytes.concat(Bytes.concat(Bytes.concat(Bytes.from_hex(if a.info.executable do
                "0101"
              else
                "0100"
              end)?,
              a.info.owner.bytes)?,
            Bytes.write_uint_le(U64.to_string(a.space), 8)?)?,
          Bytes.write_uint_le(U64.to_string(a.info.lamports), 8)?)?
        Bytes.concat(head, Crypto.sha256(a.info.data))?
    end
    Bytes.concat(List.get(keys, index).bytes, body)?
  end
  Ok(Crypto.sha256(List.reduce(parts,
    Ok(Bytes.from_utf8("morse-burn-carry-bank-v1")),
    fn(result, value) do Bytes.concat(result?, value) end)?))
end

pub fn decode_token_burn_carry_snapshot(pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> TokenBurnCarryState!String do
  if List.length(snapshot.accounts) != 12 || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("invalid_burn_carry_snapshot")
  end
  let keys = token_burn_carry_read_keys(pins, epoch)?
  let token = token_addresses(pins.program)?
  let a = token_burn_carry_addresses(pins.program, pins.usdc, epoch)?
  let config = decode_token_config(carry_read_owned(snapshot, 0, pins.program, 320)?.info.data)?
  if config.governance != pins.governance || config.mint != token.mint do
    return Err("burn_carry_config_mismatch")
  end
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let morse = mint(carry_read_owned(snapshot, 1, spl, 82)?.info)?
  let usdc = mint(carry_read_owned(snapshot, 3, spl, 82)?.info)?
  if !morse.initialized
    || morse.decimals != 6
    || morse.mint_authority != None
    || morse.freeze_authority != None
    || U64.compare(morse.supply, U64.parse("1000000000000000")?) > 0
    || !usdc.initialized
    || usdc.decimals != 6 do
    return Err("burn_carry_mint_mismatch")
  end
  let profile = decode_token_burn_profile(carry_read_owned(snapshot,
    2,
    pins.program,
    320)?.info.data)?
  if profile.config != token.config
    || profile.usdc != pins.usdc
    || profile.treasury != pins.treasury
    || profile.factory != pins.factory do
    return Err("burn_carry_profile_mismatch")
  end
  let addresses = token_burn_addresses(pins.program, profile, epoch, 0)?
  let clock = clock_sysvar(carry_read_owned(snapshot,
    4,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    40)?.info)?
  if clock.unix_timestamp <= 0 || clock.slot != snapshot.slot do
    return Err("burn_carry_clock_mismatch")
  end
  let code = carry_read_code(snapshot, pins)?
  let raw = case List.get(snapshot.accounts, 5) do
    None -> return Err("burn_carry_week_missing")
    Some(value) -> value
  end
  let length = Bytes.length(raw.info.data)
  if length != 2176 && length != 2240 do
    return Err("burn_carry_week_mismatch")
  end
  let frame = decode_token_burn_carry_frame(carry_read_owned(snapshot,
    5,
    pins.program,
    length)?.info.data)?
  let week = frame.week
  if week.profile != addresses.profile
    || week.epoch != epoch
    || week.usdc != pins.usdc
    || week.treasury != pins.treasury
    || week.vault != addresses.week_vault
    || week.source != addresses.treasury_source
    || (frame.version == 2 && frame.carry != Some(a.carry)) do
    return Err("burn_carry_week_context_mismatch")
  end
  let carry = if carry_read_absent(List.get(snapshot.accounts, 7)) do
    None
  else
    let value = decode_token_burn_carry_account(carry_read_owned(snapshot,
      7,
      pins.program,
      192)?.info.data)?
    if value.profile != addresses.profile
      || value.usdc != pins.usdc
      || value.vault != a.carry_vault do
      return Err("burn_carry_context_mismatch")
    end
    Some(value)
  end
  let accounted = case carry do
    None -> U64.parse("0")?
    Some(value) -> value.accounted
  end
  let carry_balance = if carry_read_absent(List.get(snapshot.accounts, 8)) do
    if carry != None do
      return Err("burn_carry_vault_missing")
    end
    U64.parse("0")?
  else
    carry_read_vault(snapshot, 8, pins.usdc, a.carry)?
  end
  let remaining = if frame.closed do
    U64.parse("0")?
  else
    U64.subtract(week.budget, week.spent)?
  end
  let week_balance = carry_read_vault(snapshot, 6, pins.usdc, addresses.week)?
  let receipt = if frame.closed do
    let value = decode_token_burn_close_receipt(carry_read_owned(snapshot,
      9,
      pins.program,
      256)?.info.data)?
    let c = case carry do
      None -> return Err("burn_carry_closed_custody_missing")
      Some(value) -> value
    end
    if value.profile != addresses.profile
      || value.week != addresses.week
      || value.source != addresses.week_vault
      || value.epoch != epoch
      || value.budget != week.budget
      || value.spent != week.spent
      || value.burned != week.burned
      || value.carried != U64.subtract(week.budget, week.spent)?
      || value.carry != a.carry
      || value.funding_hash != week.funding_hash
      || value.active_frame_hash != frame.active_frame_hash
      || value.version != frame.version
      || U128.compare(c.closed_total, U128.parse(U64.to_string(value.carried))?) < 0 do
      return Err("burn_carry_receipt_mismatch")
    end
    Some(value)
  else
    if !carry_read_absent(List.get(snapshot.accounts, 9)) do
      return Err("burn_carry_unexpected_receipt")
    end
    None
  end
  Ok(TokenBurnCarryState {
    context_slot: snapshot.slot,
    timestamp: clock.unix_timestamp,
    profile: profile,
    frame: Some(frame),
    carry: carry,
    receipt: receipt,
    remaining: remaining,
    week_surplus: U64.subtract(week_balance, remaining)?,
    carry_surplus: U64.subtract(carry_balance, accounted)?,
    code_current: code == pins.program_slot,
    digest: carry_read_digest(keys, snapshot)?
  })
end

pub fn read_token_burn_carry_from(client :: Int,
  url :: String,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenBurnCarryState!String do
  let request = get_multiple_accounts_slice_request(1,
    token_burn_carry_read_keys(pins, epoch)?,
    "finalized",
    0,
    2240,
    Some(minimum))?
  let response = rpc_send(client, url, request, 5000, 131072)?
  decode_token_burn_carry_snapshot(pins,
    epoch,
    minimum,
    optional_accounts_slice_from_response(response)?)
end

fn carry_agree(first :: TokenBurnCarryState!String,
  second :: TokenBurnCarryState!String) -> Option<TokenBurnCarryState> do
  case first do
    Err(_) -> None
    Ok(first) -> case second do
      Err(_) -> None
      Ok(second) -> if first.digest == second.digest do
        Some(first)
      else
        None
      end
    end
  end
end

pub fn read_token_burn_carry_quorum(client :: Int,
  urls :: List<String>,
  test_mode :: Bool,
  pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64) -> TokenBurnCarryState!String do
  token_burn_rpc_sources(urls, test_mode)?
  let first = read_token_burn_carry_from(client, List.get(urls, 0), pins, epoch, minimum)
  let second = read_token_burn_carry_from(client, List.get(urls, 1), pins, epoch, minimum)
  case carry_agree(first, second) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  let third = read_token_burn_carry_from(client, List.get(urls, 2), pins, epoch, minimum)
  case carry_agree(first, third) do
    Some(value) -> return Ok(value)
    None -> nil
  end
  case carry_agree(second, third) do
    Some(value) -> Ok(value)
    None -> Err("burn_carry_rpc_no_agreement")
  end
end

pub struct TokenBurnClosePlan do
  status :: String
  instructions :: List<Instruction>
end

pub fn plan_token_burn_carry_close(pins :: TokenBurnReadPins,
  payer :: Pubkey,
  state :: TokenBurnCarryState) -> TokenBurnClosePlan!String do
  if !state.code_current do
    return Ok(TokenBurnClosePlan { status: "paused:code", instructions: [] })
  end
  let frame = case state.frame do
    None -> return Err("burn_carry_week_missing")
    Some(value) -> value
  end
  let week = frame.week
  let a = token_burn_addresses(pins.program, state.profile, week.epoch, 0)?
  if state.profile.usdc != pins.usdc
    || state.profile.treasury != pins.treasury
    || state.profile.factory != pins.factory
    || week.profile != a.profile
    || week.usdc != pins.usdc
    || week.treasury != pins.treasury
    || week.vault != a.week_vault
    || week.source != a.treasury_source
    || state.timestamp <= 0 do
    return Err("burn_carry_close_context_mismatch")
  end
  if frame.closed do
    if state.receipt == None do
      return Err("burn_carry_close_receipt_missing")
    end
    return Ok(TokenBurnClosePlan { status: "complete", instructions: [] })
  end
  let end_time = U64.multiply(U64.add(week.epoch, U64.parse("1")?)?, U64.parse("604800")?)?
  if U64.compare(U64.parse(Int.to_string(state.timestamp))?, end_time) < 0 do
    return Ok(TokenBurnClosePlan { status: "waiting:week", instructions: [] })
  end
  Ok(TokenBurnClosePlan {
    status: "close",
    instructions: [token_burn_close_instruction(pins.program, payer, state.profile, week.epoch)?]
  })
end

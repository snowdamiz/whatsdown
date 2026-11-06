# Complete RPC bank authentication; an absent pair is preparation, never release.
from Transparency.TokenBurn import TokenBurnProfile, decode_token_burn_profile
from Transparency.TokenChain import token_addresses, decode_token_config
from Transparency.TokenBurnWrite import token_burn_addresses
from Transparency.TokenBurnCarryWrite import token_burn_carry_addresses
from Solana.Address import find_program_address
from Transparency.TokenBurnRead import TokenBurnReadPins
from Transparency.TokenBurnExpiry import (
  TokenBurnUnfundedWeek,
  TokenBurnExpiryReceipt,
  match_token_burn_unfunded,
  decode_token_burn_expiry_receipt,
  token_burn_expiry_deadline
)
from Solana.Read import (
  Pubkey,
  AccountSlice,
  OptionalAccountSlicesAtSlot,
  pubkey,
  mint,
  clock_sysvar
)

pub struct TokenBurnExpiryBank do
  context_slot :: U64
  timestamp :: U64
  profile :: TokenBurnProfile
  profile_bytes :: Bytes
  frame :: Option<TokenBurnUnfundedWeek>
  receipt :: Option<TokenBurnExpiryReceipt>
  raw_frame :: Bytes
  raw_receipt :: Bytes
  footprint :: Bytes
end

pub fn token_burn_expiry_read_keys(pins :: TokenBurnReadPins,
  epoch :: U64) -> List<Pubkey>!String do
  for key in [pins.program, pins.governance, pins.usdc, pins.treasury, pins.factory] do
    if Bytes.length(key.bytes) != 32 || Bytes.to_hex(key.bytes) == String.repeat("00", 32) do
      return Err("invalid_burn_expiry_pins")
    end
  end
  token_burn_expiry_deadline(epoch)?
  let token = token_addresses(pins.program)?
  let carry = token_burn_carry_addresses(pins.program, pins.usdc, epoch)?
  let profile = find_program_address(pins.program, [Bytes.from_utf8("swap")])?.address
  let week = find_program_address(pins.program,
    [Bytes.from_utf8("burn-week"), Bytes.write_uint_le(U64.to_string(epoch), 8)?])?.address
  Ok([
    token.config,
    token.mint,
    profile,
    pins.usdc,
    pubkey("SysvarC1ock11111111111111111111111111111111")?,
    week,
    carry.receipt,
    pins.program,
    token.program_data
  ])
end

fn expiry_bank_required(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  space :: U64,
  length :: Int,
  executable :: Bool) -> AccountSlice!String do
  let a = case List.get(snapshot.accounts, index) do
    None -> return Err("burn_expiry_account_missing")
    Some(value) -> value
  end
  if a.info.owner != owner
    || a.space != space
    || Bytes.length(a.info.data) != length
    || a.info.executable != executable
    || a.info.lamports == U64.parse("0")? do
    return Err("burn_expiry_account_mismatch")
  end
  Ok(a)
end

fn expiry_bank_owned(snapshot :: OptionalAccountSlicesAtSlot,
  index :: Int,
  owner :: Pubkey,
  length :: Int) -> AccountSlice!String do
  expiry_bank_required(snapshot, index, owner, U64.parse(Int.to_string(length))?, length, false)
end

fn expiry_bank_absent(a :: Option<AccountSlice>) -> Bool do
  case a do
    None -> true
    Some(value) -> !value.info.executable
      && Bytes.length(value.info.data) == 0
      && U64.to_string(value.space) == "0"
      && Bytes.to_hex(value.info.owner.bytes) == String.repeat("00", 32)
  end
end

pub fn decode_token_burn_expiry_snapshot(pins :: TokenBurnReadPins,
  epoch :: U64,
  minimum :: U64,
  snapshot :: OptionalAccountSlicesAtSlot) -> TokenBurnExpiryBank!String do
  if List.length(snapshot.accounts) != 9
    || snapshot.slot == U64.parse("0")?
    || U64.compare(snapshot.slot, minimum) < 0 do
    return Err("invalid_burn_expiry_snapshot")
  end
  token_burn_expiry_read_keys(pins, epoch)?
  let token = token_addresses(pins.program)?
  let config_bytes = expiry_bank_owned(snapshot, 0, pins.program, 320)?.info.data
  let config = decode_token_config(config_bytes)?
  if config.governance != pins.governance || config.mint != token.mint do
    return Err("burn_expiry_config_mismatch")
  end
  let spl = pubkey("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA")?
  let morse = mint(expiry_bank_owned(snapshot, 1, spl, 82)?.info)?
  let usdc = mint(expiry_bank_owned(snapshot, 3, spl, 82)?.info)?
  if !morse.initialized
    || morse.decimals != 6
    || morse.mint_authority != None
    || morse.freeze_authority != None
    || U64.compare(morse.supply, U64.parse("1000000000000000")?) > 0
    || !usdc.initialized
    || usdc.decimals != 6 do
    return Err("burn_expiry_mint_mismatch")
  end
  let profile_bytes = expiry_bank_owned(snapshot, 2, pins.program, 320)?.info.data
  let profile = decode_token_burn_profile(profile_bytes)?
  if profile.config != token.config
    || profile.usdc != pins.usdc
    || profile.treasury != pins.treasury
    || profile.factory != pins.factory do
    return Err("burn_expiry_profile_mismatch")
  end
  token_burn_addresses(pins.program, profile, epoch, 0)?
  let clock = clock_sysvar(expiry_bank_owned(snapshot,
    4,
    pubkey("Sysvar1111111111111111111111111111111111111")?,
    40)?.info)?
  if clock.slot != snapshot.slot || clock.unix_timestamp <= 0 do
    return Err("burn_expiry_clock_mismatch")
  end
  let timestamp = U64.parse(Int.to_string(clock.unix_timestamp))?
  if U64.compare(timestamp, token_burn_expiry_deadline(epoch)?) < 0 do
    return Err("burn_expiry_window_open")
  end
  let loader = pubkey("BPFLoaderUpgradeab1e11111111111111111111111")?
  let image = expiry_bank_required(snapshot, 7, loader, U64.parse("36")?, 36, true)?.info.data
  if Bytes.to_hex(Bytes.slice(image, 0, 4)?) != "02000000"
    || Bytes.slice(image, 4, 32)? != token.program_data.bytes do
    return Err("burn_expiry_executable_mismatch")
  end
  let pd = case List.get(snapshot.accounts, 8) do
    None -> return Err("burn_expiry_program_missing")
    Some(value) -> value
  end
  if U64.compare(pd.space, U64.parse("45")?) < 0
    || U64.compare(pd.space, U64.parse("10485760")?) > 0 do
    return Err("burn_expiry_program_mismatch")
  end
  let length = if U64.compare(pd.space, U64.parse("320")?) > 0 do
    320
  else
    case String.to_int(U64.to_string(pd.space)) do
      None -> return Err("burn_expiry_program_mismatch")
      Some(value) -> value
    end
  end
  let data = expiry_bank_required(snapshot, 8, loader, pd.space, length, false)?.info.data
  let slot = U64.parse(Bytes.read_uint_le(data, 4, 8)?)?
  if Bytes.to_hex(Bytes.slice(data, 0, 4)?) != "03000000"
    || Bytes.get(data, 12)? > 1
    || slot != pins.program_slot
    || U64.compare(slot, snapshot.slot) > 0 do
    return Err("burn_expiry_program_release_mismatch")
  end
  let absent = expiry_bank_absent(List.get(snapshot.accounts, 5))
  if absent != expiry_bank_absent(List.get(snapshot.accounts, 6)) do
    return Err("burn_expiry_incomplete_pair")
  end
  let raw = if absent do
    Bytes.empty()
  else
    expiry_bank_owned(snapshot, 5, pins.program, 192)?.info.data
  end
  let receipt_bytes = if absent do
    Bytes.empty()
  else
    expiry_bank_owned(snapshot, 6, pins.program, 256)?.info.data
  end
  let frame = if absent do
    None
  else
    let value = match_token_burn_unfunded(pins.program, profile_bytes, epoch, raw, receipt_bytes)?
    if U64.compare(value.expired_at, timestamp) > 0 do
      return Err("burn_expiry_future_receipt")
    end
    Some(value)
  end
  let receipt = if absent do
    None
  else
    Some(decode_token_burn_expiry_receipt(receipt_bytes)?)
  end
  let footprint = Crypto.sha256(List.reduce([
      Bytes.from_utf8("morse-burn-unfunded-bank-v1"),
      pins.program.bytes,
      Bytes.write_uint_le(U64.to_string(epoch), 8)?,
      Crypto.sha256(config_bytes),
      Crypto.sha256(profile_bytes),
      Crypto.sha256(image),
      Crypto.sha256(Bytes.slice(data, 0, 45)?),
      Crypto.sha256(raw),
      Crypto.sha256(receipt_bytes)
    ],
    Ok(Bytes.empty()),
    fn(result, part) do Bytes.concat(result?, part) end)?)
  Ok(TokenBurnExpiryBank {
    context_slot: snapshot.slot,
    timestamp: timestamp,
    profile: profile,
    profile_bytes: profile_bytes,
    frame: frame,
    receipt: receipt,
    raw_frame: raw,
    raw_receipt: receipt_bytes,
    footprint: footprint
  })
end

# Explicit active/closed version decoding; raw bytes still need authenticated account context.
from Transparency.TokenBurn import TokenBurnWeek, decode_token_burn_week
from Solana.Read import Pubkey

pub struct TokenBurnCarryFrame do
  week :: TokenBurnWeek
  version :: Int
  closed :: Bool
  cash_budget :: U64
  carry_budget :: U64
  carry :: Option<Pubkey>
  active_frame_hash :: Bytes
end

pub struct TokenBurnCarryAccount do
  profile :: Pubkey
  usdc :: Pubkey
  vault :: Pubkey
  accounted :: U64
  closed_total :: U128
  reserved_total :: U128
  close_count :: U64
  funding_count :: U64
end

pub struct TokenBurnCloseReceipt do
  profile :: Pubkey
  week :: Pubkey
  source :: Pubkey
  epoch :: U64
  budget :: U64
  spent :: U64
  burned :: U64
  carried :: U64
  closed_at :: U64
  carry :: Pubkey
  funding_hash :: Bytes
  active_frame_hash :: Bytes
  version :: Int
end

fn carry_part(data :: Bytes, at :: Int, length :: Int) -> Bytes!String do
  Bytes.slice(data, at, length)
end

fn carry_nonzero(data :: Bytes) -> Bool do
  Bytes.to_hex(data) != String.repeat("00", Bytes.length(data))
end

fn carry_key(data :: Bytes, at :: Int) -> Pubkey!String do
  let value = carry_part(data, at, 32)?
  if !carry_nonzero(value) do
    Err("invalid_burn_carry_key")
  else
    Ok(Pubkey { bytes: value })
  end
end

fn carry_wide(data :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, at, 8)?)
end

fn carry_large(data :: Bytes, at :: Int) -> U128!String do
  let low = U128.parse(U64.to_string(carry_wide(data, at)?))?
  let high = U128.parse(U64.to_string(carry_wide(data, at + 8)?))?
  U128.add(low, U128.multiply(high, U128.parse("18446744073709551616")?)?)
end

fn carry_time(data :: Bytes, at :: Int) -> U64!String do
  let time = carry_wide(data, at)?
  if time == U64.parse("0")? || U64.compare(time, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_burn_carry_time")
  else
    Ok(time)
  end
end

fn carry_cat(parts :: List<Bytes>) -> Bytes!String do
  List.reduce(parts, Ok(Bytes.empty()), fn(result, value) do Bytes.concat(result?, value) end)
end

pub fn decode_token_burn_carry_frame(data :: Bytes) -> TokenBurnCarryFrame!String do
  if Bytes.length(data) < 4 do
    return Err("invalid_burn_carry_frame")
  end
  let version = Bytes.get(data, 3)?
  let magic = Bytes.to_hex(carry_part(data, 0, 3)?)
  let closed = magic == "4d5443"
  let header = if version == 1 do
    256
  else
    320
  end
  if (version != 1 && version != 2)
    || (magic != "4d5457" && !closed)
    || Bytes.length(data) != header + 1920 do
    return Err("invalid_burn_carry_frame")
  end
  if Bytes.get(data, 52)? != (if closed do
      2
    else
      1
    end) do
    return Err("invalid_burn_carry_frame")
  end
  # Validate every original row and financial sum through the unchanged strict v1 codec.
  # The wrapper retains the explicit original version and terminal status.
  let legacy = carry_cat([
    Bytes.from_hex("4d545701")?,
    carry_part(data, 4, 48)?,
    Bytes.from_hex("01")?,
    carry_part(data, 53, 203)?,
    carry_part(data, header, 1920)?
  ])?
  let week = decode_token_burn_week(legacy)?
  let cash = if version == 1 do
    week.budget
  else
    carry_wide(data, 256)?
  end
  let carried = if version == 1 do
    U64.parse("0")?
  else
    carry_wide(data, 264)?
  end
  let authority = if version == 1 do
    None
  else
    Some(carry_key(data, 272)?)
  end
  if U64.add(cash, carried)? != week.budget
    || (version == 2 && carry_nonzero(carry_part(data, 304, 16)?)) do
    return Err("invalid_burn_carry_frame")
  end
  let active = carry_cat([
    Bytes.from_hex("4d5457")?,
    carry_part(data, 3, 49)?,
    Bytes.from_hex("01")?,
    carry_part(data, 53, Bytes.length(data) - 53)?
  ])?
  Ok(TokenBurnCarryFrame {
    week: week,
    version: version,
    closed: closed,
    cash_budget: cash,
    carry_budget: carried,
    carry: authority,
    active_frame_hash: Crypto.sha256(active)
  })
end

pub fn decode_token_burn_carry_account(data :: Bytes) -> TokenBurnCarryAccount!String do
  if Bytes.length(data) != 192
    || Bytes.to_hex(carry_part(data, 0, 4)?) != "4d435901"
    || carry_nonzero(carry_part(data, 156, 36)?) do
    return Err("invalid_burn_carry_account")
  end
  let accounted = carry_wide(data, 100)?
  let closed = carry_large(data, 108)?
  let reserved = carry_large(data, 124)?
  let closes = carry_wide(data, 140)?
  let funds = carry_wide(data, 148)?
  if U128.subtract(closed, reserved)? != U128.parse(U64.to_string(accounted))?
    || (closed != U128.parse("0")? && closes == U64.parse("0")?)
    || (reserved != U128.parse("0")? && funds == U64.parse("0")?) do
    return Err("invalid_burn_carry_account")
  end
  Ok(TokenBurnCarryAccount {
    profile: carry_key(data, 4)?,
    usdc: carry_key(data, 36)?,
    vault: carry_key(data, 68)?,
    accounted: accounted,
    closed_total: closed,
    reserved_total: reserved,
    close_count: closes,
    funding_count: funds
  })
end

pub fn decode_token_burn_close_receipt(data :: Bytes) -> TokenBurnCloseReceipt!String do
  if Bytes.length(data) != 256
    || Bytes.to_hex(carry_part(data, 0, 4)?) != "4d424301"
    || carry_nonzero(carry_part(data, 245, 11)?)
    || !carry_nonzero(carry_part(data, 180, 32)?)
    || !carry_nonzero(carry_part(data, 212, 32)?) do
    return Err("invalid_burn_close_receipt")
  end
  let epoch = carry_wide(data, 100)?
  let budget = carry_wide(data, 108)?
  let spent = carry_wide(data, 116)?
  let burned = carry_wide(data, 124)?
  let carried = carry_wide(data, 132)?
  let closed_at = carry_time(data, 140)?
  let version = Bytes.get(data, 244)?
  let end_time = U64.multiply(U64.add(epoch, U64.parse("1")?)?, U64.parse("604800")?)?
  if (version != 1 && version != 2)
    || U64.compare(budget, U64.parse("24")?) < 0
    || U64.subtract(budget, spent)? != carried
    || U64.compare(burned, U64.parse("1000000000000000")?) > 0
    || U64.compare(closed_at, end_time) < 0 do
    return Err("invalid_burn_close_receipt")
  end
  Ok(TokenBurnCloseReceipt {
    profile: carry_key(data, 4)?,
    week: carry_key(data, 36)?,
    source: carry_key(data, 68)?,
    epoch: epoch,
    budget: budget,
    spent: spent,
    burned: burned,
    carried: carried,
    closed_at: closed_at,
    carry: carry_key(data, 148)?,
    funding_hash: carry_part(data, 180, 32)?,
    active_frame_hash: carry_part(data, 212, 32)?,
    version: version
  })
end

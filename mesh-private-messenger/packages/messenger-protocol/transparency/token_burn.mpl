# Raw codecs and prepared instructions only. RPC owner/context/pin authentication is a separate required boundary.
from Solana.Read import Pubkey

pub struct TokenBurnProfile do
  config :: Pubkey
  usdc :: Pubkey
  treasury :: Pubkey
  pool :: Pubkey
  factory :: Pubkey
  vault0 :: Pubkey
  vault1 :: Pubkey
  observation :: Pubkey
  jupiter_slot :: U64
  raydium_slot :: U64
  ready_at :: U64
  factory_hash :: Bytes
end

pub struct TokenBurnRow do
  amount :: U64
  window_start :: U64
  window_end :: U64
  execute_at :: U64
  burned :: U64
  execution_hash :: Bytes
  complete :: Bool
end

pub struct TokenBurnWeek do
  profile :: Pubkey
  epoch :: U64
  budget :: U64
  funded_at :: U64
  usdc :: Pubkey
  treasury :: Pubkey
  vault :: Pubkey
  source :: Pubkey
  funding_hash :: Bytes
  completion_mask :: U64
  spent :: U64
  burned :: U64
  rows :: List<TokenBurnRow>
end

fn burn_part(data :: Bytes, at :: Int, count :: Int) -> Bytes!String do
  Bytes.slice(data, at, count)
end

fn burn_nonzero(data :: Bytes) -> Bool do
  Bytes.to_hex(data) != String.repeat("00", Bytes.length(data))
end

fn burn_key(data :: Bytes, at :: Int) -> Pubkey!String do
  let value = burn_part(data, at, 32)?
  if !burn_nonzero(value) do
    Err("invalid_token_burn_key")
  else
    Ok(Pubkey { bytes: value })
  end
end

fn burn_wide(data :: Bytes, at :: Int) -> U64!String do
  U64.parse(Bytes.read_uint_le(data, at, 8)?)
end

fn burn_time(data :: Bytes, at :: Int) -> U64!String do
  let value = burn_wide(data, at)?
  if value == U64.parse("0")? || U64.compare(value, U64.parse("9223372036854775807")?) > 0 do
    Err("invalid_token_burn_time")
  else
    Ok(value)
  end
end

fn burn_total(values :: List<U64>) -> U64!String do
  List.reduce(values, Ok(U64.parse("0")?), fn(result, value) do U64.add(result?, value) end)
end

pub fn decode_token_burn_profile(data :: Bytes) -> TokenBurnProfile!String do
  if Bytes.length(data) != 320
    || Bytes.to_hex(burn_part(data, 0, 4)?) != "4d545301"
    || burn_nonzero(burn_part(data, 316, 4)?)
    || !burn_nonzero(burn_part(data, 284, 32)?) do
    return Err("invalid_token_burn_profile")
  end
  Ok(TokenBurnProfile {
    config: burn_key(data, 4)?,
    usdc: burn_key(data, 36)?,
    treasury: burn_key(data, 68)?,
    pool: burn_key(data, 100)?,
    factory: burn_key(data, 132)?,
    vault0: burn_key(data, 164)?,
    vault1: burn_key(data, 196)?,
    observation: burn_key(data, 228)?,
    jupiter_slot: burn_wide(data, 260)?,
    raydium_slot: burn_wide(data, 268)?,
    ready_at: burn_time(data, 276)?,
    factory_hash: burn_part(data, 284, 32)?
  })
end

pub fn decode_token_burn_week(data :: Bytes) -> TokenBurnWeek!String do
  if Bytes.length(data) != 2176
    || Bytes.to_hex(burn_part(data, 0, 4)?) != "4d545701"
    || Bytes.get(data, 52)? != 1
    || burn_nonzero(burn_part(data, 53, 3)?)
    || burn_nonzero(burn_part(data, 248, 8)?)
    || !burn_nonzero(burn_part(data, 192, 32)?) do
    return Err("invalid_token_burn_week")
  end
  let epoch = burn_wide(data, 36)?
  let start = U64.multiply(epoch, U64.parse("604800")?)?
  let finish = U64.add(start, U64.parse("604800")?)?
  let funded = burn_time(data, 56)?
  let budget = burn_wide(data, 44)?
  let mask = burn_wide(data, 224)?
  if U64.compare(finish, U64.parse("9223372036854775807")?) > 0
    || U64.compare(budget, U64.parse("24")?) < 0
    || U64.compare(mask, U64.parse("16777215")?) > 0 do
    return Err("invalid_token_burn_week")
  end
  let rows = for index in 0..24 do
    let at = 256 + index * 80
    let amount = burn_wide(data, at)?
    let begin = U64.add(start, U64.parse(Int.to_string(index * 25200))?)?
    let window_finish = U64.add(begin, U64.parse("25200")?)?
    let due = burn_time(data, at + 24)?
    let burned = burn_wide(data, at + 32)?
    let intent = burn_part(data, at + 40, 32)?
    let divisor = List.get([1, 2, 4, 8, 16, 32, 64, 128], index % 8)
    let complete = (Bytes.get(data, 224 + index / 8)? / divisor) % 2 == 1
    if amount == U64.parse("0")?
      || burn_wide(data, at + 8)? != begin
      || burn_wide(data, at + 16)? != window_finish
      || U64.compare(due, begin) < 0
      || U64.compare(due, window_finish) >= 0
      || burn_nonzero(burn_part(data, at + 72, 8)?) do
      return Err("invalid_token_burn_week")
    end
    if complete do
      if burned == U64.parse("0")? || !burn_nonzero(intent) do
        return Err("invalid_token_burn_week")
      end
    else if burned != U64.parse("0")? || burn_nonzero(intent) do
      return Err("invalid_token_burn_week")
    end
    TokenBurnRow {
      amount: amount,
      window_start: begin,
      window_end: window_finish,
      execute_at: due,
      burned: burned,
      execution_hash: intent,
      complete: complete
    }
  end
  let amounts = for row in rows do
    row.amount
  end
  let spent = for row in rows do
    if row.complete do
      row.amount
    else
      U64.parse("0")?
    end
  end
  let burned = for row in rows do
    row.burned
  end
  let spent_total = burn_total(spent)?
  let burned_total = burn_total(burned)?
  if burn_total(amounts)? != budget
    || spent_total != burn_wide(data, 232)?
    || burned_total != burn_wide(data, 240)?
    || U64.compare(burned_total, U64.parse("1000000000000000")?) > 0 do
    return Err("invalid_token_burn_week")
  end
  Ok(TokenBurnWeek {
    profile: burn_key(data, 4)?,
    epoch: epoch,
    budget: budget,
    funded_at: funded,
    usdc: burn_key(data, 64)?,
    treasury: burn_key(data, 96)?,
    vault: burn_key(data, 128)?,
    source: burn_key(data, 160)?,
    funding_hash: burn_part(data, 192, 32)?,
    completion_mask: mask,
    spent: spent_total,
    burned: burned_total,
    rows: rows
  })
end

pub fn token_burn_route_minimum(data :: Bytes, input :: U64, spot :: U64) -> U64!String do
  if Bytes.length(data) != 39
    || Bytes.to_hex(burn_part(data, 0, 8)?) != "bb64facc31c4af14"
    || input == U64.parse("0")?
    || spot == U64.parse("0")?
    || burn_wide(data, 8)? != input
    || burn_nonzero(burn_part(data, 26, 4)?)
    || Bytes.to_hex(burn_part(data, 30, 9)?) != "010000002e10270001" do
    return Err("invalid_token_burn_route")
  end
  let quoted = burn_wide(data, 16)?
  let slippage = U64.parse(Bytes.read_uint_le(data, 24, 2)?)?
  if quoted == U64.parse("0")? || U64.compare(slippage, U64.parse("100")?) > 0 do
    return Err("invalid_token_burn_route")
  end
  let fraction = U128.parse(U64.to_string(U64.subtract(U64.parse("10000")?, slippage)?))?
  let minimum = U128.divide(U128.multiply(U128.parse(U64.to_string(quoted))?, fraction)?,
    U128.parse("10000")?)?
  let numerator = U128.multiply(U128.parse(U64.to_string(input))?, U128.parse("9900000000")?)?
  let denominator = U128.multiply(U128.parse(U64.to_string(spot))?, U128.parse("10000")?)?
  let oracle_minimum = U128.divide(U128.add(numerator,
      U128.subtract(denominator, U128.parse("1")?)?)?,
    denominator)?
  if minimum == U128.parse("0")? || U128.compare(minimum, oracle_minimum) < 0 do
    Err("invalid_token_burn_route")
  else
    U64.parse(U128.to_string(minimum))
  end
end

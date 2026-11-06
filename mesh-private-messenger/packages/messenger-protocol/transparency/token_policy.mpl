# Pure integer policy only. Callers must authenticate chain custody and the
# complete seven-day oracle coverage before applying collateral decisions.
pub struct TokenBondAssessment do
  eligible :: Bool
  underwater_since :: Int
  value_usd :: U128
end

fn token_wide(value :: U64) -> U128!String do
  U128.parse(U64.to_string(value))
end

fn token_narrow(value :: U128) -> U64!String do
  U64.parse(U128.to_string(value))
end

pub fn token_supply_units() -> U64!String do
  U64.parse("1000000000000000")
end

pub fn token_initial_allocations() -> List<U64>!String do
  Ok(for percent in [25, 20, 18, 15, 15, 5, 2] do
    U64.multiply_divide(token_supply_units()?,
      U64.parse(Int.to_string(percent))?,
      U64.parse("100")?)?
  end)
end

# Cliff is included in the total term. Accrual is linear in original calendar
# months, with exact prorating inside each month and one cumulative rounding.
# Jan31->Feb29 never changes the original March31 anniversary.
pub fn token_vested_units(allocation :: U64,
  months :: Int,
  cliff :: Int,
  started :: Int,
  now :: Int) -> U64!String do
  if months < 1
    || months > 48
    || cliff < 0
    || cliff > months
    || started <= 0
    || U64.compare(allocation, token_supply_units()?) > 0 do
    return Err("invalid_token_vesting")
  end
  let origin = DateTime.from_unix_secs(started)?
  let cliff_at = DateTime.to_unix_secs(DateTime.add_months(origin, cliff)?)
  let finish = DateTime.to_unix_secs(DateTime.add_months(origin, months)?)
  if now < cliff_at do
    return U64.parse("0")
  end
  if now >= finish do
    return Ok(allocation)
  end
  for index in 0..months do
    let before = DateTime.to_unix_secs(DateTime.add_months(origin, index)?)
    let period_end = DateTime.to_unix_secs(DateTime.add_months(origin, index + 1)?)
    if now >= before && now < period_end do
      let duration = period_end - before
      let progress = U128.parse(Int.to_string(index * duration + now - before))?
      let denominator = U128.parse(Int.to_string(months * duration))?
      return token_narrow(U128.divide(U128.multiply(token_wide(allocation)?, progress)?,
        denominator)?)
    end
  end
  Err("invalid_token_vesting_time")
end

# Both prices and USD targets use six-decimal USD units. A token amount uses
# six-decimal token units. Admission rounds UP so a fractional unit cannot evade
# the full target. Values beyond the fixed supply cannot become a valid bond.
pub fn required_token_bond(target_usd :: U64, price_usd :: U64) -> U64!String do
  if target_usd == U64.parse("0")? || price_usd == U64.parse("0")? do
    return Err("invalid_token_bond_price")
  end
  let numerator = U128.multiply(token_wide(target_usd)?, U128.parse("1000000")?)?
  let rounded = U128.add(numerator, U128.subtract(token_wide(price_usd)?, U128.parse("1")?)?)?
  let amount = token_narrow(U128.divide(rounded, token_wide(price_usd)?)?)?
  if U64.compare(amount, token_supply_units()?) > 0 do
    return Err("token_bond_exceeds_supply")
  end
  Ok(amount)
end

# Crossing strictly below80% starts a seven-day grace period once. Recovery to
# the full target clears it; a partial topup never restarts or extends the clock.
# Price movements alone never slash funds.
pub fn assess_token_bond(amount :: U64,
  price_usd :: U64,
  target_usd :: U64,
  underwater_since :: Int,
  now :: Int) -> TokenBondAssessment!String do
  if amount == U64.parse("0")?
    || U64.compare(amount, token_supply_units()?) > 0
    || price_usd == U64.parse("0")?
    || target_usd == U64.parse("0")?
    || now <= 0
    || underwater_since < 0
    || underwater_since > now do
    return Err("invalid_token_bond")
  end
  let product = U128.multiply(token_wide(amount)?, token_wide(price_usd)?)?
  let target = U128.multiply(token_wide(target_usd)?, U128.parse("1000000")?)?
  let recovered = U128.compare(product, target) >= 0
  let below = U128.compare(U128.multiply(product, U128.parse("5")?)?,
    U128.multiply(target, U128.parse("4")?)?) < 0
  let since = if recovered do
    0
  else if underwater_since != 0 do
    underwater_since
  else if below do
    now
  else
    0
  end
  Ok(TokenBondAssessment {
    eligible: since == 0 || now - since < 604800,
    underwater_since: since,
    value_usd: U128.divide(product, U128.parse("1000000")?)?
  })
end

pub struct TokenBurnChunk do
  amount :: U64
  window_start :: U64
  window_end :: U64
  execute_at :: U64
end

fn token_sum_units(values :: List<U64>) -> U64!String do
  if List.length(values) == 0 do
    return U64.parse("0")
  end
  U64.add(List.head(values), token_sum_units(List.drop(values, 1))?)
end

# Randomness is supplied by the caller through the public CSPRNG. This policy
# only maps positive bounded weights and entropy into a fixed complete schedule.
# Each chunk owns a separate execution window; late keepers cannot compress the
# entire order into one end-of-week transaction. Small budgets remain pending.
pub fn token_burn_chunks(budget :: U64,
  week_start :: U64,
  weights :: List<U64>,
  entropy :: List<U64>) -> List<TokenBurnChunk>!String do
  let count = List.length(weights)
  if count < 24 || count > 64 || List.length(entropy) != count || week_start == U64.parse("0")? do
    return Err("invalid_token_burn_schedule")
  end
  let size = U64.parse(Int.to_string(count))?
  if U64.compare(budget, size) < 0 do
    return Err("token_burn_budget_pending")
  end
  U64.to_int(U64.add(week_start, U64.parse("604800")?)?)?
  for weight in weights do
    if weight == U64.parse("0")? || U64.compare(weight, U64.parse("4294967295")?) > 0 do
      return Err("invalid_token_burn_weight")
    end
  end
  let total = token_sum_units(weights)?
  let remaining = U64.subtract(budget, size)?
  let portions = for weight in weights do
    token_narrow(U128.divide(U128.multiply(token_wide(remaining)?, token_wide(weight)?)?,
      token_wide(total)?)?)?
  end
  let dust = U64.subtract(remaining, token_sum_units(portions)?)?
  Ok(for index in 0..count do
    let ordinal = U64.parse(Int.to_string(index))?
    let extra = if U64.compare(ordinal, dust) < 0 do
      U64.parse("1")?
    else
      U64.parse("0")?
    end
    let amount = U64.add(U64.add(U64.parse("1")?, List.get(portions, index))?, extra)?
    let begin = U64.add(week_start, U64.multiply_divide(ordinal, U64.parse("604800")?, size)?)?
    let finish = U64.add(week_start,
      U64.multiply_divide(U64.add(ordinal, U64.parse("1")?)?, U64.parse("604800")?, size)?)?
    let width = U64.subtract(finish, begin)?
    let random = List.get(entropy, index)
    let offset = U64.subtract(random, U64.multiply(U64.divide(random, width)?, width)?)?
    TokenBurnChunk {
      amount: amount,
      window_start: begin,
      window_end: finish,
      execute_at: U64.add(begin, offset)?
    }
  end)
end

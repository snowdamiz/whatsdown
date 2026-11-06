pub struct TokenFloorInput do
  weight :: U128
  floor :: U64
end

pub struct TokenFloorAllocation do
  usd :: U64
  morse :: U64
  usd_floor_gap :: U64
end

pub struct TokenFloorPlan do
  required :: U64
  subsidy_used :: U64
  usd_allocated :: U64
  morse_allocated :: U64
  carry :: U64
  floor_shortfall :: U64
  rows :: List<TokenFloorAllocation>
end

fn zero() -> U64!String do
  U64.parse("0")
end

fn wide(value :: U64) -> U128!String do
  U128.parse(U64.to_string(value))
end

fn narrow(value :: U128) -> U64!String do
  U64.parse(U128.to_string(value))
end

fn sum(values :: List<U64>, result :: U64) -> U64!String do
  if List.length(values) == 0 do
    Ok(result)
  else
    sum(List.drop(values, 1), U64.add(result, List.head(values))?)
  end
end

fn weights(values :: List<TokenFloorInput>, result :: U128) -> U128!String do
  if List.length(values) == 0 do
    Ok(result)
  else
    weights(List.drop(values, 1), U128.add(result, List.head(values).weight)?)
  end
end

fn morse_for_gap(gap :: U64, price :: U64) -> U64!String do
  let product = U128.multiply(wide(gap)?, U128.parse("1000000")?)?
  let divisor = wide(price)?
  let base = U128.divide(product, divisor)?
  narrow(if U128.multiply(base, divisor)? == product do
    base
  else
    U128.add(base, U128.parse("1")?)?
  end)
end

# Inputs are authenticated by the caller. This function never accepts a token
# price as proof of a feed, and never mixes MORSE units with USD accounting.
pub fn plan_token_floor(available :: U64,
  subsidy :: U64,
  cohort :: List<TokenFloorInput>,
  twap :: U64,
  reserve_remaining :: U64) -> TokenFloorPlan!String do
  let nothing = zero()?
  let weight_zero = U128.parse("0")?
  if List.length(cohort) > 64 do
    return Err("invalid_token_floor_cohort")
  end
  for row in cohort do
    if row.weight == weight_zero && row.floor != nothing do
      return Err("invalid_token_floor_weight")
    end
  end
  let required = sum(for row in cohort do
      row.floor
    end,
    nothing)?
  let weight = weights(cohort, weight_zero)?
  let needed = if U64.compare(required, available) > 0 do
    U64.subtract(required, available)?
  else
    nothing
  end
  let used = if U64.compare(needed, subsidy) < 0 do
    needed
  else
    subsidy
  end
  let pot = U64.add(available, used)?
  let shortfall = if U64.compare(required, pot) > 0 do
    U64.subtract(required, pot)?
  else
    nothing
  end
  if shortfall != nothing && twap == nothing do
    return Err("token_reserve_unavailable")
  end
  let rows = if weight == weight_zero do
    for _row in cohort do
      TokenFloorAllocation { usd: nothing, morse: nothing, usd_floor_gap: nothing }
    end
  else if shortfall == nothing do
    let remainder = U64.subtract(pot, required)?
    for row in cohort do
      let extra = narrow(U128.multiply_divide(wide(remainder)?, row.weight, weight)?)?
      TokenFloorAllocation {
        usd: U64.add(row.floor, extra)?,
        morse: nothing,
        usd_floor_gap: nothing
      }
    end
  else
    # Difference of cumulative quotients distributes every available USD unit.
    # Independent per-row truncation would leave USD dust while asking the
    # reserve to cover that same amount again.
    for index in 0..List.length(cohort) do
      let before = sum(for prior in 0..index do
          List.get(cohort, prior).floor
        end,
        nothing)?
      let cumulative = U64.add(before, List.get(cohort, index).floor)?
      let usd = U64.subtract(U64.multiply_divide(cumulative, pot, required)?,
        U64.multiply_divide(before, pot, required)?)?
      let gap = U64.subtract(List.get(cohort, index).floor, usd)?
      TokenFloorAllocation { usd: usd, morse: morse_for_gap(gap, twap)?, usd_floor_gap: gap }
    end
  end
  let allocated = sum(for row in rows do
      row.usd
    end,
    nothing)?
  let tokens = sum(for row in rows do
      row.morse
    end,
    nothing)?
  if U64.compare(tokens, U64.parse("500000000000")?) > 0 do
    return Err("token_reserve_cap")
  end
  if U64.compare(tokens, reserve_remaining) > 0 do
    return Err("token_reserve_underfunded")
  end
  Ok(TokenFloorPlan {
    required: required,
    subsidy_used: used,
    usd_allocated: allocated,
    morse_allocated: tokens,
    carry: U64.subtract(pot, allocated)?,
    floor_shortfall: shortfall,
    rows: rows
  })
end

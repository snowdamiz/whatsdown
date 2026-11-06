from Transparency.Attendance import AttendanceEpoch, AttendanceRow

# Pure settlement policy. A caller must authenticate every member against the
# pinned judge's Witness/Bond accounts and the exclusion registry first.
pub struct RewardMember do
  witness :: Bytes
  payout :: Bytes
  active :: Bool
  excluded :: Bool
  bonded_at :: U64
end

pub struct RewardAllocation do
  witness :: Bytes
  payout :: Bytes
  weight :: U128
  floor :: U64
  amount :: U64
end

pub struct RewardPlan do
  epoch :: U64
  floor_required :: U64
  subsidy_used :: U64
  allocated :: U64
  carry :: U64
  rows :: List<RewardAllocation>
end

fn wide(value :: U64) -> U128!String do
  U128.parse(U64.to_string(value))
end

fn narrow(value :: U128) -> U64!String do
  U64.parse(U128.to_string(value))
end

fn number(value :: Int) -> U64!String do
  U64.parse(Int.to_string(value))
end

fn total(values :: List<U64>, result :: U64) -> U64!String do
  if List.length(values) == 0 do
    Ok(result)
  else
    total(List.tail(values), U64.add(result, List.head(values))?)
  end
end

fn total_weights(values :: List<U128>, result :: U128) -> U128!String do
  if List.length(values) == 0 do
    Ok(result)
  else
    total_weights(List.tail(values), U128.add(result, List.head(values))?)
  end
end

# All witnesses in a week share denominator 3 * posts. Integer weights preserve
# the exact factor without basis-point rounding: clamp(20*s - 16*n, 0, 3*n).
pub fn attendance_weight(signed :: U64, posts :: U64) -> U128!String do
  if U64.compare(signed, posts) > 0 do
    return Err("invalid_reward_attendance")
  end
  let s = U128.multiply(wide(signed)?, U128.parse("20")?)?
  let low = U128.multiply(wide(posts)?, U128.parse("16")?)?
  let high = U128.multiply(wide(posts)?, U128.parse("19")?)?
  if U128.compare(s, low) <= 0 do
    Ok(U128.parse("0")?)
  else if U128.compare(s, high) >= 0 do
    U128.multiply(wide(posts)?, U128.parse("3")?)
  else
    U128.subtract(s, low)
  end
end

# Twelve calendar anniversaries from the original network launch, clamping a
# short month's day without drifting later anniversaries. Difference of the
# cumulative integer entitlement preserves exactly $300 per full month across
# weekly boundaries. Amounts are six-decimal USDC base units, never floats.
pub fn first_year_floor(network_started :: Int,
  interval_start :: Int,
  interval_end :: Int) -> U64!String do
  if network_started < 0 || interval_start < 0 || interval_end < interval_start do
    return Err("invalid_reward_time")
  end
  let origin = DateTime.from_unix_secs(network_started)?
  let monthly = U64.parse("300000000")?
  let zero = U64.parse("0")?
  let parts = for month in 0..12 do
    let start = DateTime.to_unix_secs(DateTime.add_months(origin, month)?)
    let finish = DateTime.to_unix_secs(DateTime.add_months(origin, month + 1)?)
    let overlap_start = if interval_start > start do
      interval_start
    else
      start
    end
    let overlap_end = if interval_end < finish do
      interval_end
    else
      finish
    end
    if overlap_end <= overlap_start do
      zero
    else
      let duration = number(finish - start)?
      let before = U64.multiply_divide(monthly, number(overlap_start - start)?, duration)?
      let earned_end = U64.multiply_divide(monthly, number(overlap_end - start)?, duration)?
      U64.subtract(earned_end, before)?
    end
  end
  total(parts, zero)
end

fn key(value :: Bytes) -> Bool do
  Bytes.length(value) == 32 && Bytes.to_hex(value) != String.repeat("00", 32)
end

pub fn plan_rewards(epoch :: AttendanceEpoch,
  members :: List<RewardMember>,
  network_started :: Int,
  available :: U64,
  subsidy :: U64) -> RewardPlan!String do
  let zero = U64.parse("0")?
  let wide_zero = U128.parse("0")?
  let count = List.length(epoch.rows)
  if !epoch.sealed
    || !key(epoch.log_id)
    || count > 64
    || List.length(members) != count
    || (epoch.posts == zero && (count != 0 || epoch.max_post_slot != zero)) do
    return Err("invalid_reward_epoch")
  end
  let start = U64.multiply(epoch.epoch, U64.parse("604800")?)?
  let finish = U64.add(start, U64.parse("604800")?)?
  let base_floor = first_year_floor(network_started, U64.to_int(start)?, U64.to_int(finish)?)?
  let weights = for index in 0..count do
    let row = List.get(epoch.rows, index)
    let member = List.get(members, index)
    if !key(row.witness)
      || !key(member.payout)
      || !Bytes.secure_equals(row.witness, member.witness)
      || row.signed == zero
      || U64.compare(row.signed, epoch.posts) > 0
      || (index > 0
        && Bytes.to_hex(List.get(epoch.rows, index - 1).witness) >= Bytes.to_hex(row.witness)) do
      return Err("invalid_reward_member")
    end
    if member.active && !member.excluded && U64.compare(member.bonded_at, start) <= 0 do
      attendance_weight(row.signed, epoch.posts)?
    else
      wide_zero
    end
  end
  let denominator = U128.multiply(wide(epoch.posts)?, U128.parse("3")?)?
  let sum = total_weights(weights, wide_zero)?
  let floors = for weight in weights do
    if weight == wide_zero do
      zero
    else
      narrow(U128.multiply_divide(wide(base_floor)?, weight, denominator)?)?
    end
  end
  let required = total(floors, zero)?
  let subsidy_used = if U64.compare(required, available) > 0 do
    U64.subtract(required, available)?
  else
    zero
  end
  if U64.compare(subsidy_used, subsidy) > 0 do
    return Err("rewards_floor_underfunded")
  end
  let pot = U64.add(available, subsidy_used)?
  let remainder = U64.subtract(pot, required)?
  let rows = for index in 0..count do
    let member = List.get(members, index)
    let weight = List.get(weights, index)
    let floor = List.get(floors, index)
    let share = if weight == wide_zero do
      zero
    else
      narrow(U128.multiply_divide(wide(remainder)?, weight, sum)?)?
    end
    RewardAllocation {
      witness: member.witness,
      payout: member.payout,
      weight: weight,
      floor: floor,
      amount: U64.add(floor, share)?
    }
  end
  let allocated = total(for row in rows do
      row.amount
    end,
    zero)?
  Ok(RewardPlan {
    epoch: epoch.epoch,
    floor_required: required,
    subsidy_used: subsidy_used,
    allocated: allocated,
    carry: U64.subtract(pot, allocated)?,
    rows: rows
  })
end

#![no_std]

//! Exact arithmetic counterpart of `Transparency.Rewards` in Mesh.
//!
//! Amounts are six-decimal USDC base units. These functions allocate no memory,
//! hold no accounts, and authenticate no witness or attendance data. Callers
//! enforce epoch sealing, member eligibility, bonding and account ownership.

mod calendar;

pub const MONTHLY_FLOOR: u64 = 300_000_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MathError {
    InvalidAttendance,
    InvalidTime,
    InvalidWeight,
    DivisionByZero,
    Overflow,
    UnderfundedFloor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FloorFunding {
    pub subsidy_used: u64,
    pub remainder: u64,
}

/// 0.05% of the immutable original one-billion-token six-decimal supply.
pub const TOKEN_RESERVE_EPOCH_CAP: u64 = 500_000_000_000;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TokenFloorFunding {
    pub subsidy_used: u64,
    pub usd_pot: u64,
    pub shortfall: u64,
    pub remainder: u64,
}
/// Reserve revenue/carry first, then only the required available USD subsidy.
/// The remaining actual USD shortfall may request separately accounted MORSE.
pub fn token_floor_funding(
    available: u64,
    subsidy: u64,
    required: u64,
) -> Result<TokenFloorFunding, MathError> {
    let subsidy_used = subsidy.min(required.saturating_sub(available));
    let usd_pot = available
        .checked_add(subsidy_used)
        .ok_or(MathError::Overflow)?;
    Ok(TokenFloorFunding {
        subsidy_used,
        usd_pot,
        shortfall: required.saturating_sub(usd_pot),
        remainder: usd_pot.saturating_sub(required),
    })
}
/// Difference of cumulative quotients; all available USD units are allocated
/// before requesting MORSE. Call only for the underfunded floor branch.
pub fn token_floor_usd(before: u64, floor: u64, required: u64, pot: u64) -> Result<u64, MathError> {
    if required == 0 {
        return Err(MathError::DivisionByZero);
    }
    let after = before.checked_add(floor).ok_or(MathError::Overflow)?;
    if after > required || pot > required {
        return Err(MathError::InvalidWeight);
    }
    let end = multiply_divide(after as u128, pot as u128, required as u128)?;
    let start = multiply_divide(before as u128, pot as u128, required as u128)?;
    u64::try_from(end - start).map_err(|_| MathError::Overflow)
}
/// Minimum whole MORSE base units covering one USD gap at the pinned price.
pub fn token_floor_morse(gap: u64, price: u64) -> Result<u64, MathError> {
    if gap == 0 {
        return Ok(0);
    }
    if price == 0 {
        return Err(MathError::DivisionByZero);
    }
    let numerator = gap as u128 * 1_000_000;
    let quotient = numerator / price as u128 + u128::from(!numerator.is_multiple_of(price as u128));
    u64::try_from(quotient).map_err(|_| MathError::Overflow)
}
/// The cap uses the original fixed supply, regardless of later burns/donations.
pub fn token_reserve_available(amount: u64, remaining: u64) -> Result<(), MathError> {
    if amount > TOKEN_RESERVE_EPOCH_CAP || amount > remaining {
        Err(MathError::UnderfundedFloor)
    } else {
        Ok(())
    }
}

/// Computes `floor(a * b / divisor)` with the full 256-bit product.
///
/// An intermediate product exceeding `u128` is permitted. Only a zero divisor
/// or a quotient exceeding `u128::MAX` is an error. This is public-data math;
/// its running time does not protect secret operands.
pub fn multiply_divide(a: u128, b: u128, divisor: u128) -> Result<u128, MathError> {
    if divisor == 0 {
        return Err(MathError::DivisionByZero);
    }
    if let Some(product) = a.checked_mul(b) {
        return Ok(product / divisor);
    }

    let mask = u64::MAX as u128;
    let low_product = (a & mask) * (b & mask);
    let cross_a = (a >> 64) * (b & mask);
    let cross_b = (a & mask) * (b >> 64);
    let middle = (low_product >> 64) + (cross_a & mask) + (cross_b & mask);
    let low = (middle << 64) | (low_product & mask);
    let high = (a >> 64) * (b >> 64) + (cross_a >> 64) + (cross_b >> 64) + (middle >> 64);
    if high >= divisor {
        return Err(MathError::Overflow);
    }

    // Long division of the low limb, retaining the high limb as the initial
    // remainder. A carried bit represents 2^128 before subtracting divisor.
    let mut remainder = high;
    let mut quotient = 0u128;
    for bit in (0..128).rev() {
        let carry = remainder >> 127;
        remainder = (remainder << 1) | ((low >> bit) & 1);
        if carry != 0 || remainder >= divisor {
            remainder = remainder.wrapping_sub(divisor);
            quotient |= 1u128 << bit;
        }
    }
    Ok(quotient)
}

/// Exact factor numerator `clamp(20*signed - 16*posts, 0, 3*posts)`.
///
/// Divide by `3*posts` for the attendance factor: zero through 80 percent,
/// linearly increasing thereafter, and full weight from 95 percent onward.
pub fn attendance_weight(signed: u64, posts: u64) -> Result<u128, MathError> {
    if signed > posts {
        return Err(MathError::InvalidAttendance);
    }
    Ok((20 * signed as u128)
        .saturating_sub(16 * posts as u128)
        .min(3 * posts as u128))
}

/// Original-date UTC anniversary used by token vesting. The bounded 0..=48
/// month domain covers the fixed four-year terms without calendar drift.
pub fn utc_month_anniversary(started: i64, months: u8) -> Result<i64, MathError> {
    if months > 48 {
        return Err(MathError::InvalidTime);
    }
    calendar::Origin::from_unix_seconds(started)?.anniversary(months as i64)
}

/// Base floor earned during the half-open UTC interval `[start, end)`.
///
/// Each of the first twelve calendar months contributes exactly 300,000,000
/// base units. Boundaries derive from the original launch date, clamp its day
/// to each month's last day, and preserve its UTC time. The difference between
/// cumulative integer entitlements makes contiguous intervals telescope.
///
/// Launch and interval times must be nonnegative Unix seconds; interval times
/// must be ordered. As with Mesh's `DateTime`, the launch and all twelve
/// anniversary boundaries must fit Gregorian years through 262142. Interval
/// endpoints need only fit `i64`; time outside the first year earns zero.
pub fn first_year_floor(
    network_started: i64,
    interval_start: i64,
    interval_end: i64,
) -> Result<u64, MathError> {
    if network_started < 0 || interval_start < 0 || interval_end < interval_start {
        return Err(MathError::InvalidTime);
    }
    let origin = calendar::Origin::from_unix_seconds(network_started)?;
    let mut floor = 0;
    let mut month_start = network_started;
    for month in 1..=12 {
        let month_end = origin.anniversary(month)?;
        let start = interval_start.max(month_start);
        let end = interval_end.min(month_end);
        if end > start {
            let duration = (month_end - month_start) as u128;
            let before = multiply_divide(
                MONTHLY_FLOOR as u128,
                (start - month_start) as u128,
                duration,
            )?;
            let earned_end =
                multiply_divide(MONTHLY_FLOOR as u128, (end - month_start) as u128, duration)?;
            // Each of twelve contributions is at most MONTHLY_FLOOR.
            floor += (earned_end - before) as u64;
        }
        month_start = month_end;
    }
    Ok(floor)
}

/// Applies one witness's exact attendance factor to the interval base floor.
pub fn scaled_floor(base: u64, weight: u128, posts: u64) -> Result<u64, MathError> {
    let denominator = 3 * posts as u128;
    if weight > denominator {
        return Err(MathError::InvalidWeight);
    }
    if weight == 0 {
        return Ok(0);
    }
    u64::try_from(multiply_divide(base as u128, weight, denominator)?)
        .map_err(|_| MathError::Overflow)
}

/// Reserves every floor before distributing any revenue proportionally.
///
/// Revenue covers floors first. The separate subsidy reserve covers precisely
/// their remaining shortfall; unused subsidy never enters the revenue pot.
pub fn reserve_floor(
    available: u64,
    subsidy: u64,
    required: u64,
) -> Result<FloorFunding, MathError> {
    let subsidy_used = required.saturating_sub(available);
    if subsidy_used > subsidy {
        return Err(MathError::UnderfundedFloor);
    }
    Ok(FloorFunding {
        subsidy_used,
        remainder: available.saturating_sub(required),
    })
}

/// Adds a witness's floor and its rounded-down proportional revenue share.
///
/// Sum returned allocations and retain the unallocated remainder as carry.
/// For an empty/zero-weight cohort this returns the supplied floor; callers
/// obtain a zero floor for zero weight from `scaled_floor`.
pub fn allocation(
    remainder: u64,
    weight: u128,
    total_weight: u128,
    floor: u64,
) -> Result<u64, MathError> {
    if weight > total_weight {
        return Err(MathError::InvalidWeight);
    }
    let share = if weight == 0 {
        0
    } else {
        u64::try_from(multiply_divide(remainder as u128, weight, total_weight)?)
            .map_err(|_| MathError::Overflow)?
    };
    floor.checked_add(share).ok_or(MathError::Overflow)
}

#[cfg(test)]
mod tests;

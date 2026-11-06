use crate::ALLOCATIONS;
use morse_rewards_math::utc_month_anniversary;
use pinocchio::error::ProgramError;
fn invalid() -> ProgramError {
    ProgramError::InvalidArgument
}
pub fn vested(kind: u8, started: i64, now: i64) -> Result<u64, ProgramError> {
    let total = *ALLOCATIONS.get(kind as usize).ok_or_else(invalid)?;
    if started <= 0 || now <= 0 || kind == 4 {
        return Err(invalid());
    }
    let (months, cliff) = match kind {
        0 => (48, 0),
        1 | 5 => (0, 0),
        2 => (48, 12),
        3 => (36, 12),
        6 => (24, 12),
        _ => return Err(invalid()),
    };
    if months == 0 {
        return Ok(if now >= started { total } else { 0 });
    }
    let anniversary = |month| utc_month_anniversary(started, month).map_err(|_| invalid());
    let finish = anniversary(months)?;
    if now < anniversary(cliff)? {
        return Ok(0);
    }
    if now >= finish {
        return Ok(total);
    }
    for month in 0..months {
        let begin = anniversary(month)?;
        let end = anniversary(month + 1)?;
        if now >= begin && now < end {
            let duration = (end - begin) as u128;
            let progress = month as u128 * duration + (now - begin) as u128;
            return Ok((total as u128 * progress / (months as u128 * duration)) as u64);
        }
    }
    Err(invalid())
}

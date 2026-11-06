//! Seven-day fully covered hour buckets over authenticated Pyth publications.
use pinocchio::error::ProgramError;
pub const HEADER: usize = 320;
pub const BUCKETS: usize = 169;
pub const LEN: usize = HEADER + BUCKETS * 32;
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Publication {
    pub price: u64,
    pub time: i64,
    pub slot: u64,
}
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn read_u64(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn read_i64(d: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn read_u128(d: &[u8], at: usize) -> u128 {
    u128::from_le_bytes(d[at..at + 16].try_into().unwrap())
}
fn header(d: &[u8]) -> Result<(), ProgramError> {
    if d.len() != LEN || &d[..4] != b"MTO\x01" || d[300..HEADER].iter().any(|x| *x != 0) {
        Err(invalid())
    } else {
        Ok(())
    }
}
pub fn record(data: &mut [u8], p: Publication) -> Result<(), ProgramError> {
    header(data)?;
    if p.price == 0 || p.time < 3600 {
        return Err(invalid());
    }
    let last = read_i64(data, 164);
    let price = read_u64(data, 172);
    let slot = read_u64(data, 180);
    if last < 0 || (last > 0 && price == 0) || p.time < last || p.slot < slot {
        return Err(invalid());
    }
    if p.time == last {
        return if p.price == price && p.slot == slot {
            Ok(())
        } else {
            Err(invalid())
        };
    }
    if last == 0 || p.time - last > 60 {
        data[HEADER..].fill(0);
    } else {
        let mut begin = last;
        while begin < p.time {
            let hour = begin / 3600;
            let boundary = (hour + 1).checked_mul(3600).ok_or_else(invalid)?;
            let end = core::cmp::min(p.time, boundary);
            let duration = (end - begin) as u64;
            let at = HEADER + (hour as usize % BUCKETS) * 32;
            if read_i64(data, at) != hour {
                data[at..at + 32].fill(0);
                data[at..at + 8].copy_from_slice(&hour.to_le_bytes());
            }
            let coverage = read_u64(data, at + 24)
                .checked_add(duration)
                .ok_or_else(invalid)?;
            if coverage > 3600 {
                return Err(invalid());
            }
            let integral = read_u128(data, at + 8)
                .checked_add(price as u128 * duration as u128)
                .ok_or_else(invalid)?;
            data[at + 8..at + 24].copy_from_slice(&integral.to_le_bytes());
            data[at + 24..at + 32].copy_from_slice(&coverage.to_le_bytes());
            begin = end;
        }
    }
    data[164..172].copy_from_slice(&p.time.to_le_bytes());
    data[172..180].copy_from_slice(&p.price.to_le_bytes());
    data[180..188].copy_from_slice(&p.slot.to_le_bytes());
    Ok(())
}
pub fn latest(data: &[u8], now: i64) -> Result<u64, ProgramError> {
    header(data)?;
    let time = read_i64(data, 164);
    let price = read_u64(data, 172);
    if time < 3600 || time > now || now - time > 60 || price == 0 || read_u64(data, 180) == 0 {
        return Err(invalid());
    }
    Ok(price)
}
pub fn twap(data: &[u8], now: i64) -> Result<u64, ProgramError> {
    header(data)?;
    let last = read_i64(data, 164);
    if last < 604800
        || last > now
        || now - last > 60
        || now / 3600 != last / 3600
        || read_u64(data, 172) == 0
    {
        return Err(invalid());
    }
    let end = last / 3600;
    let mut sum = 0u128;
    for hour in end - 168..end {
        let at = HEADER + (hour as usize % BUCKETS) * 32;
        let integral = read_u128(data, at + 8);
        if read_i64(data, at) != hour
            || read_u64(data, at + 24) != 3600
            || integral < 3600
            || integral > u64::MAX as u128 * 3600
        {
            return Err(invalid());
        }
        sum = sum.checked_add(integral).ok_or_else(invalid)?;
    }
    u64::try_from(sum / 604800).map_err(|_| invalid())
}
/// Full verification only. Account owner/key authentication belongs to the calling chain boundary.
pub fn publication(
    d: &[u8],
    feed: &[u8; 32],
    now: i64,
    slot: u64,
) -> Result<Publication, ProgramError> {
    if d.len() != 134
        || d[..8] != [34, 241, 35, 99, 157, 126, 244, 205]
        || d[8..40] == [0; 32]
        || d[40] != 1
        || d[41..73] != *feed
    {
        return Err(invalid());
    }
    let price = read_i64(d, 73);
    let confidence = read_u64(d, 81);
    let exponent = i32::from_le_bytes(d[89..93].try_into().unwrap());
    let time = read_i64(d, 93);
    let previous = read_i64(d, 101);
    let posted = read_u64(d, 125);
    if price <= 0
        || confidence as u128 * 100 > price as u128
        || !(-12..=0).contains(&exponent)
        || time < 3600
        || time > now
        || now - time > 60
        || previous < 0
        || previous > time
        || posted == 0
        || posted > slot
    {
        return Err(invalid());
    }
    let conservative = price as u128 - confidence as u128;
    let shift = exponent + 6;
    let factor = 10u128.pow(shift.unsigned_abs());
    let normalized = if shift >= 0 {
        conservative.checked_mul(factor).ok_or_else(invalid)?
    } else {
        conservative / factor
    };
    let normalized = u64::try_from(normalized).map_err(|_| invalid())?;
    if normalized == 0 {
        return Err(invalid());
    }
    Ok(Publication {
        price: normalized,
        time,
        slot: posted,
    })
}

use crate::processor::{config, create, owned, pda};
use pinocchio::{
    cpi::Seed,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
pub const PYTH_RECEIVER: Address =
    Address::from_str_const("rec5EKMGg6MxZYaMdyBfgwp4d5rB9T1VQH5pJv5LtFJ");
pub const PYTH_PRO_RECEIVER: Address =
    Address::from_str_const("rec2HHDDnjLfj4kE7VyEtFA1HPGQLK33259532cRyHp");
fn source(program: &AccountView, account: &AccountView) -> ProgramResult {
    if (program.address() != &PYTH_RECEIVER && program.address() != &PYTH_PRO_RECEIVER)
        || !program.executable()
        || account.executable()
        || account.owner() != program.address()
    {
        return Err(invalid());
    }
    Ok(())
}
fn bound(
    program: &Address,
    cfg: &AccountView,
    mint: &AccountView,
    a: &AccountView,
) -> ProgramResult {
    config(program, cfg, mint)?;
    owned(program, a, false)?;
    pda(program, &[b"oracle"], a)?;
    let d = a.try_borrow()?;
    header(&d)?;
    if d[4..36] != *cfg.address().as_ref()
        || d[36..68] != *mint.address().as_ref()
        || d[100..132] == [0; 32]
        || d[132..164] == [0; 32]
        || read_u64(&d, 292) == 0
        || (read_i64(&d, 284) == 0 && d[188..284].iter().any(|x| *x != 0))
        || read_i64(&d, 284) < 0
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn initialize(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [gov, payer, cfg, mint, a, source_program, source_account, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    config(program, cfg, mint)?;
    source(source_program, source_account)?;
    {
        let c = cfg.try_borrow()?;
        if !gov.is_signer()
            || c[4..36] != *gov.address().as_ref()
            || payload[..32] != *source_account.address().as_ref()
            || payload[32..] == [0; 32]
        {
            return Err(invalid());
        }
    }
    let bump = [pda(program, &[b"oracle"], a)?];
    if a.owner() == program {
        bound(program, cfg, mint, a)?;
        let d = a.try_borrow()?;
        if d[68..100] != *source_program.address().as_ref() || d[100..164] != *payload {
            return Err(invalid());
        }
        return Ok(());
    }
    let clock = Clock::get()?;
    let p = {
        let d = source_account.try_borrow()?;
        publication(
            &d,
            payload[32..].try_into().unwrap(),
            clock.unix_timestamp,
            clock.slot,
        )?
    };
    create(
        program,
        program,
        payer,
        a,
        system,
        LEN,
        &[Seed::from(b"oracle"), Seed::from(&bump)],
    )?;
    let mut d = a.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MTO\x01");
    d[4..36].copy_from_slice(cfg.address().as_ref());
    d[36..68].copy_from_slice(mint.address().as_ref());
    d[68..100].copy_from_slice(source_program.address().as_ref());
    d[100..164].copy_from_slice(payload);
    d[292..300].copy_from_slice(&1u64.to_le_bytes());
    record(&mut d, p)
}
pub(crate) fn observe(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [cfg, mint, a, source_program, source_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    bound(program, cfg, mint, a)?;
    owned(program, a, true)?;
    source(source_program, source_account)?;
    let clock = Clock::get()?;
    let p = {
        let d = a.try_borrow()?;
        if d[68..100] != *source_program.address().as_ref()
            || d[100..132] != *source_account.address().as_ref()
        {
            return Err(invalid());
        }
        let source = source_account.try_borrow()?;
        publication(
            &source,
            d[132..164].try_into().unwrap(),
            clock.unix_timestamp,
            clock.slot,
        )?
    };
    record(&mut a.try_borrow_mut()?, p)
}
/// Fresh conservative authenticated spot; unlike bond valuation, it does not imply seven-day coverage.
pub fn spot(
    program: &Address,
    cfg: &AccountView,
    mint: &AccountView,
    a: &AccountView,
    now: i64,
) -> Result<u64, ProgramError> {
    bound(program, cfg, mint, a)?;
    latest(&a.try_borrow()?, now)
}
pub fn value(
    program: &Address,
    cfg: &AccountView,
    mint: &AccountView,
    a: &AccountView,
    now: i64,
) -> Result<u64, ProgramError> {
    bound(program, cfg, mint, a)?;
    twap(&a.try_borrow()?, now)
}
pub(crate) fn validate(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [cfg, mint, a] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    value(program, cfg, mint, a, Clock::get()?.unix_timestamp)?;
    Ok(())
}

pub fn revision(
    program: &Address,
    cfg: &AccountView,
    mint: &AccountView,
    a: &AccountView,
) -> Result<u64, ProgramError> {
    bound(program, cfg, mint, a)?;
    Ok(read_u64(&a.try_borrow()?, 292))
}
pub(crate) fn propose_source(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [gov, cfg, mint, a, source_program, source_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    bound(program, cfg, mint, a)?;
    owned(program, a, true)?;
    source(source_program, source_account)?;
    {
        let c = cfg.try_borrow()?;
        if !gov.is_signer() || c[4..36] != *gov.address().as_ref() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    if payload[..32] != *source_account.address().as_ref() || payload[32..] == [0; 32] {
        return Err(invalid());
    }
    let clock = Clock::get()?;
    publication(
        &source_account.try_borrow()?,
        payload[32..].try_into().unwrap(),
        clock.unix_timestamp,
        clock.slot,
    )?;
    let mut d = a.try_borrow_mut()?;
    if d[68..100] == *source_program.address().as_ref() && d[100..164] == *payload {
        return Err(ProgramError::InvalidArgument);
    }
    if d[188..220] == *source_program.address().as_ref() && d[220..284] == *payload {
        return Ok(());
    }
    let ready = clock
        .unix_timestamp
        .checked_add(14 * 86400)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    d[188..220].copy_from_slice(source_program.address().as_ref());
    d[220..284].copy_from_slice(payload);
    d[284..292].copy_from_slice(&ready.to_le_bytes());
    Ok(())
}
pub(crate) fn execute_source(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [cfg, mint, a, source_program, source_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    bound(program, cfg, mint, a)?;
    owned(program, a, true)?;
    source(source_program, source_account)?;
    let clock = Clock::get()?;
    let p = {
        let d = a.try_borrow()?;
        let ready = read_i64(&d, 284);
        if ready == 0
            || clock.unix_timestamp < ready
            || d[188..220] != *source_program.address().as_ref()
            || d[220..252] != *source_account.address().as_ref()
        {
            return Err(invalid());
        }
        publication(
            &source_account.try_borrow()?,
            d[252..284].try_into().unwrap(),
            clock.unix_timestamp,
            clock.slot,
        )?
    };
    let mut d = a.try_borrow_mut()?;
    let next = read_u64(&d, 292)
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    d.copy_within(188..284, 68);
    d[164..292].fill(0);
    d[292..300].copy_from_slice(&next.to_le_bytes());
    d[HEADER..].fill(0);
    record(&mut d, p)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn empty() -> Vec<u8> {
        let mut d = vec![0; LEN];
        d[..4].copy_from_slice(b"MTO\x01");
        d
    }
    #[test]
    fn complete_168_hours_use_time_weights_and_never_extrapolate_or_prorate_partial_hours() {
        let start = 1_700_002_800;
        assert_eq!(start % 3600, 0);
        let mut d = empty();
        let p = |t| Publication {
            price: if t < start + 302400 {
                1_000_000
            } else {
                3_000_000
            },
            time: t,
            slot: t as u64,
        };
        record(&mut d, p(start)).unwrap();
        assert!(twap(&d, start).is_err());
        for delta in (60..=604800).step_by(60) {
            record(&mut d, p(start + delta)).unwrap();
        }
        assert_eq!(twap(&d, start + 604800), Ok(2_000_000));
        assert_eq!(latest(&d, start + 604800), Ok(3_000_000));
        assert_eq!(twap(&d, start + 604859), Ok(2_000_000));
        assert!(twap(&d, start + 604861).is_err());
        record(&mut d, p(start + 604860)).unwrap();
        assert_eq!(twap(&d, start + 604860), Ok(2_000_000));
        let saved = d.clone();
        assert!(record(&mut d, p(start + 604800)).is_err());
        assert_eq!(d, saved);
        record(&mut d, p(start + 605000)).unwrap();
        assert!(twap(&d, start + 605000).is_err());
    }
    #[test]
    fn replay_conflict_overflow_and_missing_hour_are_fail_closed() {
        let start = 1_700_002_800;
        let mut d = empty();
        let p = Publication {
            price: u64::MAX,
            time: start,
            slot: 9,
        };
        record(&mut d, p).unwrap();
        let saved = d.clone();
        record(&mut d, p).unwrap();
        assert_eq!(d, saved);
        assert!(record(&mut d, Publication { price: 1, ..p }).is_err());
        assert_eq!(d, saved);
        for delta in (60..=604800).step_by(60) {
            record(
                &mut d,
                Publication {
                    time: start + delta,
                    slot: 9 + delta as u64,
                    ..p
                },
            )
            .unwrap();
        }
        assert_eq!(twap(&d, start + 604800), Ok(u64::MAX));
        let old = ((start / 3600) as usize % BUCKETS) * 32 + HEADER;
        d[old + 24..old + 32].copy_from_slice(&3599u64.to_le_bytes());
        assert!(twap(&d, start + 604800).is_err());
    }
    #[test]
    fn pyth_full_price_update_v2_rejects_partial_wrong_feed_stale_future_and_uncertain_prices() {
        let mut d = vec![0; 134];
        d[..8].copy_from_slice(&[34, 241, 35, 99, 157, 126, 244, 205]);
        d[8..40].fill(99);
        d[40] = 1;
        d[41..73].fill(7);
        d[73..81].copy_from_slice(&200_000_000i64.to_le_bytes());
        d[81..89].copy_from_slice(&1_000_000u64.to_le_bytes());
        d[89..93].copy_from_slice(&(-8i32).to_le_bytes());
        d[93..101].copy_from_slice(&10000i64.to_le_bytes());
        d[101..109].copy_from_slice(&9999i64.to_le_bytes());
        d[125..133].copy_from_slice(&77u64.to_le_bytes());
        assert_eq!(
            publication(&d, &[7; 32], 10060, 77),
            Ok(Publication {
                price: 1_990_000,
                time: 10000,
                slot: 77
            })
        );
        for (offset, value) in [(0, 0), (40, 0), (41, 8)] {
            let mut wrong = d.clone();
            wrong[offset] = value;
            assert!(publication(&wrong, &[7; 32], 10000, 77).is_err());
        }
        assert!(publication(&d, &[7; 32], 10061, 77).is_err());
        assert!(publication(&d, &[7; 32], 9999, 77).is_err());
        assert!(publication(&d, &[7; 32], 10000, 76).is_err());
        d[81..89].copy_from_slice(&2_000_001u64.to_le_bytes());
        assert!(publication(&d, &[7; 32], 10000, 77).is_err());
        d[81..89].copy_from_slice(&0u64.to_le_bytes());
        d[73..81].copy_from_slice(&(-1i64).to_le_bytes());
        assert!(publication(&d, &[7; 32], 10000, 77).is_err());
    }
}

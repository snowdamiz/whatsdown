//! Judge-owned weekly counters. The ring bitmap is the deduplication authority;
//! this companion retains the chain posting week and counters across ring wrap.
use crate::{
    processor::{check_governance, create_pda, load_log, owned, pda},
    witness::COSIGN_WINDOW,
};
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};

pub const EPOCH_SECONDS: i64 = 7 * 24 * 60 * 60;
pub const CLOCK_LEN: usize = 80 + 4096 * 16;
pub const EPOCH_LEN: usize = 80 + 64 * 40;

fn wide(data: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(data[offset..offset + 8].try_into().unwrap())
}

pub fn epoch_at(now: i64) -> Result<u64, ProgramError> {
    u64::try_from(now / EPOCH_SECONDS)
        .ok()
        .filter(|_| now >= 0)
        .ok_or(ProgramError::InvalidArgument)
}

#[derive(Debug, PartialEq, Eq)]
pub struct ClockHeader {
    pub log_id: [u8; 32],
    pub activated_at: i64,
    pub activated_slot: u64,
    pub first_full_epoch: u64,
    pub latest_post_epoch: u64,
}

impl ClockHeader {
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() < 80
            || data.len() > CLOCK_LEN
            || !(data.len() - 80).is_multiple_of(16)
            || &data[..4] != b"MAC\x01"
            || data[68..80].iter().any(|b| *b != 0)
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let h = Self {
            log_id: data[4..36].try_into().unwrap(),
            activated_at: i64::from_le_bytes(data[36..44].try_into().unwrap()),
            activated_slot: wide(data, 44),
            first_full_epoch: wide(data, 52),
            latest_post_epoch: wide(data, 60),
        };
        if h.activated_at < 0
            || (h.activated_at == 0 && data[44..68].iter().any(|b| *b != 0))
            || (h.activated_at > 0
                && (h.first_full_epoch != epoch_at(h.activated_at)? + 1
                    || h.latest_post_epoch < epoch_at(h.activated_at)?))
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(h)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct EpochHeader {
    pub log_id: [u8; 32],
    pub epoch: u64,
    pub posts: u64,
    pub max_post_slot: u64,
    pub witnesses: u16,
    pub sealed: bool,
}

impl EpochHeader {
    pub fn parse(data: &[u8]) -> Result<Self, ProgramError> {
        if data.len() != EPOCH_LEN
            || &data[..4] != b"MAE\x01"
            || data[62] > 1
            || data[63..80].iter().any(|b| *b != 0)
        {
            return Err(ProgramError::InvalidAccountData);
        }
        let h = Self {
            log_id: data[4..36].try_into().unwrap(),
            epoch: wide(data, 36),
            posts: wide(data, 44),
            max_post_slot: wide(data, 52),
            witnesses: u16::from_le_bytes(data[60..62].try_into().unwrap()),
            sealed: data[62] == 1,
        };
        if h.witnesses > 64
            || (h.posts == 0 && (h.max_post_slot != 0 || h.witnesses != 0))
            || data[80 + h.witnesses as usize * 40..]
                .iter()
                .any(|b| *b != 0)
        {
            return Err(ProgramError::InvalidAccountData);
        }
        for n in 0..h.witnesses as usize {
            let offset = 80 + n * 40;
            if data[offset..offset + 32] == [0; 32]
                || wide(data, offset + 32) == 0
                || wide(data, offset + 32) > h.posts
                || (n > 0 && data[offset - 40..offset - 8] >= data[offset..offset + 32])
            {
                return Err(ProgramError::InvalidAccountData);
            }
        }
        Ok(h)
    }
}

pub fn initialize_clock(data: &mut [u8], log_id: &[u8; 32]) -> ProgramResult {
    if data.len() < 80 || data.len() > CLOCK_LEN || data.iter().any(|b| *b != 0) {
        return Err(ProgramError::InvalidAccountData);
    }
    data[..4].copy_from_slice(b"MAC\x01");
    data[4..36].copy_from_slice(log_id);
    Ok(())
}

pub fn activate_clock(data: &mut [u8], now: i64, slot: u64) -> ProgramResult {
    let h = ClockHeader::parse(data)?;
    if data.len() != CLOCK_LEN || h.activated_at != 0 || now <= 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let epoch = epoch_at(now)?;
    data[36..44].copy_from_slice(&now.to_le_bytes());
    data[44..52].copy_from_slice(&slot.to_le_bytes());
    data[52..60].copy_from_slice(&(epoch + 1).to_le_bytes());
    data[60..68].copy_from_slice(&epoch.to_le_bytes());
    Ok(())
}

pub fn initialize_epoch(data: &mut [u8], log_id: &[u8; 32], epoch: u64) -> ProgramResult {
    if data.len() != EPOCH_LEN || data.iter().any(|b| *b != 0) {
        return Err(ProgramError::InvalidAccountData);
    }
    data[..4].copy_from_slice(b"MAE\x01");
    data[4..36].copy_from_slice(log_id);
    data[36..44].copy_from_slice(&epoch.to_le_bytes());
    Ok(())
}

// Only called after append_anchor returns a new ring index. A duplicate post
// must not reach here. Both accounts roll back atomically on transaction error.
pub fn record_post(
    clock: &mut [u8],
    week: &mut [u8],
    index: u16,
    slot: u64,
    epoch: u64,
) -> ProgramResult {
    let c = ClockHeader::parse(clock)?;
    let w = EpochHeader::parse(week)?;
    if clock.len() != CLOCK_LEN
        || c.activated_at == 0
        || slot < c.activated_slot
        || epoch < c.latest_post_epoch
        || w.log_id != c.log_id
        || w.epoch != epoch
        || w.sealed
        || slot < w.max_post_slot
        || index >= 4096
    {
        return Err(ProgramError::InvalidArgument);
    }
    let posts = w
        .posts
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let marker = epoch
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let offset = 80 + index as usize * 16;
    clock[offset..offset + 8].copy_from_slice(&marker.to_le_bytes());
    clock[offset + 8..offset + 16].copy_from_slice(&slot.to_le_bytes());
    clock[60..68].copy_from_slice(&epoch.to_le_bytes());
    week[44..52].copy_from_slice(&posts.to_le_bytes());
    week[52..60].copy_from_slice(&slot.to_le_bytes());
    Ok(())
}

pub fn posting_epoch(clock: &[u8], index: u16, slot: u64) -> Result<Option<u64>, ProgramError> {
    let h = ClockHeader::parse(clock)?;
    if clock.len() != CLOCK_LEN || h.activated_at == 0 || index >= 4096 {
        return Err(ProgramError::InvalidArgument);
    }
    let offset = 80 + index as usize * 16;
    let marker = wide(clock, offset);
    if marker == 0 && wide(clock, offset + 8) == 0 && slot <= h.activated_slot {
        return Ok(None);
    }
    if marker == 0 || wide(clock, offset + 8) != slot || slot < h.activated_slot {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(Some(marker - 1))
}

// The caller verifies the signature and checks that the combined ring bitmap
// did not already contain this witness. Native + C2SP counts only once.
pub fn record_signature(
    clock: &[u8],
    week: &mut [u8],
    index: u16,
    slot: u64,
    witness: &[u8; 32],
) -> Result<bool, ProgramError> {
    let Some(epoch) = posting_epoch(clock, index, slot)? else {
        return Ok(false);
    };
    let h = EpochHeader::parse(week)?;
    if h.log_id != clock[4..36] || h.epoch != epoch || h.sealed || *witness == [0; 32] {
        return Err(ProgramError::InvalidArgument);
    }
    let mut position = h.witnesses as usize;
    for n in 0..h.witnesses as usize {
        let offset = 80 + n * 40;
        let key = &week[offset..offset + 32];
        if key == witness {
            let signed = wide(week, offset + 32)
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            if signed > h.posts {
                return Err(ProgramError::InvalidAccountData);
            }
            week[offset + 32..offset + 40].copy_from_slice(&signed.to_le_bytes());
            return Ok(true);
        }
        if key > witness {
            position = n;
            break;
        }
    }
    if h.witnesses == 64 || h.posts == 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    let offset = 80 + position * 40;
    week.copy_within(offset..80 + h.witnesses as usize * 40, offset + 40);
    week[offset..offset + 32].copy_from_slice(witness);
    week[offset + 32..offset + 40].copy_from_slice(&1u64.to_le_bytes());
    week[60..62].copy_from_slice(&(h.witnesses + 1).to_le_bytes());
    Ok(true)
}

pub fn seal_epoch(week: &mut [u8], now: i64, slot: u64) -> ProgramResult {
    let h = EpochHeader::parse(week)?;
    if epoch_at(now)? <= h.epoch
        || (h.posts > 0
            && slot
                <= h.max_post_slot
                    .checked_add(COSIGN_WINDOW)
                    .ok_or(ProgramError::ArithmeticOverflow)?)
    {
        return Err(ProgramError::InvalidArgument);
    }
    week[62] = 1;
    Ok(())
}

fn check_clock(
    program: &Address,
    account: &AccountView,
    log_id: &[u8],
    writable: bool,
) -> ProgramResult {
    owned(program, account, writable)?;
    pda(program, &[b"attendance", log_id], account)?;
    if ClockHeader::parse(&account.try_borrow()?)?.log_id != log_id {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(())
}

fn check_epoch(
    program: &Address,
    account: &AccountView,
    log_id: &[u8],
) -> Result<u64, ProgramError> {
    owned(program, account, true)?;
    let h = EpochHeader::parse(&account.try_borrow()?)?;
    pda(
        program,
        &[b"attendance-epoch", log_id, &h.epoch.to_le_bytes()],
        account,
    )?;
    if h.log_id != log_id {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(h.epoch)
}

pub(crate) fn initialize(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [governance, payer, config, log, clock, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_governance(program, config, governance)?;
    let log = load_log(program, log)?;
    if log[7] != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let id = &log[40..72];
    let bump = [pda(program, &[b"attendance", id], clock)?];
    create_pda(
        program,
        payer,
        clock,
        system,
        80,
        CLOCK_LEN,
        &[Seed::from(b"attendance"), Seed::from(id), Seed::from(&bump)],
    )?;
    initialize_clock(&mut clock.try_borrow_mut()?, id.try_into().unwrap())
}

pub(crate) fn grow(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [log, clock] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let log = load_log(program, log)?;
    check_clock(program, clock, &log[40..72], true)?;
    if clock.data_len() == CLOCK_LEN {
        return Ok(());
    }
    if ClockHeader::parse(&clock.try_borrow()?)?.activated_at != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let next = (clock.data_len() + 10240).min(CLOCK_LEN);
    if clock.lamports() < Rent::get()?.try_minimum_balance(next)? {
        return Err(ProgramError::AccountNotRentExempt);
    }
    clock.resize(next)
}

pub(crate) fn enable(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [governance, config, log_account, clock] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_governance(program, config, governance)?;
    owned(program, log_account, true)?;
    let log = load_log(program, log_account)?;
    check_clock(program, clock, &log[40..72], true)?;
    if log[7] != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let now = Clock::get()?;
    activate_clock(&mut clock.try_borrow_mut()?, now.unix_timestamp, now.slot)?;
    log_account.try_borrow_mut()?[7] = 1;
    Ok(())
}

pub(crate) fn open_epoch(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [payer, log, clock, week, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log = load_log(program, log)?;
    check_clock(program, clock, &log[40..72], false)?;
    let h = ClockHeader::parse(&clock.try_borrow()?)?;
    let epoch = wide(payload, 0);
    if log[7] != 1
        || h.activated_at == 0
        || epoch < epoch_at(h.activated_at)?
        || epoch > epoch_at(Clock::get()?.unix_timestamp)?
    {
        return Err(ProgramError::InvalidArgument);
    }
    let id = &log[40..72];
    let bump = [pda(program, &[b"attendance-epoch", id, payload], week)?];
    if week.owner() == program {
        if check_epoch(program, week, id)? != epoch {
            return Err(ProgramError::InvalidAccountData);
        }
        return Ok(());
    }
    create_pda(
        program,
        payer,
        week,
        system,
        EPOCH_LEN,
        EPOCH_LEN,
        &[
            Seed::from(b"attendance-epoch"),
            Seed::from(id),
            Seed::from(payload),
            Seed::from(&bump),
        ],
    )?;
    initialize_epoch(&mut week.try_borrow_mut()?, id.try_into().unwrap(), epoch)
}

pub(crate) fn seal(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [log, week] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let log = load_log(program, log)?;
    if log[7] != 1 {
        return Err(ProgramError::InvalidArgument);
    }
    check_epoch(program, week, &log[40..72])?;
    let now = Clock::get()?;
    seal_epoch(&mut week.try_borrow_mut()?, now.unix_timestamp, now.slot)
}

pub(crate) fn post(
    program: &Address,
    accounts: &mut [AccountView],
    log_id: &[u8],
    index: Option<u16>,
    now: &Clock,
) -> ProgramResult {
    let [clock, week] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_clock(program, clock, log_id, true)?;
    if check_epoch(program, week, log_id)? != epoch_at(now.unix_timestamp)? {
        return Err(ProgramError::InvalidArgument);
    }
    if let Some(index) = index {
        record_post(
            &mut clock.try_borrow_mut()?,
            &mut week.try_borrow_mut()?,
            index,
            now.slot,
            epoch_at(now.unix_timestamp)?,
        )?;
    }
    Ok(())
}

pub(crate) fn cosign(
    program: &Address,
    accounts: &mut [AccountView],
    log_id: &[u8],
    index: u16,
    posted: u64,
    witness: &[u8; 32],
    first: bool,
) -> ProgramResult {
    let [clock, week] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_clock(program, clock, log_id, false)?;
    let bytes = clock.try_borrow()?;
    if let Some(epoch) = posting_epoch(&bytes, index, posted)? {
        if check_epoch(program, week, log_id)? != epoch {
            return Err(ProgramError::InvalidArgument);
        }
        if first {
            record_signature(&bytes, &mut week.try_borrow_mut()?, index, posted, witness)?;
        }
    }
    Ok(())
}

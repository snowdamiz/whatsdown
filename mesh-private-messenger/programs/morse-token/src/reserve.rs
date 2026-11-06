//! One immutable reserve destination, qualified before any floor-only CPI funding.
use crate::{
    collateral_state::decode_economics,
    judge_binding::{load_binding, qualified_program_slot},
    processor::{clock, config, create, owned, pda},
};
use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use pinocchio_token::state::Mint;
use solana_sha256_hasher::hash;
pub const PROFILE_LEN: usize = 320;
pub const DELAY: i64 = 14 * 86400;
const WEEK: u64 = 604800;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn wide(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn time(d: &[u8], at: usize) -> i64 {
    i64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn key(d: &[u8], at: usize) -> Address {
    Address::new_from_array(d[at..at + 32].try_into().unwrap())
}
#[derive(Clone, Debug, PartialEq)]
pub struct ReserveProfile {
    pub config: Address,
    pub mint: Address,
    pub usdc: Address,
    pub judge: Address,
    pub log: Address,
    pub binding: Address,
    pub rewards: Address,
    pub pool: Address,
    pub token_pool: Address,
    pub ready_at: i64,
    pub rewards_slot: u64,
    pub judge_slot: u64,
}
impl ReserveProfile {
    pub fn parse(d: &[u8]) -> Result<Self, ProgramError> {
        if d.len() != PROFILE_LEN
            || &d[..4] != b"MRS\x02"
            || d[4..292].as_chunks::<32>().0.contains(&[0; 32])
            || time(d, 292) <= 0
            || d[316..].iter().any(|b| *b != 0)
        {
            return Err(invalid());
        }
        let value = Self {
            config: key(d, 4),
            mint: key(d, 36),
            usdc: key(d, 68),
            judge: key(d, 100),
            log: key(d, 132),
            binding: key(d, 164),
            rewards: key(d, 196),
            pool: key(d, 228),
            token_pool: key(d, 260),
            ready_at: time(d, 292),
            rewards_slot: wide(d, 300),
            judge_slot: wide(d, 308),
        };
        if value.mint == value.usdc || value.judge == value.rewards {
            return Err(invalid());
        }
        Ok(value)
    }
}
pub fn load(program: &Address, account: &AccountView) -> Result<ReserveProfile, ProgramError> {
    owned(program, account, false)?;
    pda(program, &[b"reserve-config"], account)?;
    ReserveProfile::parse(&account.try_borrow()?)
}
pub(crate) fn initialize(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [governance, payer, cfg, mint, profile, judge, judge_data, log, economy, binding, rewards, rewards_data, pool, usdc, oracle, token, token_data, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    config(program, cfg, mint)?;
    if !governance.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if cfg.try_borrow()?[4..36] != *governance.address().as_ref() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if token.address() != program
        || judge.address() == program
        || rewards.address() == program
        || judge.address() == rewards.address()
    {
        return Err(invalid());
    }
    let token_slot = qualified_program_slot(token, token_data)?;
    let judge_slot = qualified_program_slot(judge, judge_data)?;
    let rewards_slot = qualified_program_slot(rewards, rewards_data)?;
    owned(judge.address(), log, false)?;
    let log_id = {
        let d = log.try_borrow()?;
        if d.len() != 352
            || &d[..4] != b"MLG\x01"
            || !matches!(d[4], 1 | 2)
            || d[5] > 1
            || d[6] == 0
            || d[6] > 32
            || d[7] > 1
        {
            return Err(invalid());
        }
        let name = &d[8..8 + d[6] as usize];
        if !name
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
            || d[8 + name.len()..40].iter().any(|b| *b != 0)
            || d[40..72] != hash(name).to_bytes()
        {
            return Err(invalid());
        }
        pda(judge.address(), &[b"log", name], log)?;
        <[u8; 32]>::try_from(&d[40..72]).unwrap()
    };
    let bound = load_binding(judge.address(), binding, &log_id)?;
    if bound.activated_at == 0
        || bound.log != *log.address()
        || bound.token_program != *program
        || bound.token_config != *cfg.address()
        || bound.mint != *mint.address()
        || bound.oracle != *oracle.address()
        || bound.rewards_program != *rewards.address()
        || bound.rewards_pool != *pool.address()
        || bound.token_slot != token_slot
        || bound.rewards_slot != rewards_slot
    {
        return Err(invalid());
    }
    owned(judge.address(), economy, false)?;
    pda(judge.address(), &[b"economics", &log_id], economy)?;
    {
        let d = economy.try_borrow()?;
        decode_economics(&d)?;
        if d[4..36] != log_id || d[36..68] != *usdc.address().as_ref() {
            return Err(invalid());
        }
    }
    owned(&pinocchio_token::ID, usdc, false)?;
    if usdc.data_len() != 82 {
        return Err(invalid());
    }
    let usd = Mint::from_account_view(usdc)?;
    if !usd.is_initialized() || usd.decimals() != 6 || usdc.address() == mint.address() {
        return Err(invalid());
    }
    drop(usd);
    owned(rewards.address(), pool, false)?;
    pda(rewards.address(), &[b"pool"], pool)?;
    {
        let d = pool.try_borrow()?;
        if d.len() != 304
            || &d[..3] != b"MRP"
            || !matches!(d[3], 1 | 2)
            || d[4..36] == [0; 32]
            || d[36..68] != *judge.address().as_ref()
            || d[68..100] != *log.address().as_ref()
            || d[100..132] != log_id
            || d[132..164] != *usdc.address().as_ref()
            || time(&d, 164) <= 0
            || wide(&d, 172) != (time(&d, 164) as u64 / WEEK) + 1
            || wide(&d, 180) < wide(&d, 172)
            || (wide(&d, 220) != 0
                && wide(&d, 220) != wide(&d, 180).checked_add(1).ok_or(invalid())?)
            || wide(&d, 188)
                .checked_add(wide(&d, 196))
                .and_then(|v| v.checked_add(wide(&d, 204)))
                .is_none_or(|v| v > wide(&d, 212))
            || time(&d, 260) < 0
            || (time(&d, 260) == 0 && d[228..260].iter().any(|b| *b != 0))
            || d[268..300] == [0; 32]
            || d[300..].iter().any(|b| *b != 0)
        {
            return Err(invalid());
        }
    }
    crate::oracle::revision(program, cfg, mint, oracle)?;
    let token_pool = Address::find_program_address(&[b"token-pool"], rewards.address()).0;
    let value = ReserveProfile {
        config: Address::new_from_array(*cfg.address().as_array()),
        mint: Address::new_from_array(*mint.address().as_array()),
        usdc: Address::new_from_array(*usdc.address().as_array()),
        judge: Address::new_from_array(*judge.address().as_array()),
        log: Address::new_from_array(*log.address().as_array()),
        binding: Address::new_from_array(*binding.address().as_array()),
        rewards: Address::new_from_array(*rewards.address().as_array()),
        pool: Address::new_from_array(*pool.address().as_array()),
        token_pool,
        ready_at: clock()?
            .checked_add(DELAY)
            .ok_or(ProgramError::ArithmeticOverflow)?,
        rewards_slot,
        judge_slot,
    };
    let bump = [pda(program, &[b"reserve-config"], profile)?];
    if profile.owner() == program {
        let mut old = load(program, profile)?;
        old.ready_at = value.ready_at;
        if old != value {
            return Err(invalid());
        }
        return Ok(());
    }
    crate::oracle::value(program, cfg, mint, oracle, clock()?)?;
    create(
        program,
        program,
        payer,
        profile,
        system,
        PROFILE_LEN,
        &[Seed::from(b"reserve-config"), Seed::from(&bump)],
    )?;
    let mut d = profile.try_borrow_mut()?;
    d.fill(0);
    d[..4].copy_from_slice(b"MRS\x02");
    for (at, address) in [
        (4, value.config),
        (36, value.mint),
        (68, value.usdc),
        (100, value.judge),
        (132, value.log),
        (164, value.binding),
        (196, value.rewards),
        (228, value.pool),
        (260, value.token_pool),
    ] {
        d[at..at + 32].copy_from_slice(address.as_ref());
    }
    d[292..300].copy_from_slice(&value.ready_at.to_le_bytes());
    d[300..308].copy_from_slice(&value.rewards_slot.to_le_bytes());
    d[308..316].copy_from_slice(&value.judge_slot.to_le_bytes());
    Ok(())
}

pub const RECEIPT_LEN: usize = 256;
#[allow(clippy::too_many_arguments)]
fn authorize_funding(program: &Address, a: &[AccountView]) -> ProgramResult {
    let [pool, token_pool, ledger, token_epoch, profile, cfg, mint, oracle, _, _, destination, _, _, rewards, rewards_data, judge, judge_data, economy, binding, token, token_data, _, _] =
        a
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let r = load(program, profile)?;
    config(program, cfg, mint)?;
    if !pool.is_signer()
        || r.pool != *pool.address()
        || r.token_pool != *token_pool.address()
        || r.config != *cfg.address()
        || r.mint != *mint.address()
        || r.rewards != *rewards.address()
        || r.judge != *judge.address()
        || r.binding != *binding.address()
        || token.address() != program
        || clock()? < r.ready_at
        || qualified_program_slot(rewards, rewards_data)? != r.rewards_slot
        || qualified_program_slot(judge, judge_data)? != r.judge_slot
    {
        return Err(invalid());
    }
    owned(rewards.address(), pool, false)?;
    pda(rewards.address(), &[b"pool"], pool)?;
    let log_id = {
        let d = pool.try_borrow()?;
        if d.len() != 304
            || &d[..4] != b"MRP\x02"
            || d[36..68] != *judge.address().as_ref()
            || d[68..100] != *r.log.as_ref()
            || d[132..164] != *r.usdc.as_ref()
        {
            return Err(invalid());
        }
        <[u8; 32]>::try_from(&d[100..132]).unwrap()
    };
    let b = load_binding(judge.address(), binding, &log_id)?;
    if b.activated_at == 0
        || b.log != r.log
        || b.token_program != *program
        || b.token_config != *cfg.address()
        || b.mint != *mint.address()
        || b.oracle != *oracle.address()
        || b.rewards_program != *rewards.address()
        || b.rewards_pool != *pool.address()
        || b.rewards_slot != r.rewards_slot
        || qualified_program_slot(token, token_data)? != b.token_slot
    {
        return Err(invalid());
    }
    owned(judge.address(), economy, false)?;
    pda(judge.address(), &[b"economics", &log_id], economy)?;
    let revision = {
        let d = economy.try_borrow()?;
        let s = decode_economics(&d)?;
        if d[4..36] != log_id || d[36..68] != *r.usdc.as_ref() {
            return Err(invalid());
        }
        s.revision
    };
    owned(rewards.address(), token_pool, false)?;
    pda(rewards.address(), &[b"token-pool"], token_pool)?;
    let t = crate::reward_state::TokenPool::parse(&token_pool.try_borrow()?)?;
    if t.pool != *pool.address()
        || t.binding != *binding.address()
        || t.token_program != *program
        || t.config != *cfg.address()
        || t.mint != *mint.address()
        || t.oracle != *oracle.address()
        || t.profile != *profile.address()
        || t.vault != *destination.address()
    {
        return Err(invalid());
    }
    owned(rewards.address(), token_epoch, false)?;
    let e = crate::reward_state::TokenEpoch::parse(&token_epoch.try_borrow()?)?;
    pda(
        rewards.address(),
        &[b"token-epoch", &e.epoch.to_le_bytes()],
        token_epoch,
    )?;
    owned(rewards.address(), ledger, false)?;
    pda(
        rewards.address(),
        &[b"epoch", &e.epoch.to_le_bytes()],
        ledger,
    )?;
    if e.token_pool != *token_pool.address().as_array()
        || e.ledger != *ledger.address().as_array()
        || e.status != 1
        || e.snapshot_at <= 0
        || e.snapshot_at > clock()?
        || clock()? >= e.snapshot_at.checked_add(3600).ok_or(invalid())?
        || e.claimed != 0
        || e.claimed_amount != 0
        || e.epoch < b.activated_epoch
        || crate::oracle::revision(program, cfg, mint, oracle)? != e.source_revision
    {
        return Err(invalid());
    }
    let d = ledger.try_borrow()?;
    let p = pool.try_borrow()?;
    if d.len() != 8416
        || &d[..4] != b"MRE\x02"
        || d[4..36] != *pool.address().as_ref()
        || wide(&d, 36) != e.epoch
        || d[52] != 1
        || d[53] > 64
        || d[53] != d[54]
        || d[55] != 0
        || wide(&d, 160) != 0
        || wide(&d, 176) != revision
        || time(&d, 168) != e.snapshot_at
        || d[184..224].iter().any(|b| *b != 0)
        || wide(&p, 180) != e.epoch
        || wide(&p, 220) != e.epoch.checked_add(1).ok_or(invalid())?
        || wide(&d, 128) != wide(&p, 196).checked_add(wide(&d, 44)).ok_or(invalid())?
    {
        return Err(invalid());
    }
    Ok(())
}
/// Only the pinned rewards PDA may fund actual, finalized-in-this-transaction
/// floor gaps. There is one permanent receipt per epoch across the whole reserve.
pub(crate) fn fund(program: &Address, a: &mut [AccountView]) -> ProgramResult {
    authorize_funding(program, a)?;
    let [pool, _, ledger, token_epoch, profile, cfg, mint, _, allocation, vault, destination, receipt, payer, _, _, _, _, _, _, _, _, spl, system] =
        a
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if spl.address() != &pinocchio_token::ID || !spl.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let e = crate::reward_state::TokenEpoch::parse(&token_epoch.try_borrow()?)?;
    let eb = e.epoch.to_le_bytes();
    let bump = [pda(program, &[b"reserve-epoch", &eb], receipt)?];
    if receipt.owner() == program {
        return Err(ProgramError::InvalidArgument);
    }
    let (_, claimed) = crate::processor::allocation(program, allocation, cfg, mint, 4)?;
    let mut floor = 0u64;
    let mut usd = 0u64;
    let mut amount = 0u64;
    let mut gap = 0u64;
    let rows_hash = {
        let d = ledger.try_borrow()?;
        let t = token_epoch.try_borrow()?;
        let p = pool.try_borrow()?;
        let funding =
            morse_rewards_math::token_floor_funding(wide(&d, 128), wide(&p, 188), wide(&d, 112))
                .map_err(|_| invalid())?;
        if funding.shortfall == 0 || e.floors != wide(&d, 112) || e.shortfall != funding.shortfall {
            return Err(invalid());
        }
        for n in 0..d[53] as usize {
            let at = 224 + n * 128;
            let row_floor = wide(&d, at + 112);
            let row_usd =
                morse_rewards_math::token_floor_usd(floor, row_floor, e.floors, funding.usd_pot)
                    .map_err(|_| invalid())?;
            let row_gap = row_floor.checked_sub(row_usd).ok_or(invalid())?;
            let row_token =
                morse_rewards_math::token_floor_morse(row_gap, e.price).map_err(|_| invalid())?;
            if wide(&d, at + 120) != row_usd
                || wide(&t, 256 + n * 16) != row_gap
                || wide(&t, 264 + n * 16) != row_token
                || (row_floor > 0 && d[at + 96..at + 112] == [0; 16])
            {
                return Err(invalid());
            }
            floor = floor.checked_add(row_floor).ok_or(invalid())?;
            usd = usd.checked_add(row_usd).ok_or(invalid())?;
            gap = gap.checked_add(row_gap).ok_or(invalid())?;
            amount = amount.checked_add(row_token).ok_or(invalid())?;
        }
        if floor != e.floors
            || usd != e.usd_committed
            || usd != funding.usd_pot
            || gap != e.shortfall
            || amount != e.amount
            || amount == 0
            || t[256 + d[53] as usize * 16..].iter().any(|b| *b != 0)
        {
            return Err(invalid());
        }
        morse_rewards_math::token_reserve_available(
            amount,
            crate::ALLOCATIONS[4]
                .checked_sub(claimed)
                .ok_or(invalid())?,
        )
        .map_err(|_| invalid())?;
        solana_sha256_hasher::hashv(&[
            &d[224..224 + d[53] as usize * 128],
            &t[256..256 + d[53] as usize * 16],
        ])
        .to_bytes()
    };
    pda(
        &pinocchio_associated_token_account::ID,
        &[
            allocation.address().as_ref(),
            pinocchio_token::ID.as_ref(),
            mint.address().as_ref(),
        ],
        vault,
    )?;
    pda(
        &pinocchio_associated_token_account::ID,
        &[
            pool.address().as_ref(),
            pinocchio_token::ID.as_ref(),
            mint.address().as_ref(),
        ],
        destination,
    )?;
    if vault.address() == destination.address() {
        return Err(invalid());
    }
    let before = crate::processor::balance(vault, mint.address(), allocation.address())?;
    let target = crate::processor::balance(destination, mint.address(), pool.address())?;
    create(
        program,
        program,
        payer,
        receipt,
        system,
        RECEIPT_LEN,
        &[
            Seed::from(b"reserve-epoch"),
            Seed::from(&eb),
            Seed::from(&bump),
        ],
    )?;
    let allocation_bump = [pda(program, &[b"allocation", &[4]], allocation)?];
    pinocchio_token::instructions::TransferChecked::new(
        vault,
        mint,
        destination,
        allocation,
        amount,
        6,
    )
    .invoke_signed(&[pinocchio::cpi::Signer::from(&[
        Seed::from(b"allocation"),
        Seed::from(&[4]),
        Seed::from(&allocation_bump),
    ])])?;
    if crate::processor::balance(vault, mint.address(), allocation.address())?
        != before.checked_sub(amount).ok_or(invalid())?
        || crate::processor::balance(destination, mint.address(), pool.address())?
            != target.checked_add(amount).ok_or(invalid())?
    {
        return Err(invalid());
    }
    allocation.try_borrow_mut()?[88..96]
        .copy_from_slice(&claimed.checked_add(amount).ok_or(invalid())?.to_le_bytes());
    let mut d = receipt.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MRR\x02");
    for (at, key) in [
        (4, profile.address()),
        (36, pool.address()),
        (68, token_epoch.address()),
        (148, mint.address()),
        (180, destination.address()),
    ] {
        d[at..at + 32].copy_from_slice(key.as_ref());
    }
    for (at, value) in [
        (100, e.epoch),
        (108, e.shortfall),
        (116, e.price),
        (124, amount),
        (132, e.source_revision),
        (140, clock()? as u64),
    ] {
        d[at..at + 8].copy_from_slice(&value.to_le_bytes());
    }
    d[212..244].copy_from_slice(&rows_hash);
    Ok(())
}

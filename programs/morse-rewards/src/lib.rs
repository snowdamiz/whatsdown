//! `morse-rewards`: pays witnesses of one judge log from a USDC pool, by the
//! attendance the judge records, and burns Morse tokens sent to its burn
//! account. Specification: `protocol/morse-judge-v1.md` §10.
//!
//! It never touches a bond: it only reads judge accounts. Its own pool vault
//! pays only to the payout addresses witnesses registered with the judge.
//! Upgradeable; its upgrade authority and `authority` are the time-locked
//! governance vault.
#![cfg_attr(target_os = "solana", no_std)]

use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer as SystemTransfer};
use pinocchio_token::{
    instructions::{Burn, Transfer},
    state::Account as TokenAccount,
};

#[cfg(target_os = "solana")]
mod entry {
    pinocchio::program_entrypoint!(super::process_instruction);
    pinocchio::default_allocator!();
    pinocchio::nostd_panic_handler!();
}

// ---- rules ----
pub const EPOCH_SECONDS: i64 = 604_800;
/// Settle only after the last cosigns of the epoch could have landed.
pub const SETTLE_DELAY_SECONDS: i64 = 900;
pub const PPM: u128 = 1_000_000;
pub const TOKEN_GRACE_SECONDS: i64 = 7 * 86_400;
pub const MAX_PRICE_AGE_SECONDS: i64 = 86_400;
const MAX_WITNESSES: usize = 16;

// ---- Config, PDA ["config"] ----
const CONFIG_LEN: usize = 904;
const C_POOL_BUMP: usize = 3;
const C_BURN_BUMP: usize = 4;
const C_AUTHORITY: usize = 8;
const C_JUDGE: usize = 40;
const C_LOG: usize = 72;
const C_USDC: usize = 104;
const C_TOKEN: usize = 136;
const C_ORACLE: usize = 168;
const C_FEED: usize = 200;
const C_FLOOR: usize = 232;
const C_FLOOR_UNTIL: usize = 240;
const C_TARGET: usize = 248;
const C_RESERVED: usize = 256;
const C_WATCH: usize = 264; // 16 × {witness32, i64 below_since}

// ---- Epoch, PDA ["epoch", epoch u64 LE] ----
const EPOCH_LEN: usize = 1_320;
const EP_COUNT: usize = 3;
const EP_EPOCH: usize = 8;
const EP_BUDGET: usize = 16;
const EP_ALLOCATED: usize = 24;
const EP_ANCHORS: usize = 32;
const EP_ALLOCS: usize = 40; // 16 × {witness32, payout32, u64 amount, u8 claimed, 7 zero}
const ALLOC_LEN: usize = 80;

// ---- judge layouts read here (morse-judge-v1 §3) ----
const J_LOG_TAG: u8 = 2;
const J_LOG_LEN: usize = 2_584;
const J_LOG_COUNT: usize = 4;
const J_LOG_ANCHORS: usize = 216;
const J_LOG_LIST: usize = 280;
const J_ENTRY_LEN: usize = 144;
const J_E_ACCOUNT: usize = 104;
const J_W_TAG: u8 = 3;
const J_W_LEN: usize = 336;
const J_W_STATUS: usize = 3;
const J_W_EXCLUDED: usize = 4;
const J_W_PAYOUT: usize = 168;
const J_W_VAULT: usize = 232;
const J_W_COSIGNS: usize = 272;
const J_ACTIVE: u8 = 1;

const SYSTEM_ID: Address = Address::new_from_array([0; 32]);
const TOKEN_ID: Address = pinocchio_token::ID;
const LOADER_V3_ID: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
const ATA_ID: Address = Address::from_str_const("ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL");

#[repr(u32)]
enum E {
    WrongAccount = 7000,
    Unauthorized = 7001,
    InvalidData = 7002,
    EpochNotOver = 7003,
    AlreadySettled = 7004,
    AlreadyClaimed = 7005,
    WrongDestination = 7006,
    WitnessAccountsMismatch = 7007,
    NoTokenMint = 7008,
}

fn req(c: bool, e: E) -> ProgramResult {
    if c {
        Ok(())
    } else {
        Err(ProgramError::Custom(e as u32))
    }
}

fn u64_at(d: &[u8], o: usize) -> u64 {
    u64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn i64_at(d: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(d[o..o + 8].try_into().unwrap())
}
fn key_at(d: &[u8], o: usize) -> [u8; 32] {
    d[o..o + 32].try_into().unwrap()
}
fn put(d: &mut [u8], o: usize, v: &[u8]) {
    d[o..o + v.len()].copy_from_slice(v);
}
fn zero(k: &[u8; 32]) -> bool {
    k.iter().all(|b| *b == 0)
}
fn now() -> Result<i64, ProgramError> {
    Ok(Clock::get()?.unix_timestamp)
}

fn signer(a: &AccountView) -> ProgramResult {
    req(a.is_signer(), E::Unauthorized)
}

fn load<'a>(a: &'a AccountView, owner: &Address, tag: u8, len: usize) -> Result<pinocchio::account::Ref<'a, [u8]>, ProgramError> {
    req(a.owned_by(owner) && a.data_len() == len, E::WrongAccount)?;
    let d = a.try_borrow()?;
    req(d[0] == tag, E::WrongAccount)?;
    Ok(d)
}

fn token(a: &AccountView) -> Result<([u8; 32], [u8; 32], u64), ProgramError> {
    let t = TokenAccount::from_account_view(a).map_err(|_| ProgramError::Custom(E::WrongAccount as u32))?;
    Ok((t.mint().to_bytes(), t.owner().to_bytes(), t.amount()))
}

fn create_pda(payer: &AccountView, target: &AccountView, space: usize, owner: &Address, seeds: &[Seed]) -> ProgramResult {
    req(target.owned_by(&SYSTEM_ID) && target.data_len() == 0, E::AlreadySettled)?;
    let signers = [Signer::from(seeds)];
    let rent = Rent::get()?.try_minimum_balance(space)?;
    if target.lamports() == 0 {
        return CreateAccount { from: payer, to: target, lamports: rent, space: space as u64, owner }.invoke_signed(&signers);
    }
    let deficit = rent.saturating_sub(target.lamports());
    if deficit > 0 {
        SystemTransfer { from: payer, to: target, lamports: deficit }.invoke()?;
    }
    Allocate { account: target, space: space as u64 }.invoke_signed(&signers)?;
    Assign { account: target, owner }.invoke_signed(&signers)
}

pub fn process_instruction(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let Some((&ix, rest)) = data.split_first() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match ix {
        0 => initialize(program_id, accounts, rest),
        1 => set_param(program_id, accounts, rest),
        2 => fund_pool(program_id, accounts, rest),
        3 => settle_epoch(program_id, accounts, rest),
        4 => claim_reward(program_id, accounts, rest),
        5 => burn(program_id, accounts, rest),
        6 => check_bond(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

/// initialize(authority32, judge_program32, log32, usdc_mint32,
/// floor_per_epoch u64, floor_until i64). Signed by the upgrade authority.
fn initialize(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [deployer, config, programdata, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(deployer)?;
    req(system.address() == &SYSTEM_ID && data.len() == 144, E::InvalidData)?;
    let (pd, _) = Address::find_program_address(&[program_id.as_ref()], &LOADER_V3_ID);
    req(programdata.address() == &pd && programdata.owned_by(&LOADER_V3_ID), E::WrongAccount)?;
    {
        let p = programdata.try_borrow()?;
        req(p.len() >= 45 && p[0..4] == [3, 0, 0, 0] && p[12] == 1 && p[13..45] == deployer.address().as_ref()[..], E::Unauthorized)?;
    }
    let (addr, bump) = Address::find_program_address(&[b"config"], program_id);
    req(config.address() == &addr, E::WrongAccount)?;
    let (_, pool_bump) = Address::find_program_address(&[b"pool"], program_id);
    let (_, burn_bump) = Address::find_program_address(&[b"burn"], program_id);
    let b = [bump];
    create_pda(deployer, config, CONFIG_LEN, program_id, &[Seed::from(b"config"), Seed::from(&b)])?;
    let mut d = config.try_borrow_mut()?;
    d[0] = 1;
    d[1] = 1;
    d[2] = bump;
    d[C_POOL_BUMP] = pool_bump;
    d[C_BURN_BUMP] = burn_bump;
    put(&mut d, C_AUTHORITY, &data[0..32]);
    put(&mut d, C_JUDGE, &data[32..64]);
    put(&mut d, C_LOG, &data[64..96]);
    put(&mut d, C_USDC, &data[96..128]);
    put(&mut d, C_FLOOR, &data[128..136]);
    put(&mut d, C_FLOOR_UNTIL, &data[136..144]);
    Ok(())
}

fn config_mut<'a>(config: &'a mut AccountView, program_id: &Address) -> Result<pinocchio::account::RefMut<'a, [u8]>, ProgramError> {
    load(config, program_id, 1, CONFIG_LEN)?;
    req(config.is_writable(), E::WrongAccount)?;
    config.try_borrow_mut()
}

/// set_param(kind u8, value32): 1 authority, 2 token mint, 3 oracle program,
/// 4 price feed, 5 floor per epoch (u64), 6 floor until (i64), 7 token-bond
/// target in USDC base units (u64). Integers are the first 8 bytes, LE.
fn set_param(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, config, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(auth)?;
    req(data.len() == 33, E::InvalidData)?;
    let mut d = config_mut(config, program_id)?;
    req(auth.address().as_ref() == &d[C_AUTHORITY..C_AUTHORITY + 32], E::Unauthorized)?;
    let (at, len) = match data[0] {
        1 => (C_AUTHORITY, 32),
        2 => (C_TOKEN, 32),
        3 => (C_ORACLE, 32),
        4 => (C_FEED, 32),
        5 => (C_FLOOR, 8),
        6 => (C_FLOOR_UNTIL, 8),
        7 => (C_TARGET, 8),
        _ => return Err(ProgramError::Custom(E::InvalidData as u32)),
    };
    put(&mut d, at, &data[1..1 + len]);
    Ok(())
}

/// The pool vault: the USDC associated token account of PDA ["pool"].
fn pool_address(cfg: &[u8], program_id: &Address) -> Result<Address, ProgramError> {
    let pool = Address::create_program_address(&[b"pool", &[cfg[C_POOL_BUMP]]], program_id).map_err(|_| ProgramError::InvalidSeeds)?;
    Ok(Address::find_program_address(&[pool.as_ref(), TOKEN_ID.as_ref(), &cfg[C_USDC..C_USDC + 32]], &ATA_ID).0)
}

/// fund_pool(amount u64): anyone moves USDC into the pool vault.
fn fund_pool(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [funder, source, pool, config, token_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(funder)?;
    req(token_program.address() == &TOKEN_ID && data.len() == 8, E::InvalidData)?;
    let cfg = load(config, program_id, 1, CONFIG_LEN)?;
    req(pool.address() == &pool_address(&cfg, program_id)?, E::WrongAccount)?;
    Transfer::new(source, pool, funder, u64_at(data, 0)).invoke()
}

/// `{epoch, count}` counter for `epoch` from a judge 4-slot table.
fn counter(d: &[u8], base: usize, epoch: u64) -> u64 {
    let o = base + (epoch % 4) as usize * 16;
    if u64_at(d, o) == epoch {
        u64_at(d, o + 8)
    } else {
        0
    }
}

/// clamp((attendance − 0.80) / 0.15, 0, 1) in parts per million.
pub fn pay_factor_ppm(cosigns: u64, anchors: u64) -> u128 {
    if anchors == 0 {
        return 0;
    }
    let attendance = (cosigns as u128 * PPM / anchors as u128).min(PPM);
    (attendance.saturating_sub(800_000) * PPM / 150_000).min(PPM)
}

/// Price-feed account (owner = the configured oracle program):
/// `i64 price ‖ i32 exponent ‖ i64 publish_time` at offset 0, LE; the price
/// is the 7-day TWAP in USD per whole token, `price × 10^exponent`.
fn feed_price(cfg: &[u8], feed: &AccountView, now: i64) -> Option<(i64, i32)> {
    if zero(&key_at(cfg, C_FEED))
        || feed.address().as_ref() != &cfg[C_FEED..C_FEED + 32]
        || !feed.owned_by(&Address::new_from_array(key_at(cfg, C_ORACLE)))
    {
        return None;
    }
    let d = feed.try_borrow().ok()?;
    if d.len() < 20 {
        return None;
    }
    let (price, exponent, at) = (i64_at(&d, 0), i32::from_le_bytes(d[8..12].try_into().unwrap()), i64_at(&d, 12));
    let fresh = at <= now + 60 && now - at <= MAX_PRICE_AGE_SECONDS;
    (price > 0 && (-18..=18).contains(&exponent) && fresh).then_some((price, exponent))
}

/// USDC base units of `amount` token base units (both 6 decimals).
fn usd_value(amount: u64, price: i64, exponent: i32) -> u128 {
    let v = amount as u128 * price as u128;
    let scale = 10u128.pow(exponent.unsigned_abs());
    if exponent >= 0 {
        v.saturating_mul(scale)
    } else {
        v / scale
    }
}

/// Updates the token-bond watch for list slot `i` and says whether the
/// witness is still eligible: a token bond worth less than 80% of target for
/// 7 days makes it ineligible for pay (it is never slashed for this).
fn watch(cfg: &mut [u8], i: usize, witness: &Address, vault: &AccountView, feed: &AccountView, now: i64) -> Result<bool, ProgramError> {
    let o = C_WATCH + i * 40;
    if cfg[o..o + 32] != witness.as_ref()[..] {
        put(cfg, o, witness.as_ref());
        put(cfg, o + 32, &0i64.to_le_bytes());
    }
    if vault.owned_by(&SYSTEM_ID) {
        return Ok(true);
    }
    let (mint, _, amount) = token(vault)?;
    let token_mint = key_at(cfg, C_TOKEN);
    if zero(&token_mint) || mint != token_mint {
        return Ok(true); // USDC bonds do not move
    }
    if let Some((price, exponent)) = feed_price(cfg, feed, now) {
        let below = usd_value(amount, price, exponent) * 100 < u64_at(cfg, C_TARGET) as u128 * 80;
        let since = i64_at(cfg, o + 32);
        let next = if !below {
            0
        } else if since == 0 {
            now
        } else {
            since
        };
        put(cfg, o + 32, &next.to_le_bytes());
    }
    let since = i64_at(cfg, o + 32);
    Ok(since == 0 || now - since < TOKEN_GRACE_SECONDS)
}

/// settle_epoch(epoch u64). Accounts: payer, config, judge log, pool vault,
/// epoch (new), system, price feed, then (witness, bond vault) for every
/// entry of the log's witness list, in list order.
fn settle_epoch(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [payer, config, log, pool, epoch_acct, system, feed, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(payer)?;
    req(system.address() == &SYSTEM_ID && data.len() == 8, E::InvalidData)?;
    let epoch = u64_at(data, 0);
    let t = now()?;
    req(t >= (epoch as i64 + 1) * EPOCH_SECONDS + SETTLE_DELAY_SECONDS, E::EpochNotOver)?;
    let mut cfg = config_mut(config, program_id)?;
    let judge = Address::new_from_array(key_at(&cfg, C_JUDGE));
    req(log.address().as_ref() == &cfg[C_LOG..C_LOG + 32], E::WrongAccount)?;
    req(pool.address() == &pool_address(&cfg, program_id)?, E::WrongAccount)?;
    let l = load(log, &judge, J_LOG_TAG, J_LOG_LEN)?;
    let count = l[J_LOG_COUNT] as usize;
    req(rest.len() == 2 * count, E::WitnessAccountsMismatch)?;
    let anchors = counter(&l, J_LOG_ANCHORS, epoch);
    let pool_balance = if pool.owned_by(&TOKEN_ID) { token(pool)?.2 } else { 0 };
    let budget = pool_balance.saturating_sub(u64_at(&cfg, C_RESERVED));

    // Payable witnesses and their pay factors.
    let mut factors = [0u128; MAX_WITNESSES];
    let mut who = [([0u8; 32], [0u8; 32]); MAX_WITNESSES];
    let mut eligible = 0u128;
    for i in 0..count {
        let (w, vault) = (&rest[2 * i], &rest[2 * i + 1]);
        let e = J_LOG_LIST + i * J_ENTRY_LEN;
        req(w.address().as_ref() == &l[e + J_E_ACCOUNT..e + J_E_ACCOUNT + 32], E::WitnessAccountsMismatch)?;
        let wd = load(w, &judge, J_W_TAG, J_W_LEN)?;
        req(vault.address().as_ref() == &wd[J_W_VAULT..J_W_VAULT + 32], E::WitnessAccountsMismatch)?;
        let bond_ok = watch(&mut cfg, i, w.address(), vault, feed, t)?;
        if wd[J_W_STATUS] == J_ACTIVE && wd[J_W_EXCLUDED] == 0 && bond_ok {
            eligible += 1;
            factors[i] = pay_factor_ppm(counter(&wd, J_W_COSIGNS, epoch), anchors);
            who[i] = (w.address().to_bytes(), key_at(&wd, J_W_PAYOUT));
        }
    }

    // Equal shares, raised to the floor while it lasts, scaled by pay factor;
    // never more than the pool holds. The rest carries over.
    let mut share = (budget as u128).checked_div(eligible).unwrap_or(0);
    if t < i64_at(&cfg, C_FLOOR_UNTIL) {
        share = share.max(u64_at(&cfg, C_FLOOR) as u128);
    }
    let mut pay = [0u128; MAX_WITNESSES];
    let mut total = 0u128;
    for i in 0..count {
        pay[i] = share * factors[i] / PPM;
        total += pay[i];
    }
    if total > budget as u128 {
        for p in pay.iter_mut() {
            *p = *p * budget as u128 / total;
        }
    }

    let el = epoch.to_le_bytes();
    let (addr, bump) = Address::find_program_address(&[b"epoch", &el], program_id);
    req(epoch_acct.address() == &addr, E::WrongAccount)?;
    let b = [bump];
    create_pda(payer, epoch_acct, EPOCH_LEN, program_id, &[Seed::from(b"epoch"), Seed::from(&el), Seed::from(&b)])?;
    let mut ep = epoch_acct.try_borrow_mut()?;
    ep[0] = 2;
    ep[1] = 1;
    ep[2] = bump;
    put(&mut ep, EP_EPOCH, &el);
    put(&mut ep, EP_BUDGET, &budget.to_le_bytes());
    put(&mut ep, EP_ANCHORS, &anchors.to_le_bytes());
    let mut n = 0usize;
    let mut allocated = 0u64;
    for i in (0..count).filter(|i| pay[*i] > 0) {
        let o = EP_ALLOCS + n * ALLOC_LEN;
        put(&mut ep, o, &who[i].0);
        put(&mut ep, o + 32, &who[i].1);
        put(&mut ep, o + 64, &(pay[i] as u64).to_le_bytes());
        allocated += pay[i] as u64;
        n += 1;
    }
    ep[EP_COUNT] = n as u8;
    put(&mut ep, EP_ALLOCATED, &allocated.to_le_bytes());
    let reserved = u64_at(&cfg, C_RESERVED) + allocated;
    put(&mut cfg, C_RESERVED, &reserved.to_le_bytes());
    Ok(())
}

/// claim_reward(epoch u64, index u8): anyone; pays to a USDC token account
/// owned by the witness's registered payout address.
fn claim_reward(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [config, epoch_acct, pool, pool_authority, destination, token_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    req(token_program.address() == &TOKEN_ID && data.len() == 9, E::InvalidData)?;
    let mut cfg = config_mut(config, program_id)?;
    req(pool.address() == &pool_address(&cfg, program_id)?, E::WrongAccount)?;
    let (addr, _) = Address::find_program_address(&[b"epoch", &data[0..8]], program_id);
    req(epoch_acct.address() == &addr, E::WrongAccount)?;
    load(epoch_acct, program_id, 2, EPOCH_LEN)?;
    req(epoch_acct.is_writable(), E::WrongAccount)?;
    let mut ep = epoch_acct.try_borrow_mut()?;
    let i = data[8] as usize;
    req(i < ep[EP_COUNT] as usize, E::InvalidData)?;
    let o = EP_ALLOCS + i * ALLOC_LEN;
    req(ep[o + 72] == 0, E::AlreadyClaimed)?;
    let (mint, owner, _) = token(destination)?;
    req(mint == key_at(&cfg, C_USDC) && owner == key_at(&ep, o + 32), E::WrongDestination)?;
    let amount = u64_at(&ep, o + 64);
    let pb = [cfg[C_POOL_BUMP]];
    let authority = Address::create_program_address(&[b"pool", &pb], program_id).map_err(|_| ProgramError::InvalidSeeds)?;
    req(pool_authority.address() == &authority, E::WrongAccount)?;
    let seeds = [Seed::from(b"pool"), Seed::from(&pb)];
    Transfer::new(pool, destination, pool_authority, amount).invoke_signed(&[Signer::from(&seeds)])?;
    ep[o + 72] = 1;
    let reserved = u64_at(&cfg, C_RESERVED).saturating_sub(amount);
    put(&mut cfg, C_RESERVED, &reserved.to_le_bytes());
    Ok(())
}

/// burn(): anyone burns every Morse token held by a token account owned by
/// PDA ["burn"].
fn burn(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    let [config, burn_authority, holding, mint, token_program, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    req(token_program.address() == &TOKEN_ID, E::InvalidData)?;
    let cfg = load(config, program_id, 1, CONFIG_LEN)?;
    let token_mint = key_at(&cfg, C_TOKEN);
    req(!zero(&token_mint), E::NoTokenMint)?;
    req(mint.address().as_ref() == token_mint, E::WrongAccount)?;
    let bb = [cfg[C_BURN_BUMP]];
    let authority = Address::create_program_address(&[b"burn", &bb], program_id).map_err(|_| ProgramError::InvalidSeeds)?;
    req(burn_authority.address() == &authority, E::WrongAccount)?;
    let (m, owner, amount) = token(holding)?;
    req(m == token_mint && owner == authority.to_bytes(), E::WrongAccount)?;
    if amount == 0 {
        return Ok(());
    }
    let seeds = [Seed::from(b"burn"), Seed::from(&bb)];
    Burn::new(holding, mint, burn_authority, amount).invoke_signed(&[Signer::from(&seeds)])
}

/// check_bond(): anyone refreshes the token-bond watch of one witness.
/// Accounts: config, judge log, price feed, witness, bond vault.
fn check_bond(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    let [config, log, feed, witness, vault, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let t = now()?;
    let mut cfg = config_mut(config, program_id)?;
    let judge = Address::new_from_array(key_at(&cfg, C_JUDGE));
    req(log.address().as_ref() == &cfg[C_LOG..C_LOG + 32], E::WrongAccount)?;
    let l = load(log, &judge, J_LOG_TAG, J_LOG_LEN)?;
    let wd = load(witness, &judge, J_W_TAG, J_W_LEN)?;
    req(vault.address().as_ref() == &wd[J_W_VAULT..J_W_VAULT + 32], E::WrongAccount)?;
    let i = (0..l[J_LOG_COUNT] as usize)
        .find(|i| l[J_LOG_LIST + i * J_ENTRY_LEN + J_E_ACCOUNT..][..32] == witness.address().as_ref()[..])
        .ok_or(ProgramError::Custom(E::WrongAccount as u32))?;
    watch(&mut cfg, i, witness.address(), vault, feed, t)?;
    Ok(())
}

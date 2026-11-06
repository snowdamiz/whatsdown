//! Explicit timelocked token activation. No vault authority or recipient changes.
use crate::{
    custody::{advance_eligibility, economy, i64_at, now, u64_at, ECONOMICS_LEN},
    processor::{check_governance, create_pda, load_log, owned, pda},
    state::{CONFIG_LEN, TIMELOCK_SECONDS},
    token_custody::decode_economics,
};
use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};

pub use morse_token::judge_binding::{
    load_binding, qualified_program_slot, TokenBinding, BINDING_LEN,
};
const WEEK: i64 = 604800;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn governance(program: &Address, config: &AccountView) -> Result<[u8; 32], ProgramError> {
    owned(program, config, false)?;
    pda(program, &[b"config"], config)?;
    let d = config.try_borrow()?;
    if d.len() != CONFIG_LEN
        || &d[..4] != b"MCF\x01"
        || d[4..36] == [0; 32]
        || d[36..].iter().any(|b| *b != 0)
    {
        return Err(invalid());
    }
    Ok(d[4..36].try_into().unwrap())
}
fn policy(
    program: &Address,
    a: &AccountView,
    log_id: &[u8; 32],
) -> Result<[u8; ECONOMICS_LEN], ProgramError> {
    owned(program, a, false)?;
    pda(program, &[b"economics", log_id], a)?;
    let d = a.try_borrow()?;
    if d.len() != ECONOMICS_LEN || d[4..36] != *log_id {
        return Err(invalid());
    }
    if &d[..4] == b"MEC\x02" {
        decode_economics(&d)?;
        return Ok(d[..].try_into().unwrap());
    }
    drop(d);
    economy(program, a, log_id)
}
struct Accounts<'a> {
    gov: &'a AccountView,
    payer: &'a AccountView,
    config: &'a AccountView,
    log: &'a AccountView,
    economy: &'a AccountView,
    binding: &'a AccountView,
    token: &'a AccountView,
    token_data: &'a AccountView,
    token_config: &'a AccountView,
    mint: &'a AccountView,
    oracle: &'a AccountView,
    rewards: &'a AccountView,
    rewards_data: &'a AccountView,
    pool: &'a AccountView,
    system: &'a AccountView,
}
fn matches(value: &TokenBinding, a: &Accounts<'_>, log_id: &[u8; 32]) -> bool {
    value.log == *a.log.address()
        && value.log_id == *log_id
        && value.token_program == *a.token.address()
        && value.token_config == *a.token_config.address()
        && value.mint == *a.mint.address()
        && value.oracle == *a.oracle.address()
        && value.rewards_program == *a.rewards.address()
        && value.rewards_pool == *a.pool.address()
}
pub fn read_rewards_pool(
    program: &Address,
    log: &Address,
    log_id: &[u8; 32],
    rewards: &Address,
    pool: &AccountView,
    mint: &[u8],
) -> Result<(u64, u64), ProgramError> {
    owned(rewards, pool, false)?;
    pda(rewards, &[b"pool"], pool)?;
    let d = pool.try_borrow()?;
    if d.len() != 304
        || &d[..3] != b"MRP"
        || !matches!(d[3], 1 | 2)
        || d[4..36] == [0; 32]
        || d[36..68] != *program.as_ref()
        || d[68..100] != *log.as_ref()
        || d[100..132] != *log_id
        || &d[132..164] != mint
        || d[268..300] == [0; 32]
        || d[300..].iter().any(|b| *b != 0)
        || i64_at(&d, 164) <= 0
        || u64_at(&d, 172) != (i64_at(&d, 164) / WEEK) as u64 + 1
        || u64_at(&d, 180) < u64_at(&d, 172)
        || (u64_at(&d, 220) != 0
            && u64_at(&d, 220) != u64_at(&d, 180).checked_add(1).ok_or(invalid())?)
        || u64_at(&d, 188)
            .checked_add(u64_at(&d, 196))
            .and_then(|v| v.checked_add(u64_at(&d, 204)))
            .ok_or(invalid())?
            > u64_at(&d, 212)
        || i64_at(&d, 260) < 0
        || (i64_at(&d, 260) == 0 && d[228..260].iter().any(|v| *v != 0))
    {
        return Err(invalid());
    }
    Ok((u64_at(&d, 180), u64_at(&d, 220)))
}
fn pool(
    program: &Address,
    a: &Accounts<'_>,
    log_id: &[u8; 32],
    mint: &[u8],
) -> Result<(u64, u64), ProgramError> {
    let state = read_rewards_pool(
        program,
        a.log.address(),
        log_id,
        a.rewards.address(),
        a.pool,
        mint,
    )?;
    if a.pool.try_borrow()?[4..36] != governance(program, a.config)? {
        return Err(invalid());
    }
    Ok(state)
}
fn pins(
    program: &Address,
    a: &Accounts<'_>,
    log_id: &[u8; 32],
    usdc: &[u8],
    fresh: bool,
) -> Result<(u64, u64, u64), ProgramError> {
    if a.token.address() == program
        || a.rewards.address() == program
        || a.token.address() == a.rewards.address()
        || a.mint.address().as_ref() == usdc
    {
        return Err(invalid());
    }
    let token_slot = qualified_program_slot(a.token, a.token_data)?;
    let rewards_slot = qualified_program_slot(a.rewards, a.rewards_data)?;
    let revision =
        morse_token::oracle::revision(a.token.address(), a.token_config, a.mint, a.oracle)?;
    {
        let d = a.token_config.try_borrow()?;
        if d[4..36] != governance(program, a.config)? {
            return Err(invalid());
        }
    }
    if fresh {
        morse_token::oracle::value(a.token.address(), a.token_config, a.mint, a.oracle, now()?)?;
    }
    pool(program, a, log_id, usdc)?;
    Ok((token_slot, rewards_slot, revision))
}
pub(crate) fn propose(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [gov, payer, config, log, economy_account, binding, token, token_data, token_config, mint, oracle, rewards, rewards_data, pool_account, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (fields, log_id, ready, token_slot, rewards_slot, source_revision) = {
        let a = Accounts {
            gov,
            payer,
            config,
            log,
            economy: economy_account,
            binding,
            token,
            token_data,
            token_config,
            mint,
            oracle,
            rewards,
            rewards_data,
            pool: pool_account,
            system,
        };
        check_governance(program, a.config, a.gov)?;
        let log = load_log(program, a.log)?;
        let log_id: [u8; 32] = log[40..72].try_into().unwrap();
        let policy = policy(program, a.economy, &log_id)?;
        let existing = if a.binding.owner() == program {
            Some(load_binding(program, a.binding, &log_id)?)
        } else {
            None
        };
        if let Some(value) = existing.as_ref() {
            if value.activated_at > 0 {
                if !matches(value, &a, &log_id) || &policy[..4] != b"MEC\x02" {
                    return Err(invalid());
                }
                return Ok(());
            }
        }
        if &policy[..4] != b"MEC\x01" {
            return Err(invalid());
        }
        let (token_slot, rewards_slot, source_revision) =
            pins(program, &a, &log_id, &policy[36..68], false)?;
        if existing.as_ref().is_some_and(|v| {
            matches(v, &a, &log_id)
                && v.token_slot == token_slot
                && v.rewards_slot == rewards_slot
                && v.source_revision == source_revision
        }) {
            return Ok(());
        }
        morse_token::oracle::value(a.token.address(), a.token_config, a.mint, a.oracle, now()?)?;
        let ready = now()?
            .checked_add(TIMELOCK_SECONDS)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        let bump = [pda(program, &[b"token-binding", &log_id], a.binding)?];
        if existing.is_none() {
            create_pda(
                program,
                a.payer,
                a.binding,
                a.system,
                BINDING_LEN,
                BINDING_LEN,
                &[
                    Seed::from(b"token-binding"),
                    Seed::from(&log_id),
                    Seed::from(&bump),
                ],
            )?;
        }
        owned(program, a.binding, true)?;
        let fields = [
            (4, *a.log.address().as_array()),
            (68, *a.token.address().as_array()),
            (100, *a.token_config.address().as_array()),
            (132, *a.mint.address().as_array()),
            (164, *a.oracle.address().as_array()),
            (196, *a.rewards.address().as_array()),
            (228, *a.pool.address().as_array()),
        ];
        (
            fields,
            log_id,
            ready,
            token_slot,
            rewards_slot,
            source_revision,
        )
    };
    let mut d = binding.try_borrow_mut()?;
    d.fill(0);
    d[..4].copy_from_slice(b"MJB\x02");
    for (at, key) in fields {
        d[at..at + 32].copy_from_slice(&key);
    }
    d[36..68].copy_from_slice(&log_id);
    d[260..268].copy_from_slice(&ready.to_le_bytes());
    d[284..292].copy_from_slice(&token_slot.to_le_bytes());
    d[292..300].copy_from_slice(&rewards_slot.to_le_bytes());
    d[300..308].copy_from_slice(&source_revision.to_le_bytes());
    Ok(())
}
pub(crate) fn activate(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [gov, payer, config, log, economy_account, binding, token, token_data, token_config, mint, oracle, rewards, rewards_data, pool_account, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let log_data = load_log(program, log)?;
    let log_id: [u8; 32] = log_data[40..72].try_into().unwrap();
    let value = load_binding(program, binding, &log_id)?;
    let policy_data = policy(program, economy_account, &log_id)?;
    let a = Accounts {
        gov,
        payer,
        config,
        log,
        economy: economy_account,
        binding,
        token,
        token_data,
        token_config,
        mint,
        oracle,
        rewards,
        rewards_data,
        pool: pool_account,
        system,
    };
    if !matches(&value, &a, &log_id) {
        return Err(invalid());
    }
    if value.activated_at > 0 {
        if &policy_data[..4] != b"MEC\x02" {
            return Err(invalid());
        }
        return Ok(());
    }
    let clock = now()?;
    if clock < value.ready_at || &policy_data[..4] != b"MEC\x01" {
        return Err(ProgramError::InvalidArgument);
    }
    let (token_slot, rewards_slot, source_revision) =
        pins(program, &a, &log_id, &policy_data[36..68], true)?;
    if (token_slot, rewards_slot, source_revision)
        != (value.token_slot, value.rewards_slot, value.source_revision)
    {
        return Err(invalid());
    }
    let (next, active) = pool(program, &a, &log_id, &policy_data[36..68])?;
    if next != (clock / WEEK) as u64 || active != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    owned(program, binding, true)?;
    owned(program, economy_account, true)?;
    advance_eligibility(economy_account)?;
    {
        let mut d = economy_account.try_borrow_mut()?;
        d[3] = 2;
        d[165..168].fill(0);
        d[176..192].fill(0);
        decode_economics(&d)?;
    }
    let mut d = binding.try_borrow_mut()?;
    d[268..276].copy_from_slice(&clock.to_le_bytes());
    d[276..284].copy_from_slice(&((clock / WEEK) as u64).to_le_bytes());
    Ok(())
}

//! USDC escrow. Governance sets timelocked entry requirements, never recipients
//! or transfer authority. Immutable witness records isolate rotated signing keys.
use crate::{
    processor::{authority, check_governance, create_pda, load_log, owned, pda},
    state::TIMELOCK_SECONDS,
    witness::{identity, load_witness},
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_associated_token_account::{instructions::CreateIdempotent, ID as ATA_ID};
use pinocchio_token::{
    instructions::TransferChecked,
    state::{Account as TokenAccount, AccountState, Mint},
};

pub const ECONOMICS_LEN: usize = 192;
pub const BOND_LEN: usize = 208;
pub const UNBOND_SECONDS: i64 = 30 * 24 * 60 * 60;
pub const PROOF_SECONDS: i64 = 28 * 24 * 60 * 60;
pub const FINDER_DENOMINATOR: u64 = 10;
const TOKEN_ID: Address = pinocchio_token::ID;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
pub(crate) fn u64_at(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub(crate) fn i64_at(bytes: &[u8], offset: usize) -> i64 {
    i64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
pub(crate) fn now() -> Result<i64, ProgramError> {
    let value = Clock::get()?.unix_timestamp;
    if value < 0 {
        Err(ProgramError::InvalidArgument)
    } else {
        Ok(value)
    }
}
pub(crate) fn token_program(token: &AccountView) -> ProgramResult {
    if token.address() != &TOKEN_ID || !token.executable() {
        Err(ProgramError::IncorrectProgramId)
    } else {
        Ok(())
    }
}
pub(crate) fn mint_valid(mint: &AccountView) -> ProgramResult {
    let state = Mint::from_account_view(mint)?;
    if mint.executable() || !state.is_initialized() || state.decimals() != 6 {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn associated(
    authority: &Address,
    mint: &Address,
    account: &AccountView,
) -> ProgramResult {
    pda(
        &ATA_ID,
        &[authority.as_ref(), TOKEN_ID.as_ref(), mint.as_ref()],
        account,
    )?;
    Ok(())
}
pub(crate) fn token_balance(
    account: &AccountView,
    mint: &Address,
    owner: &Address,
    vault: bool,
) -> Result<u64, ProgramError> {
    let value = TokenAccount::from_account_view(account)?;
    if account.executable()
        || !account.is_writable()
        || value.state() != AccountState::Initialized
        || value.is_native()
        || value.mint() != mint
        || value.owner() != owner
        || (vault && (value.has_delegate() || value.has_close_authority()))
    {
        return Err(invalid());
    }
    Ok(value.amount())
}
pub(crate) fn economy(
    program: &Address,
    account: &AccountView,
    log_id: &[u8],
) -> Result<[u8; ECONOMICS_LEN], ProgramError> {
    owned(program, account, false)?;
    pda(program, &[b"economics", log_id], account)?;
    let bytes = account.try_borrow()?;
    if bytes.len() != ECONOMICS_LEN
        || &bytes[..4] != b"MEC\x01"
        || &bytes[4..36] != log_id
        || bytes[165..168].iter().chain(&bytes[176..]).any(|b| *b != 0)
        || u64_at(&bytes, 100) == 0
        || u64_at(&bytes, 108) == 0
        || bytes[164] > 4
        || i64_at(&bytes, 116) < 0
    {
        return Err(invalid());
    }
    Ok(bytes[..].try_into().unwrap())
}

/// Every mutation affecting a witness settlement snapshot increments this counter.
pub(crate) fn advance_eligibility(account: &mut AccountView) -> ProgramResult {
    let mut bytes = account.try_borrow_mut()?;
    let revision = u64_at(&bytes, 168)
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    bytes[168..176].copy_from_slice(&revision.to_le_bytes());
    Ok(())
}

pub(crate) fn configure(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [governance, payer, config, log_account, account, mint, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 48
        || u64_at(payload, 0) == 0
        || u64_at(payload, 8) < u64_at(payload, 0)
        || payload[16..] == [0; 32]
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    check_governance(program, config, governance)?;
    let log = load_log(program, log_account)?;
    mint_valid(mint)?;
    if payload[16..] == log[72..104] {
        return Err(ProgramError::InvalidArgument);
    }
    let ready = now()?
        .checked_add(TIMELOCK_SECONDS)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let bump = [pda(program, &[b"economics", &log[40..72]], account)?];
    create_pda(
        program,
        payer,
        account,
        system,
        ECONOMICS_LEN,
        ECONOMICS_LEN,
        &[
            Seed::from(b"economics"),
            Seed::from(&log[40..72]),
            Seed::from(&bump),
        ],
    )?;
    let mut bytes = account.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MEC\x01");
    bytes[4..36].copy_from_slice(&log[40..72]);
    bytes[36..68].copy_from_slice(mint.address().as_ref());
    bytes[68..100].copy_from_slice(&payload[16..]);
    bytes[100..116].copy_from_slice(&payload[..16]);
    bytes[116..124].copy_from_slice(&ready.to_le_bytes());
    Ok(())
}

struct Deposit<'a> {
    operator: &'a AccountView,
    log: &'a mut AccountView,
    economy: &'a mut AccountView,
    witness: Option<&'a mut AccountView>,
    bond: &'a mut AccountView,
    vault: &'a AccountView,
    source: &'a AccountView,
    mint: &'a AccountView,
    token: &'a AccountView,
    ata: &'a AccountView,
    system: &'a AccountView,
}

pub(crate) fn bond_witness(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [operator, log, economy, witness, bond, vault, source, mint, token, ata, system] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    deposit(
        program,
        Deposit {
            operator,
            log,
            economy,
            witness: Some(witness),
            bond,
            vault,
            source,
            mint,
            token,
            ata,
            system,
        },
        payload,
    )
}
pub(crate) fn bond_directory(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [governance, operator, config, log, economy, bond, vault, source, mint, token, ata, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    check_governance(program, config, governance)?;
    deposit(
        program,
        Deposit {
            operator,
            log,
            economy,
            witness: None,
            bond,
            vault,
            source,
            mint,
            token,
            ata,
            system,
        },
        payload,
    )
}
pub(crate) fn load_bond(
    program: &Address,
    account: &AccountView,
    log_id: &[u8],
    subject: &[u8],
) -> Result<[u8; BOND_LEN], ProgramError> {
    owned(program, account, true)?;
    pda(program, &[b"bond", log_id, subject], account)?;
    let bytes = account.try_borrow()?;
    if bytes.len() != BOND_LEN
        || &bytes[..4] != b"MBD\x01"
        || !matches!(bytes[4], 1..=4)
        || bytes[5] > 1
        || bytes[6..8].iter().chain(&bytes[200..]).any(|b| *b != 0)
        || &bytes[8..40] != log_id
    {
        return Err(invalid());
    }
    Ok(bytes[..].try_into().unwrap())
}
fn deposit(program: &Address, mut accounts: Deposit<'_>, payload: &[u8]) -> ProgramResult {
    if payload.len() != 8 || u64_at(payload, 0) == 0 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let amount = u64_at(payload, 0);
    let clock = now()?;
    let log = load_log(program, accounts.log)?;
    let policy = economy(program, accounts.economy, &log[40..72])?;
    owned(program, accounts.economy, true)?;
    if log[5] != 0
        || clock < i64_at(&policy, 116)
        || accounts.mint.address().as_ref() != &policy[36..68]
    {
        return Err(ProgramError::InvalidArgument);
    }
    token_program(accounts.token)?;
    mint_valid(accounts.mint)?;
    if accounts.ata.address() != &ATA_ID || !accounts.ata.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let record = if let Some(witness) = accounts.witness.as_ref() {
        Some(load_witness(program, witness, &log[40..72])?)
    } else {
        None
    };
    let id = record
        .as_ref()
        .map(|r| identity(&r[8..8 + r[4] as usize], &r[72..104]));
    let subject = id
        .as_ref()
        .map_or(b"directory".as_slice(), |v| v.as_slice());
    let owner = record.as_ref().map_or(&policy[68..100], |r| &r[104..136]);
    authority(accounts.operator, owner)?;
    if accounts.source.address() == accounts.vault.address() {
        return Err(ProgramError::InvalidArgument);
    }
    let bump = [pda(
        program,
        &[b"bond", &log[40..72], subject],
        accounts.bond,
    )?];
    associated(
        accounts.bond.address(),
        accounts.mint.address(),
        accounts.vault,
    )?;
    let mut prior = None;
    if accounts.bond.owner() == program {
        let bytes = load_bond(program, accounts.bond, &log[40..72], subject)?;
        if !matches!(bytes[4], 1 | 4)
            || &bytes[72..104] != owner
            || &bytes[104..136] != accounts.mint.address().as_ref()
            || &bytes[136..168] != accounts.vault.address().as_ref()
            || bytes[5] != u8::from(record.is_some())
        {
            return Err(invalid());
        }
        prior = Some(bytes);
    }
    let previous_principal = prior.as_ref().map_or(0, |p| u64_at(p, 168));
    let active = prior.as_ref().is_some_and(|p| p[4] == 1);
    let minimum = u64_at(&policy, if record.is_some() { 100 } else { 108 });
    if !active && amount < minimum {
        return Err(ProgramError::InvalidArgument);
    }
    if let Some(record) = &record {
        if record[5] != prior.as_ref().map_or(0, |p| p[4]) {
            return Err(invalid());
        }
        owned(program, accounts.witness.as_ref().unwrap(), true)?;
    } else {
        owned(program, accounts.log, true)?;
    }
    let principal = previous_principal
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let counter = if record.is_some() { 148 } else { 156 };
    let total = u64_at(&policy, counter)
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if record.is_some() && (policy[164] != 1 || total > u64_at(&policy, 156)) {
        return Err(ProgramError::InvalidArgument);
    }
    token_balance(
        accounts.source,
        accounts.mint.address(),
        accounts.operator.address(),
        false,
    )?;
    if prior.is_none() {
        create_pda(
            program,
            accounts.operator,
            accounts.bond,
            accounts.system,
            BOND_LEN,
            BOND_LEN,
            &[
                Seed::from(b"bond"),
                Seed::from(&log[40..72]),
                Seed::from(subject),
                Seed::from(&bump),
            ],
        )?;
    }
    CreateIdempotent {
        funding_account: accounts.operator,
        account: accounts.vault,
        wallet: accounts.bond,
        mint: accounts.mint,
        system_program: accounts.system,
        token_program: accounts.token,
    }
    .invoke()?;
    token_balance(
        accounts.vault,
        accounts.mint.address(),
        accounts.bond.address(),
        true,
    )?;
    TransferChecked::new(
        accounts.source,
        accounts.mint,
        accounts.vault,
        accounts.operator,
        amount,
        6,
    )
    .invoke()?;
    {
        let mut bytes = accounts.bond.try_borrow_mut()?;
        bytes[..4].copy_from_slice(b"MBD\x01");
        bytes[4] = 1;
        bytes[5] = u8::from(record.is_some());
        bytes[8..40].copy_from_slice(&log[40..72]);
        if let Some(witness) = accounts.witness.as_ref() {
            bytes[40..72].copy_from_slice(witness.address().as_ref());
        }
        bytes[72..104].copy_from_slice(owner);
        bytes[104..136].copy_from_slice(accounts.mint.address().as_ref());
        bytes[136..168].copy_from_slice(accounts.vault.address().as_ref());
        bytes[168..176].copy_from_slice(&principal.to_le_bytes());
        if !active {
            bytes[176..184].copy_from_slice(&clock.to_le_bytes());
        }
        bytes[184..200].fill(0);
    }
    accounts.economy.try_borrow_mut()?[counter..counter + 8].copy_from_slice(&total.to_le_bytes());
    if let Some(witness) = accounts.witness.as_mut() {
        // A top-up preserves Active, bonded_at, and nonzero principal; it must
        // not let an operator invalidate staged settlements one base unit at a time.
        if !active {
            advance_eligibility(accounts.economy)?;
        }
        let mut bytes = witness.try_borrow_mut()?;
        bytes[5] = 1;
        bytes[232..264].copy_from_slice(accounts.vault.address().as_ref());
        bytes[264..272].fill(0);
    } else {
        accounts.log.try_borrow_mut()?[168..200].copy_from_slice(accounts.vault.address().as_ref());
        accounts.economy.try_borrow_mut()?[164] = 1;
    }
    Ok(())
}

pub(crate) fn request_unbond(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if payload.len() != 1 || payload[0] > 1 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (base, extra) = accounts.split_at_mut(core::cmp::min(4, accounts.len()));
    let [operator, log_account, target, bond] = base else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if extra.len() != usize::from(payload[0] == 1) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log = load_log(program, log_account)?;
    let witness = if payload[0] == 1 {
        Some(load_witness(program, target, &log[40..72])?)
    } else {
        None
    };
    let id = witness
        .as_ref()
        .map(|r| identity(&r[8..8 + r[4] as usize], &r[72..104]));
    let subject = id
        .as_ref()
        .map_or(b"directory".as_slice(), |v| v.as_slice());
    let state = load_bond(program, bond, &log[40..72], subject)?;
    authority(operator, &state[72..104])?;
    owned(program, target, true)?;
    if state[5] != payload[0] || !matches!(state[4], 1 | 2) {
        return Err(ProgramError::InvalidArgument);
    }
    if let Some(witness) = witness {
        if witness[5] != state[4]
            || witness[104..136] != state[72..104]
            || state[40..72] != *target.address().as_ref()
        {
            return Err(invalid());
        }
    } else {
        let policy = economy(program, target, &log[40..72])?;
        if policy[68..100] != state[72..104] || policy[164] != state[4] {
            return Err(invalid());
        }
    }
    if state[4] == 2 {
        return Ok(());
    }
    if payload[0] == 1 {
        let account = &mut extra[0];
        economy(program, account, &log[40..72])?;
        owned(program, account, true)?;
        advance_eligibility(account)?;
    }
    let clock = now()?;
    if clock < i64_at(&state, 176) || clock.checked_add(UNBOND_SECONDS).is_none() {
        return Err(ProgramError::InvalidArgument);
    }
    {
        let mut bytes = bond.try_borrow_mut()?;
        bytes[4] = 2;
        bytes[184..192].copy_from_slice(&clock.to_le_bytes());
    }
    let mut bytes = target.try_borrow_mut()?;
    if payload[0] == 1 {
        bytes[5] = 2;
        bytes[264..272].copy_from_slice(&clock.to_le_bytes());
    } else {
        bytes[164] = 2;
    }
    Ok(())
}

struct Withdrawal<'a> {
    operator: &'a AccountView,
    log: &'a AccountView,
    economy: &'a mut AccountView,
    witness: Option<&'a mut AccountView>,
    bond: &'a mut AccountView,
    vault: &'a AccountView,
    destination: &'a AccountView,
    mint: &'a AccountView,
    token: &'a AccountView,
}
pub(crate) fn withdraw(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    match payload {
        [1] => {
            let [operator, log, economy, witness, bond, vault, destination, mint, token] = accounts
            else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            release(
                program,
                Withdrawal {
                    operator,
                    log,
                    economy,
                    witness: Some(witness),
                    bond,
                    vault,
                    destination,
                    mint,
                    token,
                },
            )
        }
        [0] => {
            let [operator, log, economy, bond, vault, destination, mint, token] = accounts else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            release(
                program,
                Withdrawal {
                    operator,
                    log,
                    economy,
                    witness: None,
                    bond,
                    vault,
                    destination,
                    mint,
                    token,
                },
            )
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
fn release(program: &Address, mut accounts: Withdrawal<'_>) -> ProgramResult {
    let log = load_log(program, accounts.log)?;
    let policy = economy(program, accounts.economy, &log[40..72])?;
    owned(program, accounts.economy, true)?;
    let witness = if let Some(witness) = accounts.witness.as_ref() {
        Some(load_witness(program, witness, &log[40..72])?)
    } else {
        None
    };
    let id = witness
        .as_ref()
        .map(|r| identity(&r[8..8 + r[4] as usize], &r[72..104]));
    let subject = id
        .as_ref()
        .map_or(b"directory".as_slice(), |v| v.as_slice());
    let state = load_bond(program, accounts.bond, &log[40..72], subject)?;
    authority(accounts.operator, &state[72..104])?;
    if state[4] != 2
        || state[5] != u8::from(witness.is_some())
        || now()?
            < i64_at(&state, 184)
                .checked_add(UNBOND_SECONDS)
                .ok_or(ProgramError::ArithmeticOverflow)?
        || accounts.mint.address().as_ref() != &state[104..136]
        || policy[36..68] != state[104..136]
        || accounts.vault.address().as_ref() != &state[136..168]
        || accounts.vault.address() == accounts.destination.address()
    {
        return Err(ProgramError::InvalidArgument);
    }
    if let Some(witness) = &witness {
        owned(program, accounts.witness.as_ref().unwrap(), true)?;
        if witness[5] != 2
            || witness[104..136] != state[72..104]
            || witness[232..264] != state[136..168]
            || state[40..72] != *accounts.witness.as_ref().unwrap().address().as_ref()
        {
            return Err(invalid());
        }
    } else if policy[68..100] != state[72..104]
        || policy[164] != 2
        || u64_at(&policy, 148) != 0
        || log[5] != 0
    {
        return Err(ProgramError::InvalidArgument);
    }
    token_program(accounts.token)?;
    mint_valid(accounts.mint)?;
    associated(
        accounts.bond.address(),
        accounts.mint.address(),
        accounts.vault,
    )?;
    associated(
        accounts.operator.address(),
        accounts.mint.address(),
        accounts.destination,
    )?;
    let balance = token_balance(
        accounts.vault,
        accounts.mint.address(),
        accounts.bond.address(),
        true,
    )?;
    token_balance(
        accounts.destination,
        accounts.mint.address(),
        accounts.operator.address(),
        false,
    )?;
    let principal = u64_at(&state, 168);
    let counter = if witness.is_some() { 148 } else { 156 };
    if balance < principal {
        return Err(invalid());
    }
    let total = u64_at(&policy, counter)
        .checked_sub(principal)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let bump = [pda(
        program,
        &[b"bond", &log[40..72], subject],
        accounts.bond,
    )?];
    let seeds = [
        Seed::from(b"bond"),
        Seed::from(&log[40..72]),
        Seed::from(subject),
        Seed::from(&bump),
    ];
    TransferChecked::new(
        accounts.vault,
        accounts.mint,
        accounts.destination,
        accounts.bond,
        balance,
        6,
    )
    .invoke_signed(&[Signer::from(&seeds)])?;
    {
        let mut bytes = accounts.bond.try_borrow_mut()?;
        bytes[4] = 4;
        bytes[168..176].fill(0);
    }
    if witness.is_some() {
        advance_eligibility(accounts.economy)?;
    }
    let mut policy = accounts.economy.try_borrow_mut()?;
    policy[counter..counter + 8].copy_from_slice(&total.to_le_bytes());
    if let Some(witness) = accounts.witness.as_mut() {
        witness.try_borrow_mut()?[5] = 4;
    } else {
        policy[164] = 4;
    }
    Ok(())
}

pub(crate) fn propose_minimums(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [governance, config, log_account, account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 16 || u64_at(payload, 0) == 0 || u64_at(payload, 8) < u64_at(payload, 0) {
        return Err(ProgramError::InvalidInstructionData);
    }
    check_governance(program, config, governance)?;
    let log = load_log(program, log_account)?;
    let policy = economy(program, account, &log[40..72])?;
    owned(program, account, true)?;
    let clock = now()?;
    if clock < i64_at(&policy, 116) {
        return Err(ProgramError::InvalidArgument);
    }
    let ready = clock
        .checked_add(TIMELOCK_SECONDS)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let mut bytes = account.try_borrow_mut()?;
    bytes[124..140].copy_from_slice(payload);
    bytes[140..148].copy_from_slice(&ready.to_le_bytes());
    Ok(())
}
pub(crate) fn activate_minimums(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [log_account, account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let log = load_log(program, log_account)?;
    let policy = economy(program, account, &log[40..72])?;
    owned(program, account, true)?;
    let clock = now()?;
    if clock < i64_at(&policy, 116) || clock < i64_at(&policy, 140) {
        return Err(ProgramError::InvalidArgument);
    }
    if i64_at(&policy, 140) == 0 {
        return Ok(());
    }
    if u64_at(&policy, 124) == 0 || u64_at(&policy, 132) < u64_at(&policy, 124) {
        return Err(invalid());
    }
    let mut bytes = account.try_borrow_mut()?;
    bytes[100..116].copy_from_slice(&policy[124..140]);
    bytes[124..148].fill(0);
    Ok(())
}

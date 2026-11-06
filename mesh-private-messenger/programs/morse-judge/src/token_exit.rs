//! Owner-only exits remain available without an oracle or an external router.
use crate::{
    custody::{
        advance_eligibility, associated, mint_valid, now, token_balance, token_program, u64_at,
        UNBOND_SECONDS,
    },
    processor::{authority, check_governance, load_log, owned, pda},
    token_binding::load_binding,
    token_custody::{decode_bond, load_economics},
    token_deposit::{optional_pending, subject, CollateralState},
    witness::{identity, load_witness},
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_token::instructions::TransferChecked;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
pub(crate) fn state(
    program: &Address,
    log: &AccountView,
    economy: &AccountView,
    binding: &AccountView,
) -> Result<CollateralState, ProgramError> {
    let d = load_log(program, log)?;
    let id = d[40..72].try_into().unwrap();
    let bound = load_binding(program, binding, &id)?;
    if bound.activated_at == 0 || bound.log != *log.address() {
        return Err(invalid());
    }
    Ok(CollateralState {
        log: d,
        policy: load_economics(program, economy, &id, false)?,
        active_epoch: 0,
    })
}
pub(crate) fn propose_minimums(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [governance, config, log, economy, binding] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 16 || u64_at(payload, 0) == 0 || u64_at(payload, 8) < u64_at(payload, 0) {
        return Err(ProgramError::InvalidInstructionData);
    }
    check_governance(program, config, governance)?;
    let s = state(program, log, economy, binding)?;
    owned(program, economy, true)?;
    if now()? < crate::custody::i64_at(&s.policy, 116) {
        return Err(ProgramError::InvalidArgument);
    }
    if s.policy[124..140] == *payload && crate::custody::i64_at(&s.policy, 140) != 0 {
        return Ok(());
    }
    let ready = now()?
        .checked_add(crate::state::TIMELOCK_SECONDS)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let mut d = economy.try_borrow_mut()?;
    d[124..140].copy_from_slice(payload);
    d[140..148].copy_from_slice(&ready.to_le_bytes());
    Ok(())
}
pub(crate) fn activate_minimums(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [log, economy, binding] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let s = state(program, log, economy, binding)?;
    owned(program, economy, true)?;
    let ready = crate::custody::i64_at(&s.policy, 140);
    if ready == 0 {
        return Ok(());
    }
    if now()? < ready {
        return Err(ProgramError::InvalidArgument);
    }
    let mut d = economy.try_borrow_mut()?;
    d[100..116].copy_from_slice(&s.policy[124..140]);
    d[124..148].fill(0);
    // Entry targets apply only to new/rebonded accounts. No live eligibility input changes.
    Ok(())
}
pub(crate) fn request(
    program: &Address,
    accounts: &mut [AccountView],
    witness: bool,
) -> ProgramResult {
    let (base, tail) = accounts.split_at_mut(core::cmp::min(6, accounts.len()));
    let [operator, log, economy, binding, bond, pending] = base else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if tail.len() != usize::from(witness) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let s = state(program, log, economy, binding)?;
    owned(program, economy, true)?;
    owned(program, bond, true)?;
    let bound = load_binding(program, binding, s.log[40..72].try_into().unwrap())?;
    let d = subject(program, &s, &bound.mint, bond, tail.first())?;
    let b = decode_bond(&d)?;
    authority(operator, &d[72..104])?;
    let mint = Address::new_from_array(d[104..136].try_into().unwrap());
    optional_pending(program, pending, bond.address(), &mint, b.asset)?;
    if !matches!(b.status, 1 | 2) {
        return Err(ProgramError::InvalidArgument);
    }
    if let Some(record) = tail.first() {
        owned(program, record, true)?;
    }
    if b.status == 2 {
        return Ok(());
    }
    let clock = now()?;
    if clock < b.bonded_at || clock.checked_add(UNBOND_SECONDS).is_none() {
        return Err(ProgramError::InvalidArgument);
    }
    advance_eligibility(economy)?;
    let mut d = bond.try_borrow_mut()?;
    d[4] = 2;
    d[184..192].copy_from_slice(&clock.to_le_bytes());
    drop(d);
    if let Some(record) = tail.first_mut() {
        let mut d = record.try_borrow_mut()?;
        d[5] = 2;
        d[264..272].copy_from_slice(&clock.to_le_bytes());
    } else {
        economy.try_borrow_mut()?[164] = 2;
    }
    Ok(())
}
pub(crate) fn withdraw(
    program: &Address,
    accounts: &mut [AccountView],
    witness: bool,
) -> ProgramResult {
    let (base, tail) = accounts.split_at_mut(core::cmp::min(10, accounts.len()));
    let [operator, log, economy, binding, bond, pending, vault, destination, mint, token] = base
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if tail.len() != usize::from(witness) {
        return Err(ProgramError::InvalidInstructionData);
    }
    let s = state(program, log, economy, binding)?;
    owned(program, economy, true)?;
    owned(program, bond, true)?;
    let bound = load_binding(program, binding, s.log[40..72].try_into().unwrap())?;
    let d = subject(program, &s, &bound.mint, bond, tail.first())?;
    let b = decode_bond(&d)?;
    authority(operator, &d[72..104])?;
    if d[104..136] != *mint.address().as_ref()
        || d[136..168] != *vault.address().as_ref()
        || vault.address() == destination.address()
    {
        return Err(invalid());
    }
    let pending_state =
        optional_pending(program, pending, bond.address(), mint.address(), b.asset)?;
    if pending_state.is_some() {
        owned(program, pending, true)?;
    }
    if let Some(record) = tail.first() {
        owned(program, record, true)?;
    }
    token_program(token)?;
    mint_valid(mint)?;
    associated(bond.address(), mint.address(), vault)?;
    associated(operator.address(), mint.address(), destination)?;
    if b.status == 4 {
        return Ok(());
    }
    if b.status != 2
        || now()?
            < b.unbond_at
                .checked_add(UNBOND_SECONDS)
                .ok_or(ProgramError::ArithmeticOverflow)?
        || (!witness
            && (u64_at(&s.policy, 148) != 0 || u64_at(&s.policy, 176) != 0 || s.log[5] != 0))
    {
        return Err(ProgramError::InvalidArgument);
    }
    let counter = match (witness, b.asset) {
        (true, 0) => 148,
        (false, 0) => 156,
        (true, 1) => 176,
        _ => 184,
    };
    let remaining = u64_at(&s.policy, counter)
        .checked_sub(b.principal)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let balance = token_balance(vault, mint.address(), bond.address(), true)?;
    let tracked = b
        .principal
        .checked_add(pending_state.map_or(0, |p| p.amount))
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let before = token_balance(destination, mint.address(), operator.address(), false)?;
    if balance < tracked {
        return Err(invalid());
    }
    let identity = tail
        .first()
        .map(|record| load_witness(program, record, &s.log[40..72]))
        .transpose()?
        .map(|r| identity(&r[8..8 + r[4] as usize], &r[72..104]));
    let subject = identity
        .as_ref()
        .map_or(b"directory".as_slice(), |id| id.as_slice());
    let bump = [pda(program, &[b"bond", &s.log[40..72], subject], bond)?];
    let seeds = [
        Seed::from(b"bond"),
        Seed::from(&s.log[40..72]),
        Seed::from(subject),
        Seed::from(&bump),
    ];
    TransferChecked::new(vault, mint, destination, bond, balance, 6)
        .invoke_signed(&[Signer::from(&seeds)])?;
    if token_balance(vault, mint.address(), bond.address(), true)? != 0
        || token_balance(destination, mint.address(), operator.address(), false)?
            != before
                .checked_add(balance)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    advance_eligibility(economy)?;
    let mut d = bond.try_borrow_mut()?;
    d[4] = 4;
    d[168..176].fill(0);
    d[200..208].fill(0);
    drop(d);
    let mut d = economy.try_borrow_mut()?;
    d[counter..counter + 8].copy_from_slice(&remaining.to_le_bytes());
    if !witness {
        d[164] = 4;
    }
    drop(d);
    if let Some(record) = tail.first_mut() {
        record.try_borrow_mut()?[5] = 4;
    }
    if pending_state.is_some() {
        pending.try_borrow_mut()?[68..84].fill(0);
    }
    Ok(())
}

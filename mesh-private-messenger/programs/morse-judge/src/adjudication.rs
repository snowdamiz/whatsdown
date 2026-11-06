//! Atomic USDC settlement of a staged verdict. No authority can select a source
//! or destination: every vault and receipt address is derived and checked.
use crate::{
    custody::{
        associated, economy, i64_at, load_bond, mint_valid, token_balance, token_program, u64_at,
        FINDER_DENOMINATOR,
    },
    processor::{create_pda, load_log, owned, pda},
    verdict::{self, Verdict},
    witness::{identity, load_witness},
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_token::instructions::TransferChecked;

pub const RECEIPT_HEADER: usize = 288;
pub const RECEIPT_ENTRY: usize = 96;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
struct Target<'a> {
    witness: Option<&'a AccountView>,
    bond: &'a AccountView,
    vault: &'a AccountView,
    subject: &'a [u8],
}
struct Settlement<'a> {
    program: &'a Address,
    log_id: &'a [u8],
    mint: &'a AccountView,
    finder: &'a AccountView,
    locked: &'a AccountView,
    clock: i64,
}
struct Amount {
    principal: u64,
    balance: u64,
}

pub(crate) fn prove(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
    kind: u8,
) -> ProgramResult {
    if payload.len() != 32 || accounts.len() < 12 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (fixed, remaining) = accounts.split_at_mut(12);
    let [payer, log_account, stage, policy_account, receipt, directory, vault, finder, locked, mint, token, system] =
        fixed
    else {
        unreachable!()
    };
    owned(program, log_account, true)?;
    let log = load_log(program, log_account)?;
    let verdict = verdict::verify(program, &log, stage, remaining, kind, payload)?;
    let witnesses = if verdict.anchored {
        &mut remaining[2..]
    } else {
        remaining
    };
    if witnesses.len() != verdict.count * 3 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    owned(program, policy_account, true)?;
    let policy = economy(program, policy_account, &log[40..72])?;
    token_program(token)?;
    mint_valid(mint)?;
    if mint.address().as_ref() != &policy[36..68] {
        return Err(invalid());
    }
    let finder_owner = Address::new_from_array(verdict.finder);
    let locked_owner = Address::try_find_program_address(&[b"locked", &log[40..72]], program)
        .ok_or(ProgramError::InvalidSeeds)?
        .0;
    associated(&finder_owner, mint.address(), finder)?;
    associated(&locked_owner, mint.address(), locked)?;
    if finder.address() == locked.address() {
        return Err(invalid());
    }
    token_balance(finder, mint.address(), &finder_owner, false)?;
    token_balance(locked, mint.address(), &locked_owner, true)?;
    let settlement = Settlement {
        program,
        log_id: &log[40..72],
        mint,
        finder,
        locked,
        clock: verdict.clock,
    };
    let directory_target = Target {
        witness: None,
        bond: directory,
        vault,
        subject: b"directory",
    };
    let directory_amount = check(&settlement, &directory_target)?;
    let directory_state = load_bond(program, directory, &log[40..72], b"directory")?;
    if directory_state[72..104] != policy[68..100]
        || directory_state[4] != policy[164]
        || directory_state[136..168] != log[168..200]
        || directory_amount.principal != u64_at(&policy, 156)
        || (directory_state[4] == 3) != (log[5] == 1)
    {
        return Err(invalid());
    }
    let mut total = directory_amount.balance;
    let mut finder_total = directory_amount.balance / FINDER_DENOMINATOR;
    let mut principal = 0u64;
    for (index, group) in witnesses.as_chunks::<3>().0.iter().enumerate() {
        let target = Target {
            witness: Some(&group[0]),
            bond: &group[1],
            vault: &group[2],
            subject: &verdict.subjects[index],
        };
        let amount = check(&settlement, &target)?;
        total = total
            .checked_add(amount.balance)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        finder_total = finder_total
            .checked_add(amount.balance / FINDER_DENOMINATOR)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        principal = principal
            .checked_add(amount.principal)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    if total == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let remaining_principal = u64_at(&policy, 148)
        .checked_sub(principal)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let bump = [pda(
        program,
        &[b"proof", &log[40..72], &verdict.hash],
        receipt,
    )?];
    let length = RECEIPT_HEADER + verdict.count * RECEIPT_ENTRY;
    create_pda(
        program,
        payer,
        receipt,
        system,
        length,
        length,
        &[
            Seed::from(b"proof"),
            Seed::from(&log[40..72]),
            Seed::from(&verdict.hash),
            Seed::from(&bump),
        ],
    )?;
    transfer(&settlement, &directory_target, &directory_amount)?;
    mark(directory, None, &directory_amount, verdict.clock)?;
    for (index, [witness_account, bond_account, vault_account]) in
        witnesses.as_chunks_mut::<3>().0.iter_mut().enumerate()
    {
        let target = Target {
            witness: Some(witness_account),
            bond: bond_account,
            vault: vault_account,
            subject: &verdict.subjects[index],
        };
        let amount = check(&settlement, &target)?;
        transfer(&settlement, &target, &amount)?;
        let witness = load_witness(program, witness_account, &log[40..72])?;
        mark(bond_account, Some(witness_account), &amount, verdict.clock)?;
        let mut bytes = receipt.try_borrow_mut()?;
        let row = &mut bytes
            [RECEIPT_HEADER + index * RECEIPT_ENTRY..RECEIPT_HEADER + (index + 1) * RECEIPT_ENTRY];
        row[..32].copy_from_slice(witness_account.address().as_ref());
        row[32..64].copy_from_slice(&witness[72..104]);
        row[64..72].copy_from_slice(&amount.principal.to_le_bytes());
        row[72..80].copy_from_slice(&amount.balance.to_le_bytes());
        row[80..88].copy_from_slice(&(amount.balance / FINDER_DENOMINATOR).to_le_bytes());
    }
    // The proof may change several witnesses; a single new revision invalidates
    // every staged rewards read from the preceding coherent custody state.
    if principal > 0 {
        crate::custody::advance_eligibility(policy_account)?;
    }
    log_account.try_borrow_mut()?[5] = 1;
    {
        let mut bytes = policy_account.try_borrow_mut()?;
        bytes[148..156].copy_from_slice(&remaining_principal.to_le_bytes());
        bytes[156..164].fill(0);
        bytes[164] = 3;
    }
    receipt_header(
        receipt,
        &log[40..72],
        mint.address(),
        &verdict,
        total,
        finder_total,
        directory_amount.balance,
    )?;
    Ok(())
}

#[inline(never)]
fn check(settlement: &Settlement, target: &Target) -> Result<Amount, ProgramError> {
    let state = load_bond(
        settlement.program,
        target.bond,
        settlement.log_id,
        target.subject,
    )?;
    if !matches!(state[4], 1..=3)
        || state[5] != u8::from(target.witness.is_some())
        || state[104..136] != *settlement.mint.address().as_ref()
        || state[136..168] != *target.vault.address().as_ref()
        || target.vault.address() == settlement.finder.address()
        || target.vault.address() == settlement.locked.address()
        || i64_at(&state, 176) < 0
        || i64_at(&state, 176) > settlement.clock
    {
        return Err(invalid());
    }
    associated(
        target.bond.address(),
        settlement.mint.address(),
        target.vault,
    )?;
    let balance = token_balance(
        target.vault,
        settlement.mint.address(),
        target.bond.address(),
        true,
    )?;
    let principal = u64_at(&state, 168);
    if balance < principal || (state[4] == 3 && principal != 0) || (state[4] != 3 && principal == 0)
    {
        return Err(invalid());
    }
    if let Some(witness) = target.witness {
        owned(settlement.program, witness, true)?;
        let record = load_witness(settlement.program, witness, settlement.log_id)?;
        if identity(&record[8..8 + record[4] as usize], &record[72..104]) != target.subject
            || record[5] != state[4]
            || record[104..136] != state[72..104]
            || record[232..264] != state[136..168]
            || record[264..272] != state[184..192]
            || state[40..72] != *witness.address().as_ref()
        {
            return Err(invalid());
        }
    } else if state[40..72] != [0; 32] {
        return Err(invalid());
    }
    Ok(Amount {
        principal,
        balance: if state[4] == 3 { 0 } else { balance },
    })
}
#[inline(never)]
fn transfer(settlement: &Settlement, target: &Target, amount: &Amount) -> ProgramResult {
    if amount.balance == 0 {
        return Ok(());
    }
    let bump = [pda(
        settlement.program,
        &[b"bond", settlement.log_id, target.subject],
        target.bond,
    )?];
    let seeds = [
        Seed::from(b"bond"),
        Seed::from(settlement.log_id),
        Seed::from(target.subject),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    let finder = amount.balance / FINDER_DENOMINATOR;
    if finder != 0 {
        TransferChecked::new(
            target.vault,
            settlement.mint,
            settlement.finder,
            target.bond,
            finder,
            6,
        )
        .invoke_signed(core::slice::from_ref(&signer))?;
    }
    TransferChecked::new(
        target.vault,
        settlement.mint,
        settlement.locked,
        target.bond,
        amount.balance - finder,
        6,
    )
    .invoke_signed(&[signer])?;
    Ok(())
}
#[inline(never)]
fn mark(
    bond: &mut AccountView,
    witness: Option<&mut AccountView>,
    amount: &Amount,
    clock: i64,
) -> ProgramResult {
    if amount.balance == 0 {
        return Ok(());
    }
    let mut bytes = bond.try_borrow_mut()?;
    bytes[4] = 3;
    bytes[168..176].fill(0);
    bytes[192..200].copy_from_slice(&clock.to_le_bytes());
    if let Some(witness) = witness {
        witness.try_borrow_mut()?[5] = 3;
    }
    Ok(())
}
#[inline(never)]
fn receipt_header(
    receipt: &mut AccountView,
    log_id: &[u8],
    mint: &Address,
    verdict: &Verdict,
    total: u64,
    finder: u64,
    directory: u64,
) -> ProgramResult {
    let mut bytes = receipt.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MPR\x01");
    bytes[4] = verdict.kind;
    bytes[5] = u8::from(verdict.anchored);
    bytes[6] = verdict.count as u8;
    bytes[8..40].copy_from_slice(log_id);
    bytes[40..72].copy_from_slice(&verdict.hash);
    bytes[72..104].copy_from_slice(&verdict.finder);
    bytes[104..136].copy_from_slice(&verdict.submitter);
    bytes[136..168].copy_from_slice(mint.as_ref());
    bytes[168..200].copy_from_slice(&verdict.first);
    bytes[200..232].copy_from_slice(&verdict.second);
    bytes[232..240].copy_from_slice(&verdict.clock.to_le_bytes());
    bytes[240..248].copy_from_slice(&total.to_le_bytes());
    bytes[248..256].copy_from_slice(&finder.to_le_bytes());
    bytes[256..264].copy_from_slice(&directory.to_le_bytes());
    bytes[264..272].copy_from_slice(&verdict.verified.to_le_bytes());
    Ok(())
}

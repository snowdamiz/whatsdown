//! Prepare authenticated immutable verdict identities, then settle every asset atomically.
use crate::{
    custody::{
        advance_eligibility, associated, i64_at, mint_valid, now, token_balance, token_program,
        u64_at,
    },
    processor::{create_pda, owned, pda},
    token_binding::load_binding,
    token_custody::decode_bond,
    token_deposit::{subject, subject_compatible, CollateralState},
    token_exit, verdict,
};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_token::instructions::TransferChecked;
pub const HEADER: usize = 400;
pub const ROW: usize = 144;
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or(ProgramError::ArithmeticOverflow)
}
#[derive(Clone, Copy)]
pub struct PreparedProof {
    pub count: usize,
    pub settled: bool,
    pub deadline_ms: u64,
    pub directory_asset: u8,
    pub directory_bonded_at: i64,
}
pub fn decode(d: &[u8]) -> Result<PreparedProof, ProgramError> {
    if d.len() < HEADER
        || &d[..4] != b"MPR\x02"
        || !(1..=3).contains(&d[4])
        || d[5] > 1
        || d[6] > 16
        || d[7] > 1
        || d.len() != HEADER + d[6] as usize * ROW
        || d[8..40] == [0; 32]
        || d[40..72] == [0; 32]
        || d[72..104] == [0; 32]
        || d[104..136] == [0; 32]
        || d[136..168] == [0; 32]
        || d[168..200] == [0; 32]
        || d[136..168] == d[168..200]
        || d[200..232] == [0; 32]
        || d[232..264] == [0; 32]
        || i64_at(d, 264) <= 0
        || d[328..360] == [0; 32]
        || i64_at(d, 368) <= 0
        || i64_at(d, 368) > i64_at(d, 264)
        || d[376] > 1
        || d[377..384].iter().chain(&d[392..400]).any(|b| *b != 0)
        || (i64_at(d, 264) as u64)
            .checked_mul(1000)
            .is_none_or(|v| v > u64_at(d, 360))
        || (d[7] == 0 && (d[272..320].iter().chain(&d[384..392]).any(|b| *b != 0)))
        || (d[7] == 1
            && (i64_at(d, 384) < i64_at(d, 264)
                || (i64_at(d, 384) as u64)
                    .checked_mul(1000)
                    .is_none_or(|v| v > u64_at(d, 360))))
    {
        return Err(invalid());
    }
    let mut balances = [0u64; 2];
    let mut finders = [0u64; 2];
    let dir_asset = d[376] as usize;
    let directory = u64_at(d, if dir_asset == 0 { 288 } else { 312 });
    if u64_at(d, if dir_asset == 0 { 312 } else { 288 }) != 0 {
        return Err(invalid());
    }
    balances[dir_asset] = directory;
    finders[dir_asset] = directory / 10;
    for n in 0..d[6] as usize {
        let r = &d[HEADER + n * ROW..HEADER + (n + 1) * ROW];
        if r[..32] == [0; 32]
            || r[32..64] == [0; 32]
            || r[64..96] == [0; 32]
            || r[96] > 1
            || r[97..104].iter().chain(&r[136..144]).any(|b| *b != 0)
            || i64_at(r, 104) <= 0
            || i64_at(r, 104) > i64_at(d, 264)
            || (d[7] == 0 && r[112..136].iter().any(|b| *b != 0))
            || u64_at(r, 120) < u64_at(r, 112)
            || u64_at(r, 128) != u64_at(r, 120) / 10
        {
            return Err(invalid());
        }
        for prior in 0..n {
            if d[HEADER + prior * ROW..HEADER + prior * ROW + 32] == r[..32] {
                return Err(invalid());
            }
        }
        let asset = r[96] as usize;
        balances[asset] = add(balances[asset], u64_at(r, 120))?;
        finders[asset] = add(finders[asset], u64_at(r, 128))?;
    }
    if d[7] == 1
        && (balances != [u64_at(d, 272), u64_at(d, 296)]
            || finders != [u64_at(d, 280), u64_at(d, 304)]
            || balances == [0; 2])
    {
        return Err(invalid());
    }
    Ok(PreparedProof {
        count: d[6] as usize,
        settled: d[7] == 1,
        deadline_ms: u64_at(d, 360),
        directory_asset: d[376],
        directory_bonded_at: i64_at(d, 368),
    })
}
pub(crate) fn prepare(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
    kind: u8,
) -> ProgramResult {
    if payload.len() != 32 || accounts.len() < 8 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (base, extra) = accounts.split_at_mut(8);
    let [payer, log, stage, economy, binding, receipt, system, directory] = base else {
        unreachable!()
    };
    let state = token_exit::state(program, log, economy, binding)?;
    let bound = load_binding(program, binding, state.log[40..72].try_into().unwrap())?;
    let v = verdict::verify(program, &state.log, stage, extra, kind, payload)?;
    let targets = if v.anchored { &extra[2..] } else { extra };
    if targets.len() != v.count * 2 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let bump = [pda(
        program,
        &[b"proof", &state.log[40..72], &v.hash],
        receipt,
    )?];
    if receipt.owner() == program {
        owned(program, receipt, true)?;
        let d = receipt.try_borrow()?;
        let old = decode(&d)?;
        if old.count != v.count
            || d[4] != kind
            || d[5] != u8::from(v.anchored)
            || d[8..40] != state.log[40..72]
            || d[40..72] != v.hash
            || d[72..104] != v.finder
            || d[104..136] != v.submitter
            || d[136..168] != state.policy[36..68]
            || d[168..200] != *bound.mint.as_ref()
            || d[200..232] != v.first
            || d[232..264] != v.second
            || u64_at(&d, 320) != v.verified
            || d[328..360] != *stage.address().as_ref()
            || old.deadline_ms != v.deadline_ms
        {
            return Err(invalid());
        }
        for n in 0..v.count {
            pda(
                program,
                &[b"bond", &state.log[40..72], &v.subjects[n]],
                &targets[n * 2 + 1],
            )?;
            if d[HEADER + n * ROW..HEADER + n * ROW + 32] != v.subjects[n]
                || d[HEADER + n * ROW + 32..HEADER + n * ROW + 64]
                    != *targets[n * 2].address().as_ref()
            {
                return Err(invalid());
            }
        }
        pda(
            program,
            &[b"bond", &state.log[40..72], b"directory"],
            directory,
        )?;
        return Ok(());
    }
    let dir = subject_compatible(program, &state, &bound.mint, directory, None, true)?;
    let dir_state = decode_bond(&dir)?;
    if !matches!(dir_state.status, 1..=3) || dir_state.bonded_at > v.clock {
        return Err(invalid());
    }
    // Validate all subjects before creating the permanent prepared receipt.
    for (n, [witness, bond]) in targets.as_chunks::<2>().0.iter().enumerate() {
        pda(
            program,
            &[b"witness", &state.log[40..72], &v.subjects[n]],
            witness,
        )?;
        let b = subject_compatible(program, &state, &bound.mint, bond, Some(witness), true)?;
        let b = decode_bond(&b)?;
        if !matches!(b.status, 1..=3) || b.bonded_at > v.clock {
            return Err(invalid());
        }
    }
    let length = HEADER + ROW * v.count;
    create_pda(
        program,
        payer,
        receipt,
        system,
        length,
        length,
        &[
            Seed::from(b"proof"),
            Seed::from(&state.log[40..72]),
            Seed::from(&v.hash),
            Seed::from(&bump),
        ],
    )?;
    {
        let mut d = receipt.try_borrow_mut()?;
        d.fill(0);
        d[..4].copy_from_slice(b"MPR\x02");
        d[4] = kind;
        d[5] = u8::from(v.anchored);
        d[6] = v.count as u8;
        for (at, bytes) in [
            (8, state.log[40..72].as_ref()),
            (40, v.hash.as_ref()),
            (72, v.finder.as_ref()),
            (104, v.submitter.as_ref()),
            (136, state.policy[36..68].as_ref()),
            (168, bound.mint.as_ref()),
            (200, v.first.as_ref()),
            (232, v.second.as_ref()),
            (328, stage.address().as_ref()),
        ] {
            d[at..at + 32].copy_from_slice(bytes);
        }
        d[264..272].copy_from_slice(&v.clock.to_le_bytes());
        d[320..328].copy_from_slice(&v.verified.to_le_bytes());
        d[360..368].copy_from_slice(&v.deadline_ms.to_le_bytes());
        d[368..376].copy_from_slice(&dir_state.bonded_at.to_le_bytes());
        d[376] = dir_state.asset;
    }
    for (n, [witness, bond]) in targets.as_chunks::<2>().0.iter().enumerate() {
        let b = subject_compatible(program, &state, &bound.mint, bond, Some(witness), true)?;
        let w = witness.try_borrow()?;
        let mut d = receipt.try_borrow_mut()?;
        let r = &mut d[HEADER + n * ROW..HEADER + (n + 1) * ROW];
        r[..32].copy_from_slice(&v.subjects[n]);
        r[32..64].copy_from_slice(witness.address().as_ref());
        r[64..96].copy_from_slice(&w[72..104]);
        r[96] = b[6];
        r[104..112].copy_from_slice(&b[176..184]);
    }
    decode(&receipt.try_borrow()?)?;
    // Preparation never moves token custody, changes a bond, or advances eligibility.
    Ok(())
}
struct Settlement<'a> {
    program: &'a Address,
    state: &'a CollateralState,
    morse: &'a Address,
    mints: [&'a AccountView; 2],
    finders: [&'a AccountView; 2],
    locked: [&'a AccountView; 2],
    finder_owner: &'a Address,
    locked_owner: &'a Address,
}
struct Target<'a> {
    witness: Option<&'a AccountView>,
    bond: &'a AccountView,
    vault: &'a AccountView,
    identity: &'a [u8],
}
#[derive(Clone, Copy)]
struct Amount {
    asset: u8,
    principal: u64,
    balance: u64,
}
#[inline(never)]
fn check(
    s: &Settlement<'_>,
    t: &Target<'_>,
    asset: u8,
    bonded_at: i64,
) -> Result<Amount, ProgramError> {
    owned(s.program, t.bond, true)?;
    if let Some(w) = t.witness {
        owned(s.program, w, true)?;
        pda(
            s.program,
            &[b"witness", &s.state.log[40..72], t.identity],
            w,
        )?;
    }
    let d = subject(s.program, s.state, s.morse, t.bond, t.witness)?;
    let b = decode_bond(&d)?;
    if !matches!(b.status, 1..=3)
        || b.asset != asset
        || b.bonded_at != bonded_at
        || d[136..168] != *t.vault.address().as_ref()
        || t.vault.address() == s.finders[asset as usize].address()
        || t.vault.address() == s.locked[asset as usize].address()
    {
        return Err(invalid());
    }
    let balance = token_balance(
        t.vault,
        s.mints[asset as usize].address(),
        t.bond.address(),
        true,
    )?;
    if balance < b.principal {
        return Err(invalid());
    }
    Ok(Amount {
        asset,
        principal: b.principal,
        balance: if b.status == 3 { 0 } else { balance },
    })
}
#[inline(never)]
fn transfer(s: &Settlement<'_>, t: &Target<'_>, amount: Amount) -> ProgramResult {
    if amount.balance == 0 {
        return Ok(());
    }
    let asset = amount.asset as usize;
    let before = [
        token_balance(
            s.finders[asset],
            s.mints[asset].address(),
            s.finder_owner,
            false,
        )?,
        token_balance(
            s.locked[asset],
            s.mints[asset].address(),
            s.locked_owner,
            true,
        )?,
    ];
    let source_before = token_balance(t.vault, s.mints[asset].address(), t.bond.address(), true)?;
    let bump = [pda(
        s.program,
        &[b"bond", &s.state.log[40..72], t.identity],
        t.bond,
    )?];
    let seeds = [
        Seed::from(b"bond"),
        Seed::from(&s.state.log[40..72]),
        Seed::from(t.identity),
        Seed::from(&bump),
    ];
    let signer = Signer::from(&seeds);
    let bounty = amount.balance / 10;
    if bounty != 0 {
        TransferChecked::new(t.vault, s.mints[asset], s.finders[asset], t.bond, bounty, 6)
            .invoke_signed(core::slice::from_ref(&signer))?;
    }
    TransferChecked::new(
        t.vault,
        s.mints[asset],
        s.locked[asset],
        t.bond,
        amount.balance - bounty,
        6,
    )
    .invoke_signed(&[signer])?;
    if token_balance(t.vault, s.mints[asset].address(), t.bond.address(), true)?
        != source_before - amount.balance
        || token_balance(
            s.finders[asset],
            s.mints[asset].address(),
            s.finder_owner,
            false,
        )? != add(before[0], bounty)?
        || token_balance(
            s.locked[asset],
            s.mints[asset].address(),
            s.locked_owner,
            true,
        )? != add(before[1], amount.balance - bounty)?
    {
        return Err(invalid());
    }
    Ok(())
}
#[inline(never)]
fn mark(
    bond: &mut AccountView,
    witness: Option<&mut AccountView>,
    amount: Amount,
    clock: i64,
) -> ProgramResult {
    if amount.balance == 0 {
        return Ok(());
    }
    let mut d = bond.try_borrow_mut()?;
    d[4] = 3;
    d[168..176].fill(0);
    d[192..200].copy_from_slice(&clock.to_le_bytes());
    d[200..208].fill(0);
    drop(d);
    if let Some(w) = witness {
        w.try_borrow_mut()?[5] = 3;
    }
    // Pending companions are now historical only: every mutating pending path
    // rejects a Slashed bond. All actual pending tokens were included in balance.
    Ok(())
}
pub(crate) fn settle(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    if accounts.len() < 13 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (base, targets) = accounts.split_at_mut(13);
    let [log, economy, binding, receipt, directory, directory_vault, usd, usd_finder, usd_locked, morse, morse_finder, morse_locked, token] =
        base
    else {
        unreachable!()
    };
    owned(program, log, true)?;
    owned(program, economy, true)?;
    owned(program, receipt, true)?;
    let state = token_exit::state(program, log, economy, binding)?;
    let bound = load_binding(program, binding, state.log[40..72].try_into().unwrap())?;
    let (proof, finder_owner) = {
        let d = receipt.try_borrow()?;
        let proof = decode(&d)?;
        pda(
            program,
            &[b"proof", &state.log[40..72], &d[40..72]],
            receipt,
        )?;
        let clock = now()?;
        if proof.settled
            || targets.len() != proof.count * 3
            || d[8..40] != state.log[40..72]
            || d[136..168] != state.policy[36..68]
            || d[136..168] != *usd.address().as_ref()
            || d[168..200] != *bound.mint.as_ref()
            || d[168..200] != *morse.address().as_ref()
            || clock < i64_at(&d, 264)
            || (clock as u64)
                .checked_mul(1000)
                .is_none_or(|v| v > proof.deadline_ms)
        {
            return Err(ProgramError::InvalidArgument);
        }
        (
            proof,
            Address::new_from_array(d[72..104].try_into().unwrap()),
        )
    };
    token_program(token)?;
    mint_valid(usd)?;
    mint_valid(morse)?;
    let locked_owner = Address::find_program_address(&[b"locked", &state.log[40..72]], program).0;
    let s = Settlement {
        program,
        state: &state,
        morse: &bound.mint,
        mints: [usd, morse],
        finders: [usd_finder, morse_finder],
        locked: [usd_locked, morse_locked],
        finder_owner: &finder_owner,
        locked_owner: &locked_owner,
    };
    for asset in 0..2 {
        associated(&finder_owner, s.mints[asset].address(), s.finders[asset])?;
        associated(&locked_owner, s.mints[asset].address(), s.locked[asset])?;
        if s.finders[asset].address() == s.locked[asset].address() {
            return Err(invalid());
        }
        token_balance(
            s.finders[asset],
            s.mints[asset].address(),
            &finder_owner,
            false,
        )?;
        token_balance(
            s.locked[asset],
            s.mints[asset].address(),
            &locked_owner,
            true,
        )?;
    }
    let dir = Target {
        witness: None,
        bond: directory,
        vault: directory_vault,
        identity: b"directory",
    };
    let directory_amount = check(&s, &dir, proof.directory_asset, proof.directory_bonded_at)?;
    if (state.policy[164] == 3) != (state.log[5] == 1) {
        return Err(invalid());
    }
    let mut balances = [0u64; 2];
    let mut finders = [0u64; 2];
    let mut principals = [0u64; 2];
    balances[directory_amount.asset as usize] = directory_amount.balance;
    finders[directory_amount.asset as usize] = directory_amount.balance / 10;
    for (n, [witness, bond, vault]) in targets.as_chunks::<3>().0.iter().enumerate() {
        let (identity, asset, bonded_at, key) = {
            let d = receipt.try_borrow()?;
            let r = &d[HEADER + n * ROW..HEADER + (n + 1) * ROW];
            if r[32..64] != *witness.address().as_ref() {
                return Err(invalid());
            }
            (
                <[u8; 32]>::try_from(&r[..32]).unwrap(),
                r[96],
                i64_at(r, 104),
                <[u8; 32]>::try_from(&r[64..96]).unwrap(),
            )
        };
        let amount = check(
            &s,
            &Target {
                witness: Some(witness),
                bond,
                vault,
                identity: &identity,
            },
            asset,
            bonded_at,
        )?;
        if key != witness.try_borrow()?[72..104] {
            return Err(invalid());
        }
        let asset = amount.asset as usize;
        balances[asset] = add(balances[asset], amount.balance)?;
        finders[asset] = add(finders[asset], amount.balance / 10)?;
        principals[asset] = add(principals[asset], amount.principal)?;
    }
    if balances == [0; 2] {
        return Err(ProgramError::InvalidArgument);
    }
    let remaining = [
        u64_at(&state.policy, 148)
            .checked_sub(principals[0])
            .ok_or(ProgramError::ArithmeticOverflow)?,
        u64_at(&state.policy, 176)
            .checked_sub(principals[1])
            .ok_or(ProgramError::ArithmeticOverflow)?,
    ];
    transfer(&s, &dir, directory_amount)?;
    // Release immutable borrows before mutating any source metadata.
    mark(directory, None, directory_amount, now()?)?;
    for (n, [witness, bond, vault]) in targets.as_chunks_mut::<3>().0.iter_mut().enumerate() {
        let (identity, asset, bonded_at) = {
            let d = receipt.try_borrow()?;
            let r = &d[HEADER + n * ROW..HEADER + (n + 1) * ROW];
            (
                <[u8; 32]>::try_from(&r[..32]).unwrap(),
                r[96],
                i64_at(r, 104),
            )
        };
        let target = Target {
            witness: Some(witness),
            bond,
            vault,
            identity: &identity,
        };
        let amount = check(&s, &target, asset, bonded_at)?;
        transfer(&s, &target, amount)?;
        mark(bond, Some(witness), amount, now()?)?;
        let mut d = receipt.try_borrow_mut()?;
        let r = &mut d[HEADER + n * ROW..HEADER + (n + 1) * ROW];
        r[112..120].copy_from_slice(&amount.principal.to_le_bytes());
        r[120..128].copy_from_slice(&amount.balance.to_le_bytes());
        r[128..136].copy_from_slice(&(amount.balance / 10).to_le_bytes());
    }
    advance_eligibility(economy)?;
    log.try_borrow_mut()?[5] = 1;
    let mut d = economy.try_borrow_mut()?;
    d[148..156].copy_from_slice(&remaining[0].to_le_bytes());
    d[156..164].fill(0);
    d[164] = 3;
    d[176..184].copy_from_slice(&remaining[1].to_le_bytes());
    d[184..192].fill(0);
    drop(d);
    let mut d = receipt.try_borrow_mut()?;
    d[7] = 1;
    for (at, v) in [
        (272, balances[0]),
        (280, finders[0]),
        (
            288,
            if directory_amount.asset == 0 {
                directory_amount.balance
            } else {
                0
            },
        ),
        (296, balances[1]),
        (304, finders[1]),
        (
            312,
            if directory_amount.asset == 1 {
                directory_amount.balance
            } else {
                0
            },
        ),
    ] {
        d[at..at + 8].copy_from_slice(&v.to_le_bytes());
    }
    d[384..392].copy_from_slice(&now()?.to_le_bytes());
    decode(&d)?;
    Ok(())
}

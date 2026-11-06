use crate::{math, ALLOCATIONS, ALLOCATION_LEN, CONFIG_LEN, SUPPLY};
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_associated_token_account::{instructions::CreateIdempotent, ID as ATA};
use pinocchio_system::instructions::{Allocate, Assign, CreateAccount, Transfer};
use pinocchio_token::{
    instructions::{AuthorityType, InitializeMint2, MintToChecked, SetAuthority, TransferChecked},
    state::{Account as TokenAccount, AccountState, Mint},
    ID as TOKEN,
};
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
pub(crate) fn owned(program: &Address, a: &AccountView, w: bool) -> ProgramResult {
    if a.owner() != program || a.executable() || (w && !a.is_writable()) {
        Err(invalid())
    } else {
        Ok(())
    }
}
pub(crate) fn pda(program: &Address, seeds: &[&[u8]], a: &AccountView) -> Result<u8, ProgramError> {
    let (key, bump) =
        Address::try_find_program_address(seeds, program).ok_or(ProgramError::InvalidSeeds)?;
    if a.address() != &key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(bump)
}
fn associated(owner: &Address, mint: &Address, a: &AccountView) -> ProgramResult {
    pda(&ATA, &[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], a)?;
    Ok(())
}
pub(crate) fn clock() -> Result<i64, ProgramError> {
    let value = Clock::get()?.unix_timestamp;
    if value <= 0 {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(value)
}
pub(crate) fn create(
    program: &Address,
    owner: &Address,
    payer: &AccountView,
    a: &AccountView,
    system: &AccountView,
    space: usize,
    seeds: &[Seed],
) -> ProgramResult {
    if a.owner() == program && owner == program {
        owned(program, a, true)?;
        let d = a.try_borrow()?;
        if d.len() == space && d.iter().all(|x| *x == 0) {
            return Ok(());
        }
        return Err(invalid());
    }
    if system.address() != &pinocchio_system::ID
        || !system.executable()
        || a.owner() != &pinocchio_system::ID
        || a.data_len() != 0
        || a.executable()
        || !a.is_writable()
        || !payer.is_writable()
        || !payer.is_signer()
        || payer.address() == a.address()
    {
        return Err(invalid());
    }
    let rent = Rent::get()?.try_minimum_balance(space)?;
    if a.lamports() == 0 {
        return CreateAccount {
            from: payer,
            to: a,
            lamports: rent,
            space: space as u64,
            owner,
        }
        .invoke_signed(&[Signer::from(seeds)]);
    }
    if rent > a.lamports() {
        Transfer {
            from: payer,
            to: a,
            lamports: rent - a.lamports(),
        }
        .invoke()?;
    }
    let signers = [Signer::from(seeds)];
    Allocate {
        account: a,
        space: space as u64,
    }
    .invoke_signed(&signers)?;
    Assign { account: a, owner }.invoke_signed(&signers)?;
    let _ = program;
    Ok(())
}
fn token_programs(token: &AccountView, ata: &AccountView, system: &AccountView) -> ProgramResult {
    if token.address() != &TOKEN
        || !token.executable()
        || ata.address() != &ATA
        || !ata.executable()
        || system.address() != &pinocchio_system::ID
        || !system.executable()
    {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
fn locked_mint(a: &AccountView) -> ProgramResult {
    owned(&TOKEN, a, false)?;
    if a.data_len() != 82 {
        return Err(invalid());
    }
    let mint = Mint::from_account_view(a)?;
    if !mint.is_initialized()
        || mint.decimals() != 6
        || mint.supply() > SUPPLY
        || mint.has_mint_authority()
        || mint.has_freeze_authority()
    {
        return Err(invalid());
    }
    let d = a.try_borrow()?;
    if d[..4] != [0; 4] || d[46..50] != [0; 4] {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn balance(
    a: &AccountView,
    mint: &Address,
    owner: &Address,
) -> Result<u64, ProgramError> {
    owned(&TOKEN, a, true)?;
    if a.data_len() != 165 {
        return Err(invalid());
    }
    let value = TokenAccount::from_account_view(a)?;
    if value.mint() != mint
        || value.owner() != owner
        || value.state() != AccountState::Initialized
        || value.is_native()
        || value.has_delegate()
        || value.has_close_authority()
    {
        return Err(invalid());
    }
    Ok(value.amount())
}
fn bootstrap(
    program: &Address,
    authority: &AccountView,
    image: &AccountView,
    programdata: &AccountView,
) -> ProgramResult {
    const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    if image.address() != program
        || !image.executable()
        || image.owner() != &LOADER
        || programdata.owner() != &LOADER
        || programdata.executable()
    {
        return Err(invalid());
    }
    pda(&LOADER, &[program.as_ref()], programdata)?;
    let executable = image.try_borrow()?;
    let data = programdata.try_borrow()?;
    if executable.len() != 36
        || executable[..4] != 2u32.to_le_bytes()
        || executable[4..36] != *programdata.address().as_ref()
        || data.len() < 45
        || data[..4] != 3u32.to_le_bytes()
        || data[12] != 1
        || !authority.is_signer()
        || data[13..45] != *authority.address().as_ref()
    {
        return Err(ProgramError::MissingRequiredSignature);
    }
    Ok(())
}
pub(crate) fn config(
    program: &Address,
    a: &AccountView,
    mint: &AccountView,
) -> Result<i64, ProgramError> {
    owned(program, a, false)?;
    pda(program, &[b"token"], a)?;
    pda(program, &[b"mint"], mint)?;
    locked_mint(mint)?;
    let d = a.try_borrow()?;
    if d.len() != CONFIG_LEN
        || &d[..4] != b"MTK\x01"
        || d[4..36] == [0; 32]
        || d[36..68] != *mint.address().as_ref()
        || d[76..80].iter().chain(&d[304..]).any(|x| *x != 0)
    {
        return Err(invalid());
    }
    let started = i64::from_le_bytes(d[68..76].try_into().unwrap());
    if started <= 0 {
        return Err(invalid());
    }
    Ok(started)
}
pub fn process_instruction(
    program: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    match data.split_first() {
        Some((0, p)) if p.len() == 256 => initialize(program, accounts, p),
        Some((1, [kind])) if *kind < 7 => claim(program, accounts, *kind),
        Some((2, [])) => prepare(program, accounts),
        Some((3, p)) if p.len() == 64 => crate::oracle::initialize(program, accounts, p),
        Some((4, [])) => crate::oracle::observe(program, accounts),
        Some((5, [])) => crate::oracle::validate(program, accounts),
        Some((6, p)) if p.len() == 64 => crate::oracle::propose_source(program, accounts, p),
        Some((7, [])) => crate::oracle::execute_source(program, accounts),
        Some((8, [])) => crate::burn::initialize(program, accounts),
        Some((9, payload)) if payload.len() == 304 => crate::burn::open(program, accounts, payload),
        Some((10, payload)) if payload.len() == 40 => {
            crate::burn::execute(program, accounts, payload)
        }
        Some((11, [])) => crate::reserve::initialize(program, accounts),
        Some((12, [])) => crate::reserve::fund(program, accounts),
        Some((13, payload)) if payload.len() == 8 => {
            crate::burn::carry::close(program, accounts, payload)
        }
        Some((14, payload)) if payload.len() == 312 => {
            crate::burn::carry::open(program, accounts, payload)
        }
        Some((15, payload)) if payload.len() == 8 => {
            crate::burn::expiry::expire(program, accounts, payload)
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
// Permissionless rent preparation commits no beneficiaries and never exposes an uninitialized SPL mint.
fn prepare(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [payer, cfg, system, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if rest.len() != 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let cb = [pda(program, &[b"token"], cfg)?];
    create(
        program,
        program,
        payer,
        cfg,
        system,
        CONFIG_LEN,
        &[Seed::from(b"token"), Seed::from(&cb)],
    )?;
    for (i, state) in rest.iter().enumerate() {
        let index = [i as u8];
        let bump = [pda(program, &[b"allocation", &index], state)?];
        create(
            program,
            program,
            payer,
            state,
            system,
            ALLOCATION_LEN,
            &[
                Seed::from(b"allocation"),
                Seed::from(&index),
                Seed::from(&bump),
            ],
        )?;
    }
    Ok(())
}
fn initialize(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    if accounts.len() != 23 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (base, allocations) = accounts.split_at_mut(9);
    let [authority, payer, cfg, mint, image, programdata, token, ata, system] = base else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    bootstrap(program, authority, image, programdata)?;
    token_programs(token, ata, system)?;
    let cb = [pda(program, &[b"token"], cfg)?];
    let mb = [pda(program, &[b"mint"], mint)?];
    if payload[..32] == [0; 32] {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut bumps = [0u8; 7];
    for i in 0..7 {
        let index = [i as u8];
        bumps[i] = pda(program, &[b"allocation", &index], &allocations[i * 2])?;
        associated(
            allocations[i * 2].address(),
            mint.address(),
            &allocations[1 + i * 2],
        )?;
        let beneficiary = &payload[32 + i * 32..64 + i * 32];
        if beneficiary == [0; 32]
            || beneficiary == cfg.address().as_ref()
            || beneficiary == mint.address().as_ref()
            || (0..7).any(|j| beneficiary == allocations[j * 2].address().as_ref())
        {
            return Err(ProgramError::InvalidArgument);
        }
    }
    if cfg.owner() == program && cfg.try_borrow()?.iter().any(|x| *x != 0) {
        config(program, cfg, mint)?;
        let d = cfg.try_borrow()?;
        if d[4..36] != payload[..32] || d[80..304] != payload[32..] {
            return Err(ProgramError::InvalidArgument);
        }
        for i in 0..7 {
            allocation(program, &allocations[i * 2], cfg, mint, i as u8)?;
            balance(
                &allocations[1 + i * 2],
                mint.address(),
                allocations[i * 2].address(),
            )?;
        }
        return Ok(());
    }
    let started = clock()?;
    morse_rewards_math::utc_month_anniversary(started, 48)
        .map_err(|_| ProgramError::InvalidArgument)?;
    create(
        program,
        program,
        payer,
        cfg,
        system,
        CONFIG_LEN,
        &[Seed::from(b"token"), Seed::from(&cb)],
    )?;
    create(
        program,
        &TOKEN,
        payer,
        mint,
        system,
        82,
        &[Seed::from(b"mint"), Seed::from(&mb)],
    )?;
    InitializeMint2::new(mint, 6, cfg.address(), None).invoke()?;
    for (i, pair) in allocations.as_chunks_mut::<2>().0.iter_mut().enumerate() {
        let [state, vault] = pair;
        let index = [i as u8];
        let bump = [bumps[i]];
        create(
            program,
            program,
            payer,
            state,
            system,
            ALLOCATION_LEN,
            &[
                Seed::from(b"allocation"),
                Seed::from(&index),
                Seed::from(&bump),
            ],
        )?;
        {
            let mut d = state.try_borrow_mut()?;
            d[..4].copy_from_slice(b"MTA\x01");
            d[4] = i as u8;
            d[8..40].copy_from_slice(cfg.address().as_ref());
            d[40..72].copy_from_slice(&payload[32 + i * 32..64 + i * 32]);
            d[72..80].copy_from_slice(&started.to_le_bytes());
            d[80..88].copy_from_slice(&ALLOCATIONS[i].to_le_bytes());
            d[96..128].copy_from_slice(mint.address().as_ref());
        }
        CreateIdempotent {
            funding_account: payer,
            account: vault,
            wallet: state,
            mint,
            system_program: system,
            token_program: token,
        }
        .invoke()?;
        if balance(vault, mint.address(), state.address())? != 0 {
            return Err(invalid());
        }
        MintToChecked::new(mint, vault, cfg, ALLOCATIONS[i], 6)
            .invoke_signed(&[Signer::from(&[Seed::from(b"token"), Seed::from(&cb)])])?;
        if balance(vault, mint.address(), state.address())? != ALLOCATIONS[i] {
            return Err(invalid());
        }
    }
    if Mint::from_account_view(mint)?.supply() != SUPPLY {
        return Err(invalid());
    }
    SetAuthority::new(mint, cfg, AuthorityType::MintTokens, None)
        .invoke_signed(&[Signer::from(&[Seed::from(b"token"), Seed::from(&cb)])])?;
    locked_mint(mint)?;
    let mut d = cfg.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MTK\x01");
    d[4..36].copy_from_slice(&payload[..32]);
    d[36..68].copy_from_slice(mint.address().as_ref());
    d[68..76].copy_from_slice(&started.to_le_bytes());
    d[80..304].copy_from_slice(&payload[32..]);
    Ok(())
}
pub(crate) fn allocation(
    program: &Address,
    a: &AccountView,
    cfg: &AccountView,
    mint: &AccountView,
    kind: u8,
) -> Result<(i64, u64), ProgramError> {
    owned(program, a, true)?;
    pda(program, &[b"allocation", &[kind]], a)?;
    let d = a.try_borrow()?;
    let c = cfg.try_borrow()?;
    if d.len() != ALLOCATION_LEN
        || &d[..4] != b"MTA\x01"
        || d[4] != kind
        || d[5..8].iter().any(|x| *x != 0)
        || d[8..40] != *cfg.address().as_ref()
        || d[40..72] != c[80 + kind as usize * 32..112 + kind as usize * 32]
        || d[72..80] != c[68..76]
        || d[80..88] != ALLOCATIONS[kind as usize].to_le_bytes()
        || d[96..128] != *mint.address().as_ref()
    {
        return Err(invalid());
    }
    let claimed = u64::from_le_bytes(d[88..96].try_into().unwrap());
    if claimed > ALLOCATIONS[kind as usize] {
        return Err(invalid());
    }
    Ok((i64::from_le_bytes(d[72..80].try_into().unwrap()), claimed))
}
fn claim(program: &Address, accounts: &mut [AccountView], kind: u8) -> ProgramResult {
    let [payer, cfg, state, vault, destination, beneficiary, mint, token, ata, system] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if kind == 4 {
        return Err(ProgramError::InvalidInstructionData);
    }
    config(program, cfg, mint)?;
    token_programs(token, ata, system)?;
    let (started, claimed) = allocation(program, state, cfg, mint, kind)?;
    let bump = [pda(program, &[b"allocation", &[kind]], state)?];
    associated(state.address(), mint.address(), vault)?;
    associated(beneficiary.address(), mint.address(), destination)?;
    {
        let d = state.try_borrow()?;
        if d[40..72] != *beneficiary.address().as_ref()
            || beneficiary.executable()
            || vault.address() == destination.address()
        {
            return Err(invalid());
        }
    }
    let vested = math::vested(kind, started, clock()?)?;
    let due = vested.saturating_sub(claimed);
    if due == 0 {
        return Ok(());
    }
    let before = balance(vault, mint.address(), state.address())?;
    CreateIdempotent {
        funding_account: payer,
        account: destination,
        wallet: beneficiary,
        mint,
        system_program: system,
        token_program: token,
    }
    .invoke()?;
    let target_before = balance(destination, mint.address(), beneficiary.address())?;
    TransferChecked::new(vault, mint, destination, state, due, 6).invoke_signed(&[
        Signer::from(&[
            Seed::from(b"allocation"),
            Seed::from(&[kind]),
            Seed::from(&bump),
        ]),
    ])?;
    if balance(vault, mint.address(), state.address())?
        != before
            .checked_sub(due)
            .ok_or(ProgramError::ArithmeticOverflow)?
        || balance(destination, mint.address(), beneficiary.address())?
            != target_before
                .checked_add(due)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    state.try_borrow_mut()?[88..96].copy_from_slice(&vested.max(claimed).to_le_bytes());
    Ok(())
}

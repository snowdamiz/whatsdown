mod token;
use crate::state::*;
use judge_core::attendance::{ClockHeader, EpochHeader, CLOCK_LEN};
use morse_rewards_math as math;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{clock::Clock, rent::Rent, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_associated_token_account::{instructions::CreateIdempotent, ID as ATA};
use pinocchio_system::instructions::{Allocate, Assign, Transfer};
use pinocchio_token::{
    instructions::TransferChecked,
    state::{Account as TokenAccount, AccountState, Mint},
};
use solana_sha256_hasher::{hash, hashv};
const TOKEN: Address = pinocchio_token::ID;
const STAGE_SECONDS: i64 = 3600;
fn overflow() -> ProgramError {
    ProgramError::ArithmeticOverflow
}
fn add(a: u64, b: u64) -> Result<u64, ProgramError> {
    a.checked_add(b).ok_or_else(overflow)
}
fn err(_: math::MathError) -> ProgramError {
    ProgramError::Custom(1)
}
pub fn validate_instruction(data: &[u8]) -> ProgramResult {
    match data.split_first() {
        Some((0, p)) if p.len() == 72 => Ok(()),
        Some((1 | 14, p)) if p.len() == 8 => Ok(()),
        Some((2, p)) if p.len() == 9 && p[0] <= 1 && u64_at(p, 1) > 0 => Ok(()),
        Some((3, p)) if p.len() == 1 && p[0] <= 2 => Ok(()),
        Some((4..=7, [])) => Ok(()),
        Some((8 | 18, p)) if p.len() == 1 && p[0] < 64 => Ok(()),
        Some((9, p)) if p.len() == 32 && p != [0; 32] => Ok(()),
        Some((10..=11 | 13 | 15..=17 | 19, [])) => Ok(()),
        Some((12, p)) if p.len() == 41 && p[0] <= 1 && u64_at(p, 1) > 0 && p[9..] != [0; 32] => {
            Ok(())
        }
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
pub fn process_instruction(
    program: &Address,
    accounts: &mut [AccountView],
    data: &[u8],
) -> ProgramResult {
    validate_instruction(data)?;
    match data[0] {
        0 => initialize(program, accounts, &data[1..]),
        1 => open(program, accounts, &data[1..]),
        2 => fund(program, accounts, &data[1..]),
        3 => propose_member(program, accounts, data[1]),
        4 => apply_member(program, accounts),
        5 => begin(program, accounts),
        6 => append(program, accounts),
        7 => finalize(program, accounts),
        8 => claim(program, accounts, data[1]),
        9 => propose_governance(program, accounts, &data[1..]),
        10 => apply_governance(program, accounts),
        11 => cancel(program, accounts),
        12 => fund_once(program, accounts, &data[1..]),
        13 => token::activate(program, accounts),
        14 => token::open_token(program, accounts, &data[1..]),
        15 => token::begin_token(program, accounts),
        16 => token::append_token(program, accounts),
        17 => token::finalize_token(program, accounts),
        18 => token::claim_token(program, accounts, data[1]),
        19 => token::cancel_token(program, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
fn owned(p: &Address, a: &AccountView, w: bool) -> ProgramResult {
    if a.owner() != p || a.executable() {
        return Err(ProgramError::InvalidAccountOwner);
    }
    if w && !a.is_writable() {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(())
}
fn pda(p: &Address, seeds: &[&[u8]], a: &AccountView) -> Result<u8, ProgramError> {
    let (key, bump) =
        Address::try_find_program_address(seeds, p).ok_or(ProgramError::InvalidSeeds)?;
    if a.address() != &key {
        return Err(ProgramError::InvalidSeeds);
    }
    Ok(bump)
}
fn now() -> Result<i64, ProgramError> {
    let n = Clock::get()?.unix_timestamp;
    if n <= 0 {
        return Err(ProgramError::InvalidArgument);
    }
    Ok(n)
}
fn epoch() -> Result<u64, ProgramError> {
    Ok((now()? / EPOCH_SECONDS) as u64)
}
fn auth(a: &AccountView, key: &[u8]) -> ProgramResult {
    if !a.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    if a.address().as_ref() != key {
        return Err(ProgramError::InvalidAccountOwner);
    }
    Ok(())
}
fn pool(p: &Address, a: &AccountView, w: bool) -> Result<Pool, ProgramError> {
    owned(p, a, w)?;
    pda(p, &[b"pool"], a)?;
    Pool::parse(&a.try_borrow()?)
}
fn ledger(
    p: &Address,
    a: &AccountView,
    pool: &AccountView,
    w: bool,
) -> Result<Ledger, ProgramError> {
    owned(p, a, w)?;
    let d = a.try_borrow()?;
    let l = Ledger::parse(&d)?;
    if &d[4..36] != pool.address().as_ref() {
        return Err(invalid());
    }
    pda(p, &[b"epoch", &l.epoch.to_le_bytes()], a)?;
    Ok(l)
}
fn create(
    p: &Address,
    payer: &AccountView,
    a: &AccountView,
    system: &AccountView,
    space: usize,
    seeds: &[Seed],
) -> ProgramResult {
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
    Assign {
        account: a,
        owner: p,
    }
    .invoke_signed(&signers)
}
fn token_program(a: &AccountView) -> ProgramResult {
    if a.address() != &TOKEN || !a.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    Ok(())
}
fn mint(a: &AccountView, expected: &[u8]) -> ProgramResult {
    let m = Mint::from_account_view(a)?;
    if a.address().as_ref() != expected
        || a.executable()
        || !m.is_initialized()
        || m.decimals() != 6
    {
        return Err(invalid());
    }
    Ok(())
}
fn associated(owner: &Address, mint: &Address, a: &AccountView) -> ProgramResult {
    pda(&ATA, &[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], a)?;
    Ok(())
}
fn balance(
    a: &AccountView,
    mint: &Address,
    owner: &Address,
    vault: bool,
) -> Result<u64, ProgramError> {
    let t = TokenAccount::from_account_view(a)?;
    if a.executable()
        || !a.is_writable()
        || t.state() != AccountState::Initialized
        || t.is_native()
        || t.mint() != mint
        || t.owner() != owner
        || (vault && (t.has_delegate() || t.has_close_authority()))
    {
        return Err(invalid());
    }
    Ok(t.amount())
}
fn log(p: &Pool, a: &AccountView) -> ProgramResult {
    let judge = Address::from(p.judge);
    owned(&judge, a, false)?;
    let d = a.try_borrow()?;
    if a.address().as_ref() != p.log
        || d.len() != 352
        || &d[..4] != b"MLG\x01"
        || !matches!(d[4], 1 | 2)
        || d[5] > 1
        || d[6] == 0
        || d[6] > 32
        || d[7] != 1
        || d[40..72] != p.log_id
        || d[340..].iter().any(|x| *x != 0)
    {
        return Err(invalid());
    }
    let name = &d[8..8 + d[6] as usize];
    if !name
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        || d[8 + name.len()..40].iter().any(|x| *x != 0)
        || hash(name).as_ref() != p.log_id
    {
        return Err(invalid());
    }
    pda(&judge, &[b"log", name], a)?;
    Ok(())
}
fn clock(p: &Pool, a: &AccountView) -> Result<ClockHeader, ProgramError> {
    let judge = Address::from(p.judge);
    owned(&judge, a, false)?;
    pda(&judge, &[b"attendance", &p.log_id], a)?;
    let d = a.try_borrow()?;
    let c = ClockHeader::parse(&d)?;
    if d.len() != CLOCK_LEN
        || c.log_id != p.log_id
        || c.activated_at != p.started
        || c.first_full_epoch != p.first_epoch
    {
        return Err(invalid());
    }
    Ok(c)
}
fn revision(p: &Pool, a: &AccountView) -> Result<u64, ProgramError> {
    let judge = Address::from(p.judge);
    owned(&judge, a, false)?;
    pda(&judge, &[b"economics", &p.log_id], a)?;
    let d = a.try_borrow()?;
    if d.len() != 192
        || &d[..4] != b"MEC\x01"
        || d[4..36] != p.log_id
        || d[36..68] != p.mint
        || d[165..168].iter().chain(&d[176..]).any(|x| *x != 0)
        || d[164] > 4
        || u64_at(&d, 100) == 0
        || u64_at(&d, 108) == 0
        || i64_at(&d, 116) < 0
    {
        return Err(invalid());
    }
    Ok(u64_at(&d, 168))
}
fn week(p: &Pool, a: &AccountView, e: u64) -> Result<EpochHeader, ProgramError> {
    let judge = Address::from(p.judge);
    owned(&judge, a, false)?;
    pda(
        &judge,
        &[b"attendance-epoch", &p.log_id, &e.to_le_bytes()],
        a,
    )?;
    let w = EpochHeader::parse(&a.try_borrow()?)?;
    if w.log_id != p.log_id || w.epoch != e || !w.sealed || e < p.first_epoch || e >= epoch()? {
        return Err(invalid());
    }
    Ok(w)
}
fn initialize(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [authority, payer, pool_account, vault, executable, programdata, judge, log_account, clock_account, mint_account, token, ata, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let loader = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
    if executable.address() != program
        || !executable.executable()
        || executable.owner() != &loader
        || programdata.owner() != &loader
        || programdata.executable()
        || !judge.executable()
        || judge.address() == program
    {
        return Err(ProgramError::InvalidAccountOwner);
    }
    pda(&loader, &[program.as_ref()], programdata)?;
    {
        let image = executable.try_borrow()?;
        let meta = programdata.try_borrow()?;
        if image.len() != 36
            || image[..4] != 2u32.to_le_bytes()
            || image[4..36] != *programdata.address().as_ref()
            || meta.len() < 45
            || meta[..4] != 3u32.to_le_bytes()
            || meta[12] != 1
        {
            return Err(invalid());
        }
        auth(authority, &meta[13..45])?;
    }
    if payload[..32] == [0; 32] || payload[40..72] == [0; 32] {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log_id = {
        let d = log_account.try_borrow()?;
        if d.len() != 352 {
            return Err(invalid());
        }
        <[u8; 32]>::try_from(&d[40..72]).unwrap()
    };
    let started = i64_at(payload, 32);
    if started <= 0 || started > now()? {
        return Err(ProgramError::InvalidArgument);
    }
    let first = (started / EPOCH_SECONDS) as u64 + 1;
    let p = Pool {
        version: 1,
        governance: payload[..32].try_into().unwrap(),
        judge: *judge.address().as_array(),
        log: *log_account.address().as_array(),
        log_id,
        mint: *mint_account.address().as_array(),
        started,
        first_epoch: first,
        next_epoch: first,
        subsidy: 0,
        carry: 0,
        liabilities: 0,
        accounted: 0,
        active: 0,
        morse_witness: payload[40..72].try_into().unwrap(),
    };
    log(&p, log_account)?;
    clock(&p, clock_account)?;
    mint(mint_account, &p.mint)?;
    token_program(token)?;
    if ata.address() != &ATA || !ata.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    let bump = [pda(program, &[b"pool"], pool_account)?];
    associated(pool_account.address(), mint_account.address(), vault)?;
    create(
        program,
        payer,
        pool_account,
        system,
        POOL_LEN,
        &[Seed::from(b"pool"), Seed::from(&bump)],
    )?;
    CreateIdempotent {
        funding_account: payer,
        account: vault,
        wallet: pool_account,
        mint: mint_account,
        system_program: system,
        token_program: token,
    }
    .invoke()?;
    balance(vault, mint_account.address(), pool_account.address(), true)?;
    let mut d = pool_account.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MRP\x01");
    d[4..36].copy_from_slice(&p.governance);
    d[36..68].copy_from_slice(&p.judge);
    d[68..100].copy_from_slice(&p.log);
    d[100..132].copy_from_slice(&p.log_id);
    d[132..164].copy_from_slice(&p.mint);
    d[164..172].copy_from_slice(&started.to_le_bytes());
    put64(&mut d, 172, first);
    put64(&mut d, 180, first);
    d[268..300].copy_from_slice(&p.morse_witness);
    Ok(())
}
fn open(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [payer, pool_account, epoch_account, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, false)?;
    let e = u64_at(payload, 0);
    if e < p.next_epoch || e > epoch()? {
        return Err(ProgramError::InvalidArgument);
    }
    let eb = e.to_le_bytes();
    let bump = [pda(program, &[b"epoch", &eb], epoch_account)?];
    if epoch_account.owner() == program {
        let l = ledger(program, epoch_account, pool_account, false)?;
        if l.epoch != e {
            return Err(invalid());
        }
        return Ok(());
    }
    create(
        program,
        payer,
        epoch_account,
        system,
        LEDGER_LEN,
        &[Seed::from(b"epoch"), Seed::from(&eb), Seed::from(&bump)],
    )?;
    let mut d = epoch_account.try_borrow_mut()?;
    d[..3].copy_from_slice(b"MRE");
    d[3] = p.version;
    d[4..36].copy_from_slice(pool_account.address().as_ref());
    put64(&mut d, 36, e);
    Ok(())
}
fn fund(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [funder, pool_account, epoch_account, vault, source, mint_account, token] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    let l = ledger(program, epoch_account, pool_account, true)?;
    if l.epoch != epoch()? || l.status != 0 || source.address() == vault.address() {
        return Err(ProgramError::InvalidArgument);
    }
    auth(funder, funder.address().as_ref())?;
    mint(mint_account, &p.mint)?;
    token_program(token)?;
    associated(pool_account.address(), mint_account.address(), vault)?;
    if balance(vault, mint_account.address(), pool_account.address(), true)? < p.accounted {
        return Err(invalid());
    }
    balance(source, mint_account.address(), funder.address(), false)?;
    let amount = u64_at(payload, 1);
    let accounted = add(p.accounted, amount)?;
    let value = add(
        if payload[0] == 0 {
            l.revenue
        } else {
            p.subsidy
        },
        amount,
    )?;
    TransferChecked::new(source, mint_account, vault, funder, amount, 6).invoke()?;
    put64(&mut pool_account.try_borrow_mut()?, 212, accounted);
    if payload[0] == 0 {
        put64(&mut epoch_account.try_borrow_mut()?, 44, value)
    } else {
        put64(&mut pool_account.try_borrow_mut()?, 188, value)
    }
    Ok(())
}
fn propose_member(program: &Address, accounts: &mut [AccountView], status: u8) -> ProgramResult {
    let [governance, payer, pool_account, witness, member_account, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, false)?;
    auth(governance, &p.governance)?;
    validate_witness(&p, witness)?;
    if status == 1 && witness.address().as_ref() == p.morse_witness {
        return Err(ProgramError::InvalidArgument);
    }
    let bump = [pda(
        program,
        &[b"member", witness.address().as_ref()],
        member_account,
    )?];
    if member_account.owner() != program {
        create(
            program,
            payer,
            member_account,
            system,
            MEMBER_LEN,
            &[
                Seed::from(b"member"),
                Seed::from(witness.address().as_ref()),
                Seed::from(&bump),
            ],
        )?;
        let mut d = member_account.try_borrow_mut()?;
        d[..4].copy_from_slice(b"MRM\x01");
        d[4..36].copy_from_slice(witness.address().as_ref());
    }
    owned(program, member_account, true)?;
    let m = Member::parse(&member_account.try_borrow()?)?;
    if m.witness != *witness.address().as_array() || (m.status == 2 && status != 2) {
        return Err(ProgramError::InvalidArgument);
    }
    let ready = now()?.checked_add(TIMELOCK_SECONDS).ok_or_else(overflow)?;
    let mut d = member_account.try_borrow_mut()?;
    d[37] = status;
    d[40..48].copy_from_slice(&ready.to_le_bytes());
    Ok(())
}
fn apply_member(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [pool_account, member_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, false)?;
    owned(program, member_account, true)?;
    let m = Member::parse(&member_account.try_borrow()?)?;
    pda(program, &[b"member", &m.witness], member_account)?;
    if p.active != 0
        || m.ready == 0
        || now()? < m.ready
        || (m.pending == 1 && m.witness == p.morse_witness)
    {
        return Err(ProgramError::InvalidArgument);
    }
    let mut d = member_account.try_borrow_mut()?;
    d[36] = m.pending;
    d[37] = 0;
    put64(&mut d, 40, 0);
    d[48..56].copy_from_slice(&now()?.to_le_bytes());
    Ok(())
}
fn context(
    program: &Address,
    pool_account: &AccountView,
    epoch_account: &AccountView,
    log_account: &AccountView,
    clock_account: &AccountView,
    week_account: &AccountView,
    economy: &AccountView,
) -> Result<(Pool, Ledger, EpochHeader, u64), ProgramError> {
    let p = pool(program, pool_account, true)?;
    let l = ledger(program, epoch_account, pool_account, true)?;
    log(&p, log_account)?;
    clock(&p, clock_account)?;
    let w = week(&p, week_account, l.epoch)?;
    if p.version != 1 || l.version != 1 {
        return Err(ProgramError::InvalidArgument);
    }
    let rev = revision(&p, economy)?;
    if l.epoch != p.next_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    Ok((p, l, w, rev))
}
fn begin(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [pool_account, epoch_account, log_account, clock_account, week_account, economy] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (p, l, w, rev) = context(
        program,
        pool_account,
        epoch_account,
        log_account,
        clock_account,
        week_account,
        economy,
    )?;
    if l.status != 0 || p.active != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let start = i64::try_from(l.epoch)
        .map_err(|_| overflow())?
        .checked_mul(EPOCH_SECONDS)
        .ok_or_else(overflow)?;
    let base = math::first_year_floor(
        p.started,
        start,
        start.checked_add(EPOCH_SECONDS).ok_or_else(overflow)?,
    )
    .map_err(err)?;
    let digest = hash(&week_account.try_borrow()?);
    let mut d = epoch_account.try_borrow_mut()?;
    d[52] = 1;
    d[54] = w.witnesses as u8;
    d[56..88].copy_from_slice(digest.as_ref());
    put64(&mut d, 88, w.posts);
    put64(&mut d, 120, base);
    put64(&mut d, 128, add(p.carry, l.revenue)?);
    d[168..176].copy_from_slice(&now()?.to_le_bytes());
    put64(&mut d, 176, rev);
    put64(&mut pool_account.try_borrow_mut()?, 220, add(l.epoch, 1)?);
    Ok(())
}
fn collecting(
    program: &Address,
    pool_account: &AccountView,
    epoch_account: &AccountView,
    log_account: &AccountView,
    clock_account: &AccountView,
    week_account: &AccountView,
    economy: &AccountView,
) -> Result<(Pool, Ledger), ProgramError> {
    let (p, l, _, rev) = context(
        program,
        pool_account,
        epoch_account,
        log_account,
        clock_account,
        week_account,
        economy,
    )?;
    if l.status != 1
        || p.active != add(l.epoch, 1)?
        || rev != l.revision
        || now()?
            >= i64_at(&epoch_account.try_borrow()?, 168)
                .checked_add(STAGE_SECONDS)
                .ok_or_else(overflow)?
        || epoch_account.try_borrow()?[56..88] != *hash(&week_account.try_borrow()?).as_ref()
    {
        return Err(ProgramError::InvalidArgument);
    }
    Ok((p, l))
}
fn validate_witness(p: &Pool, a: &AccountView) -> Result<[u8; 32], ProgramError> {
    let judge = Address::from(p.judge);
    owned(&judge, a, false)?;
    let d = a.try_borrow()?;
    if d.len() != 320
        || &d[..4] != b"MWI\x01"
        || d[4] == 0
        || d[4] > 64
        || d[5] > 4
        || d[6] > 1
        || d[7] != 0
        || d[200..232] != p.log_id
        || d[272..].iter().any(|x| *x != 0)
    {
        return Err(invalid());
    }
    let id = &d[8..8 + d[4] as usize];
    if !id
        .iter()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        || d[8 + id.len()..72].iter().any(|x| *x != 0)
        || d[72..104] == [0; 32]
        || d[104..136] == [0; 32]
        || d[136..168] == [0; 32]
    {
        return Err(invalid());
    }
    let identity = hashv(&[
        b"morse-witness-record-v1",
        &[id.len() as u8],
        id,
        &d[72..104],
    ])
    .to_bytes();
    pda(&judge, &[b"witness", &p.log_id, &identity], a)?;
    Ok(identity)
}
fn admitted(
    program: &Address,
    p: &Pool,
    witness: &AccountView,
    member: &AccountView,
    start: i64,
) -> Result<bool, ProgramError> {
    pda(program, &[b"member", witness.address().as_ref()], member)?;
    if member.owner() == &pinocchio_system::ID && member.data_len() == 0 && !member.executable() {
        return Ok(false);
    }
    owned(program, member, false)?;
    let m = Member::parse(&member.try_borrow()?)?;
    if m.witness != *witness.address().as_array() {
        return Err(invalid());
    }
    Ok(m.status == 1 && m.effective <= start && m.witness != p.morse_witness)
}
fn append(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    if accounts.len() < 9 || !(accounts.len() - 6).is_multiple_of(3) {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (pool_account, rest) = accounts.split_first_mut().unwrap();
    let (epoch_account, rest) = rest.split_first_mut().unwrap();
    let (log_account, rest) = rest.split_first().unwrap();
    let (clock_account, rest) = rest.split_first().unwrap();
    let (week_account, rest) = rest.split_first().unwrap();
    let (economy, rows) = rest.split_first().unwrap();
    let (p, l) = collecting(
        program,
        pool_account,
        epoch_account,
        log_account,
        clock_account,
        week_account,
        economy,
    )?;
    let count = rows.len() / 3;
    if l.count as usize + count > l.expected as usize {
        return Err(ProgramError::InvalidArgument);
    }
    let start = i64::try_from(l.epoch)
        .map_err(|_| overflow())?
        .checked_mul(EPOCH_SECONDS)
        .ok_or_else(overflow)?;
    let judge = Address::from(p.judge);
    let mut total_weight = l.weight;
    let mut floors = l.floors;
    for (offset, chunk) in rows.as_chunks::<3>().0.iter().enumerate() {
        let [witness, bond, member] = chunk;
        let n = l.count as usize + offset;
        let signed = {
            let d = week_account.try_borrow()?;
            let o = 80 + n * 40;
            if &d[o..o + 32] != witness.address().as_ref() {
                return Err(invalid());
            }
            u64_at(&d, o + 32)
        };
        let identity = validate_witness(&p, witness)?;
        pda(&judge, &[b"bond", &p.log_id, &identity], bond)?;
        let outside = admitted(program, &p, witness, member, start)?;
        let w = witness.try_borrow()?;
        let eligible = if bond.owner() == &pinocchio_system::ID
            && bond.data_len() == 0
            && !bond.executable()
        {
            if w[5] != 0 || w[232..272].iter().any(|x| *x != 0) {
                return Err(invalid());
            }
            false
        } else {
            owned(&judge, bond, false)?;
            let b = bond.try_borrow()?;
            if b.len() != 208
                || &b[..4] != b"MBD\x01"
                || b[4] > 4
                || b[5] != 1
                || b[6..8].iter().chain(&b[200..]).any(|x| *x != 0)
                || b[8..40] != p.log_id
                || &b[40..72] != witness.address().as_ref()
                || b[72..104] != w[104..136]
                || b[104..136] != p.mint
                || b[136..168] != w[232..264]
                || b[4] != w[5]
            {
                return Err(invalid());
            }
            let vault = Address::find_program_address(
                &[bond.address().as_ref(), TOKEN.as_ref(), &p.mint],
                &ATA,
            )
            .0;
            if b[136..168] != *vault.as_ref() {
                return Err(invalid());
            }
            w[5] == 1
                && w[6] == 0
                && u64_at(&b, 168) > 0
                && i64_at(&b, 176) > 0
                && i64_at(&b, 176) <= start
                && i64_at(&b, 184) == 0
                && i64_at(&b, 192) == 0
                && outside
        };
        let weight = if eligible {
            math::attendance_weight(signed, l.posts).map_err(err)?
        } else {
            0
        };
        let floor = math::scaled_floor(l.base, weight, l.posts).map_err(err)?;
        total_weight = total_weight.checked_add(weight).ok_or_else(overflow)?;
        floors = add(floors, floor)?;
        let mut d = epoch_account.try_borrow_mut()?;
        let o = LEDGER_HEADER + n * ROW_LEN;
        d[o..o + 32].copy_from_slice(witness.address().as_ref());
        d[o + 32..o + 64].copy_from_slice(&w[136..168]);
        d[o + 64..o + 96].copy_from_slice(bond.address().as_ref());
        put128(&mut d, o + 96, weight);
        put64(&mut d, o + 112, floor);
    }
    let mut d = epoch_account.try_borrow_mut()?;
    d[53] = l.count + count as u8;
    put128(&mut d, 96, total_weight);
    put64(&mut d, 112, floors);
    Ok(())
}
fn finalize(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [pool_account, epoch_account, log_account, clock_account, week_account, economy] = accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let (p, l) = collecting(
        program,
        pool_account,
        epoch_account,
        log_account,
        clock_account,
        week_account,
        economy,
    )?;
    if l.count != l.expected {
        return Err(ProgramError::InvalidArgument);
    }
    let available = add(p.carry, l.revenue)?;
    let funding = math::reserve_floor(available, p.subsidy, l.floors).map_err(err)?;
    let mut allocated = 0u64;
    // Two passes operate directly on account data; no 64-row SBF stack allocation.
    {
        let mut d = epoch_account.try_borrow_mut()?;
        for n in 0..l.count as usize {
            let o = LEDGER_HEADER + n * ROW_LEN;
            let weight = u128_at(&d, o + 96);
            let amount = if l.weight == 0 {
                0
            } else {
                math::allocation(funding.remainder, weight, l.weight, u64_at(&d, o + 112))
                    .map_err(err)?
            };
            put64(&mut d, o + 120, amount);
            allocated = add(allocated, amount)?;
        }
    }
    let carry = add(available, funding.subsidy_used)?
        .checked_sub(allocated)
        .ok_or_else(overflow)?;
    let liabilities = add(p.liabilities, allocated)?;
    {
        let mut d = pool_account.try_borrow_mut()?;
        put64(&mut d, 188, p.subsidy - funding.subsidy_used);
        put64(&mut d, 196, carry);
        put64(&mut d, 204, liabilities);
        put64(&mut d, 180, add(p.next_epoch, 1)?);
        put64(&mut d, 220, 0);
    }
    let mut d = epoch_account.try_borrow_mut()?;
    d[52] = 2;
    put64(&mut d, 136, funding.subsidy_used);
    put64(&mut d, 144, allocated);
    put64(&mut d, 152, carry);
    Ok(())
}
fn claim(program: &Address, accounts: &mut [AccountView], row: u8) -> ProgramResult {
    let [pool_account, epoch_account, vault, destination, mint_account, token] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    let l = ledger(program, epoch_account, pool_account, true)?;
    let (amount, payout, claimed) = {
        let d = epoch_account.try_borrow()?;
        if l.status != 2 || row >= l.count {
            return Err(ProgramError::InvalidArgument);
        }
        let o = LEDGER_HEADER + row as usize * ROW_LEN;
        (
            u64_at(&d, o + 120),
            Address::from(<[u8; 32]>::try_from(&d[o + 32..o + 64]).unwrap()),
            u64_at(&d, 160),
        )
    };
    if claimed & (1u64 << row) != 0 || amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    mint(mint_account, &p.mint)?;
    token_program(token)?;
    associated(pool_account.address(), mint_account.address(), vault)?;
    associated(&payout, mint_account.address(), destination)?;
    if destination.address() == vault.address()
        || balance(vault, mint_account.address(), pool_account.address(), true)? < p.accounted
    {
        return Err(invalid());
    }
    balance(destination, mint_account.address(), &payout, false)?;
    let liabilities = p.liabilities.checked_sub(amount).ok_or_else(overflow)?;
    let accounted = p.accounted.checked_sub(amount).ok_or_else(overflow)?;
    let bump = [pda(program, &[b"pool"], pool_account)?];
    let seeds = [Seed::from(b"pool"), Seed::from(&bump)];
    TransferChecked::new(vault, mint_account, destination, pool_account, amount, 6)
        .invoke_signed(&[Signer::from(&seeds)])?;
    put64(
        &mut epoch_account.try_borrow_mut()?,
        160,
        claimed | (1u64 << row),
    );
    let mut d = pool_account.try_borrow_mut()?;
    put64(&mut d, 204, liabilities);
    put64(&mut d, 212, accounted);
    Ok(())
}
fn cancel(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [pool_account, epoch_account, economy] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    let l = ledger(program, epoch_account, pool_account, true)?;
    if l.status != 1
        || p.active != add(l.epoch, 1)?
        || (revision(&p, economy)? == l.revision
            && now()?
                < i64_at(&epoch_account.try_borrow()?, 168)
                    .checked_add(STAGE_SECONDS)
                    .ok_or_else(overflow)?)
    {
        return Err(ProgramError::InvalidArgument);
    }
    epoch_account.try_borrow_mut()?[52..].fill(0);
    put64(&mut pool_account.try_borrow_mut()?, 220, 0);
    Ok(())
}
fn propose_governance(
    program: &Address,
    accounts: &mut [AccountView],
    next: &[u8],
) -> ProgramResult {
    let [governance, pool_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    auth(governance, &p.governance)?;
    let ready = now()?.checked_add(TIMELOCK_SECONDS).ok_or_else(overflow)?;
    let mut d = pool_account.try_borrow_mut()?;
    d[228..260].copy_from_slice(next);
    d[260..268].copy_from_slice(&ready.to_le_bytes());
    Ok(())
}
fn apply_governance(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [pool_account] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    let mut d = pool_account.try_borrow_mut()?;
    let ready = i64_at(&d, 260);
    if p.active != 0 || ready == 0 || now()? < ready {
        return Err(ProgramError::InvalidArgument);
    }
    let next: [u8; 32] = d[228..260].try_into().unwrap();
    d[4..36].copy_from_slice(&next);
    d[228..268].fill(0);
    Ok(())
}

fn fund_once(program: &Address, accounts: &mut [AccountView], payload: &[u8]) -> ProgramResult {
    let [funder, payer, pool_account, epoch_account, vault, source, mint_account, token, receipt, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    let l = ledger(program, epoch_account, pool_account, true)?;
    auth(funder, funder.address().as_ref())?;
    auth(payer, payer.address().as_ref())?;
    if !payer.is_writable() || source.address() == vault.address() {
        return Err(ProgramError::InvalidArgument);
    }
    mint(mint_account, &p.mint)?;
    token_program(token)?;
    associated(pool_account.address(), mint_account.address(), vault)?;
    let id = &payload[9..41];
    let amount = u64_at(payload, 1);
    let bump = [pda(
        program,
        &[b"funding", funder.address().as_ref(), id],
        receipt,
    )?];
    if receipt.owner() == program {
        owned(program, receipt, true)?;
        let r = FundingReceipt::parse(&receipt.try_borrow()?)?;
        if r.pool != *pool_account.address().as_array()
            || r.funder != *funder.address().as_array()
            || r.operation != id
            || r.epoch != l.epoch
            || r.kind != payload[0]
            || r.amount != amount
            || r.source != *source.address().as_array()
            || r.mint != p.mint
        {
            return Err(ProgramError::InvalidArgument);
        }
        // A durable exact-intent match is authoritative even after blockhash
        // expiry, epoch rollover, source closure, settlement, or later claims.
        return Ok(());
    }
    if l.epoch != epoch()? || l.status != 0 {
        return Err(ProgramError::InvalidArgument);
    }
    if balance(vault, mint_account.address(), pool_account.address(), true)? < p.accounted {
        return Err(invalid());
    }
    balance(source, mint_account.address(), funder.address(), false)?;
    let accounted = add(p.accounted, amount)?;
    let value = add(
        if payload[0] == 0 {
            l.revenue
        } else {
            p.subsidy
        },
        amount,
    )?;
    let funded_at = now()?;
    create(
        program,
        payer,
        receipt,
        system,
        FUNDING_LEN,
        &[
            Seed::from(b"funding"),
            Seed::from(funder.address().as_ref()),
            Seed::from(id),
            Seed::from(&bump),
        ],
    )?;
    TransferChecked::new(source, mint_account, vault, funder, amount, 6).invoke()?;
    put64(&mut pool_account.try_borrow_mut()?, 212, accounted);
    if payload[0] == 0 {
        put64(&mut epoch_account.try_borrow_mut()?, 44, value)
    } else {
        put64(&mut pool_account.try_borrow_mut()?, 188, value)
    }
    let mut d = receipt.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MRF\x01");
    d[4..36].copy_from_slice(pool_account.address().as_ref());
    d[36..68].copy_from_slice(funder.address().as_ref());
    d[68..100].copy_from_slice(id);
    put64(&mut d, 100, l.epoch);
    d[108] = payload[0];
    put64(&mut d, 112, amount);
    d[120..152].copy_from_slice(source.address().as_ref());
    d[152..184].copy_from_slice(mint_account.address().as_ref());
    d[184..192].copy_from_slice(&funded_at.to_le_bytes());
    Ok(())
}

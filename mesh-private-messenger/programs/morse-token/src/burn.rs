//! Bounded weekly burn custody; approved single-hop CPI never receives the week vault.
pub mod carry;
pub mod expiry;
use crate::processor::{config, create, owned, pda};
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use pinocchio_associated_token_account::{instructions::CreateIdempotent, ID as ATA};
use pinocchio_token::{
    instructions::TransferChecked,
    state::{Account as TokenAccount, AccountState, Mint},
    ID as TOKEN,
};
use solana_sha256_hasher::{hash, hashv};
pub const CONFIG_LEN: usize = 320;
pub const WEEK_HEADER: usize = 256;
pub const CHUNK_LEN: usize = 80;
pub const CHUNKS: usize = 24;
pub const WEEK_LEN: usize = WEEK_HEADER + CHUNKS * CHUNK_LEN;
pub const WEEK_SECONDS: u64 = 604800;
pub const JUPITER: Address = Address::from_str_const("JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4");
pub const RAYDIUM: Address =
    Address::from_str_const("CPMMoo8L3F4NbTegBCKVNunggL7H1ZpdTHKxQB5qKP1C");
const LOADER: Address = Address::from_str_const("BPFLoaderUpgradeab1e11111111111111111111111");
fn invalid() -> ProgramError {
    ProgramError::InvalidAccountData
}
fn wide(d: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(d[at..at + 8].try_into().unwrap())
}
fn address(d: &[u8], at: usize) -> Address {
    Address::new_from_array(d[at..at + 32].try_into().unwrap())
}
fn now() -> Result<i64, ProgramError> {
    let time = Clock::get()?.unix_timestamp;
    if time <= 0 {
        Err(ProgramError::InvalidArgument)
    } else {
        Ok(time)
    }
}
fn associated(owner: &Address, mint: &Address, a: &AccountView) -> ProgramResult {
    pda(&ATA, &[owner.as_ref(), TOKEN.as_ref(), mint.as_ref()], a)?;
    Ok(())
}
fn mint(a: &AccountView) -> ProgramResult {
    owned(&TOKEN, a, false)?;
    if a.data_len() != 82 {
        return Err(invalid());
    }
    let m = Mint::from_account_view(a)?;
    if !m.is_initialized() || m.decimals() != 6 {
        return Err(invalid());
    }
    Ok(())
}
fn balance(
    a: &AccountView,
    mint: &Address,
    owner: &Address,
    writable: bool,
) -> Result<u64, ProgramError> {
    owned(&TOKEN, a, writable)?;
    if a.data_len() != 165 {
        return Err(invalid());
    }
    let s = TokenAccount::from_account_view(a)?;
    if s.mint() != mint
        || s.owner() != owner
        || s.state() != AccountState::Initialized
        || s.is_native()
        || s.has_delegate()
        || s.has_close_authority()
    {
        return Err(invalid());
    }
    Ok(s.amount())
}
fn program_slot(
    expected: &Address,
    executable: &AccountView,
    data: &AccountView,
) -> Result<u64, ProgramError> {
    if executable.address() != expected
        || !executable.executable()
        || executable.owner() != &LOADER
        || data.owner() != &LOADER
        || data.executable()
    {
        return Err(invalid());
    }
    pda(&LOADER, &[expected.as_ref()], data)?;
    let image = executable.try_borrow()?;
    let d = data.try_borrow()?;
    if image.len() != 36
        || image[..4] != 2u32.to_le_bytes()
        || image[4..36] != *data.address().as_ref()
        || d.len() < 45
        || d[..4] != 3u32.to_le_bytes()
        || d[12] > 1
    {
        return Err(invalid());
    }
    Ok(wide(&d, 4))
}
struct Profile {
    usdc: Address,
    treasury: Address,
    pool: Address,
    amm: Address,
    vault0: Address,
    vault1: Address,
    observation: Address,
    jupiter_slot: u64,
    raydium_slot: u64,
    ready: i64,
    amm_hash: [u8; 32],
}
fn profile(
    program: &Address,
    cfg: &AccountView,
    morse: &AccountView,
    a: &AccountView,
) -> Result<Profile, ProgramError> {
    config(program, cfg, morse)?;
    owned(program, a, false)?;
    pda(program, &[b"swap"], a)?;
    let d = a.try_borrow()?;
    if d.len() != CONFIG_LEN
        || &d[..4] != b"MTS\x01"
        || d[4..36] != *cfg.address().as_ref()
        || d[36..260].as_chunks::<32>().0.contains(&[0; 32])
        || d[316..].iter().any(|v| *v != 0)
    {
        return Err(invalid());
    }
    let ready = i64::from_le_bytes(d[276..284].try_into().unwrap());
    if ready <= 0 {
        return Err(invalid());
    }
    Ok(Profile {
        usdc: address(&d, 36),
        treasury: address(&d, 68),
        pool: address(&d, 100),
        amm: address(&d, 132),
        vault0: address(&d, 164),
        vault1: address(&d, 196),
        observation: address(&d, 228),
        jupiter_slot: wide(&d, 260),
        raydium_slot: wide(&d, 268),
        ready,
        amm_hash: d[284..316].try_into().unwrap(),
    })
}
fn code(
    p: &Profile,
    jupiter: &AccountView,
    jupiter_data: &AccountView,
    raydium: &AccountView,
    raydium_data: &AccountView,
) -> ProgramResult {
    if program_slot(&JUPITER, jupiter, jupiter_data)? != p.jupiter_slot
        || program_slot(&RAYDIUM, raydium, raydium_data)? != p.raydium_slot
    {
        return Err(invalid());
    }
    Ok(())
}
fn pool(
    morse: &Address,
    usdc: &Address,
    state: &AccountView,
    amm: &AccountView,
    vault0: &AccountView,
    vault1: &AccountView,
    observation: &AccountView,
) -> Result<[u8; 32], ProgramError> {
    owned(&RAYDIUM, state, false)?;
    owned(&RAYDIUM, amm, false)?;
    owned(&RAYDIUM, observation, false)?;
    let d = state.try_borrow()?;
    let c = amm.try_borrow()?;
    let o = observation.try_borrow()?;
    if d.len() != 637
        || d[..8] != hash(b"account:PoolState").to_bytes()[..8]
        || c.len() != 236
        || c[..8] != hash(b"account:AmmConfig").to_bytes()[..8]
        || o.len() != 4075
        || o[..8] != hash(b"account:ObservationState").to_bytes()[..8]
        || d[8..40] != *amm.address().as_ref()
        || d[72..104] != *vault0.address().as_ref()
        || d[104..136] != *vault1.address().as_ref()
        || d[296..328] != *observation.address().as_ref()
        || d[232..264] != *TOKEN.as_ref()
        || d[264..296] != *TOKEN.as_ref()
        || d[331] != 6
        || d[332] != 6
        || d[329] & 4 != 0
    {
        return Err(invalid());
    }
    let m0 = address(&d, 168);
    let m1 = address(&d, 200);
    if !((m0 == *morse && m1 == *usdc) || (m0 == *usdc && m1 == *morse)) {
        return Err(invalid());
    }
    pda(
        &RAYDIUM,
        &[b"pool", amm.address().as_ref(), m0.as_ref(), m1.as_ref()],
        state,
    )?;
    pda(
        &RAYDIUM,
        &[b"pool_vault", state.address().as_ref(), m0.as_ref()],
        vault0,
    )?;
    pda(
        &RAYDIUM,
        &[b"pool_vault", state.address().as_ref(), m1.as_ref()],
        vault1,
    )?;
    pda(
        &RAYDIUM,
        &[b"observation", state.address().as_ref()],
        observation,
    )?;
    let index = u16::from_le_bytes(c[10..12].try_into().unwrap()).to_be_bytes();
    pda(&RAYDIUM, &[b"amm_config", &index], amm)?;
    let authority = Address::try_find_program_address(&[b"vault_and_lp_mint_auth_seed"], &RAYDIUM)
        .ok_or(ProgramError::InvalidSeeds)?
        .0;
    balance(vault0, &m0, &authority, false)?;
    balance(vault1, &m1, &authority, false)?;
    if wide(&c, 12)
        .checked_add(wide(&c, 108))
        .ok_or(ProgramError::ArithmeticOverflow)?
        > 10000
        || wide(&c, 20)
            .checked_add(wide(&c, 28))
            .ok_or(ProgramError::ArithmeticOverflow)?
            > 1_000_000
        || wide(&c, 116) > 1_000_000
    {
        return Err(invalid());
    }
    Ok(hash(&c).to_bytes())
}
pub(crate) fn initialize(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [gov, payer, cfg, morse, a, usdc, treasury, state, amm, vault0, vault1, observation, jupiter, jupiter_data, raydium, raydium_data, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    config(program, cfg, morse)?;
    {
        let d = cfg.try_borrow()?;
        if !gov.is_signer() || d[4..36] != *gov.address().as_ref() {
            return Err(ProgramError::MissingRequiredSignature);
        }
    }
    mint(usdc)?;
    if usdc.address() == morse.address()
        || treasury.address().as_ref() == [0; 32]
        || treasury.executable()
    {
        return Err(invalid());
    }
    let hash = pool(
        morse.address(),
        usdc.address(),
        state,
        amm,
        vault0,
        vault1,
        observation,
    )?;
    let jslot = program_slot(&JUPITER, jupiter, jupiter_data)?;
    let rslot = program_slot(&RAYDIUM, raydium, raydium_data)?;
    let bump = [pda(program, &[b"swap"], a)?];
    if a.owner() == program {
        let p = profile(program, cfg, morse, a)?;
        if p.usdc != *usdc.address()
            || p.treasury != *treasury.address()
            || p.pool != *state.address()
            || p.amm != *amm.address()
            || p.vault0 != *vault0.address()
            || p.vault1 != *vault1.address()
            || p.observation != *observation.address()
            || p.jupiter_slot != jslot
            || p.raydium_slot != rslot
            || p.amm_hash != hash
        {
            return Err(invalid());
        }
        return Ok(());
    }
    let ready = now()?
        .checked_add(14 * 86400)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    create(
        program,
        program,
        payer,
        a,
        system,
        CONFIG_LEN,
        &[Seed::from(b"swap"), Seed::from(&bump)],
    )?;
    let mut d = a.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MTS\x01");
    for (at, key) in [
        (4, cfg.address()),
        (36, usdc.address()),
        (68, treasury.address()),
        (100, state.address()),
        (132, amm.address()),
        (164, vault0.address()),
        (196, vault1.address()),
        (228, observation.address()),
    ] {
        d[at..at + 32].copy_from_slice(key.as_ref());
    }
    d[260..268].copy_from_slice(&jslot.to_le_bytes());
    d[268..276].copy_from_slice(&rslot.to_le_bytes());
    d[276..284].copy_from_slice(&ready.to_le_bytes());
    d[284..316].copy_from_slice(&hash);
    Ok(())
}
struct Week {
    epoch: u64,
    budget: u64,
    spent: u64,
    header: usize,
}
fn week(d: &[u8]) -> Result<Week, ProgramError> {
    parse_week(d, false)
}
fn parse_week(d: &[u8], closed: bool) -> Result<Week, ProgramError> {
    let header = match (d.get(..4), d.len(), closed) {
        (Some(b"MTW\x01"), WEEK_LEN, false) | (Some(b"MTC\x01"), WEEK_LEN, true) => WEEK_HEADER,
        (Some(b"MTW\x02"), carry::WEEK_V2_LEN, false)
        | (Some(b"MTC\x02"), carry::WEEK_V2_LEN, true) => carry::WEEK_V2_HEADER,
        _ => return Err(invalid()),
    };
    if d[52] != if closed { 2 } else { 1 }
        || d[53..56].iter().chain(&d[248..256]).any(|v| *v != 0)
        || d[4..36] == [0; 32]
        || d[64..224].as_chunks::<32>().0.contains(&[0; 32])
        || wide(d, 56) == 0
    {
        return Err(invalid());
    }
    let epoch = wide(d, 36);
    let budget = wide(d, 44);
    if header == carry::WEEK_V2_HEADER
        && (wide(d, 256).checked_add(wide(d, 264)) != Some(budget)
            || d[272..304] == [0; 32]
            || d[304..320].iter().any(|v| *v != 0))
    {
        return Err(invalid());
    }
    let start = epoch.checked_mul(WEEK_SECONDS).ok_or(invalid())?;
    let end = start.checked_add(WEEK_SECONDS).ok_or(invalid())?;
    let mask = wide(d, 224);
    if end > i64::MAX as u64 || budget < CHUNKS as u64 || mask >> CHUNKS != 0 {
        return Err(invalid());
    }
    let mut total = 0u64;
    let mut spent = 0u64;
    let mut burned = 0u64;
    for i in 0..CHUNKS {
        let r = &d[header + i * CHUNK_LEN..header + (i + 1) * CHUNK_LEN];
        let amount = wide(r, 0);
        let begin = start + i as u64 * WEEK_SECONDS / CHUNKS as u64;
        let end = start + (i + 1) as u64 * WEEK_SECONDS / CHUNKS as u64;
        if amount == 0
            || wide(r, 8) != begin
            || wide(r, 16) != end
            || wide(r, 24) < begin
            || wide(r, 24) >= end
            || r[72..80].iter().any(|v| *v != 0)
        {
            return Err(invalid());
        }
        total = total.checked_add(amount).ok_or(invalid())?;
        if mask & (1 << i) != 0 {
            if wide(r, 32) == 0 || r[40..72] == [0; 32] {
                return Err(invalid());
            }
            spent = spent.checked_add(amount).ok_or(invalid())?;
            burned = burned.checked_add(wide(r, 32)).ok_or(invalid())?;
        } else if r[32..72].iter().any(|v| *v != 0) {
            return Err(invalid());
        }
    }
    if total != budget || spent != wide(d, 232) || burned != wide(d, 240) || burned > crate::SUPPLY
    {
        return Err(invalid());
    }
    Ok(Week {
        epoch,
        budget,
        spent,
        header,
    })
}
pub(crate) fn open(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [funder, payer, cfg, morse, swap, usdc, a, vault, source, token, ata, system, jupiter, jupiter_data, raydium, raydium_data, oracle] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = profile(program, cfg, morse, swap)?;
    mint(usdc)?;
    if usdc.address() != &p.usdc
        || funder.address() != &p.treasury
        || !funder.is_signer()
        || token.address() != &TOKEN
        || !token.executable()
        || ata.address() != &ATA
        || !ata.executable()
    {
        return Err(invalid());
    }
    let epoch = wide(payload, 0);
    let budget = wide(payload, 8);
    let bump = [pda(program, &[b"burn-week", &epoch.to_le_bytes()], a)?];
    associated(a.address(), usdc.address(), vault)?;
    associated(funder.address(), usdc.address(), source)?;
    let intent = hashv(&[b"morse-burn-week-v1", swap.address().as_ref(), payload]).to_bytes();
    if a.owner() == program {
        owned(program, a, false)?;
        let d = a.try_borrow()?;
        let w = week(&d)?;
        if w.header != WEEK_HEADER
            || w.epoch != epoch
            || w.budget != budget
            || d[4..36] != *swap.address().as_ref()
            || d[64..96] != *usdc.address().as_ref()
            || d[96..128] != *funder.address().as_ref()
            || d[128..160] != *vault.address().as_ref()
            || d[160..192] != *source.address().as_ref()
            || d[192..224] != intent
        {
            return Err(invalid());
        }
        if balance(vault, usdc.address(), a.address(), false)? < budget - w.spent {
            return Err(invalid());
        }
        return Ok(());
    }
    let time = now()?;
    if time < p.ready {
        return Err(ProgramError::InvalidArgument);
    }
    code(&p, jupiter, jupiter_data, raydium, raydium_data)?;
    crate::oracle::spot(program, cfg, morse, oracle, time)?;
    let current = time as u64 / WEEK_SECONDS;
    let start = epoch.checked_mul(WEEK_SECONDS).ok_or(invalid())?;
    let end = start.checked_add(WEEK_SECONDS).ok_or(invalid())?;
    if (epoch != current && epoch != current.checked_add(1).ok_or(invalid())?)
        || end > i64::MAX as u64
        || (time as u64) >= start + WEEK_SECONDS / CHUNKS as u64
        || budget < CHUNKS as u64
    {
        return Err(ProgramError::InvalidArgument);
    }
    let mut weights = 0u64;
    for i in 0..CHUNKS {
        let w = u32::from_le_bytes(payload[16 + i * 12..20 + i * 12].try_into().unwrap()) as u64;
        if w == 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        weights += w;
    }
    let before = balance(source, usdc.address(), funder.address(), true)?;
    create(
        program,
        program,
        payer,
        a,
        system,
        WEEK_LEN,
        &[
            Seed::from(b"burn-week"),
            Seed::from(&epoch.to_le_bytes()),
            Seed::from(&bump),
        ],
    )?;
    {
        let mut d = a.try_borrow_mut()?;
        d[..4].copy_from_slice(b"MTW\x01");
        d[4..36].copy_from_slice(swap.address().as_ref());
        d[36..44].copy_from_slice(&epoch.to_le_bytes());
        d[44..52].copy_from_slice(&budget.to_le_bytes());
        d[52] = 1;
        d[56..64].copy_from_slice(&time.to_le_bytes());
        for (at, key) in [
            (64, usdc.address()),
            (96, funder.address()),
            (128, vault.address()),
            (160, source.address()),
        ] {
            d[at..at + 32].copy_from_slice(key.as_ref());
        }
        d[192..224].copy_from_slice(&intent);
        let mut assigned = 0u64;
        for i in 0..CHUNKS {
            let weight =
                u32::from_le_bytes(payload[16 + i * 12..20 + i * 12].try_into().unwrap()) as u128;
            let entropy = wide(payload, 20 + i * 12);
            let amount = 1 + ((budget - CHUNKS as u64) as u128 * weight / weights as u128) as u64;
            assigned = assigned
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            let begin = start + i as u64 * WEEK_SECONDS / CHUNKS as u64;
            let end = start + (i + 1) as u64 * WEEK_SECONDS / CHUNKS as u64;
            let due = begin + entropy % (end - begin);
            let r = &mut d[WEEK_HEADER + i * CHUNK_LEN..WEEK_HEADER + (i + 1) * CHUNK_LEN];
            for (at, value) in [(0, amount), (8, begin), (16, end), (24, due)] {
                r[at..at + 8].copy_from_slice(&value.to_le_bytes());
            }
        }
        let dust = budget
            .checked_sub(assigned)
            .ok_or(ProgramError::ArithmeticOverflow)?;
        if dust >= CHUNKS as u64 {
            return Err(invalid());
        }
        for i in 0..dust as usize {
            let at = WEEK_HEADER + i * CHUNK_LEN;
            let value = wide(&d, at)
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            d[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        week(&d)?;
    }
    CreateIdempotent {
        funding_account: payer,
        account: vault,
        wallet: a,
        mint: usdc,
        system_program: system,
        token_program: token,
    }
    .invoke()?;
    let target = balance(vault, usdc.address(), a.address(), true)?;
    TransferChecked::new(source, usdc, vault, funder, budget, 6).invoke()?;
    if balance(source, usdc.address(), funder.address(), true)?
        != before
            .checked_sub(budget)
            .ok_or(ProgramError::ArithmeticOverflow)?
        || balance(vault, usdc.address(), a.address(), true)?
            != target
                .checked_add(budget)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    Ok(())
}

#[inline(never)]
fn invoke_route(accounts: [&AccountView; 24], data: &[u8], seeds: &[Seed]) -> ProgramResult {
    use pinocchio::{
        cpi::{invoke_signed, Signer},
        instruction::{InstructionAccount, InstructionView},
    };
    let metas = core::array::from_fn::<_, 24, _>(|i| {
        if i == 0 {
            InstructionAccount::readonly_signer(accounts[i].address())
        } else if matches!(i, 1 | 2 | 14 | 15 | 16 | 17 | 18 | 23) {
            InstructionAccount::writable(accounts[i].address())
        } else {
            InstructionAccount::readonly(accounts[i].address())
        }
    });
    invoke_signed(
        &InstructionView {
            program_id: &JUPITER,
            accounts: &metas,
            data,
        },
        &accounts,
        &[Signer::from(seeds)],
    )
}
pub(crate) fn execute(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    use pinocchio::cpi::Signer;
    use pinocchio_token::instructions::BurnChecked;
    let [payer, cfg, morse, swap, usdc, a, vault, chunk, input, output, oracle, token, ata, system, jupiter, jupiter_data, raydium, raydium_data, state, amm, input_vault, output_vault, observation, authority, event] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let index = payload[0] as usize;
    if index >= CHUNKS {
        return Err(ProgramError::InvalidInstructionData);
    }
    let p = profile(program, cfg, morse, swap)?;
    mint(usdc)?;
    if usdc.address() != &p.usdc
        || token.address() != &TOKEN
        || !token.executable()
        || ata.address() != &ATA
        || !ata.executable()
        || system.address() != &pinocchio_system::ID
        || !system.executable()
    {
        return Err(invalid());
    }
    owned(program, a, true)?;
    associated(a.address(), usdc.address(), vault)?;
    let cb = [pda(
        program,
        &[b"burn-chunk", a.address().as_ref(), &[index as u8]],
        chunk,
    )?];
    if chunk.executable() || chunk.owner() != &pinocchio_system::ID || chunk.data_len() != 0 {
        return Err(invalid());
    }
    associated(chunk.address(), usdc.address(), input)?;
    associated(chunk.address(), morse.address(), output)?;
    let intent = hashv(&[b"morse-burn-chunk-v1", payload]).to_bytes();
    let (epoch, amount, due, end, mask, spent, burned, header) = {
        let d = a.try_borrow()?;
        let w = week(&d)?;
        pda(program, &[b"burn-week", &w.epoch.to_le_bytes()], a)?;
        if d[4..36] != *swap.address().as_ref()
            || d[64..96] != *usdc.address().as_ref()
            || d[96..128] != *p.treasury.as_ref()
            || d[128..160] != *vault.address().as_ref()
        {
            return Err(invalid());
        }
        if w.header == carry::WEEK_V2_HEADER {
            let carry = Address::try_find_program_address(&[b"burn-carry"], program)
                .ok_or(ProgramError::InvalidSeeds)?
                .0;
            if d[272..304] != *carry.as_ref() {
                return Err(invalid());
            }
        }
        let r = &d[w.header + index * CHUNK_LEN..w.header + (index + 1) * CHUNK_LEN];
        let mask = wide(&d, 224);
        if mask & (1 << index) != 0 {
            return if r[40..72] == intent {
                Ok(())
            } else {
                Err(ProgramError::InvalidInstructionData)
            };
        }
        (
            w.epoch,
            wide(r, 0),
            wide(r, 24),
            wide(r, 16),
            mask,
            w.spent,
            wide(&d, 240),
            w.header,
        )
    };
    let time = now()?;
    if time < p.ready || (time as u64) < due || (time as u64) >= end {
        return Err(ProgramError::InvalidArgument);
    }
    code(&p, jupiter, jupiter_data, raydium, raydium_data)?;
    if state.address() != &p.pool
        || amm.address() != &p.amm
        || observation.address() != &p.observation
    {
        return Err(invalid());
    }
    let (v0, v1) = if input_vault.address() == &p.vault0 && output_vault.address() == &p.vault1 {
        (input_vault as &AccountView, output_vault as &AccountView)
    } else if input_vault.address() == &p.vault1 && output_vault.address() == &p.vault0 {
        (output_vault as &AccountView, input_vault as &AccountView)
    } else {
        return Err(invalid());
    };
    if pool(
        morse.address(),
        usdc.address(),
        state,
        amm,
        v0,
        v1,
        observation,
    )? != p.amm_hash
    {
        return Err(invalid());
    }
    let not_open = {
        let d = state.try_borrow()?;
        wide(&d, 373) > time as u64
    };
    if not_open {
        return Err(ProgramError::InvalidArgument);
    }
    pda(&RAYDIUM, &[b"vault_and_lp_mint_auth_seed"], authority)?;
    pda(&JUPITER, &[b"__event_authority"], event)?;
    balance(input_vault, usdc.address(), authority.address(), true)?;
    balance(output_vault, morse.address(), authority.address(), true)?;
    let price = crate::oracle::spot(program, cfg, morse, oracle, time)?;
    let route = crate::swap::route(&payload[1..], amount, price)?;
    let before = balance(vault, usdc.address(), a.address(), true)?;
    if before < amount {
        return Err(invalid());
    }
    CreateIdempotent {
        funding_account: payer,
        account: input,
        wallet: chunk,
        mint: usdc,
        system_program: system,
        token_program: token,
    }
    .invoke()?;
    CreateIdempotent {
        funding_account: payer,
        account: output,
        wallet: chunk,
        mint: morse,
        system_program: system,
        token_program: token,
    }
    .invoke()?;
    let input_before = balance(input, usdc.address(), chunk.address(), true)?;
    let output_before = balance(output, morse.address(), chunk.address(), true)?;
    let supply = Mint::from_account_view(morse)?.supply();
    let wb = [pda(program, &[b"burn-week", &epoch.to_le_bytes()], a)?];
    let eb = epoch.to_le_bytes();
    TransferChecked::new(vault, usdc, input, a, amount, 6).invoke_signed(&[Signer::from(&[
        Seed::from(b"burn-week"),
        Seed::from(&eb),
        Seed::from(&wb),
    ])])?;
    if balance(input, usdc.address(), chunk.address(), true)?
        != input_before
            .checked_add(amount)
            .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    let ix = [index as u8];
    let seeds = [
        Seed::from(b"burn-chunk"),
        Seed::from(a.address().as_ref()),
        Seed::from(&ix),
        Seed::from(&cb),
    ];
    invoke_route(
        [
            chunk,
            input,
            output,
            usdc,
            morse,
            token,
            token,
            jupiter,
            event,
            jupiter,
            raydium,
            chunk,
            authority,
            amm,
            state,
            input,
            output,
            input_vault,
            output_vault,
            token,
            token,
            usdc,
            morse,
            observation,
        ],
        &payload[1..],
        &seeds,
    )?;
    let actual = balance(output, morse.address(), chunk.address(), true)?
        .checked_sub(output_before)
        .ok_or(invalid())?;
    if actual < route.minimum_output
        || balance(input, usdc.address(), chunk.address(), true)? != input_before
        || Mint::from_account_view(morse)?.supply() != supply
    {
        return Err(invalid());
    }
    BurnChecked::new(output, morse, chunk, actual, 6).invoke_signed(&[Signer::from(&seeds)])?;
    if balance(output, morse.address(), chunk.address(), true)? != output_before
        || Mint::from_account_view(morse)?.supply()
            != supply
                .checked_sub(actual)
                .ok_or(ProgramError::ArithmeticOverflow)?
        || balance(vault, usdc.address(), a.address(), true)?
            != before
                .checked_sub(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    let next_spent = spent
        .checked_add(amount)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let next_burned = burned
        .checked_add(actual)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let mut d = a.try_borrow_mut()?;
    let at = header + index * CHUNK_LEN;
    d[at + 32..at + 40].copy_from_slice(&actual.to_le_bytes());
    d[at + 40..at + 72].copy_from_slice(&intent);
    d[224..232].copy_from_slice(&(mask | (1 << index)).to_le_bytes());
    d[232..240].copy_from_slice(&next_spent.to_le_bytes());
    d[240..248].copy_from_slice(&next_burned.to_le_bytes());
    week(&d)?;
    solana_msg::sol_log("MORSE_BURN_V1");
    Ok(())
}

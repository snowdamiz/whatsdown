//! Permanent missed-window closure and exclusively burn-owned USDC carry.
use super::*;
use pinocchio::cpi::Signer;
pub const WEEK_V2_HEADER: usize = 320;
pub const WEEK_V2_LEN: usize = WEEK_V2_HEADER + CHUNKS * CHUNK_LEN;
pub const CARRY_LEN: usize = 192;
pub const RECEIPT_LEN: usize = 256;
fn large(d: &[u8], at: usize) -> u128 {
    u128::from_le_bytes(d[at..at + 16].try_into().unwrap())
}
struct Carry {
    accounted: u64,
    closed: u128,
    reserved: u128,
    closes: u64,
    funds: u64,
}
fn load(
    program: &Address,
    a: &AccountView,
    swap: &Address,
    usdc: &Address,
    vault: &Address,
) -> Result<Carry, ProgramError> {
    owned(program, a, true)?;
    pda(program, &[b"burn-carry"], a)?;
    let d = a.try_borrow()?;
    if d.len() != CARRY_LEN
        || &d[..4] != b"MCY\x01"
        || d[4..36] != *swap.as_ref()
        || d[36..68] != *usdc.as_ref()
        || d[68..100] != *vault.as_ref()
        || d[156..].iter().any(|x| *x != 0)
        || large(&d, 108).checked_sub(large(&d, 124)) != Some(wide(&d, 100) as u128)
    {
        return Err(invalid());
    }
    Ok(Carry {
        accounted: wide(&d, 100),
        closed: large(&d, 108),
        reserved: large(&d, 124),
        closes: wide(&d, 140),
        funds: wide(&d, 148),
    })
}
fn store(a: &mut AccountView, c: &Carry) -> ProgramResult {
    let mut d = a.try_borrow_mut()?;
    d[100..108].copy_from_slice(&c.accounted.to_le_bytes());
    d[108..124].copy_from_slice(&c.closed.to_le_bytes());
    d[124..140].copy_from_slice(&c.reserved.to_le_bytes());
    d[140..148].copy_from_slice(&c.closes.to_le_bytes());
    d[148..156].copy_from_slice(&c.funds.to_le_bytes());
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn initialize(
    program: &Address,
    payer: &AccountView,
    a: &mut AccountView,
    vault: &AccountView,
    swap: &AccountView,
    usdc: &AccountView,
    token: &AccountView,
    system: &AccountView,
) -> Result<Carry, ProgramError> {
    let bump = [pda(program, &[b"burn-carry"], a)?];
    associated(a.address(), usdc.address(), vault)?;
    if a.owner() != program {
        create(
            program,
            program,
            payer,
            a,
            system,
            CARRY_LEN,
            &[Seed::from(b"burn-carry"), Seed::from(&bump)],
        )?;
        let mut d = a.try_borrow_mut()?;
        d[..4].copy_from_slice(b"MCY\x01");
        for (at, key) in [
            (4, swap.address()),
            (36, usdc.address()),
            (68, vault.address()),
        ] {
            d[at..at + 32].copy_from_slice(key.as_ref());
        }
    }
    let c = load(program, a, swap.address(), usdc.address(), vault.address())?;
    CreateIdempotent {
        funding_account: payer,
        account: vault,
        wallet: a,
        mint: usdc,
        system_program: system,
        token_program: token,
    }
    .invoke()?;
    if balance(vault, usdc.address(), a.address(), true)? < c.accounted {
        return Err(invalid());
    }
    Ok(c)
}
fn programs(
    payer: &AccountView,
    token: &AccountView,
    ata: &AccountView,
    system: &AccountView,
) -> ProgramResult {
    if !payer.is_signer()
        || !payer.is_writable()
        || token.address() != &TOKEN
        || !token.executable()
        || ata.address() != &ATA
        || !ata.executable()
        || system.address() != &pinocchio_system::ID
        || !system.executable()
    {
        return Err(invalid());
    }
    Ok(())
}
fn frame_hash(d: &[u8]) -> [u8; 32] {
    hashv(&[b"MTW", &d[3..4], &d[4..52], &[1], &d[53..]]).to_bytes()
}
#[allow(clippy::too_many_arguments)]
fn receipt_matches(
    program: &Address,
    receipt: &AccountView,
    a: &AccountView,
    vault: &AccountView,
    swap: &AccountView,
    carry: &AccountView,
    d: &[u8],
    w: &Week,
) -> ProgramResult {
    owned(program, receipt, true)?;
    let r = receipt.try_borrow()?;
    let end = w
        .epoch
        .checked_add(1)
        .and_then(|x| x.checked_mul(WEEK_SECONDS))
        .ok_or(invalid())?;
    if r.len() != RECEIPT_LEN
        || &r[..4] != b"MBC\x01"
        || r[4..36] != *swap.address().as_ref()
        || r[36..68] != *a.address().as_ref()
        || r[68..100] != *vault.address().as_ref()
        || wide(&r, 100) != w.epoch
        || wide(&r, 108) != w.budget
        || wide(&r, 116) != w.spent
        || wide(&r, 124) != wide(d, 240)
        || wide(&r, 132) != w.budget - w.spent
        || wide(&r, 140) < end
        || wide(&r, 140) > i64::MAX as u64
        || r[148..180] != *carry.address().as_ref()
        || r[180..212] != d[192..224]
        || r[212..244] != frame_hash(d)
        || r[244] != d[3]
        || r[245..].iter().any(|x| *x != 0)
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn close(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [payer, cfg, morse, swap, a, vault, carry, carry_vault, receipt, usdc, token, ata, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    programs(payer, token, ata, system)?;
    let p = profile(program, cfg, morse, swap)?;
    mint(usdc)?;
    if usdc.address() != &p.usdc {
        return Err(invalid());
    }
    let epoch = wide(payload, 0);
    let eb = epoch.to_le_bytes();
    let wb = [pda(program, &[b"burn-week", &eb], a)?];
    let rb = [pda(program, &[b"burn-carry-epoch", &eb], receipt)?];
    pda(program, &[b"burn-carry"], carry)?;
    associated(a.address(), usdc.address(), vault)?;
    associated(carry.address(), usdc.address(), carry_vault)?;
    owned(program, a, true)?;
    let (remaining, spent, burned, budget, original, version, closed) = {
        let d = a.try_borrow()?;
        let closed = d.get(..3) == Some(b"MTC");
        let w = parse_week(&d, closed)?;
        if w.epoch != epoch
            || d[4..36] != *swap.address().as_ref()
            || d[64..96] != *usdc.address().as_ref()
            || d[96..128] != *p.treasury.as_ref()
            || d[128..160] != *vault.address().as_ref()
            || (w.header == WEEK_V2_HEADER && d[272..304] != *carry.address().as_ref())
        {
            return Err(invalid());
        }
        let original = frame_hash(&d);
        if closed {
            receipt_matches(program, receipt, a, vault, swap, carry, &d, &w)?;
        }
        (
            w.budget - w.spent,
            w.spent,
            wide(&d, 240),
            w.budget,
            original,
            d[3],
            closed,
        )
    };
    let source_before = balance(vault, usdc.address(), a.address(), true)?;
    if closed {
        let c = load(
            program,
            carry,
            swap.address(),
            usdc.address(),
            carry_vault.address(),
        )?;
        if balance(carry_vault, usdc.address(), carry.address(), true)? < c.accounted {
            return Err(invalid());
        }
        return Ok(());
    }
    let time = now()?;
    let end = epoch
        .checked_add(1)
        .and_then(|x| x.checked_mul(WEEK_SECONDS))
        .ok_or(invalid())?;
    if (time as u64) < end || source_before < remaining {
        return Err(ProgramError::InvalidArgument);
    }
    let mut c = initialize(
        program,
        payer,
        carry,
        carry_vault,
        swap,
        usdc,
        token,
        system,
    )?;
    c.accounted = c
        .accounted
        .checked_add(remaining)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    c.closed = c
        .closed
        .checked_add(remaining as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    c.closes = c
        .closes
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let target_before = balance(carry_vault, usdc.address(), carry.address(), true)?;
    create(
        program,
        program,
        payer,
        receipt,
        system,
        RECEIPT_LEN,
        &[
            Seed::from(b"burn-carry-epoch"),
            Seed::from(&eb),
            Seed::from(&rb),
        ],
    )?;
    if remaining > 0 {
        TransferChecked::new(vault, usdc, carry_vault, a, remaining, 6).invoke_signed(&[
            Signer::from(&[Seed::from(b"burn-week"), Seed::from(&eb), Seed::from(&wb)]),
        ])?;
    }
    if balance(vault, usdc.address(), a.address(), true)? != source_before - remaining
        || balance(carry_vault, usdc.address(), carry.address(), true)?
            != target_before
                .checked_add(remaining)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    {
        let mut r = receipt.try_borrow_mut()?;
        r[..4].copy_from_slice(b"MBC\x01");
        for (at, key) in [
            (4, swap.address()),
            (36, a.address()),
            (68, vault.address()),
            (148, carry.address()),
        ] {
            r[at..at + 32].copy_from_slice(key.as_ref());
        }
        for (at, value) in [
            (100, epoch),
            (108, budget),
            (116, spent),
            (124, burned),
            (132, remaining),
            (140, time as u64),
        ] {
            r[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        let d = a.try_borrow()?;
        r[180..212].copy_from_slice(&d[192..224]);
        r[212..244].copy_from_slice(&original);
        r[244] = version;
    }
    let mut d = a.try_borrow_mut()?;
    d[..3].copy_from_slice(b"MTC");
    d[52] = 2;
    drop(d);
    store(carry, &c)?;
    solana_msg::sol_log("MORSE_BURN_CARRY_CLOSE");
    Ok(())
}
pub(crate) fn open(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [funder, payer, cfg, morse, swap, usdc, a, vault, source, token, ata, system, jupiter, jupiter_data, raydium, raydium_data, oracle, carry, carry_vault] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    programs(payer, token, ata, system)?;
    let p = profile(program, cfg, morse, swap)?;
    mint(usdc)?;
    if usdc.address() != &p.usdc || funder.address() != &p.treasury || !funder.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let epoch = wide(payload, 0);
    let cash = wide(payload, 8);
    let take = wide(payload, 16);
    let budget = cash
        .checked_add(take)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let eb = epoch.to_le_bytes();
    let wb = [pda(program, &[b"burn-week", &eb], a)?];
    let cb = [pda(program, &[b"burn-carry"], carry)?];
    associated(a.address(), usdc.address(), vault)?;
    associated(funder.address(), usdc.address(), source)?;
    associated(carry.address(), usdc.address(), carry_vault)?;
    let intent = hashv(&[b"morse-burn-week-v2", swap.address().as_ref(), payload]).to_bytes();
    if a.owner() == program {
        owned(program, a, false)?;
        let d = a.try_borrow()?;
        let w = week(&d)?;
        if w.header != WEEK_V2_HEADER
            || w.epoch != epoch
            || w.budget != budget
            || d[4..36] != *swap.address().as_ref()
            || d[64..96] != *usdc.address().as_ref()
            || d[96..128] != *funder.address().as_ref()
            || d[128..160] != *vault.address().as_ref()
            || d[160..192] != *source.address().as_ref()
            || d[192..224] != intent
            || wide(&d, 256) != cash
            || wide(&d, 264) != take
            || d[272..304] != *carry.address().as_ref()
        {
            return Err(invalid());
        }
        let c = load(
            program,
            carry,
            swap.address(),
            usdc.address(),
            carry_vault.address(),
        )?;
        if balance(vault, usdc.address(), a.address(), false)? < budget - w.spent
            || balance(carry_vault, usdc.address(), carry.address(), true)? < c.accounted
        {
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
        || time as u64 >= start + WEEK_SECONDS / CHUNKS as u64
        || budget < CHUNKS as u64
    {
        return Err(ProgramError::InvalidArgument);
    }
    let mut weights = 0u64;
    for i in 0..CHUNKS {
        let weight =
            u32::from_le_bytes(payload[24 + i * 12..28 + i * 12].try_into().unwrap()) as u64;
        if weight == 0 {
            return Err(ProgramError::InvalidInstructionData);
        }
        weights = weights
            .checked_add(weight)
            .ok_or(ProgramError::ArithmeticOverflow)?;
    }
    let source_before = if cash > 0 || source.owner() == &TOKEN {
        balance(source, usdc.address(), funder.address(), true)?
    } else {
        if source.owner() != &pinocchio_system::ID || source.executable() || source.data_len() != 0
        {
            return Err(invalid());
        }
        0
    };
    if source_before < cash {
        return Err(ProgramError::InsufficientFunds);
    }
    let mut c = initialize(
        program,
        payer,
        carry,
        carry_vault,
        swap,
        usdc,
        token,
        system,
    )?;
    if take > c.accounted {
        return Err(ProgramError::InsufficientFunds);
    }
    let carry_before = balance(carry_vault, usdc.address(), carry.address(), true)?;
    c.accounted -= take;
    c.reserved = c
        .reserved
        .checked_add(take as u128)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    c.funds = c
        .funds
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    create(
        program,
        program,
        payer,
        a,
        system,
        WEEK_V2_LEN,
        &[Seed::from(b"burn-week"), Seed::from(&eb), Seed::from(&wb)],
    )?;
    {
        let mut d = a.try_borrow_mut()?;
        d[..4].copy_from_slice(b"MTW\x02");
        d[52] = 1;
        for (at, key) in [
            (4, swap.address()),
            (64, usdc.address()),
            (96, funder.address()),
            (128, vault.address()),
            (160, source.address()),
            (272, carry.address()),
        ] {
            d[at..at + 32].copy_from_slice(key.as_ref());
        }
        for (at, value) in [
            (36, epoch),
            (44, budget),
            (56, time as u64),
            (256, cash),
            (264, take),
        ] {
            d[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        d[192..224].copy_from_slice(&intent);
        let mut assigned = 0u64;
        for i in 0..CHUNKS {
            let weight =
                u32::from_le_bytes(payload[24 + i * 12..28 + i * 12].try_into().unwrap()) as u128;
            let entropy = wide(payload, 28 + i * 12);
            let amount = 1 + ((budget - CHUNKS as u64) as u128 * weight / weights as u128) as u64;
            assigned = assigned
                .checked_add(amount)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            let begin = start + i as u64 * WEEK_SECONDS / CHUNKS as u64;
            let end = start + (i + 1) as u64 * WEEK_SECONDS / CHUNKS as u64;
            let due = begin + entropy % (end - begin);
            let r = &mut d[WEEK_V2_HEADER + i * CHUNK_LEN..WEEK_V2_HEADER + (i + 1) * CHUNK_LEN];
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
            let at = WEEK_V2_HEADER + i * CHUNK_LEN;
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
    let target_before = balance(vault, usdc.address(), a.address(), true)?;
    if cash > 0 {
        TransferChecked::new(source, usdc, vault, funder, cash, 6).invoke()?;
    }
    if take > 0 {
        TransferChecked::new(carry_vault, usdc, vault, carry, take, 6)
            .invoke_signed(&[Signer::from(&[Seed::from(b"burn-carry"), Seed::from(&cb)])])?;
    }
    if (cash > 0
        && balance(source, usdc.address(), funder.address(), true)? != source_before - cash)
        || balance(carry_vault, usdc.address(), carry.address(), true)? != carry_before - take
        || balance(vault, usdc.address(), a.address(), true)?
            != target_before
                .checked_add(budget)
                .ok_or(ProgramError::ArithmeticOverflow)?
    {
        return Err(invalid());
    }
    store(carry, &c)?;
    solana_msg::sol_log("MORSE_BURN_CARRY_FUND");
    Ok(())
}

//! Permanent proof that an absent burn week can never receive funding.
use super::*;
pub const TOMBSTONE_LEN: usize = 192;
pub const EXPIRY_RECEIPT_LEN: usize = 256;
fn absent(a: &AccountView) -> ProgramResult {
    if a.owner() != &pinocchio_system::ID || a.data_len() != 0 || a.executable() || !a.is_writable()
    {
        return Err(invalid());
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn matches(
    program: &Address,
    cfg: &AccountView,
    swap: &AccountView,
    a: &AccountView,
    receipt: &AccountView,
    p: &Profile,
    epoch: u64,
    deadline: u64,
    profile_hash: &[u8; 32],
) -> ProgramResult {
    owned(program, a, true)?;
    owned(program, receipt, true)?;
    let d = a.try_borrow()?;
    if d.len() != TOMBSTONE_LEN
        || &d[..4] != b"MBX\x01"
        || d[4..36] != *swap.address().as_ref()
        || d[36..68] != *cfg.address().as_ref()
        || d[68..100] != *p.usdc.as_ref()
        || d[100..132] != *p.treasury.as_ref()
        || wide(&d, 132) != epoch
        || wide(&d, 140) != deadline
        || wide(&d, 148) < deadline
        || wide(&d, 148) > i64::MAX as u64
        || d[156..188] != *profile_hash
        || d[188..].iter().any(|x| *x != 0)
    {
        return Err(invalid());
    }
    let r = receipt.try_borrow()?;
    if r.len() != EXPIRY_RECEIPT_LEN
        || &r[..4] != b"MBU\x01"
        || r[4..36] != *swap.address().as_ref()
        || r[36..68] != *a.address().as_ref()
        || r[68..100] != *cfg.address().as_ref()
        || r[100..132] != *p.usdc.as_ref()
        || r[132..164] != *p.treasury.as_ref()
        || wide(&r, 164) != epoch
        || wide(&r, 172) != deadline
        || wide(&r, 180) != wide(&d, 148)
        || r[188..220] != *profile_hash
        || r[220..252] != hash(&d).to_bytes()
        || r[252..].iter().any(|x| *x != 0)
    {
        return Err(invalid());
    }
    Ok(())
}
pub(crate) fn expire(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [payer, cfg, morse, swap, a, receipt, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if !payer.is_signer()
        || !payer.is_writable()
        || payer.address() == a.address()
        || payer.address() == receipt.address()
        || system.address() != &pinocchio_system::ID
        || !system.executable()
    {
        return Err(invalid());
    }
    let p = profile(program, cfg, morse, swap)?;
    let epoch = wide(payload, 0);
    let eb = epoch.to_le_bytes();
    let wb = [pda(program, &[b"burn-week", &eb], a)?];
    let rb = [pda(program, &[b"burn-carry-epoch", &eb], receipt)?];
    let deadline = epoch
        .checked_mul(WEEK_SECONDS)
        .and_then(|start| start.checked_add(WEEK_SECONDS / CHUNKS as u64))
        .filter(|x| *x <= i64::MAX as u64)
        .ok_or(ProgramError::InvalidArgument)?;
    let profile_hash = hash(&swap.try_borrow()?).to_bytes();
    // A terminal retry is independent of subsequent wall-clock movement. It
    // authenticates both permanent records, never converting a funded week.
    if a.owner() == program {
        return matches(
            program,
            cfg,
            swap,
            a,
            receipt,
            &p,
            epoch,
            deadline,
            &profile_hash,
        );
    }
    absent(a)?;
    absent(receipt)?;
    let time = now()? as u64;
    if time < deadline {
        return Err(ProgramError::InvalidArgument);
    }
    create(
        program,
        program,
        payer,
        a,
        system,
        TOMBSTONE_LEN,
        &[Seed::from(b"burn-week"), Seed::from(&eb), Seed::from(&wb)],
    )?;
    create(
        program,
        program,
        payer,
        receipt,
        system,
        EXPIRY_RECEIPT_LEN,
        &[
            Seed::from(b"burn-carry-epoch"),
            Seed::from(&eb),
            Seed::from(&rb),
        ],
    )?;
    {
        let mut d = a.try_borrow_mut()?;
        d.fill(0);
        d[..4].copy_from_slice(b"MBX\x01");
        for (at, key) in [
            (4, swap.address()),
            (36, cfg.address()),
            (68, &p.usdc),
            (100, &p.treasury),
        ] {
            d[at..at + 32].copy_from_slice(key.as_ref());
        }
        for (at, value) in [(132, epoch), (140, deadline), (148, time)] {
            d[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        d[156..188].copy_from_slice(&profile_hash);
    }
    let frame_hash = hash(&a.try_borrow()?).to_bytes();
    {
        let mut r = receipt.try_borrow_mut()?;
        r.fill(0);
        r[..4].copy_from_slice(b"MBU\x01");
        for (at, key) in [
            (4, swap.address()),
            (36, a.address()),
            (68, cfg.address()),
            (100, &p.usdc),
            (132, &p.treasury),
        ] {
            r[at..at + 32].copy_from_slice(key.as_ref());
        }
        for (at, value) in [(164, epoch), (172, deadline), (180, time)] {
            r[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        r[188..220].copy_from_slice(&profile_hash);
        r[220..252].copy_from_slice(&frame_hash);
    }
    solana_msg::sol_log("MORSE_BURN_UNFUNDED_EXPIRE");
    Ok(())
}

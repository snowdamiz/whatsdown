//! Version two: separate MORSE reserve liabilities, immutable USDC accounting.
use super::*;
use morse_token::{
    collateral_state::decode_economics,
    judge_binding::{load_binding, qualified_program_slot},
    reserve::{self, ReserveProfile},
    reward_state::{TokenPool, TOKEN_POOL_LEN},
};
struct Pins {
    activated_epoch: u64,
}
#[allow(clippy::too_many_arguments)]
fn pins(
    program: &Address,
    p: &Pool,
    pool_account: &AccountView,
    judge: &AccountView,
    judge_data: &AccountView,
    log_account: &AccountView,
    economy: &AccountView,
    binding: &AccountView,
    token: &AccountView,
    token_data: &AccountView,
    cfg: &AccountView,
    mint_account: &AccountView,
    oracle: &AccountView,
    profile: &AccountView,
    rewards: &AccountView,
    rewards_data: &AccountView,
) -> Result<Pins, ProgramError> {
    if judge.address().as_ref() != p.judge || rewards.address() != program {
        return Err(invalid());
    }
    log(p, log_account)?;
    let judge_slot = qualified_program_slot(judge, judge_data)?;
    let token_slot = qualified_program_slot(token, token_data)?;
    let rewards_slot = qualified_program_slot(rewards, rewards_data)?;
    let b = load_binding(judge.address(), binding, &p.log_id)?;
    if b.activated_at == 0
        || b.log != *log_account.address()
        || b.token_program != *token.address()
        || b.token_config != *cfg.address()
        || b.mint != *mint_account.address()
        || b.oracle != *oracle.address()
        || b.rewards_program != *program
        || b.rewards_pool != *pool_account.address()
        || b.token_slot != token_slot
        || b.rewards_slot != rewards_slot
    {
        return Err(invalid());
    }
    owned(judge.address(), economy, false)?;
    pda(judge.address(), &[b"economics", &p.log_id], economy)?;
    let d = economy.try_borrow()?;
    decode_economics(&d)?;
    if d[4..36] != p.log_id || d[36..68] != p.mint {
        return Err(invalid());
    }
    drop(d);
    let r: ReserveProfile = reserve::load(token.address(), profile)?;
    if r.config != *cfg.address()
        || r.mint != *mint_account.address()
        || r.usdc.as_ref() != p.mint
        || r.judge != *judge.address()
        || r.log != *log_account.address()
        || r.binding != *binding.address()
        || r.rewards != *program
        || r.pool != *pool_account.address()
        || r.token_pool != Address::find_program_address(&[b"token-pool"], program).0
        || r.rewards_slot != rewards_slot
        || r.judge_slot != judge_slot
        || now()? < r.ready_at
    {
        return Err(invalid());
    }
    // A missing price disables MORSE rewards, rather than trapping USDC funds.
    // The owner/PDA/schema/source revision are still authenticated here.
    morse_token::oracle::revision(token.address(), cfg, mint_account, oracle)?;
    Ok(Pins {
        activated_epoch: b.activated_epoch,
    })
}
pub(super) fn activate(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [governance, payer, pool_account, token_pool, vault, judge, judge_data, log_account, economy, binding, token, token_data, cfg, mint_account, oracle, profile, rewards, rewards_data, spl, ata, system] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    auth(governance, &p.governance)?;
    let pinned = pins(
        program,
        &p,
        pool_account,
        judge,
        judge_data,
        log_account,
        economy,
        binding,
        token,
        token_data,
        cfg,
        mint_account,
        oracle,
        profile,
        rewards,
        rewards_data,
    )?;
    token_program(spl)?;
    if ata.address() != &ATA || !ata.executable() {
        return Err(ProgramError::IncorrectProgramId);
    }
    associated(pool_account.address(), mint_account.address(), vault)?;
    let bump = [pda(program, &[b"token-pool"], token_pool)?];
    if token_pool.owner() == program {
        owned(program, token_pool, true)?;
        let old = TokenPool::parse(&token_pool.try_borrow()?)?;
        if p.version != 2
            || old.pool != *pool_account.address()
            || old.binding != *binding.address()
            || old.token_program != *token.address()
            || old.config != *cfg.address()
            || old.mint != *mint_account.address()
            || old.oracle != *oracle.address()
            || old.profile != *profile.address()
            || old.vault != *vault.address()
            || old.activation_epoch != pinned.activated_epoch
            || balance(vault, mint_account.address(), pool_account.address(), true)? < old.accounted
        {
            return Err(invalid());
        }
        return Ok(());
    }
    if p.version != 1 || p.active != 0 || p.next_epoch < pinned.activated_epoch {
        return Err(ProgramError::InvalidArgument);
    }
    create(
        program,
        payer,
        token_pool,
        system,
        TOKEN_POOL_LEN,
        &[Seed::from(b"token-pool"), Seed::from(&bump)],
    )?;
    CreateIdempotent {
        funding_account: payer,
        account: vault,
        wallet: pool_account,
        mint: mint_account,
        system_program: system,
        token_program: spl,
    }
    .invoke()?;
    balance(vault, mint_account.address(), pool_account.address(), true)?;
    let mut d = token_pool.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MRT\x02");
    for (at, a) in [
        (4, &*pool_account),
        (36, binding),
        (68, token),
        (100, cfg),
        (132, mint_account),
        (164, oracle),
        (196, profile),
        (228, vault),
    ] {
        d[at..at + 32].copy_from_slice(a.address().as_ref());
    }
    put64(&mut d, 276, pinned.activated_epoch);
    pool_account.try_borrow_mut()?[3] = 2;
    Ok(())
}

use morse_token::{
    collateral_state,
    reward_state::{TokenEpoch, TOKEN_EPOCH_HEADER, TOKEN_EPOCH_LEN, TOKEN_ROW_LEN},
};
const CONTEXT_LEN: usize = 19;
fn companion(
    program: &Address,
    p: &Pool,
    pool_account: &AccountView,
    a: &AccountView,
    w: bool,
) -> Result<TokenPool, ProgramError> {
    owned(program, a, w)?;
    pda(program, &[b"token-pool"], a)?;
    let t = TokenPool::parse(&a.try_borrow()?)?;
    if p.version != 2 || t.pool != *pool_account.address() {
        return Err(invalid());
    }
    Ok(t)
}
fn token_epoch(
    program: &Address,
    a: &AccountView,
    t: &AccountView,
    l: &AccountView,
    e: u64,
    w: bool,
) -> Result<TokenEpoch, ProgramError> {
    owned(program, a, w)?;
    pda(program, &[b"token-epoch", &e.to_le_bytes()], a)?;
    let v = TokenEpoch::parse(&a.try_borrow()?)?;
    if v.token_pool != *t.address().as_array()
        || v.ledger != *l.address().as_array()
        || v.epoch != e
    {
        return Err(invalid());
    }
    Ok(v)
}
pub(super) fn open_token(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [payer, pool_account, token_pool, epoch_account, token_account, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, false)?;
    let t = companion(program, &p, pool_account, token_pool, false)?;
    let e = u64_at(payload, 0);
    if e < p.next_epoch || e < t.activation_epoch || e > epoch()? {
        return Err(ProgramError::InvalidArgument);
    }
    let eb = e.to_le_bytes();
    let bump = [pda(program, &[b"epoch", &eb], epoch_account)?];
    if epoch_account.owner() == program {
        let l = ledger(program, epoch_account, pool_account, true)?;
        if l.epoch != e || (l.version == 1 && l.status != 0) {
            return Err(invalid());
        }
        epoch_account.try_borrow_mut()?[3] = 2;
    } else {
        create(
            program,
            payer,
            epoch_account,
            system,
            LEDGER_LEN,
            &[Seed::from(b"epoch"), Seed::from(&eb), Seed::from(&bump)],
        )?;
        let mut d = epoch_account.try_borrow_mut()?;
        d[..4].copy_from_slice(b"MRE\x02");
        d[4..36].copy_from_slice(pool_account.address().as_ref());
        put64(&mut d, 36, e);
    }
    let bump = [pda(program, &[b"token-epoch", &eb], token_account)?];
    if token_account.owner() == program {
        token_epoch(program, token_account, token_pool, epoch_account, e, true)?;
        return Ok(());
    }
    create(
        program,
        payer,
        token_account,
        system,
        TOKEN_EPOCH_LEN,
        &[
            Seed::from(b"token-epoch"),
            Seed::from(&eb),
            Seed::from(&bump),
        ],
    )?;
    let mut d = token_account.try_borrow_mut()?;
    d[..4].copy_from_slice(b"MTE\x02");
    d[4..36].copy_from_slice(token_pool.address().as_ref());
    d[36..68].copy_from_slice(epoch_account.address().as_ref());
    put64(&mut d, 68, e);
    Ok(())
}
fn base_context(
    program: &Address,
    a: &[AccountView],
) -> Result<(Pool, Ledger, TokenPool, TokenEpoch, u64, u64), ProgramError> {
    let [pool_account, token_pool, epoch_account, token_account, log_account, clock_account, week_account, economy, binding, token, token_data, cfg, mint_account, oracle, rewards, rewards_data, judge, judge_data, profile] =
        a
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, true)?;
    let l = ledger(program, epoch_account, pool_account, true)?;
    let t = companion(program, &p, pool_account, token_pool, false)?;
    let e = token_epoch(
        program,
        token_account,
        token_pool,
        epoch_account,
        l.epoch,
        true,
    )?;
    pins(
        program,
        &p,
        pool_account,
        judge,
        judge_data,
        log_account,
        economy,
        binding,
        token,
        token_data,
        cfg,
        mint_account,
        oracle,
        profile,
        rewards,
        rewards_data,
    )?;
    if l.version != 2
        || l.epoch != p.next_epoch
        || l.epoch < t.activation_epoch
        || t.binding != *binding.address()
        || t.token_program != *token.address()
        || t.config != *cfg.address()
        || t.mint != *mint_account.address()
        || t.oracle != *oracle.address()
        || t.profile != *profile.address()
    {
        return Err(invalid());
    }
    clock(&p, clock_account)?;
    week(&p, week_account, l.epoch)?;
    let revision = decode_economics(&economy.try_borrow()?)?.revision;
    let source = morse_token::oracle::revision(token.address(), cfg, mint_account, oracle)?;
    Ok((p, l, t, e, revision, source))
}
pub(super) fn begin_token(program: &Address, a: &mut [AccountView]) -> ProgramResult {
    let (p, l, _, e, revision, source) = base_context(program, a)?;
    if l.status != 0 || e.status != 0 || p.active != 0 {
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
    let w = week(&p, &a[6], l.epoch)?;
    let stamp = now()?;
    let price = match morse_token::oracle::value(a[9].address(), &a[11], &a[12], &a[13], stamp) {
        Ok(v) => v,
        Err(ProgramError::InvalidAccountData) => 0,
        Err(v) => return Err(v),
    };
    let digest = hash(&a[6].try_borrow()?);
    {
        let mut d = a[2].try_borrow_mut()?;
        d[52] = 1;
        d[54] = w.witnesses as u8;
        d[56..88].copy_from_slice(digest.as_ref());
        put64(&mut d, 88, w.posts);
        put64(&mut d, 120, base);
        put64(&mut d, 128, add(p.carry, l.revenue)?);
        d[168..176].copy_from_slice(&stamp.to_le_bytes());
        put64(&mut d, 176, revision);
    }
    {
        let mut d = a[3].try_borrow_mut()?;
        put64(&mut d, 76, price);
        put64(&mut d, 84, source);
        d[92..100].copy_from_slice(&stamp.to_le_bytes());
        d[148] = 1;
    }
    put64(&mut a[0].try_borrow_mut()?, 220, add(l.epoch, 1)?);
    Ok(())
}
fn collecting_token(
    program: &Address,
    a: &[AccountView],
) -> Result<(Pool, Ledger, TokenPool, TokenEpoch), ProgramError> {
    let (p, l, t, e, revision, source) = base_context(program, a)?;
    if l.status != 1
        || e.status != 1
        || p.active != add(l.epoch, 1)?
        || revision != l.revision
        || source != e.source_revision
        || e.snapshot_at != i64_at(&a[2].try_borrow()?, 168)
        || now()?
            >= e.snapshot_at
                .checked_add(STAGE_SECONDS)
                .ok_or_else(overflow)?
        || a[2].try_borrow()?[56..88] != *hash(&a[6].try_borrow()?).as_ref()
    {
        return Err(ProgramError::InvalidArgument);
    }
    Ok((p, l, t, e))
}
pub(super) fn append_token(program: &Address, a: &mut [AccountView]) -> ProgramResult {
    if a.len() < CONTEXT_LEN + 4 || !(a.len() - CONTEXT_LEN).is_multiple_of(4) {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, rows) = a.split_at_mut(CONTEXT_LEN);
    let (p, l, t, e) = collecting_token(program, head)?;
    let count = rows.len() / 4;
    if l.count as usize + count > l.expected as usize {
        return Err(ProgramError::InvalidArgument);
    }
    let start = i64::try_from(l.epoch)
        .map_err(|_| overflow())?
        .checked_mul(EPOCH_SECONDS)
        .ok_or_else(overflow)?;
    let judge = Address::from(p.judge);
    let mut total = l.weight;
    let mut floors = l.floors;
    for (offset, [witness, bond, pending, member]) in rows.as_chunks::<4>().0.iter().enumerate() {
        let n = l.count as usize + offset;
        let signed = {
            let d = head[6].try_borrow()?;
            let at = 80 + n * 40;
            if d[at..at + 32] != *witness.address().as_ref() {
                return Err(invalid());
            }
            u64_at(&d, at + 32)
        };
        let id = validate_witness(&p, witness)?;
        pda(&judge, &[b"bond", &p.log_id, &id], bond)?;
        pda(&judge, &[b"bond-pending", bond.address().as_ref()], pending)?;
        let outside = admitted(program, &p, witness, member, start)?;
        let w = witness.try_borrow()?;
        let eligible = if bond.owner() == &pinocchio_system::ID
            && bond.data_len() == 0
            && !bond.executable()
        {
            if w[5] != 0
                || w[232..272].iter().any(|b| *b != 0)
                || pending.owner() != &pinocchio_system::ID
                || pending.data_len() != 0
                || pending.executable()
            {
                return Err(invalid());
            }
            false
        } else {
            owned(&judge, bond, false)?;
            let d = bond.try_borrow()?;
            let b = collateral_state::decode_bond(&d)?;
            let asset_mint = if b.asset == 0 {
                Address::from(p.mint)
            } else {
                Address::new_from_array(*t.mint.as_array())
            };
            if !b.witness
                || d[8..40] != p.log_id
                || d[40..72] != *witness.address().as_ref()
                || d[72..104] != w[104..136]
                || d[104..136] != *asset_mint.as_ref()
                || d[136..168] != w[232..264]
                || b.status != w[5]
                || d[136..168]
                    != *Address::find_program_address(
                        &[bond.address().as_ref(), TOKEN.as_ref(), asset_mint.as_ref()],
                        &ATA,
                    )
                    .0
                    .as_ref()
            {
                return Err(invalid());
            }
            let target = if pending.owner() == &judge {
                judge_core::token_deposit::load_pending(
                    &judge,
                    pending,
                    bond.address(),
                    &asset_mint,
                    b.asset,
                )?
                .target
            } else {
                if b.asset != 0
                    || pending.owner() != &pinocchio_system::ID
                    || pending.data_len() != 0
                    || pending.executable()
                {
                    return Err(invalid());
                }
                0
            };
            b.status == 1
                && w[6] == 0
                && b.bonded_at <= start
                && outside
                && collateral_state::eligible(b, e.price, target, e.snapshot_at)?
        };
        let weight = if eligible {
            math::attendance_weight(signed, l.posts).map_err(err)?
        } else {
            0
        };
        let floor = math::scaled_floor(l.base, weight, l.posts).map_err(err)?;
        total = total.checked_add(weight).ok_or_else(overflow)?;
        floors = add(floors, floor)?;
        let mut d = head[2].try_borrow_mut()?;
        let at = LEDGER_HEADER + n * ROW_LEN;
        d[at..at + 32].copy_from_slice(witness.address().as_ref());
        d[at + 32..at + 64].copy_from_slice(&w[136..168]);
        d[at + 64..at + 96].copy_from_slice(bond.address().as_ref());
        put128(&mut d, at + 96, weight);
        put64(&mut d, at + 112, floor);
    }
    let mut d = head[2].try_borrow_mut()?;
    d[53] = l.count + count as u8;
    put128(&mut d, 96, total);
    put64(&mut d, 112, floors);
    Ok(())
}
pub(super) fn cancel_token(program: &Address, a: &mut [AccountView]) -> ProgramResult {
    let (p, l, _, e, revision, source) = base_context(program, a)?;
    if l.status != 1
        || e.status != 1
        || p.active != add(l.epoch, 1)?
        || (l.revision == revision
            && e.source_revision == source
            && now()?
                < e.snapshot_at
                    .checked_add(STAGE_SECONDS)
                    .ok_or_else(overflow)?)
    {
        return Err(ProgramError::InvalidArgument);
    }
    a[2].try_borrow_mut()?[52..].fill(0);
    a[3].try_borrow_mut()?[76..].fill(0);
    put64(&mut a[0].try_borrow_mut()?, 220, 0);
    Ok(())
}

#[inline(never)]
fn invoke_reserve(program: &Address, head: &[AccountView], extra: &[AccountView]) -> ProgramResult {
    use pinocchio::{
        cpi::invoke_signed,
        instruction::{InstructionAccount, InstructionView},
    };
    let accounts = [
        &head[0], &head[1], &head[2], &head[3], &head[18], &head[11], &head[12], &head[13],
        &extra[0], &extra[1], &extra[2], &extra[3], &extra[4], &head[14], &head[15], &head[16],
        &head[17], &head[7], &head[8], &head[9], &head[10], &extra[5], &extra[6],
    ];
    let metas = core::array::from_fn::<_, 23, _>(|i| {
        if i == 0 {
            InstructionAccount::readonly_signer(accounts[i].address())
        } else if i == 12 {
            InstructionAccount::writable_signer(accounts[i].address())
        } else if matches!(i, 8..=11) {
            InstructionAccount::writable(accounts[i].address())
        } else {
            InstructionAccount::readonly(accounts[i].address())
        }
    });
    let bump = [pda(program, &[b"pool"], &head[0])?];
    let seeds = [Seed::from(b"pool"), Seed::from(&bump)];
    invoke_signed(
        &InstructionView {
            program_id: head[9].address(),
            accounts: &metas,
            data: &[12],
        },
        &accounts,
        &[Signer::from(&seeds)],
    )
}
pub(super) fn finalize_token(program: &Address, a: &mut [AccountView]) -> ProgramResult {
    if a.len() != CONTEXT_LEN + 7 {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    let (head, extra) = a.split_at_mut(CONTEXT_LEN);
    let (p, l, t, e) = collecting_token(program, head)?;
    owned(program, &head[1], true)?;
    if l.count != l.expected {
        return Err(ProgramError::InvalidArgument);
    }
    token_program(&extra[5])?;
    associated(head[0].address(), head[12].address(), &extra[2])?;
    if t.vault != *extra[2].address()
        || balance(&extra[2], head[12].address(), head[0].address(), true)? < t.accounted
    {
        return Err(invalid());
    }
    let funding =
        math::token_floor_funding(add(p.carry, l.revenue)?, p.subsidy, l.floors).map_err(err)?;
    let mut floor = 0u64;
    let mut usd = 0u64;
    let mut tokens = 0u64;
    {
        let (left, right) = head.split_at_mut(3);
        let mut d = left[2].try_borrow_mut()?;
        let mut m = right[0].try_borrow_mut()?;
        for n in 0..l.count as usize {
            let at = LEDGER_HEADER + n * ROW_LEN;
            let row_floor = u64_at(&d, at + 112);
            let allocated = if funding.shortfall != 0 {
                math::token_floor_usd(floor, row_floor, l.floors, funding.usd_pot).map_err(err)?
            } else if l.weight == 0 {
                0
            } else {
                math::allocation(funding.remainder, u128_at(&d, at + 96), l.weight, row_floor)
                    .map_err(err)?
            };
            let gap = if funding.shortfall != 0 {
                row_floor.checked_sub(allocated).ok_or_else(overflow)?
            } else {
                0
            };
            let morse = math::token_floor_morse(gap, e.price).map_err(err)?;
            floor = add(floor, row_floor)?;
            usd = add(usd, allocated)?;
            tokens = add(tokens, morse)?;
            put64(&mut d, at + 120, allocated);
            put64(&mut m, TOKEN_EPOCH_HEADER + n * TOKEN_ROW_LEN, gap);
            put64(&mut m, TOKEN_EPOCH_HEADER + n * TOKEN_ROW_LEN + 8, morse);
        }
        if floor != l.floors {
            return Err(invalid());
        }
        math::token_reserve_available(tokens, u64::MAX).map_err(err)?;
        put64(&mut m, 100, funding.shortfall);
        put64(&mut m, 108, tokens);
        put64(&mut m, 132, usd);
        put64(&mut m, 140, l.floors);
    }
    if tokens != 0 {
        pda(
            head[9].address(),
            &[b"reserve-epoch", &l.epoch.to_le_bytes()],
            &extra[3],
        )?;
        head[3].try_borrow_mut()?[152..184].copy_from_slice(extra[3].address().as_ref());
        invoke_reserve(program, head, extra)?;
    }
    let carry = funding.usd_pot.checked_sub(usd).ok_or_else(overflow)?;
    {
        let mut d = head[0].try_borrow_mut()?;
        put64(&mut d, 188, p.subsidy - funding.subsidy_used);
        put64(&mut d, 196, carry);
        put64(&mut d, 204, add(p.liabilities, usd)?);
        put64(&mut d, 180, add(p.next_epoch, 1)?);
        put64(&mut d, 220, 0);
    }
    {
        let mut d = head[1].try_borrow_mut()?;
        put64(&mut d, 260, add(t.accounted, tokens)?);
        put64(&mut d, 268, add(t.liabilities, tokens)?);
    }
    {
        let mut d = head[2].try_borrow_mut()?;
        d[52] = 2;
        put64(&mut d, 136, funding.subsidy_used);
        put64(&mut d, 144, usd);
        put64(&mut d, 152, carry);
    }
    head[3].try_borrow_mut()?[148] = 2;
    Ok(())
}
pub(super) fn claim_token(program: &Address, a: &mut [AccountView], row: u8) -> ProgramResult {
    let [pool_account, token_pool, epoch_account, token_account, vault, destination, mint_account, spl] =
        a
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let p = pool(program, pool_account, false)?;
    let t = companion(program, &p, pool_account, token_pool, true)?;
    let l = ledger(program, epoch_account, pool_account, false)?;
    let e = token_epoch(
        program,
        token_account,
        token_pool,
        epoch_account,
        l.epoch,
        true,
    )?;
    if l.version != 2
        || l.status != 2
        || e.status != 2
        || row >= l.count
        || e.claimed & (1u64 << row) != 0
        || t.mint != *mint_account.address()
        || t.vault != *vault.address()
    {
        return Err(ProgramError::InvalidArgument);
    }
    let payout = {
        let d = epoch_account.try_borrow()?;
        Address::new_from_array(
            d[LEDGER_HEADER + row as usize * ROW_LEN + 32
                ..LEDGER_HEADER + row as usize * ROW_LEN + 64]
                .try_into()
                .unwrap(),
        )
    };
    let amount = u64_at(
        &token_account.try_borrow()?,
        TOKEN_EPOCH_HEADER + row as usize * TOKEN_ROW_LEN + 8,
    );
    if amount == 0 {
        return Err(ProgramError::InvalidArgument);
    }
    mint(mint_account, t.mint.as_ref())?;
    token_program(spl)?;
    associated(pool_account.address(), mint_account.address(), vault)?;
    associated(&payout, mint_account.address(), destination)?;
    if vault.address() == destination.address()
        || balance(vault, mint_account.address(), pool_account.address(), true)? < t.accounted
    {
        return Err(invalid());
    }
    balance(destination, mint_account.address(), &payout, false)?;
    let next = t.accounted.checked_sub(amount).ok_or_else(overflow)?;
    let claimed_amount = add(e.claimed_amount, amount)?;
    if claimed_amount > e.amount {
        return Err(invalid());
    }
    let bump = [pda(program, &[b"pool"], pool_account)?];
    let seeds = [Seed::from(b"pool"), Seed::from(&bump)];
    TransferChecked::new(vault, mint_account, destination, pool_account, amount, 6)
        .invoke_signed(&[Signer::from(&seeds)])?;
    {
        let mut d = token_pool.try_borrow_mut()?;
        put64(&mut d, 260, next);
        put64(&mut d, 268, next);
    }
    {
        let mut d = token_account.try_borrow_mut()?;
        put64(&mut d, 116, e.claimed | (1u64 << row));
        put64(&mut d, 124, claimed_amount);
    }
    Ok(())
}

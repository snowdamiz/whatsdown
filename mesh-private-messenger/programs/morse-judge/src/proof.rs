//! Staging, fork proofs and slashing (plan §5.2, §6.3, §6.6).

use crate::ed25519::verified;
use crate::error::{err, require, JudgeError};
use crate::frk::{is_fork, witness_message, Checkpoint, Frk, Second};
use crate::state::*;
use crate::util::*;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_token::instructions::{Burn, Transfer};

// ---------------------------------------------------------------- staging

pub(crate) fn stage_data<'a>(stage: &'a AccountView, program_id: &Address) -> Result<pinocchio::account::Ref<'a, [u8]>, ProgramError> {
    require(stage.owned_by(program_id) && stage.data_len() >= STAGE_HEADER_LEN, JudgeError::WrongAccount)?;
    let d = stage.try_borrow()?;
    require(d[0] == TAG_STAGE, JudgeError::WrongAccount)?;
    Ok(d)
}

fn complete(s: &[u8]) -> bool {
    u16_at(s, S_WRITTEN) == u16_at(s, S_TOTAL)
}

/// stage_init(nonce u64, total_len u16).
pub fn stage_init(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [submitter, log, stage, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(submitter)?;
    is_program(system, &SYSTEM_ID)?;
    require(data.len() == 10, JudgeError::InvalidData)?;
    let total = u16_at(data, 8) as usize;
    require((1..=MAX_FRK_LEN).contains(&total), JudgeError::StageInvalid)?;
    load(log, program_id, TAG_LOG, LOG_LEN)?;
    let nonce = &data[0..8];
    let (addr, bump) = pda(&[b"stage", submitter.address().as_ref(), nonce], program_id);
    require(stage.address() == &addr, JudgeError::WrongAccount)?;
    let b = [bump];
    let seeds = [Seed::from(b"stage"), Seed::from(submitter.address().as_ref()), Seed::from(nonce), Seed::from(&b)];
    create_pda(submitter, stage, STAGE_HEADER_LEN + total, program_id, &seeds)?;
    let mut s = stage.try_borrow_mut()?;
    s[0] = TAG_STAGE;
    s[1] = VERSION;
    s[S_BUMP] = bump;
    put(&mut s, S_SUBMITTER, submitter.address().as_ref());
    put(&mut s, S_LOG, log.address().as_ref());
    put(&mut s, S_NONCE, nonce);
    put_u16(&mut s, S_TOTAL, total as u16);
    Ok(())
}

/// stage_write(offset u16, bytes): append-only; offset must equal the bytes
/// written so far, so staged bytes never change once written.
pub fn stage_write(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [submitter, stage, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(submitter)?;
    require(data.len() > 2, JudgeError::InvalidData)?;
    stage_data(stage, program_id)?;
    let mut s = stage.try_borrow_mut()?;
    require(s[S_SUBMITTER..S_SUBMITTER + 32] == submitter.address().as_ref()[..], JudgeError::Unauthorized)?;
    let (offset, chunk) = (u16_at(data, 0) as usize, &data[2..]);
    let written = u16_at(&s, S_WRITTEN) as usize;
    require(offset == written && written + chunk.len() <= u16_at(&s, S_TOTAL) as usize, JudgeError::StageInvalid)?;
    put(&mut s, STAGE_HEADER_LEN + written, chunk);
    put_u16(&mut s, S_WRITTEN, (written + chunk.len()) as u16);
    Ok(())
}

/// stage_verify(ed_ix u8): records which of the complete proof's signatures
/// the Ed25519 instruction at `ed_ix` verifies. Anyone may call it: marks
/// only record facts about fixed bytes.
pub fn stage_verify(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [stage, log, sysvar, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == 1, JudgeError::InvalidData)?;
    let marks = {
        let s = stage_data(stage, program_id)?;
        require(complete(&s), JudgeError::StageInvalid)?;
        require(s[S_LOG..S_LOG + 32] == log.address().as_ref()[..], JudgeError::WrongAccount)?;
        let l = load(log, program_id, TAG_LOG, LOG_LEN)?;
        let frk = Frk::parse(&s[STAGE_HEADER_LEN..])?;
        marks(&frk, &l, sysvar, data[0])
    };
    require(stage.is_writable(), JudgeError::WrongAccount)?;
    let mut s = stage.try_borrow_mut()?;
    let old = u32_at(&s, S_MARKS);
    put_u32(&mut s, S_MARKS, old | marks);
    Ok(())
}

/// stage_close(): the submitter abandons a stage and gets its rent back.
pub fn stage_close(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    let [submitter, stage, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(submitter)?;
    {
        let s = stage_data(stage, program_id)?;
        require(s[S_SUBMITTER..S_SUBMITTER + 32] == submitter.address().as_ref()[..], JudgeError::Unauthorized)?;
    }
    close(stage, submitter)
}

pub(crate) fn close(stage: &mut AccountView, to: &mut AccountView) -> ProgramResult {
    to.set_lamports(to.lamports() + stage.lamports());
    stage.close()
}

// ---------------------------------------------------------------- judging

fn list_index(l: &[u8], id: &[u8]) -> Option<usize> {
    (0..l[LOG_WITNESS_COUNT] as usize).find(|i| {
        let e = entry(*i);
        l[e + E_ID_LEN] as usize == id.len() && &l[e + E_ID..e + E_ID + id.len()] == id
    })
}

/// Bit 0: C1's service signature; bit 1: inline C2's service signature;
/// bit 2 + j: attestation j by the listed witness of that ID.
fn marks(frk: &Frk, l: &[u8], sysvar: &AccountView, ed_ix: u8) -> u32 {
    let key = key_at(l, LOG_SERVICE_KEY);
    let mut m = 0;
    if *frk.log_key == key {
        let c1 = &frk.c1;
        if *c1.key() == key && verified(sysvar, ed_ix, &key, &c1.statement(), Some(c1.signature())) {
            m |= 1;
        }
        if let Second::Inline(c2) = &frk.c2 {
            if *c2.key() == key && verified(sysvar, ed_ix, &key, &c2.statement(), Some(c2.signature())) {
                m |= 2;
            }
        }
    }
    for (j, a) in frk.attestations.iter().enumerate() {
        let Some(a) = a else { break };
        let Some(i) = list_index(l, a.id) else { continue };
        let mut msg = [0u8; 128];
        let n = witness_message(a.id, a.hash, &mut msg);
        if verified(sysvar, ed_ix, &key_at(l, entry(i) + E_KEY), &msg[..n], Some(a.signature)) {
            m |= 1 << (2 + j);
        }
    }
    m
}

struct Verdict {
    proof_hash: [u8; 32],
    finder: [u8; 32],
    implicated: u16,
}

/// Decides whether `frk` proves a fork of this log and who it implicates.
/// Every attestation by a listed witness on either checkpoint must be
/// verified, so the proof's bytes alone fix who is slashed (the pay-once PDA
/// is keyed by those bytes).
fn judge(frk: &Frk, kind: u8, l: &[u8], ring: Option<&[u8]>, marks: u32, now_ms: u64) -> Result<Verdict, ProgramError> {
    require(frk.kind == kind, JudgeError::KindMismatch)?;
    require(frk.log_key[..] == l[LOG_SERVICE_KEY..LOG_SERVICE_KEY + 32], JudgeError::WrongLogKey)?;
    require(marks & 1 != 0, JudgeError::SignatureNotVerified)?;
    let c1 = frk.c1.checkpoint();
    let (c2, ring_entry_at): (Checkpoint, Option<usize>) = match &frk.c2 {
        Second::Inline(k) => {
            require(marks & 2 != 0, JudgeError::SignatureNotVerified)?;
            (k.checkpoint(), None)
        }
        Second::Ring(index) => {
            let Some(r) = ring else {
                return err(JudgeError::RingNotReady);
            };
            require(*index < u32_at(r, RH_COUNT), JudgeError::RingIndexInvalid)?;
            let o = ring_entry(*index);
            let c = Checkpoint {
                sequence: u64_at(r, o + RE_SEQUENCE),
                size: u64_at(r, o + RE_SIZE),
                root: key_at(r, o + RE_ROOT),
                hash: key_at(r, o + RE_HASH),
                timestamp_ms: u64_at(r, o + RE_TIMESTAMP),
            };
            (c, Some(o))
        }
    };
    require(is_fork(frk.kind, &c1, &c2, frk.contradiction.as_ref()), JudgeError::NotAFork)?;
    let oldest = c1.timestamp_ms.min(c2.timestamp_ms);
    require(now_ms <= oldest.saturating_add(PROOF_WINDOW_MS), JudgeError::ProofWindowClosed)?;
    let mut implicated = 0u16;
    for i in 0..l[LOG_WITNESS_COUNT] as usize {
        let e = entry(i);
        let id = &l[e + E_ID..e + E_ID + l[e + E_ID_LEN] as usize];
        let (mut signed1, mut signed2) = (false, false);
        if let (Some(o), Some(r)) = (ring_entry_at, ring) {
            let bit = u16_at(r, o + RE_BITMAP) & (1 << i) != 0;
            signed2 = bit && u64_at(r, o + RE_SLOT) >= u64_at(l, e + E_SINCE_SLOT);
        }
        for (j, a) in frk.attestations.iter().enumerate() {
            let Some(a) = a else { break };
            if a.id != id || (*a.hash != c1.hash && *a.hash != c2.hash) {
                continue;
            }
            require(marks & (1 << (2 + j)) != 0, JudgeError::AttestationNotVerified)?;
            signed1 |= *a.hash == c1.hash;
            signed2 |= *a.hash == c2.hash;
        }
        if signed1 && signed2 {
            implicated |= 1 << i;
        }
    }
    Ok(Verdict { proof_hash: frk.proof_hash(), finder: frk.finder, implicated })
}

// ---------------------------------------------------------------- slashing

struct Payout<'a> {
    usdc: [u8; 32],
    token: [u8; 32],
    payee: [u8; 32],
    named: bool,
    finder_usdc: &'a AccountView,
    finder_token: &'a AccountView,
    locked: &'a AccountView,
    token_mint: &'a AccountView,
}

/// The finder account must be a token account of `mint` owned by the payee;
/// when the proof names a finder it must also be that address's associated
/// token account.
fn check_finder(acct: &AccountView, mint: &[u8; 32], p: &Payout) -> ProgramResult {
    let (m, owner, _) = token_account(acct).map_err(|_| ProgramError::from(JudgeError::FinderAccountMismatch))?;
    require(m == *mint && owner == p.payee, JudgeError::FinderAccountMismatch)?;
    if p.named {
        let (ata, _) = pda(&[&p.payee, TOKEN_ID.as_ref(), mint], &ATA_ID);
        require(acct.address() == &ata, JudgeError::FinderAccountMismatch)?;
    }
    Ok(())
}

/// Takes the whole vault: 10% to the finder, 90% to the locked vault (USDC)
/// or burned (the Morse token).
fn slash_vault(vault: &AccountView, seeds: &[Seed], p: &Payout) -> ProgramResult {
    let Some((mint, amount)) = vault_balance(vault)? else {
        return Ok(());
    };
    if amount == 0 {
        return Ok(());
    }
    let is_usdc = mint == p.usdc;
    require(is_usdc || (!zero(&p.token) && mint == p.token), JudgeError::MintNotAllowed)?;
    let finder = if is_usdc { p.finder_usdc } else { p.finder_token };
    check_finder(finder, &mint, p)?;
    let share = amount / FINDER_DIVISOR;
    let rest = amount - share;
    let signers = [Signer::from(seeds)];
    if share > 0 {
        Transfer::new(vault, finder, vault, share).invoke_signed(&signers)?;
    }
    if is_usdc {
        Transfer::new(vault, p.locked, vault, rest).invoke_signed(&signers)
    } else {
        require(p.token_mint.address().as_ref() == p.token, JudgeError::WrongAccount)?;
        Burn::new(vault, p.token_mint, vault, rest).invoke_signed(&signers)
    }
}

const MODE_INLINE: u8 = 0;
const MODE_STAGED: u8 = 1;

/// prove_same_size / prove_contradiction / prove_rollback.
/// data: mode u8 (0 inline: ed_ix u8 ‖ FRK; 1 staged: nothing more).
pub fn prove(program_id: &Address, accounts: &mut [AccountView], data: &[u8], kind: u8) -> ProgramResult {
    let [submitter, config, log, ring, proof, stage, sysvar, system, token, locked, token_mint, finder_usdc, finder_token, dir_vault, rest @ ..] =
        accounts
    else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(submitter)?;
    is_program(system, &SYSTEM_ID)?;
    is_program(token, &TOKEN_ID)?;
    require(!data.is_empty(), JudgeError::InvalidData)?;
    let (t, slot) = now()?;
    let now_ms = (t.max(0) as u64).saturating_mul(1000);
    let (usdc, token_key) = {
        let cfg = load(config, program_id, TAG_CONFIG, CONFIG_LEN)?;
        (key_at(&cfg, CFG_USDC_MINT), key_at(&cfg, CFG_TOKEN_MINT))
    };
    let verdict = {
        let l = load(log, program_id, TAG_LOG, LOG_LEN)?;
        require(ring.address().as_ref() == &l[LOG_RING..LOG_RING + 32], JudgeError::WrongAccount)?;
        require(locked.address().as_ref() == &l[LOG_LOCKED_VAULT..LOG_LOCKED_VAULT + 32], JudgeError::WrongAccount)?;
        require(dir_vault.address().as_ref() == &l[LOG_DIR_VAULT..LOG_DIR_VAULT + 32], JudgeError::WrongAccount)?;
        let ring_ready = ring.owned_by(program_id) && ring.data_len() == RING_LEN;
        let r = if ring_ready { Some(ring.try_borrow()?) } else { None };
        match data[0] {
            MODE_INLINE => {
                require(data.len() >= 2, JudgeError::InvalidData)?;
                let frk = Frk::parse(&data[2..])?;
                let m = marks(&frk, &l, sysvar, data[1]);
                judge(&frk, kind, &l, r.as_deref(), m, now_ms)?
            }
            MODE_STAGED => {
                let s = stage_data(stage, program_id)?;
                require(s[S_SUBMITTER..S_SUBMITTER + 32] == submitter.address().as_ref()[..], JudgeError::Unauthorized)?;
                require(s[S_LOG..S_LOG + 32] == log.address().as_ref()[..], JudgeError::WrongAccount)?;
                require(complete(&s), JudgeError::StageInvalid)?;
                let frk = Frk::parse(&s[STAGE_HEADER_LEN..])?;
                judge(&frk, kind, &l, r.as_deref(), u32_at(&s, S_MARKS), now_ms)?
            }
            _ => return err(JudgeError::InvalidData),
        }
    };

    // Pay once per proof hash.
    let (paddr, pbump) = pda(&[b"proof", &verdict.proof_hash], program_id);
    require(proof.address() == &paddr, JudgeError::WrongAccount)?;
    require(!proof.owned_by(program_id), JudgeError::AlreadyProven)?;
    let pb = [pbump];
    create_pda(submitter, proof, PROOF_LEN, program_id, &[Seed::from(b"proof"), Seed::from(&verdict.proof_hash), Seed::from(&pb)])?;

    let named = !zero(&verdict.finder);
    let payout = Payout {
        usdc,
        token: token_key,
        payee: if named { verdict.finder } else { submitter.address().to_bytes() },
        named,
        finder_usdc,
        finder_token,
        locked,
        token_mint,
    };
    let mut slashed = false;
    let mut l = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
    let log_id = key_at(&l, LOG_ID);
    if !matches!(l[LOG_DIR_STATUS], SLASHED | WITHDRAWN) {
        let b = [l[LOG_DIR_VAULT_BUMP]];
        slash_vault(dir_vault, &[Seed::from(b"bond"), Seed::from(&log_id), Seed::from(b"directory"), Seed::from(&b)], &payout)?;
        l[LOG_DIR_STATUS] = SLASHED;
        l[LOG_SERVICE_SLASHED] = 1;
        put_i64(&mut l, LOG_SLASHED_AT, t);
        slashed = true;
    }
    require(rest.len() == 2 * verdict.implicated.count_ones() as usize, JudgeError::ImplicatedAccountsMismatch)?;
    let mut pairs = rest.chunks_exact_mut(2);
    for i in (0..MAX_WITNESSES).filter(|i| verdict.implicated & (1 << i) != 0) {
        let [w, vault] = pairs.next().unwrap() else { unreachable!() };
        let e = entry(i);
        require(w.address().as_ref() == &l[e + E_ACCOUNT..e + E_ACCOUNT + 32], JudgeError::ImplicatedAccountsMismatch)?;
        let mut wd = load_mut(w, program_id, TAG_WITNESS, WITNESS_LEN)?;
        if matches!(wd[W_STATUS], SLASHED | WITHDRAWN) {
            continue;
        }
        require(vault.address().as_ref() == &wd[W_VAULT..W_VAULT + 32], JudgeError::ImplicatedAccountsMismatch)?;
        let idh = sha256(&[&wd[W_ID..W_ID + wd[W_ID_LEN] as usize]]);
        let b = [wd[W_VAULT_BUMP]];
        slash_vault(vault, &[Seed::from(b"bond"), Seed::from(&log_id), Seed::from(&idh), Seed::from(&b)], &payout)?;
        wd[W_STATUS] = SLASHED;
        slashed = true;
    }
    require(slashed, JudgeError::NothingToSlash)?;
    drop(l);

    let mut pd = proof.try_borrow_mut()?;
    pd[0] = TAG_PROOF;
    pd[1] = VERSION;
    pd[2] = pbump;
    pd[P_KIND] = kind;
    put(&mut pd, P_LOG, log.address().as_ref());
    put(&mut pd, P_HASH, &verdict.proof_hash);
    put(&mut pd, P_PAID_TO, &payout.payee);
    put_u64(&mut pd, P_SLOT, slot);
    drop(pd);
    if data[0] == MODE_STAGED {
        close(stage, submitter)?;
    }
    Ok(())
}

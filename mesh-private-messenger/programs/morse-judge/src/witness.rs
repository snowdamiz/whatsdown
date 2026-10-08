//! Witness registration and bond custody (plan §6.6 "Bond custody").
//! Money leaves a bond vault only through `withdraw` (here) or a slash
//! (`proof.rs`).

use crate::ed25519::verified;
use crate::error::{require, JudgeError};
use crate::governance::authority;
use crate::state::*;
use crate::util::*;
use pinocchio::{
    cpi::{Seed, Signer},
    error::ProgramError,
    AccountView, Address, ProgramResult,
};
use pinocchio_token::instructions::Transfer;

const REGISTER_DOMAIN: &[u8; 25] = b"morse-witness-register-v1";
const REPLACE_NONE: u8 = 0xFF;

fn valid_id(id: &[u8]) -> bool {
    (1..=64).contains(&id.len()) && id.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// register_witness(signing_key32, payout32, operator_hash32, excluded u8,
/// ed_ix u8, id_len u8, id). Signed by the operator wallet; the Ed25519
/// instruction proves control of the witness key over
/// "morse-witness-register-v1" ‖ id ‖ operator ‖ payout. The witness is not
/// in the log's list (and so cannot cosign or be implicated) until
/// governance admits it.
pub fn register_witness(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [operator, log, witness, sysvar, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(operator)?;
    is_program(system, &SYSTEM_ID)?;
    require(data.len() >= 99 && data.len() == 99 + data[98] as usize, JudgeError::InvalidData)?;
    let key: &[u8; 32] = data[0..32].try_into().unwrap();
    let payout = &data[32..64];
    let (excluded, ed_ix, id) = (data[96], data[97], &data[99..]);
    require(valid_id(id), JudgeError::InvalidWitnessId)?;
    require(excluded <= 1, JudgeError::InvalidData)?;
    let mut msg = [0u8; 25 + 64 + 64];
    msg[..25].copy_from_slice(REGISTER_DOMAIN);
    msg[25..25 + id.len()].copy_from_slice(id);
    msg[25 + id.len()..57 + id.len()].copy_from_slice(operator.address().as_ref());
    msg[57 + id.len()..89 + id.len()].copy_from_slice(payout);
    require(verified(sysvar, ed_ix, key, &msg[..89 + id.len()], None), JudgeError::SignatureNotVerified)?;
    let log_id = key_at(&load(log, program_id, TAG_LOG, LOG_LEN)?, LOG_ID);
    let idh = sha256(&[id]);
    let (waddr, wbump) = pda(&[b"witness", &log_id, &idh], program_id);
    let (vault, vbump) = pda(&[b"bond", &log_id, &idh], program_id);
    require(witness.address() == &waddr, JudgeError::WrongAccount)?;
    let wb = [wbump];
    create_pda(operator, witness, WITNESS_LEN, program_id, &[Seed::from(b"witness"), Seed::from(&log_id), Seed::from(&idh), Seed::from(&wb)])?;
    let mut w = witness.try_borrow_mut()?;
    w[0] = TAG_WITNESS;
    w[1] = VERSION;
    w[W_BUMP] = wbump;
    w[W_STATUS] = REGISTERED;
    w[W_EXCLUDED] = excluded;
    w[W_LIST_INDEX] = NOT_LISTED;
    w[W_VAULT_BUMP] = vbump;
    w[W_ID_LEN] = id.len() as u8;
    put(&mut w, W_ID, id);
    put(&mut w, W_LOG, log.address().as_ref());
    put(&mut w, W_KEY, key);
    put(&mut w, W_OPERATOR, operator.address().as_ref());
    put(&mut w, W_PAYOUT, payout);
    put(&mut w, W_OPERATOR_HASH, &data[64..96]);
    put(&mut w, W_VAULT, vault.as_ref());
    Ok(())
}

/// admit_witness(replace u8, excluded u8): governance puts a registered
/// witness into the log's list of 16 (bit i of every cosign bitmap is list
/// entry i). `replace` = 0xFF appends; otherwise it names a slot whose
/// witness is Slashed or Withdrawn. `excluded` = 1 marks the witness as
/// never paid (one-way).
pub fn admit_witness(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, config, log, witness, replaced, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == 2 && data[1] <= 1, JudgeError::InvalidData)?;
    let (replace, excluded) = (data[0], data[1]);
    authority(auth, &load(config, program_id, TAG_CONFIG, CONFIG_LEN)?)?;
    let (_, slot) = now()?;
    let log_addr = log.address().to_bytes();
    let witness_addr = witness.address().to_bytes();
    let mut l = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
    let mut w = load_mut(witness, program_id, TAG_WITNESS, WITNESS_LEN)?;
    require(w[W_LOG..W_LOG + 32] == log_addr, JudgeError::WrongAccount)?;
    require(w[W_LIST_INDEX] == NOT_LISTED && matches!(w[W_STATUS], REGISTERED | ACTIVE), JudgeError::InvalidStatus)?;
    let count = l[LOG_WITNESS_COUNT] as usize;
    let index = if replace == REPLACE_NONE {
        require(count < MAX_WITNESSES, JudgeError::WitnessListFull)?;
        count
    } else {
        let i = replace as usize;
        require(i < count && replaced.address().as_ref() == &l[entry(i) + E_ACCOUNT..entry(i) + E_ACCOUNT + 32], JudgeError::SlotNotReusable)?;
        let mut old = load_mut(replaced, program_id, TAG_WITNESS, WITNESS_LEN)?;
        require(matches!(old[W_STATUS], SLASHED | WITHDRAWN), JudgeError::SlotNotReusable)?;
        old[W_LIST_INDEX] = NOT_LISTED;
        i
    };
    for i in (0..count).filter(|i| *i != index) {
        require(l[entry(i) + E_KEY..entry(i) + E_KEY + 32] != w[W_KEY..W_KEY + 32], JudgeError::DuplicateSigningKey)?;
    }
    let e = entry(index);
    let id_len = w[W_ID_LEN] as usize;
    l[e..e + ENTRY_LEN].fill(0);
    l[e + E_ID_LEN] = id_len as u8;
    put(&mut l, e + E_ID, &w[W_ID..W_ID + id_len]);
    put(&mut l, e + E_KEY, &w[W_KEY..W_KEY + 32]);
    put(&mut l, e + E_ACCOUNT, &witness_addr);
    put_u64(&mut l, e + E_SINCE_SLOT, slot);
    if replace == REPLACE_NONE {
        l[LOG_WITNESS_COUNT] += 1;
    }
    w[W_LIST_INDEX] = index as u8;
    w[W_EXCLUDED] |= excluded;
    Ok(())
}

/// bond_directory(amount u64): governance posts or tops up the log's
/// directory bond. The first bond fixes the vault's mint (USDC or token).
pub fn bond_directory(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, config, log, vault, mint, source, system, token, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    is_program(system, &SYSTEM_ID)?;
    is_program(token, &TOKEN_ID)?;
    require(data.len() == 8, JudgeError::InvalidData)?;
    let amount = u64_at(data, 0);
    require(amount > 0, JudgeError::AmountZero)?;
    {
        let cfg = load(config, program_id, TAG_CONFIG, CONFIG_LEN)?;
        authority(auth, &cfg)?;
        allowed_mint(&cfg, &mint.address().to_bytes())?;
    }
    let mut l = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
    require(matches!(l[LOG_DIR_STATUS], REGISTERED | ACTIVE), JudgeError::InvalidStatus)?;
    require(vault.address().as_ref() == &l[LOG_DIR_VAULT..LOG_DIR_VAULT + 32], JudgeError::WrongAccount)?;
    let log_id = key_at(&l, LOG_ID);
    let b = [l[LOG_DIR_VAULT_BUMP]];
    match vault_balance(vault)? {
        None => create_vault(auth, vault, mint, &[Seed::from(b"bond"), Seed::from(&log_id), Seed::from(b"directory"), Seed::from(&b)])?,
        Some((m, _)) => require(m == mint.address().to_bytes(), JudgeError::MintNotAllowed)?,
    }
    Transfer::new(source, vault, auth, amount).invoke()?;
    l[LOG_DIR_STATUS] = ACTIVE;
    Ok(())
}

/// bond(amount u64): the operator posts or tops up its witness bond. The
/// first bond must reach the minimum for new bonds in that mint.
pub fn bond(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [operator, config, log, witness, vault, mint, source, system, token, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(operator)?;
    is_program(system, &SYSTEM_ID)?;
    is_program(token, &TOKEN_ID)?;
    require(data.len() == 8, JudgeError::InvalidData)?;
    let amount = u64_at(data, 0);
    require(amount > 0, JudgeError::AmountZero)?;
    let mint_key = mint.address().to_bytes();
    let minimum = {
        let cfg = load(config, program_id, TAG_CONFIG, CONFIG_LEN)?;
        allowed_mint(&cfg, &mint_key)?;
        u64_at(&cfg, if mint_key == key_at(&cfg, CFG_USDC_MINT) { CFG_MIN_BOND_USDC } else { CFG_MIN_BOND_TOKEN })
    };
    let log_id = key_at(&load(log, program_id, TAG_LOG, LOG_LEN)?, LOG_ID);
    let mut w = load_mut(witness, program_id, TAG_WITNESS, WITNESS_LEN)?;
    require(w[W_LOG..W_LOG + 32] == log.address().as_ref()[..], JudgeError::WrongAccount)?;
    require(w[W_OPERATOR..W_OPERATOR + 32] == operator.address().as_ref()[..], JudgeError::Unauthorized)?;
    require(matches!(w[W_STATUS], REGISTERED | ACTIVE), JudgeError::InvalidStatus)?;
    require(vault.address().as_ref() == &w[W_VAULT..W_VAULT + 32], JudgeError::WrongAccount)?;
    let idh = sha256(&[&w[W_ID..W_ID + w[W_ID_LEN] as usize]]);
    let b = [w[W_VAULT_BUMP]];
    let held = match vault_balance(vault)? {
        None => {
            create_vault(operator, vault, mint, &[Seed::from(b"bond"), Seed::from(&log_id), Seed::from(&idh), Seed::from(&b)])?;
            0
        }
        Some((m, held)) => {
            require(m == mint_key, JudgeError::MintNotAllowed)?;
            held
        }
    };
    if w[W_STATUS] == REGISTERED {
        require(held.saturating_add(amount) >= minimum, JudgeError::BondBelowMinimum)?;
    }
    Transfer::new(source, vault, operator, amount).invoke()?;
    w[W_STATUS] = ACTIVE;
    Ok(())
}

const TARGET_DIRECTORY: u8 = 0;
const TARGET_WITNESS: u8 = 1;

/// request_unbond(target u8: 0 directory | 1 witness).
pub fn request_unbond(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [owner, config, log, witness, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == 1, JudgeError::InvalidData)?;
    let (t, _) = now()?;
    match data[0] {
        TARGET_DIRECTORY => {
            authority(owner, &load(config, program_id, TAG_CONFIG, CONFIG_LEN)?)?;
            let mut l = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
            require(matches!(l[LOG_DIR_STATUS], REGISTERED | ACTIVE), JudgeError::InvalidStatus)?;
            l[LOG_DIR_STATUS] = UNBONDING;
            put_i64(&mut l, LOG_DIR_UNBOND_AT, t + UNBONDING_SECONDS);
        }
        TARGET_WITNESS => {
            signer(owner)?;
            let mut w = load_mut(witness, program_id, TAG_WITNESS, WITNESS_LEN)?;
            require(w[W_OPERATOR..W_OPERATOR + 32] == owner.address().as_ref()[..], JudgeError::Unauthorized)?;
            require(matches!(w[W_STATUS], REGISTERED | ACTIVE), JudgeError::InvalidStatus)?;
            w[W_STATUS] = UNBONDING;
            put_i64(&mut w, W_UNBOND_AT, t + UNBONDING_SECONDS);
        }
        _ => return Err(JudgeError::InvalidData.into()),
    }
    Ok(())
}

/// withdraw(target u8): the whole vault to a token account owned by the bond
/// owner, 30 days after request_unbond, never after a slash.
pub fn withdraw(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [owner, config, log, witness, vault, destination, token, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    is_program(token, &TOKEN_ID)?;
    require(data.len() == 1, JudgeError::InvalidData)?;
    let (t, _) = now()?;
    let (_, dest_owner, _) = token_account(destination)?;
    require(dest_owner == owner.address().to_bytes(), JudgeError::WrongDestination)?;
    let log_addr = log.address().to_bytes();
    let mut l = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
    let log_id = key_at(&l, LOG_ID);
    match data[0] {
        TARGET_DIRECTORY => {
            authority(owner, &load(config, program_id, TAG_CONFIG, CONFIG_LEN)?)?;
            require(l[LOG_DIR_STATUS] == UNBONDING, JudgeError::InvalidStatus)?;
            require(t >= i64_at(&l, LOG_DIR_UNBOND_AT), JudgeError::UnbondingNotElapsed)?;
            require(vault.address().as_ref() == &l[LOG_DIR_VAULT..LOG_DIR_VAULT + 32], JudgeError::WrongAccount)?;
            let b = [l[LOG_DIR_VAULT_BUMP]];
            drain(vault, destination, &[Seed::from(b"bond"), Seed::from(&log_id), Seed::from(b"directory"), Seed::from(&b)])?;
            l[LOG_DIR_STATUS] = WITHDRAWN;
        }
        TARGET_WITNESS => {
            signer(owner)?;
            let mut w = load_mut(witness, program_id, TAG_WITNESS, WITNESS_LEN)?;
            require(w[W_LOG..W_LOG + 32] == log_addr, JudgeError::WrongAccount)?;
            require(w[W_OPERATOR..W_OPERATOR + 32] == owner.address().as_ref()[..], JudgeError::Unauthorized)?;
            require(w[W_STATUS] == UNBONDING, JudgeError::InvalidStatus)?;
            require(t >= i64_at(&w, W_UNBOND_AT), JudgeError::UnbondingNotElapsed)?;
            require(vault.address().as_ref() == &w[W_VAULT..W_VAULT + 32], JudgeError::WrongAccount)?;
            let idh = sha256(&[&w[W_ID..W_ID + w[W_ID_LEN] as usize]]);
            let b = [w[W_VAULT_BUMP]];
            drain(vault, destination, &[Seed::from(b"bond"), Seed::from(&log_id), Seed::from(&idh), Seed::from(&b)])?;
            w[W_STATUS] = WITHDRAWN;
        }
        _ => return Err(JudgeError::InvalidData.into()),
    }
    Ok(())
}

fn drain(vault: &AccountView, destination: &AccountView, seeds: &[Seed]) -> ProgramResult {
    if let Some((_, amount)) = vault_balance(vault)? {
        if amount > 0 {
            Transfer::new(vault, destination, vault, amount).invoke_signed(&[Signer::from(seeds)])?;
        }
    }
    Ok(())
}

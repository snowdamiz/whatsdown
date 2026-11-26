//! Logs, the anchor ring, `post_anchor` and `cosign` (plan §6.5, §6.6).

use crate::ed25519::verified;
use crate::error::{err, require, JudgeError};
use crate::frk::{witness_message, Ktk};
use crate::governance::authority;
use crate::proof::{close, stage_data};
use crate::state::*;
use crate::util::*;
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{rent::Rent, Sysvar},
    AccountView, Address, ProgramResult, Resize,
};
use pinocchio_system::instructions::Transfer as SystemTransfer;

/// register_log(log_id32, service_key32, anchor_authority32).
pub fn register_log(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, payer, config, log, locked, usdc_mint, system, token, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(payer)?;
    is_program(system, &SYSTEM_ID)?;
    is_program(token, &TOKEN_ID)?;
    // 96 bytes (a main log) or 97 with the kind byte.
    let kind = data.get(96).copied().unwrap_or(KIND_MAIN);
    require((data.len() == 96 || data.len() == 97) && kind <= KIND_CANARY, JudgeError::InvalidData)?;
    let log_id: &[u8; 32] = data[0..32].try_into().unwrap();
    {
        let cfg = load(config, program_id, TAG_CONFIG, CONFIG_LEN)?;
        authority(auth, &cfg)?;
        require(usdc_mint.address().as_ref() == &cfg[CFG_USDC_MINT..CFG_USDC_MINT + 32], JudgeError::MintNotAllowed)?;
    }
    let (log_addr, log_bump) = pda(&[b"log", log_id], program_id);
    let (ring, _) = pda(&[b"ring", log_id], program_id);
    let (dir_vault, dir_bump) = pda(&[b"bond", log_id, b"directory"], program_id);
    let (locked_addr, locked_bump) = pda(&[b"locked", log_id], program_id);
    require(log.address() == &log_addr && locked.address() == &locked_addr, JudgeError::WrongAccount)?;
    let lb = [log_bump];
    create_pda(payer, log, LOG_LEN, program_id, &[Seed::from(b"log"), Seed::from(log_id), Seed::from(&lb)])?;
    let kb = [locked_bump];
    create_vault(payer, locked, usdc_mint, &[Seed::from(b"locked"), Seed::from(log_id), Seed::from(&kb)])?;
    let mut d = log.try_borrow_mut()?;
    d[0] = TAG_LOG;
    d[1] = VERSION;
    d[LOG_BUMP] = log_bump;
    d[LOG_DIR_STATUS] = REGISTERED;
    d[LOG_DIR_VAULT_BUMP] = dir_bump;
    d[LOG_KIND] = kind;
    put(&mut d, LOG_ID, log_id);
    put(&mut d, LOG_SERVICE_KEY, &data[32..64]);
    put(&mut d, LOG_ANCHOR_AUTHORITY, &data[64..96]);
    put(&mut d, LOG_RING, ring.as_ref());
    put(&mut d, LOG_DIR_VAULT, dir_vault.as_ref());
    put(&mut d, LOG_LOCKED_VAULT, locked_addr.as_ref());
    Ok(())
}

/// set_anchor_authority(new32): governance rotates a log's hot anchor key.
pub fn set_anchor_authority(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, config, log, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == 32, JudgeError::InvalidData)?;
    authority(auth, &load(config, program_id, TAG_CONFIG, CONFIG_LEN)?)?;
    let mut d = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
    put(&mut d, LOG_ANCHOR_AUTHORITY, data);
    Ok(())
}

/// grow_ring(): creates the ring at 10,240 bytes, then each call adds 10,240
/// until it reaches 426,048. Anyone may pay.
pub fn grow_ring(program_id: &Address, accounts: &mut [AccountView], _data: &[u8]) -> ProgramResult {
    let [payer, log, ring, system, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(payer)?;
    is_program(system, &SYSTEM_ID)?;
    let (log_id, ring_addr) = {
        let d = load(log, program_id, TAG_LOG, LOG_LEN)?;
        (key_at(&d, LOG_ID), key_at(&d, LOG_RING))
    };
    require(ring.address().as_ref() == ring_addr, JudgeError::WrongAccount)?;
    if ring.owned_by(&SYSTEM_ID) {
        let (_, bump) = pda(&[b"ring", &log_id], program_id);
        let b = [bump];
        create_pda(payer, ring, RING_GROW_STEP, program_id, &[Seed::from(b"ring"), Seed::from(&log_id), Seed::from(&b)])?;
        put(&mut ring.try_borrow_mut()?, RH_LOG_ID, &log_id);
        return Ok(());
    }
    require(ring.owned_by(program_id), JudgeError::WrongAccount)?;
    let len = ring.data_len();
    require(len < RING_LEN, JudgeError::RingAlreadyGrown)?;
    let new_len = (len + RING_GROW_STEP).min(RING_LEN);
    let deficit = Rent::get()?.try_minimum_balance(new_len)?.saturating_sub(ring.lamports());
    if deficit > 0 {
        SystemTransfer { from: payer, to: ring, lamports: deficit }.invoke()?;
    }
    ring.resize(new_len)
}

/// Where the newest non-evidence ("tip") entry is, if any.
fn tip(r: &[u8]) -> Option<u32> {
    let (head, count) = (u32_at(r, RH_HEAD), u32_at(r, RH_COUNT));
    (1..=count).map(|back| (head + RING_CAPACITY - back) % RING_CAPACITY).find(|i| r[ring_entry(*i) + RE_EVIDENCE] == 0)
}

/// post_anchor(ed_ix u8, KTK188).
pub fn post_anchor(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [anchor_authority, log, ring, sysvar, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    signer(anchor_authority)?;
    require(data.len() == 1 + 188, JudgeError::InvalidData)?;
    let ktk = Ktk::parse(&data[1..])?;
    let (t, slot) = now()?;
    let mut l = load_mut(log, program_id, TAG_LOG, LOG_LEN)?;
    require(anchor_authority.address().as_ref() == &l[LOG_ANCHOR_AUTHORITY..LOG_ANCHOR_AUTHORITY + 32], JudgeError::Unauthorized)?;
    // A slashed canary log's ring is frozen, so its closing date (close_log)
    // is at least 28 days after every anchor it holds.
    require(!(l[LOG_KIND] == KIND_CANARY && l[LOG_SERVICE_SLASHED] == 1), JudgeError::InvalidStatus)?;
    require(ring.address().as_ref() == &l[LOG_RING..LOG_RING + 32], JudgeError::WrongAccount)?;
    require(ktk.key()[..] == l[LOG_SERVICE_KEY..LOG_SERVICE_KEY + 32], JudgeError::InvalidCheckpoint)?;
    require(verified(sysvar, data[0], ktk.key(), &ktk.statement(), Some(ktk.signature())), JudgeError::SignatureNotVerified)?;
    require(ring.owned_by(program_id) && ring.data_len() == RING_LEN, JudgeError::RingNotReady)?;
    let c = ktk.checkpoint();
    let mut r = ring.try_borrow_mut()?;
    let evidence = match tip(&r) {
        None => 0,
        Some(i) => {
            let o = ring_entry(i);
            let (seq, size) = (u64_at(&r, o + RE_SEQUENCE), u64_at(&r, o + RE_SIZE));
            let same_root = c.root[..] == r[o + RE_ROOT..o + RE_ROOT + 32];
            if c.sequence == seq {
                require(c.hash[..] != r[o + RE_HASH..o + RE_HASH + 32], JudgeError::DuplicateAnchor)?;
                3
            } else if (c.sequence > seq) != (c.size > size) && c.size != size {
                3 // sequence order and size order disagree: F3
            } else if c.size == size && !same_root {
                1 // same size, different root: F1
            } else if c.sequence < seq {
                return err(JudgeError::StaleAnchor);
            } else {
                0
            }
        }
    };
    let epoch = epoch_of(t);
    let head = u32_at(&r, RH_HEAD);
    let o = ring_entry(head);
    put_u64(&mut r, o + RE_SEQUENCE, c.sequence);
    put_u64(&mut r, o + RE_SIZE, c.size);
    put(&mut r, o + RE_ROOT, &c.root);
    put(&mut r, o + RE_HASH, &c.hash);
    put_u64(&mut r, o + RE_TIMESTAMP, c.timestamp_ms);
    put_u64(&mut r, o + RE_SLOT, slot);
    put_u16(&mut r, o + RE_BITMAP, 0);
    r[o + RE_EVIDENCE] = evidence;
    r[o + RE_EVIDENCE + 1] = 0;
    put_u32(&mut r, o + RE_EPOCH, epoch as u32);
    put_u32(&mut r, RH_HEAD, (head + 1) % RING_CAPACITY);
    let count = u32_at(&r, RH_COUNT);
    put_u32(&mut r, RH_COUNT, (count + 1).min(RING_CAPACITY));
    if evidence == 0 {
        put_u64(&mut r, RH_LAST_SEQUENCE, c.sequence);
        put_u64(&mut r, RH_LAST_SIZE, c.size);
        put_u64(&mut r, RH_LAST_SLOT, slot);
        bump_counter(&mut l, LOG_ANCHOR_COUNTS, epoch);
    }
    Ok(())
}

/// cosign(ring_index u32, list_index u8, ed_ix u8). Anyone may pay; the
/// Ed25519 instruction at `ed_ix` carries the witness signature (it is not
/// stored, so the judge does not need its bytes).
pub fn cosign(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [log, ring, witness, sysvar, ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.len() == 6, JudgeError::InvalidData)?;
    let index = u32_at(data, 0);
    let li = data[4] as usize;
    let (_, slot) = now()?;
    let l = load(log, program_id, TAG_LOG, LOG_LEN)?;
    require(ring.address().as_ref() == &l[LOG_RING..LOG_RING + 32], JudgeError::WrongAccount)?;
    require(li < l[LOG_WITNESS_COUNT] as usize, JudgeError::WrongAccount)?;
    let e = entry(li);
    require(witness.address().as_ref() == &l[e + E_ACCOUNT..e + E_ACCOUNT + 32], JudgeError::WrongAccount)?;
    require(ring.owned_by(program_id) && ring.data_len() == RING_LEN, JudgeError::RingNotReady)?;
    let mut r = ring.try_borrow_mut()?;
    require(index < u32_at(&r, RH_COUNT), JudgeError::RingIndexInvalid)?;
    let o = ring_entry(index);
    let posted = u64_at(&r, o + RE_SLOT);
    require(posted >= u64_at(&l, e + E_SINCE_SLOT), JudgeError::RingIndexInvalid)?;
    require(slot <= posted + COSIGN_WINDOW_SLOTS, JudgeError::CosignWindowClosed)?;
    let mut msg = [0u8; 128];
    let n = witness_message(&l[e + E_ID..e + E_ID + l[e + E_ID_LEN] as usize], &key_at(&r, o + RE_HASH), &mut msg);
    require(verified(sysvar, data[5], &key_at(&l, e + E_KEY), &msg[..n], None), JudgeError::SignatureNotVerified)?;
    let mut w = load_mut(witness, program_id, TAG_WITNESS, WITNESS_LEN)?;
    require(matches!(w[W_STATUS], REGISTERED | ACTIVE | UNBONDING), JudgeError::InvalidStatus)?;
    let bitmap = u16_at(&r, o + RE_BITMAP);
    if bitmap & (1 << li) != 0 {
        return Ok(()); // already counted; a no-op keeps cranks idempotent
    }
    put_u16(&mut r, o + RE_BITMAP, bitmap | (1 << li));
    if r[o + RE_EVIDENCE] == 0 {
        bump_counter(&mut w, W_COSIGN_COUNTS, u32_at(&r, o + RE_EPOCH) as u64);
    }
    Ok(())
}

/// close_log(): governance closes a slashed canary log's ring, 28 days after
/// the slash, sending its rent to `destination`; stages made for the log are
/// closed with their rent returned to their submitters. Main-kind logs are
/// never closable. The Log, Witness, Proof and vault accounts stay.
/// Accounts: authority (s), Config, Log, ring (w), destination (w), then
/// (stage (w), its submitter (w)) pairs.
pub fn close_log(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [auth, config, log, ring, destination, rest @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    require(data.is_empty() && rest.len() % 2 == 0, JudgeError::InvalidData)?;
    authority(auth, &load(config, program_id, TAG_CONFIG, CONFIG_LEN)?)?;
    let (t, _) = now()?;
    let (ring_addr, closable, slashed_at) = {
        let l = load(log, program_id, TAG_LOG, LOG_LEN)?;
        (key_at(&l, LOG_RING), l[LOG_KIND] == KIND_CANARY && l[LOG_SERVICE_SLASHED] == 1, i64_at(&l, LOG_SLASHED_AT))
    };
    require(closable, JudgeError::NotClosable)?;
    require(t >= slashed_at + (PROOF_WINDOW_MS / 1000) as i64, JudgeError::CloseTooEarly)?;
    require(ring.address().as_ref() == ring_addr, JudgeError::WrongAccount)?;
    if ring.owned_by(program_id) {
        close(ring, destination)?;
    }
    for pair in rest.chunks_exact_mut(2) {
        let [stage, submitter] = pair else { unreachable!() };
        {
            let s = stage_data(stage, program_id)?;
            require(s[S_LOG..S_LOG + 32] == log.address().as_ref()[..], JudgeError::WrongAccount)?;
            require(s[S_SUBMITTER..S_SUBMITTER + 32] == submitter.address().as_ref()[..], JudgeError::WrongAccount)?;
        }
        close(stage, submitter)?;
    }
    Ok(())
}

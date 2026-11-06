//! Immutable witness identities and generation snapshots. A bitmap is only
//! meaningful with the exact generation recorded when its checkpoint was posted.
use crate::{
    checkpoint::{require_ed25519, Checkpoint},
    processor::{check_governance, check_ring, create_pda, load_log, owned, pda},
    state::{RingHeader, RING_LEN, TIMELOCK_SECONDS},
};
use base64::{engine::general_purpose::STANDARD, Engine};
use pinocchio::{
    cpi::Seed,
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address, ProgramResult,
};
use solana_sha256_hasher::{hash, hashv};

pub const WITNESS_LEN: usize = 320;
pub const SET_LEN: usize = 64 + 16 * 168;
pub const COSIGN_WINDOW: u64 = 1500;

fn valid_id(id: &[u8]) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

pub(crate) fn identity(id: &[u8], key: &[u8]) -> [u8; 32] {
    hashv(&[b"morse-witness-record-v1", &[id.len() as u8], id, key]).to_bytes()
}

pub(crate) fn load_witness(
    program: &Address,
    account: &AccountView,
    log_id: &[u8],
) -> Result<[u8; WITNESS_LEN], ProgramError> {
    owned(program, account, false)?;
    let bytes = account.try_borrow()?;
    if bytes.len() != WITNESS_LEN
        || &bytes[..4] != b"MWI\x01"
        || bytes[4] == 0
        || bytes[4] > 64
        || bytes[5] > 4
        || bytes[6] > 1
        || bytes[7] != 0
        || &bytes[200..232] != log_id
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let id = &bytes[8..8 + bytes[4] as usize];
    if !valid_id(id)
        || bytes[8 + id.len()..72].iter().any(|b| *b != 0)
        || bytes[272..].iter().any(|b| *b != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    pda(
        program,
        &[b"witness", log_id, &identity(id, &bytes[72..104])],
        account,
    )?;
    Ok(bytes[..].try_into().unwrap())
}

pub(crate) fn register(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [operator, payer, log_account, witness, system, instructions] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() < 164 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let length = payload[2] as usize;
    if payload.len() != 163 + length {
        return Err(ProgramError::InvalidInstructionData);
    }
    let id = &payload[3..3 + length];
    let key: &[u8; 32] = payload[3 + length..35 + length].try_into().unwrap();
    let payout = &payload[35 + length..67 + length];
    if !valid_id(id)
        || *key == [0; 32]
        || payout == [0; 32]
        || key == operator.address().as_ref()
        || key == payout
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    if !operator.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let log = load_log(program, log_account)?;
    let mut statement = Message::new();
    statement.push(b"morse-witness-register-v1")?;
    statement.push(id)?;
    statement.push(operator.address().as_ref())?;
    statement.push(payout)?;
    require_ed25519(
        instructions,
        u16::from_le_bytes(payload[..2].try_into().unwrap()),
        key,
        payload[99 + length..].try_into().unwrap(),
        statement.as_slice(),
    )?;
    let record = identity(id, key);
    let bump = [pda(program, &[b"witness", &log[40..72], &record], witness)?];
    create_pda(
        program,
        payer,
        witness,
        system,
        WITNESS_LEN,
        WITNESS_LEN,
        &[
            Seed::from(b"witness"),
            Seed::from(&log[40..72]),
            Seed::from(&record),
            Seed::from(&bump),
        ],
    )?;
    let mut bytes = witness.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MWI\x01");
    bytes[4] = length as u8;
    bytes[8..8 + length].copy_from_slice(id);
    bytes[72..104].copy_from_slice(key);
    bytes[104..136].copy_from_slice(operator.address().as_ref());
    bytes[136..168].copy_from_slice(payout);
    bytes[168..200].copy_from_slice(&payload[67 + length..99 + length]);
    bytes[200..232].copy_from_slice(&log[40..72]);
    Ok(())
}

pub(crate) fn check_set(
    program: &Address,
    account: &AccountView,
    log_id: &[u8],
) -> Result<(u16, u8, i64), ProgramError> {
    owned(program, account, false)?;
    let bytes = account.try_borrow()?;
    if bytes.len() != SET_LEN
        || &bytes[..4] != b"MWS\x01"
        || &bytes[4..36] != log_id
        || bytes[38] == 0
        || bytes[38] > 16
        || bytes[39] != 0
        || bytes[48..64].iter().any(|b| *b != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let generation = u16::from_le_bytes(bytes[36..38].try_into().unwrap());
    let ready = i64::from_le_bytes(bytes[40..48].try_into().unwrap());
    if generation == 0 || ready < 0 {
        return Err(ProgramError::InvalidAccountData);
    }
    pda(
        program,
        &[b"witness-set", log_id, &generation.to_le_bytes()],
        account,
    )?;
    Ok((generation, bytes[38], ready))
}

pub(crate) fn prepare_set(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if accounts.len() < 7 || accounts.len() > 22 || payload.len() != 2 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (fixed, witnesses) = accounts.split_at_mut(6);
    let [governance, payer, config, log_account, set, system] = fixed else {
        unreachable!()
    };
    check_governance(program, config, governance)?;
    let log = load_log(program, log_account)?;
    let generation = u16::from_le_bytes(payload.try_into().unwrap());
    let active = u16::from_le_bytes(log[208..210].try_into().unwrap());
    if active.checked_add(1) != Some(generation) {
        return Err(ProgramError::InvalidArgument);
    }
    let now = Clock::get()?.unix_timestamp;
    if now < 0 {
        return Err(ProgramError::InvalidArgument);
    }
    let ready = now
        .checked_add(TIMELOCK_SECONDS)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let bump = [pda(program, &[b"witness-set", &log[40..72], payload], set)?];
    create_pda(
        program,
        payer,
        set,
        system,
        SET_LEN,
        SET_LEN,
        &[
            Seed::from(b"witness-set"),
            Seed::from(&log[40..72]),
            Seed::from(payload),
            Seed::from(&bump),
        ],
    )?;
    let mut bytes = set.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MWS\x01");
    bytes[4..36].copy_from_slice(&log[40..72]);
    bytes[36..38].copy_from_slice(payload);
    bytes[38] = witnesses.len() as u8;
    bytes[40..48].copy_from_slice(&ready.to_le_bytes());
    for (index, account) in witnesses.iter().enumerate() {
        let witness = load_witness(program, account, &log[40..72])?;
        let length = witness[4] as usize;
        let id = &witness[8..8 + length];
        if witness[5] > 1 {
            return Err(ProgramError::InvalidArgument);
        }
        if index > 0 {
            let previous = &bytes[64 + (index - 1) * 168..64 + index * 168];
            if &previous[40..40 + previous[32] as usize] >= id {
                return Err(ProgramError::InvalidArgument);
            }
        }
        for earlier in 0..index {
            let offset = 64 + earlier * 168;
            if bytes[offset + 104..offset + 136] == witness[72..104] {
                return Err(ProgramError::InvalidArgument);
            }
        }
        let offset = 64 + index * 168;
        bytes[offset..offset + 32].copy_from_slice(account.address().as_ref());
        bytes[offset + 32] = length as u8;
        bytes[offset + 40..offset + 40 + length].copy_from_slice(id);
        bytes[offset + 104..offset + 136].copy_from_slice(&witness[72..104]);
        bytes[offset + 136..offset + 168].copy_from_slice(&witness[136..168]);
    }
    Ok(())
}

pub(crate) fn activate_set(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [log_account, set] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    owned(program, log_account, true)?;
    let log = load_log(program, log_account)?;
    let (generation, _, ready) = check_set(program, set, &log[40..72])?;
    let active = u16::from_le_bytes(log[208..210].try_into().unwrap());
    if active.checked_add(1) != Some(generation) || Clock::get()?.unix_timestamp < ready {
        return Err(ProgramError::InvalidArgument);
    }
    log_account.try_borrow_mut()?[208..210].copy_from_slice(&generation.to_le_bytes());
    Ok(())
}

/// Bounded, allocation-free canonical message. This does not verify a signature.
pub struct Message {
    bytes: [u8; 512],
    length: usize,
}
impl Message {
    pub(crate) fn new() -> Self {
        Self {
            bytes: [0; 512],
            length: 0,
        }
    }
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
    pub(crate) fn push(&mut self, bytes: &[u8]) -> ProgramResult {
        let end = self
            .length
            .checked_add(bytes.len())
            .ok_or(ProgramError::InvalidInstructionData)?;
        if end > self.bytes.len() {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.bytes[self.length..end].copy_from_slice(bytes);
        self.length = end;
        Ok(())
    }
    fn decimal(&mut self, mut value: u64) -> ProgramResult {
        let mut buffer = [0; 20];
        let mut start = 20;
        loop {
            start -= 1;
            buffer[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        self.push(&buffer[start..])
    }
    fn base64(&mut self, bytes: &[u8]) -> ProgramResult {
        let count = STANDARD
            .encode_slice(bytes, &mut self.bytes[self.length..])
            .map_err(|_| ProgramError::InvalidInstructionData)?;
        self.length += count;
        Ok(())
    }
}

pub fn c2sp_statement(origin: &[u8], wire: &[u8], seconds: u64) -> Result<Message, ProgramError> {
    let cp = Checkpoint::parse(wire)?;
    if cp.version != 2
        || cp.tree_size > u32::MAX as u64
        || (cp.tree_size == 0 && cp.tree_root != hash(&[]).to_bytes())
        || origin.is_empty()
        || origin.len() > 128
        || !origin.iter().all(|b| (33..=126).contains(b) && *b != b'+')
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    let mut message = Message::new();
    message.push(b"cosignature/v1\ntime ")?;
    message.decimal(seconds)?;
    message.push(b"\n")?;
    message.push(origin)?;
    message.push(b"\n")?;
    message.decimal(cp.tree_size)?;
    message.push(b"\n")?;
    message.base64(&cp.tree_root)?;
    message.push(b"\nmorse-checkpoint ")?;
    message.base64(wire)?;
    message.push(b"\n")?;
    Ok(message)
}

pub(crate) fn cosign(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
    c2sp: bool,
) -> ProgramResult {
    cosign_inner(program, accounts, payload, c2sp, false)
}

pub(crate) fn compact_cosign(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    cosign_inner(program, accounts, payload, false, true)
}

pub(crate) fn compact_c2sp_cosign(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    cosign_inner(program, accounts, payload, true, true)
}

fn cosign_inner(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
    c2sp: bool,
    compact: bool,
) -> ProgramResult {
    let [log_account, ring, set, instructions, attendance @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len()
        != if c2sp && compact {
            201
        } else if c2sp {
            265
        } else if compact {
            5
        } else {
            69
        }
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log = load_log(program, log_account)?;
    if attendance.len() != if log[7] == 1 { 2 } else { 0 } {
        return Err(ProgramError::NotEnoughAccountKeys);
    }
    check_ring(program, &log, ring)?;
    let (generation, count, _) = check_set(program, set, &log[40..72])?;
    let index = u16::from_le_bytes(payload[..2].try_into().unwrap()) as usize;
    let bit = payload[4] as usize;
    let clock = Clock::get()?;
    let mut bytes = ring.try_borrow_mut()?;
    let header = RingHeader::parse(&bytes[..64])?;
    if bytes.len() != RING_LEN || index >= header.count as usize || bit >= count as usize {
        return Err(ProgramError::InvalidArgument);
    }
    let entry = &mut bytes[64 + index * 104..64 + (index + 1) * 104];
    let posted = u64::from_le_bytes(entry[88..96].try_into().unwrap());
    if entry[102..104] != generation.to_le_bytes()
        || clock.slot < posted
        || clock.slot - posted > COSIGN_WINDOW
    {
        return Err(ProgramError::InvalidArgument);
    }
    let set_bytes = set.try_borrow()?;
    let witness = &set_bytes[64 + bit * 168..64 + (bit + 1) * 168];
    let key = witness[104..136].try_into().unwrap();
    let (message, signature) = if c2sp {
        let offset = if compact { 13 } else { 77 };
        let cp = Checkpoint::parse(&payload[offset..])?;
        if cp.hash() != entry[48..80] || cp.service_key != log[72..104] || cp.version != log[4] {
            return Err(ProgramError::InvalidArgument);
        }
        let origin_length = u16::from_le_bytes(log[210..212].try_into().unwrap()) as usize;
        if origin_length > 128 {
            return Err(ProgramError::InvalidAccountData);
        }
        // The chain slot window governs recording. A cosignature's own time is
        // preserved verbatim, not substituted for the authenticated posting slot.
        (
            c2sp_statement(
                &log[212..212 + origin_length],
                &payload[offset..],
                u64::from_be_bytes(payload[5..13].try_into().unwrap()),
            )?,
            if compact {
                None
            } else {
                Some(payload[13..77].try_into().unwrap())
            },
        )
    } else {
        let length = witness[32] as usize;
        if length == 0 || length > 64 {
            return Err(ProgramError::InvalidAccountData);
        }
        let mut message = Message::new();
        message.push(b"mesh-msg/v1/transparency-witness")?;
        message.push(&witness[40..40 + length])?;
        message.push(&entry[48..80])?;
        (
            message,
            if compact {
                None
            } else {
                Some(payload[5..].try_into().unwrap())
            },
        )
    };
    let ed_index = u16::from_le_bytes(payload[2..4].try_into().unwrap());
    if let Some(signature) = signature {
        require_ed25519(instructions, ed_index, key, signature, message.as_slice())?;
    } else {
        crate::checkpoint::require_ed25519_message(
            instructions,
            ed_index,
            key,
            message.as_slice(),
        )?;
    }
    let flag = 1u16 << bit;
    let bitmap = u16::from_le_bytes(entry[96..98].try_into().unwrap());
    if log[7] == 1 {
        crate::attendance::cosign(
            program,
            attendance,
            &log[40..72],
            index as u16,
            posted,
            witness[..32].try_into().unwrap(),
            bitmap & flag == 0,
        )?;
    }
    entry[96..98].copy_from_slice(&(bitmap | flag).to_le_bytes());
    if !c2sp {
        let native = u16::from_le_bytes(entry[100..102].try_into().unwrap());
        entry[100..102].copy_from_slice(&(native | flag).to_le_bytes());
    }
    Ok(())
}

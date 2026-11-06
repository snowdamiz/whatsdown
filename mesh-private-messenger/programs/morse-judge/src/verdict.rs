//! Consumes authenticated stage bits and historical anchor state. Relations
//! alone never authorize a transfer. Witnesses are named only by verified keys.
use crate::{
    checkpoint::Checkpoint,
    custody::PROOF_SECONDS,
    fork::{Fork, Position, Target},
    processor::{owned, pda},
    stage,
    state::{RingHeader, LOG_LEN, RING_LEN},
    witness::{check_set, identity},
};
use pinocchio::{
    error::ProgramError,
    sysvars::{clock::Clock, Sysvar},
    AccountView, Address,
};

pub(crate) struct Verdict {
    pub hash: [u8; 32],
    pub finder: [u8; 32],
    pub submitter: [u8; 32],
    pub first: [u8; 32],
    pub second: [u8; 32],
    pub kind: u8,
    pub anchored: bool,
    pub subjects: [[u8; 32]; 16],
    pub count: usize,
    pub clock: i64,
    pub verified: u64,
    pub deadline_ms: u64,
}
fn invalid() -> ProgramError {
    ProgramError::InvalidInstructionData
}
fn wide(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().unwrap())
}
fn short(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().unwrap())
}
fn key(bytes: &[u8], index: u8) -> [u8; 32] {
    bytes[120 + index as usize * 32..152 + index as usize * 32]
        .try_into()
        .unwrap()
}

#[inline(never)]
pub(crate) fn verify(
    program: &Address,
    log: &[u8; LOG_LEN],
    stage: &AccountView,
    extra: &[AccountView],
    kind: u8,
    expected: &[u8],
) -> Result<Verdict, ProgramError> {
    let submitter = stage::admitted(program, stage, &log[40..72])?;
    let bytes = stage.try_borrow()?;
    let proof = Fork::parse(&bytes[stage::HEADER_LEN..])?;
    let bits = wide(&bytes, 112);
    let first = Checkpoint::parse(proof.first)?;
    if proof.kind != kind
        || first.version != log[4]
        || *proof.service_key != log[72..104]
        || bits & 1 == 0
        || bits >> (proof.attestation_count + 2) != 0
    {
        return Err(invalid());
    }
    let clock = Clock::get()?;
    if clock.unix_timestamp < 0 {
        return Err(invalid());
    }
    let now = (clock.unix_timestamp as u64)
        .checked_mul(1000)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    let anchored = matches!(proof.second, Target::Anchor(_));
    let (second, timestamp, bitmap, generation) = match proof.second {
        Target::Checkpoint(wire) => {
            let cp = Checkpoint::parse(wire)?;
            if bits & 2 == 0 || cp.service_key != first.service_key {
                return Err(invalid());
            }
            (Position::from(&cp), cp.timestamp, 0, 0)
        }
        Target::Anchor(index) => {
            let ring = extra.first().ok_or(ProgramError::NotEnoughAccountKeys)?;
            owned(program, ring, false)?;
            pda(program, &[b"ring", &log[8..8 + log[6] as usize]], ring)?;
            if ring.address().as_ref() != &log[136..168] || ring.data_len() != RING_LEN {
                return Err(invalid());
            }
            let data = ring.try_borrow()?;
            let header = RingHeader::parse(&data[..64])?;
            if header.log_id != log[40..72] || index >= header.count as u32 {
                return Err(invalid());
            }
            let entry = &data[64 + index as usize * 104..64 + (index as usize + 1) * 104];
            let all = short(entry, 96);
            let native = short(entry, 100);
            if entry[99] > 1 || native & !all != 0 || wide(entry, 88) > clock.slot {
                return Err(invalid());
            }
            (
                Position {
                    version: entry[98],
                    sequence: wide(entry, 0),
                    tree_size: wide(entry, 8),
                    root: entry[16..48].try_into().unwrap(),
                    hash: entry[48..80].try_into().unwrap(),
                },
                wide(entry, 80),
                if kind == 3 { native } else { all },
                short(entry, 102),
            )
        }
    };
    if second.hash != expected
        || second.version != log[4]
        || first.timestamp > now
        || timestamp > now
        || now - first.timestamp.min(timestamp) > PROOF_SECONDS as u64 * 1000
        || !proof.conflicts(&second)?
    {
        return Err(invalid());
    }
    let mut value = Verdict {
        hash: proof.hash(),
        finder: if *proof.finder == [0; 32] {
            submitter
        } else {
            *proof.finder
        },
        submitter,
        first: first.hash(),
        second: second.hash,
        kind,
        anchored,
        subjects: [[0; 32]; 16],
        count: 0,
        clock: clock.unix_timestamp,
        verified: bits,
        deadline_ms: first
            .timestamp
            .min(timestamp)
            .checked_add(PROOF_SECONDS as u64 * 1000)
            .ok_or(ProgramError::ArithmeticOverflow)?,
    };
    // A C2SP signature cannot establish Morse rollback metadata. Unverified or
    // invalid annotations never accuse a key; a valid duplicate still can.
    for (i, a) in proof.attestations().enumerate() {
        if bits & (1u64 << (i + 2)) == 0 {
            continue;
        }
        let a = a?;
        if a.checkpoint_hash != &value.first || (kind == 3 && a.algorithm != 0) {
            continue;
        }
        let signing_key = key(&bytes, i as u8);
        let double = if anchored {
            anchored_signer(program, log, extra, generation, bitmap, a.id, &signing_key)?
        } else {
            let mut found = false;
            for (j, b) in proof.attestations().enumerate() {
                if bits & (1u64 << (j + 2)) == 0 {
                    continue;
                }
                let b = b?;
                if b.id == a.id
                    && b.checkpoint_hash == &value.second
                    && key(&bytes, j as u8) == signing_key
                    && (kind != 3 || b.algorithm == 0)
                {
                    found = true;
                    break;
                }
            }
            found
        };
        if double {
            let subject = identity(a.id, &signing_key);
            if !value.subjects[..value.count].contains(&subject) {
                if value.count == 16 {
                    return Err(invalid());
                }
                value.subjects[value.count] = subject;
                value.count += 1;
            }
        }
    }
    // Authenticate the historical set even when no provided signature matches.
    // Generation zero has no cosigners and uses the Log as an explicit sentinel.
    if anchored {
        anchored_signer(program, log, extra, generation, bitmap, b"", &[0; 32])?;
    }
    Ok(value)
}
#[inline(never)]
fn anchored_signer(
    program: &Address,
    log: &[u8; LOG_LEN],
    extra: &[AccountView],
    generation: u16,
    bitmap: u16,
    id: &[u8],
    key: &[u8; 32],
) -> Result<bool, ProgramError> {
    let set = extra.get(1).ok_or(ProgramError::NotEnoughAccountKeys)?;
    if generation == 0 {
        if bitmap != 0 {
            return Err(invalid());
        }
        pda(program, &[b"log", &log[8..8 + log[6] as usize]], set)?;
        return Ok(false);
    }
    let (actual, count, _) = check_set(program, set, &log[40..72])?;
    if actual != generation || (bitmap as u32) >> count != 0 {
        return Err(invalid());
    }
    let data = set.try_borrow()?;
    for index in 0..count as usize {
        if bitmap & (1u16 << index) == 0 {
            continue;
        }
        let member = &data[64 + index * 168..64 + (index + 1) * 168];
        let length = member[32] as usize;
        if !(1..=64).contains(&length) {
            return Err(invalid());
        }
        if &member[40..40 + length] == id && &member[104..136] == key {
            return Ok(true);
        }
    }
    Ok(false)
}

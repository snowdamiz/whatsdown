//! Bounded proof upload and durable signature verification. A stage is not a
//! verdict or a payout receipt. Each verified bit is earned by an exact earlier
//! Ed25519 precompile in the current transaction, over immutable staged bytes.
use crate::{
    checkpoint::{require_ed25519, Checkpoint},
    fork::{Fork, Target, MAX_PROOF_LEN},
    processor::{authority, create_pda, load_log, owned, pda},
    witness::{c2sp_statement, load_witness, Message},
};
use pinocchio::{cpi::Seed, error::ProgramError, AccountView, Address, ProgramResult};
use solana_sha256_hasher::hash;

pub const HEADER_LEN: usize = 1152;
pub const CHUNK_LEN: usize = 900;

struct Header {
    total: usize,
    received: usize,
    sealed: bool,
    submitter: [u8; 32],
    log_id: [u8; 32],
    digest: [u8; 32],
}
fn header(program: &Address, stage: &AccountView) -> Result<Header, ProgramError> {
    owned(program, stage, false)?;
    let bytes = stage.try_borrow()?;
    if bytes.len() < HEADER_LEN
        || &bytes[..4] != b"MST\x01"
        || bytes[4] > 1
        || bytes[5..8]
            .iter()
            .chain(&bytes[12..16])
            .chain(&bytes[1144..1152])
            .any(|v| *v != 0)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    let value = Header {
        total: u16::from_le_bytes(bytes[8..10].try_into().unwrap()) as usize,
        received: u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize,
        sealed: bytes[4] == 1,
        submitter: bytes[16..48].try_into().unwrap(),
        log_id: bytes[48..80].try_into().unwrap(),
        digest: bytes[80..112].try_into().unwrap(),
    };
    if value.total == 0
        || value.total > MAX_PROOF_LEN
        || bytes.len() != HEADER_LEN + value.total
        || value.received > value.total
        || (value.sealed && value.received != value.total)
    {
        return Err(ProgramError::InvalidAccountData);
    }
    pda(program, &[b"stage", &value.submitter, &value.digest], stage)?;
    Ok(value)
}

/// Settlement only consumes sealed state. Signature bits and key slots were
/// written by `verify` after real Ed25519 precompiles, never by the uploader.
pub(crate) fn admitted(
    program: &Address,
    stage: &AccountView,
    log_id: &[u8],
) -> Result<[u8; 32], ProgramError> {
    let value = header(program, stage)?;
    if !value.sealed || value.log_id != log_id {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(value.submitter)
}

pub(crate) fn initialize(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [submitter, log_account, stage, system] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() != 34 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let total = u16::from_le_bytes(payload[..2].try_into().unwrap()) as usize;
    if total == 0 || total > MAX_PROOF_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let log = load_log(program, log_account)?;
    let digest = &payload[2..];
    let bump = [pda(
        program,
        &[b"stage", submitter.address().as_ref(), digest],
        stage,
    )?];
    create_pda(
        program,
        submitter,
        stage,
        system,
        HEADER_LEN + total,
        HEADER_LEN + total,
        &[
            Seed::from(b"stage"),
            Seed::from(submitter.address().as_ref()),
            Seed::from(digest),
            Seed::from(&bump),
        ],
    )?;
    let mut bytes = stage.try_borrow_mut()?;
    bytes[..4].copy_from_slice(b"MST\x01");
    bytes[8..10].copy_from_slice(&payload[..2]);
    bytes[16..48].copy_from_slice(submitter.address().as_ref());
    bytes[48..80].copy_from_slice(&log[40..72]);
    bytes[80..112].copy_from_slice(digest);
    Ok(())
}

pub(crate) fn append(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    let [submitter, stage] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if payload.len() < 3 || payload.len() > 2 + CHUNK_LEN {
        return Err(ProgramError::InvalidInstructionData);
    }
    let value = header(program, stage)?;
    owned(program, stage, true)?;
    authority(submitter, &value.submitter)?;
    let offset = u16::from_le_bytes(payload[..2].try_into().unwrap()) as usize;
    let end = offset + payload.len() - 2;
    if value.sealed || end > value.total || offset > value.received {
        return Err(ProgramError::InvalidArgument);
    }
    let mut bytes = stage.try_borrow_mut()?;
    if offset < value.received {
        // Exact retries are safe; overlapping writes that extend or change an
        // uploaded prefix are refused, including before the proof is sealed.
        return if end <= value.received
            && bytes[HEADER_LEN + offset..HEADER_LEN + end] == payload[2..]
        {
            Ok(())
        } else {
            Err(ProgramError::InvalidArgument)
        };
    }
    bytes[HEADER_LEN + offset..HEADER_LEN + end].copy_from_slice(&payload[2..]);
    bytes[10..12].copy_from_slice(&(end as u16).to_le_bytes());
    Ok(())
}

pub(crate) fn seal(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [submitter, log_account, stage] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let value = header(program, stage)?;
    owned(program, stage, true)?;
    authority(submitter, &value.submitter)?;
    let log = load_log(program, log_account)?;
    if value.log_id != log[40..72] || value.received != value.total {
        return Err(ProgramError::InvalidAccountData);
    }
    {
        let bytes = stage.try_borrow()?;
        let wire = &bytes[HEADER_LEN..];
        if hash(wire).to_bytes() != value.digest {
            return Err(ProgramError::InvalidInstructionData);
        }
        let proof = Fork::parse(wire)?;
        if *proof.service_key != log[72..104]
            || Checkpoint::parse(proof.first)?.version != log[4]
            || matches!(proof.second, Target::Checkpoint(cp) if cp[0] != log[4])
        {
            return Err(ProgramError::InvalidInstructionData);
        }
    }
    stage.try_borrow_mut()?[4] = 1;
    Ok(())
}

/// Ordinals 0/1 are the service checkpoints; 2..33 are the exact attestation
/// positions. The 32 key slots bind witness identities across later transactions.
pub(crate) fn verify(
    program: &Address,
    accounts: &mut [AccountView],
    payload: &[u8],
) -> ProgramResult {
    if payload.len() != 3 || accounts.len() < 3 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let (base, extra) = accounts.split_at_mut(3);
    let [log_account, stage, instructions] = base else {
        unreachable!()
    };
    let ordinal = payload[0];
    let ed_index = u16::from_le_bytes(payload[1..3].try_into().unwrap());
    let value = header(program, stage)?;
    owned(program, stage, true)?;
    let log = load_log(program, log_account)?;
    if !value.sealed || value.log_id != log[40..72] {
        return Err(ProgramError::InvalidAccountData);
    }
    let key = {
        let bytes = stage.try_borrow()?;
        let proof = Fork::parse(&bytes[HEADER_LEN..])?;
        if ordinal < 2 {
            if !extra.is_empty() {
                return Err(ProgramError::InvalidInstructionData);
            }
            let wire = if ordinal == 0 {
                proof.first
            } else {
                match proof.second {
                    Target::Checkpoint(cp) => cp,
                    Target::Anchor(_) => return Err(ProgramError::InvalidInstructionData),
                }
            };
            let cp = Checkpoint::parse(wire)?;
            require_ed25519(
                instructions,
                ed_index,
                &cp.service_key,
                &cp.signature,
                &cp.statement(),
            )?;
            cp.service_key
        } else {
            let [witness, submitter] = extra else {
                return Err(ProgramError::NotEnoughAccountKeys);
            };
            // Optional annotations select the identities an atomic verdict must
            // settle. Outsiders must not add an unfunded/withdrawn identity and
            // thereby make an otherwise collectible proof impossible to file.
            authority(submitter, &value.submitter)?;
            let attestation = proof.attestation(ordinal - 2)?;
            let record = load_witness(program, witness, &value.log_id)?;
            if &record[8..8 + record[4] as usize] != attestation.id {
                return Err(ProgramError::InvalidAccountData);
            }
            let key: [u8; 32] = record[72..104].try_into().unwrap();
            let cp_wire = if Checkpoint::parse(proof.first)?.hash() == *attestation.checkpoint_hash
            {
                proof.first
            } else {
                match proof.second {
                    Target::Checkpoint(cp)
                        if Checkpoint::parse(cp)?.hash() == *attestation.checkpoint_hash =>
                    {
                        cp
                    }
                    _ => return Err(ProgramError::InvalidInstructionData),
                }
            };
            let (message, signature) = if attestation.algorithm == 0 {
                let mut message = Message::new();
                message.push(b"mesh-msg/v1/transparency-witness")?;
                message.push(attestation.id)?;
                message.push(attestation.checkpoint_hash)?;
                (message, attestation.signature.try_into().unwrap())
            } else {
                // C2SP witnesses do not interpret Morse's sequence metadata.
                if proof.kind == 3 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                let length = u16::from_le_bytes(log[210..212].try_into().unwrap()) as usize;
                if length > 128 {
                    return Err(ProgramError::InvalidAccountData);
                }
                (
                    c2sp_statement(
                        &log[212..212 + length],
                        cp_wire,
                        u64::from_be_bytes(attestation.signature[..8].try_into().unwrap()),
                    )?,
                    attestation.signature[8..].try_into().unwrap(),
                )
            };
            require_ed25519(instructions, ed_index, &key, signature, message.as_slice())?;
            key
        }
    };
    let mut bytes = stage.try_borrow_mut()?;
    let bits = u64::from_le_bytes(bytes[112..120].try_into().unwrap());
    if ordinal >= 2 {
        let start = 120 + (ordinal as usize - 2) * 32;
        if bits & (1u64 << ordinal) != 0 && bytes[start..start + 32] != key {
            return Err(ProgramError::InvalidAccountData);
        }
        bytes[start..start + 32].copy_from_slice(&key);
    }
    bytes[112..120].copy_from_slice(&(bits | (1u64 << ordinal)).to_le_bytes());
    Ok(())
}

pub(crate) fn close(program: &Address, accounts: &mut [AccountView]) -> ProgramResult {
    let [submitter, stage] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    let value = header(program, stage)?;
    owned(program, stage, true)?;
    authority(submitter, &value.submitter)?;
    if !submitter.is_writable() || submitter.address() == stage.address() {
        return Err(ProgramError::InvalidArgument);
    }
    let balance = submitter
        .lamports()
        .checked_add(stage.lamports())
        .ok_or(ProgramError::ArithmeticOverflow)?;
    submitter.set_lamports(balance);
    stage.close()
}

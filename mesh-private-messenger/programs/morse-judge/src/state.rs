use crate::checkpoint::Checkpoint;
use pinocchio::{error::ProgramError, ProgramResult};

pub const RING_LEN: usize = 64 + 4096 * 104;
pub const TIMELOCK_SECONDS: i64 = 14 * 24 * 60 * 60;
pub const LOG_LEN: usize = 352;
pub const CONFIG_LEN: usize = 40;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RingHeader {
    pub log_id: [u8; 32],
    pub head: u16,
    pub count: u16,
    pub sequence: u64,
    pub size: u64,
    pub slot: u64,
}

impl RingHeader {
    pub fn parse(bytes: &[u8]) -> Result<Self, ProgramError> {
        if bytes.len() != 64 || &bytes[..4] != b"MRG\x01" {
            return Err(ProgramError::InvalidAccountData);
        }
        let header = Self {
            log_id: bytes[4..36].try_into().unwrap(),
            head: u16::from_le_bytes(bytes[36..38].try_into().unwrap()),
            count: u16::from_le_bytes(bytes[38..40].try_into().unwrap()),
            sequence: u64::from_le_bytes(bytes[40..48].try_into().unwrap()),
            size: u64::from_le_bytes(bytes[48..56].try_into().unwrap()),
            slot: u64::from_le_bytes(bytes[56..64].try_into().unwrap()),
        };
        if header.head >= 4096
            || header.count > 4096
            || (header.count > 0 && header.count < 4096 && header.head != header.count - 1)
            || (header.count == 0
                && (header.head != 0
                    || header.sequence != 0
                    || header.size != 0
                    || header.slot != 0))
        {
            return Err(ProgramError::InvalidAccountData);
        }
        Ok(header)
    }
}

pub fn initialize_ring(data: &mut [u8], log_id: &[u8; 32]) -> ProgramResult {
    if data.len() < 64 || data.iter().any(|byte| *byte != 0) {
        return Err(ProgramError::InvalidAccountData);
    }
    data[..4].copy_from_slice(b"MRG\x01");
    data[4..36].copy_from_slice(log_id);
    Ok(())
}

// The caller authenticates the service, authority, log identity and clock.
// A non-monotonic post is retained for comparison, never itself a verdict of
// equivocation: replaying an old signed checkpoint is not proof of a fork.
pub fn append_anchor(
    data: &mut [u8],
    checkpoint: &Checkpoint,
    slot: u64,
    generation: u16,
) -> Result<Option<u16>, ProgramError> {
    if data.len() != RING_LEN || !matches!(checkpoint.version, 1 | 2) {
        return Err(ProgramError::InvalidAccountData);
    }
    let header = RingHeader::parse(&data[..64])?;
    if slot < header.slot {
        return Err(ProgramError::InvalidArgument);
    }
    let hash = checkpoint.hash();
    let latest = 64 + header.head as usize * 104;
    if header.count > 0 && data[latest + 48..latest + 80] == hash {
        return Ok(None);
    }
    let regressed = header.count > 0
        && (checkpoint.sequence < header.sequence
            || checkpoint.tree_size < header.size
            || checkpoint.sequence == header.sequence);
    let next = if header.count == 0 {
        0
    } else {
        (header.head + 1) % 4096
    };
    let offset = 64 + next as usize * 104;
    let entry = &mut data[offset..offset + 104];
    entry.fill(0);
    entry[..8].copy_from_slice(&checkpoint.sequence.to_le_bytes());
    entry[8..16].copy_from_slice(&checkpoint.tree_size.to_le_bytes());
    entry[16..48].copy_from_slice(&checkpoint.tree_root);
    entry[48..80].copy_from_slice(&hash);
    entry[80..88].copy_from_slice(&checkpoint.timestamp.to_le_bytes());
    entry[88..96].copy_from_slice(&slot.to_le_bytes());
    entry[98] = checkpoint.version;
    entry[99] = u8::from(regressed);
    entry[102..104].copy_from_slice(&generation.to_le_bytes());
    data[36..38].copy_from_slice(&next.to_le_bytes());
    data[38..40].copy_from_slice(&(header.count + 1).min(4096).to_le_bytes());
    data[40..48].copy_from_slice(&checkpoint.sequence.to_le_bytes());
    data[48..56].copy_from_slice(&checkpoint.tree_size.to_le_bytes());
    data[56..64].copy_from_slice(&slot.to_le_bytes());
    Ok(Some(next))
}

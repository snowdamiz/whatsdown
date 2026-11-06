//! Canonical checkpoint reconstruction and Ed25519 instruction introspection.
//! Parsing is not signature verification. Only `require_ed25519` establishes
//! that Solana executed the exact precompile statement in this transaction.
use pinocchio::{
    error::ProgramError, sysvars::instructions::Instructions, AccountView, Address, ProgramResult,
};
use solana_sha256_hasher::hashv;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Checkpoint {
    pub version: u8,
    pub sequence: u64,
    pub tree_size: u64,
    pub tree_root: [u8; 32],
    pub previous_hash: [u8; 32],
    pub timestamp: u64,
    pub service_key: [u8; 32],
    pub signature: [u8; 64],
}

impl Checkpoint {
    pub fn parse(wire: &[u8]) -> Result<Self, ProgramError> {
        if wire.len() != 188 || !matches!(wire[0], 1 | 2) || &wire[1..4] != b"KTK" {
            return Err(ProgramError::InvalidInstructionData);
        }
        // Every slice is within the exact checked wire length above.
        Ok(Self {
            version: wire[0],
            sequence: u64::from_be_bytes(wire[4..12].try_into().unwrap()),
            tree_size: u64::from_be_bytes(wire[12..20].try_into().unwrap()),
            tree_root: wire[20..52].try_into().unwrap(),
            previous_hash: wire[52..84].try_into().unwrap(),
            timestamp: u64::from_be_bytes(wire[84..92].try_into().unwrap()),
            service_key: wire[92..124].try_into().unwrap(),
            signature: wire[124..188].try_into().unwrap(),
        })
    }

    pub fn statement(&self) -> [u8; 146] {
        let mut bytes = [0; 146];
        bytes[..24].copy_from_slice(b"mesh-key-transparency-v1");
        bytes[24..26].copy_from_slice(&(self.version as u16).to_be_bytes());
        bytes[26..34].copy_from_slice(&self.sequence.to_be_bytes());
        bytes[34..42].copy_from_slice(&self.tree_size.to_be_bytes());
        bytes[42..74].copy_from_slice(&self.tree_root);
        bytes[74..106].copy_from_slice(&self.previous_hash);
        bytes[106..114].copy_from_slice(&self.timestamp.to_be_bytes());
        bytes[114..146].copy_from_slice(&self.service_key);
        bytes
    }

    pub fn hash(&self) -> [u8; 32] {
        hashv(&[
            b"mesh-msg/v1/transparency-checkpoint",
            &self.statement(),
            &self.signature,
        ])
        .to_bytes()
    }
}

/// Accept only a self-contained single-signature precompile instruction.
/// This byte matcher alone does not verify that the instruction executed.
pub fn matches_ed25519_instruction(
    data: &[u8],
    key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> bool {
    if message.len() > u16::MAX as usize || data.len() != 112 + message.len() {
        return false;
    }
    let mut header = [0; 16];
    header[0] = 1;
    for (index, value) in [
        48,
        u16::MAX,
        16,
        u16::MAX,
        112,
        message.len() as u16,
        u16::MAX,
    ]
    .iter()
    .enumerate()
    {
        header[2 + index * 2..4 + index * 2].copy_from_slice(&value.to_le_bytes());
    }
    data[..16] == header
        && data[16..48] == *key
        && data[48..112] == *signature
        && data[112..] == *message
}

/// Require an earlier Ed25519 precompile in the current transaction. Offsets
/// cannot point into a different instruction, key, signature or message.
pub fn require_ed25519(
    instructions: &AccountView,
    index: u16,
    key: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> ProgramResult {
    checked_ed25519(instructions, index, key, Some(signature), message)
}

/// Compact cosigns do not repeat a signature already carried by the exact
/// earlier precompile. The key and entire reconstructed statement remain fixed
/// by authenticated chain accounts, and the precompile verifies the signature.
pub fn require_ed25519_message(
    instructions: &AccountView,
    index: u16,
    key: &[u8; 32],
    message: &[u8],
) -> ProgramResult {
    checked_ed25519(instructions, index, key, None, message)
}

fn checked_ed25519(
    instructions: &AccountView,
    index: u16,
    key: &[u8; 32],
    signature: Option<&[u8; 64]>,
    message: &[u8],
) -> ProgramResult {
    const ED25519_ID: Address = Address::new_from_array([
        3, 125, 70, 214, 124, 147, 251, 190, 18, 249, 66, 143, 131, 141, 64, 255, 5, 112, 116, 73,
        39, 244, 138, 100, 252, 202, 112, 68, 128, 0, 0, 0,
    ]);
    // Checks the real Instructions sysvar address before reading its data.
    let view = Instructions::try_from(instructions)?;
    if index >= view.load_current_index() {
        return Err(ProgramError::InvalidInstructionData);
    }
    let instruction = view.load_instruction_at(index as usize)?;
    let data = instruction.get_instruction_data();
    let supplied: &[u8; 64] = data
        .get(48..112)
        .ok_or(ProgramError::InvalidInstructionData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidInstructionData)?;
    if instruction.get_program_id() != &ED25519_ID
        || instruction.num_account_metas() != 0
        || signature.is_some_and(|expected| supplied != expected)
        || !matches_ed25519_instruction(data, key, supplied, message)
    {
        return Err(ProgramError::InvalidInstructionData);
    }
    Ok(())
}

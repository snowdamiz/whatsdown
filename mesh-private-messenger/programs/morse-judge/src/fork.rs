//! Canonical, allocation-free FRK parsing and Merkle relations shared with the
//! Mesh oracle. Neither parsing nor `conflicts` establishes signature validity.
use crate::checkpoint::Checkpoint;
use pinocchio::error::ProgramError;
use solana_sha256_hasher::hashv;

pub const MAX_PROOF_LEN: usize = 8009;
pub const MAX_ATTESTATIONS: usize = 32;

#[derive(Clone, Copy)]
pub enum Target<'a> {
    Checkpoint(&'a [u8]),
    Anchor(u32),
}

pub struct Attestation<'a> {
    pub id: &'a [u8],
    pub checkpoint_hash: &'a [u8; 32],
    pub algorithm: u8,
    pub signature: &'a [u8],
}

pub struct Paths<'a> {
    pub index: u64,
    pub first: &'a [u8],
    pub first_leaf: &'a [u8; 32],
    pub second: &'a [u8],
    pub second_leaf: &'a [u8; 32],
}

pub struct Fork<'a> {
    wire: &'a [u8],
    pub version: u8,
    pub kind: u8,
    pub finder: &'a [u8; 32],
    pub service_key: &'a [u8; 32],
    pub first: &'a [u8],
    pub second: Target<'a>,
    pub attestation_count: u8,
    attestations: &'a [u8],
    pub paths: Option<Paths<'a>>,
}

pub struct Position {
    pub version: u8,
    pub sequence: u64,
    pub tree_size: u64,
    pub root: [u8; 32],
    pub hash: [u8; 32],
}
impl From<&Checkpoint> for Position {
    fn from(cp: &Checkpoint) -> Self {
        Self {
            version: cp.version,
            sequence: cp.sequence,
            tree_size: cp.tree_size,
            root: cp.tree_root,
            hash: cp.hash(),
        }
    }
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], ProgramError> {
        let (bytes, rest) = self
            .0
            .split_at_checked(length)
            .ok_or(ProgramError::InvalidInstructionData)?;
        self.0 = rest;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    fn attestation(&mut self, version: u8) -> Result<Attestation<'a>, ProgramError> {
        let length = self.byte()? as usize;
        if !(1..=64).contains(&length) {
            return Err(ProgramError::InvalidInstructionData);
        }
        let id = self.take(length)?;
        core::str::from_utf8(id).map_err(|_| ProgramError::InvalidInstructionData)?;
        let checkpoint_hash = self.take(32)?.try_into().unwrap();
        let algorithm = if version == 1 { 0 } else { self.byte()? };
        let length = match algorithm {
            0 => 64,
            4 => 72,
            _ => return Err(ProgramError::InvalidInstructionData),
        };
        Ok(Attestation {
            id,
            checkpoint_hash,
            algorithm,
            signature: self.take(length)?,
        })
    }
    fn path(&mut self) -> Result<&'a [u8], ProgramError> {
        let length = self.byte()? as usize;
        if length > 32 {
            return Err(ProgramError::InvalidInstructionData);
        }
        self.take(length * 32)
    }
}

impl<'a> Fork<'a> {
    pub fn parse(wire: &'a [u8]) -> Result<Self, ProgramError> {
        if wire.len() > MAX_PROOF_LEN {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut reader = Reader(wire);
        let version = reader.byte()?;
        if !matches!(version, 1..=3)
            || reader.take(3)? != b"FRK"
            || (version == 1 && wire.len() > 5145)
            || (version == 2 && wire.len() > 5289)
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let kind = reader.byte()?;
        if !matches!(kind, 1..=3) {
            return Err(ProgramError::InvalidInstructionData);
        }
        let finder = reader.take(32)?.try_into().unwrap();
        let service_key: &[u8; 32] = reader.take(32)?.try_into().unwrap();
        let first = reader.take(188)?;
        if Checkpoint::parse(first)?.service_key != *service_key {
            return Err(ProgramError::InvalidInstructionData);
        }
        let second = match reader.byte()? {
            0 => {
                let cp = reader.take(188)?;
                if Checkpoint::parse(cp)?.service_key != *service_key {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Target::Checkpoint(cp)
            }
            1 => {
                let index = u32::from_be_bytes(reader.take(4)?.try_into().unwrap());
                if index >= 4096 {
                    return Err(ProgramError::InvalidInstructionData);
                }
                Target::Anchor(index)
            }
            _ => return Err(ProgramError::InvalidInstructionData),
        };
        let attestation_count = reader.byte()?;
        if attestation_count as usize > MAX_ATTESTATIONS
            || (version != 3 && attestation_count > 16)
            || (version == 3 && attestation_count <= 16)
        {
            return Err(ProgramError::InvalidInstructionData);
        }
        let start = reader.0;
        let mut has_c2sp = false;
        for _ in 0..attestation_count {
            has_c2sp |= reader.attestation(version)?.algorithm == 4;
        }
        if version == 2 && !has_c2sp {
            return Err(ProgramError::InvalidInstructionData);
        }
        let attestations = &start[..start.len() - reader.0.len()];
        let paths = if kind == 2 {
            Some(Paths {
                index: u64::from_be_bytes(reader.take(8)?.try_into().unwrap()),
                first: reader.path()?,
                first_leaf: reader.take(32)?.try_into().unwrap(),
                second: reader.path()?,
                second_leaf: reader.take(32)?.try_into().unwrap(),
            })
        } else {
            None
        };
        if !reader.0.is_empty() {
            return Err(ProgramError::InvalidInstructionData);
        }
        Ok(Self {
            wire,
            version,
            kind,
            finder,
            service_key,
            first,
            second,
            attestation_count,
            attestations,
            paths,
        })
    }

    pub fn attestation(&self, index: u8) -> Result<Attestation<'a>, ProgramError> {
        if index >= self.attestation_count {
            return Err(ProgramError::InvalidInstructionData);
        }
        let mut reader = Reader(self.attestations);
        for _ in 0..index {
            reader.attestation(self.version)?;
        }
        reader.attestation(self.version)
    }

    /// Sequential traversal is bounded by the wire length. Repeated indexed
    /// reads inside verdict matching otherwise reparse long IDs quadratically.
    pub fn attestations(&self) -> impl Iterator<Item = Result<Attestation<'a>, ProgramError>> {
        let mut reader = Reader(self.attestations);
        let version = self.version;
        (0..self.attestation_count).map(move |_| reader.attestation(version))
    }

    pub fn hash(&self) -> [u8; 32] {
        hashv(&[&self.wire[..5], &self.wire[37..]]).to_bytes()
    }

    /// The caller must authenticate both positions under the registered log.
    pub fn conflicts(&self, second: &Position) -> Result<bool, ProgramError> {
        let first = Checkpoint::parse(self.first)?;
        if first.version != second.version {
            return Ok(false);
        }
        Ok(match self.kind {
            1 => first.tree_size == second.tree_size && first.tree_root != second.root,
            3 => {
                (first.sequence < second.sequence && first.tree_size > second.tree_size)
                    || (first.sequence > second.sequence && first.tree_size < second.tree_size)
                    || (first.sequence == second.sequence && first.hash() != second.hash)
            }
            2 => {
                let paths = self
                    .paths
                    .as_ref()
                    .ok_or(ProgramError::InvalidInstructionData)?;
                paths.first_leaf != paths.second_leaf
                    && inclusion(
                        first.version,
                        paths.index,
                        first.tree_size,
                        paths.first_leaf,
                        paths.first,
                        &first.tree_root,
                    )
                    && inclusion(
                        first.version,
                        paths.index,
                        second.tree_size,
                        paths.second_leaf,
                        paths.second,
                        &second.root,
                    )
            }
            _ => false,
        })
    }
}

/// Compact audit path, consumed exactly. Morse's legacy and RFC 6962 profiles
/// differ only in the internal-node prefix because the leaves are already hashes.
pub fn inclusion(
    version: u8,
    index: u64,
    size: u64,
    leaf: &[u8; 32],
    path: &[u8],
    root: &[u8; 32],
) -> bool {
    if !matches!(version, 1 | 2)
        || size == 0
        || size > u32::MAX as u64
        || index >= size
        || path.len() > 1024
        || !path.len().is_multiple_of(32)
    {
        return false;
    }
    let prefix = if version == 1 {
        b"mesh-msg/v1/transparency-node".as_slice()
    } else {
        &[1]
    };
    let mut value = *leaf;
    let mut node = index;
    let mut last = size - 1;
    for sibling in path.as_chunks::<32>().0 {
        if last == 0 {
            return false;
        }
        if node & 1 == 1 || node == last {
            value = hashv(&[prefix, sibling, &value]).to_bytes();
            while node != 0 && node & 1 == 0 {
                node >>= 1;
                last >>= 1;
            }
        } else {
            value = hashv(&[prefix, &value, sibling]).to_bytes();
        }
        node >>= 1;
        last >>= 1;
    }
    last == 0 && value == *root
}

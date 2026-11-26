//! Morse wire formats the judge reads verbatim (big-endian, INTERFACES §1, §5):
//! KTK checkpoints, the 146-byte checkpoint statement, witness statements and
//! `FRK` v1 fork evidence; plus RFC 9162 inclusion verification with Morse's
//! node hashing, and the fork rules F1/F2/F3.

use crate::error::{err, require, JudgeError};
use crate::state::MAX_FRK_LEN;
use crate::util::sha256;
use pinocchio::error::ProgramError;

pub const KTK_LEN: usize = 188;
pub const STATEMENT_LEN: usize = 146;
const STATEMENT_PREFIX: &[u8; 24] = b"mesh-key-transparency-v1";
const CHECKPOINT_DOMAIN: &[u8] = b"mesh-msg/v1/transparency-checkpoint";
pub const WITNESS_DOMAIN: &[u8; 32] = b"mesh-msg/v1/transparency-witness";
const NODE_DOMAIN: &[u8] = b"mesh-msg/v1/transparency-node";
const PROOF_DOMAIN: &[u8] = b"morse-frk-v1/proof";

pub const KIND_SAME_SIZE: u8 = 1;
pub const KIND_CONTRADICTION: u8 = 2;
pub const KIND_ROLLBACK: u8 = 3;

fn be64(d: &[u8], o: usize) -> u64 {
    u64::from_be_bytes(d[o..o + 8].try_into().unwrap())
}

/// A checkpoint as the judge compares it.
#[derive(Clone, Copy)]
pub struct Checkpoint {
    pub sequence: u64,
    pub size: u64,
    pub root: [u8; 32],
    pub hash: [u8; 32],
    pub timestamp_ms: u64,
}

/// `u8 1 ‖ "KTK" ‖ u64 seq ‖ u64 size ‖ root32 ‖ prev32 ‖ u64 ts_ms ‖ key32 ‖ sig64`.
#[derive(Clone, Copy)]
pub struct Ktk<'a>(pub &'a [u8]);

impl<'a> Ktk<'a> {
    pub fn parse(b: &'a [u8]) -> Result<Self, ProgramError> {
        require(b.len() == KTK_LEN && b[0] == 1 && &b[1..4] == b"KTK", JudgeError::InvalidCheckpoint)?;
        Ok(Ktk(b))
    }
    pub fn key(&self) -> &'a [u8; 32] {
        self.0[92..124].try_into().unwrap()
    }
    pub fn signature(&self) -> &'a [u8; 64] {
        self.0[124..188].try_into().unwrap()
    }
    /// The 146-byte statement the service signs, rebuilt byte for byte.
    pub fn statement(&self) -> [u8; STATEMENT_LEN] {
        let mut s = [0u8; STATEMENT_LEN];
        s[..24].copy_from_slice(STATEMENT_PREFIX);
        s[24..26].copy_from_slice(&1u16.to_be_bytes());
        s[26..].copy_from_slice(&self.0[4..124]);
        s
    }
    pub fn checkpoint(&self) -> Checkpoint {
        Checkpoint {
            sequence: be64(self.0, 4),
            size: be64(self.0, 12),
            root: self.0[20..52].try_into().unwrap(),
            hash: sha256(&[CHECKPOINT_DOMAIN, &self.statement(), self.signature()]),
            timestamp_ms: be64(self.0, 84),
        }
    }
}

pub fn witness_message(id: &[u8], checkpoint_hash: &[u8; 32], out: &mut [u8; 128]) -> usize {
    out[..32].copy_from_slice(WITNESS_DOMAIN);
    out[32..32 + id.len()].copy_from_slice(id);
    out[32 + id.len()..64 + id.len()].copy_from_slice(checkpoint_hash);
    64 + id.len()
}

pub enum Second<'a> {
    Inline(Ktk<'a>),
    Ring(u32),
}

#[derive(Clone, Copy)]
pub struct Attestation<'a> {
    pub id: &'a [u8],
    pub hash: &'a [u8; 32],
    pub signature: &'a [u8; 64],
}

pub struct Contradiction<'a> {
    pub index: u64,
    pub path1: &'a [u8],
    pub leaf1: &'a [u8; 32],
    pub path2: &'a [u8],
    pub leaf2: &'a [u8; 32],
}

pub struct Frk<'a> {
    pub bytes: &'a [u8],
    pub kind: u8,
    pub finder: [u8; 32],
    pub log_key: &'a [u8; 32],
    pub c1: Ktk<'a>,
    pub c2: Second<'a>,
    pub attestations: [Option<Attestation<'a>>; 16],
    pub contradiction: Option<Contradiction<'a>>,
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ProgramError> {
        let end = self.at.checked_add(n).filter(|e| *e <= self.b.len());
        let Some(end) = end else {
            return err(JudgeError::FrkMalformed);
        };
        let s = &self.b[self.at..end];
        self.at = end;
        Ok(s)
    }
    fn byte(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }
    fn key(&mut self) -> Result<&'a [u8; 32], ProgramError> {
        Ok(self.take(32)?.try_into().unwrap())
    }
    fn path(&mut self) -> Result<&'a [u8], ProgramError> {
        let p = self.byte()? as usize;
        require(p <= 64, JudgeError::FrkMalformed)?;
        self.take(p * 32)
    }
}

impl<'a> Frk<'a> {
    /// Strict decode of `FRK` v1 (INTERFACES §5): no trailing bytes, ≤ 8,192.
    pub fn parse(b: &'a [u8]) -> Result<Self, ProgramError> {
        require(b.len() <= MAX_FRK_LEN, JudgeError::FrkMalformed)?;
        let mut r = Reader { b, at: 0 };
        require(r.byte()? == 1 && r.take(3)? == b"FRK", JudgeError::FrkMalformed)?;
        let kind = r.byte()?;
        require((KIND_SAME_SIZE..=KIND_ROLLBACK).contains(&kind), JudgeError::FrkMalformed)?;
        let finder = *r.key()?;
        let log_key = r.key()?;
        let c1 = Ktk::parse(r.take(KTK_LEN)?).map_err(|_| ProgramError::from(JudgeError::FrkMalformed))?;
        let c2 = match r.byte()? {
            0 => Second::Inline(Ktk::parse(r.take(KTK_LEN)?).map_err(|_| ProgramError::from(JudgeError::FrkMalformed))?),
            1 => Second::Ring(u32::from_be_bytes(r.take(4)?.try_into().unwrap())),
            _ => return err(JudgeError::FrkMalformed),
        };
        let count = r.byte()? as usize;
        require(count <= 16, JudgeError::FrkMalformed)?;
        let mut attestations = [None; 16];
        for slot in attestations.iter_mut().take(count) {
            let len = r.byte()? as usize;
            require((1..=64).contains(&len), JudgeError::FrkMalformed)?;
            let id = r.take(len)?;
            let hash = r.key()?;
            let signature = r.take(64)?.try_into().unwrap();
            *slot = Some(Attestation { id, hash, signature });
        }
        let contradiction = if kind == KIND_CONTRADICTION {
            let index = u64::from_be_bytes(r.take(8)?.try_into().unwrap());
            let path1 = r.path()?;
            let leaf1 = r.key()?;
            let path2 = r.path()?;
            let leaf2 = r.key()?;
            Some(Contradiction { index, path1, leaf1, path2, leaf2 })
        } else {
            None
        };
        require(r.at == b.len(), JudgeError::FrkMalformed)?;
        Ok(Frk { bytes: b, kind, finder, log_key, c1, c2, attestations, contradiction })
    }

    /// `SHA-256("morse-frk-v1/proof" ‖ bytes[0..5] ‖ bytes[37..])`: every byte
    /// except the finder address, so one fork pays once whoever is named.
    pub fn proof_hash(&self) -> [u8; 32] {
        sha256(&[PROOF_DOMAIN, &self.bytes[..5], &self.bytes[37..]])
    }
}

fn node(l: &[u8], r: &[u8]) -> [u8; 32] {
    sha256(&[NODE_DOMAIN, l, r])
}

/// RFC 9162 §2.1.3.2 inclusion verification with Morse's node hash.
pub fn inclusion_verifies(index: u64, size: u64, leaf: &[u8; 32], path: &[u8], root: &[u8; 32]) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode, mut r) = (index, size - 1, *leaf);
    for p in path.chunks_exact(32) {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node(p, &r);
            if fnode & 1 == 0 {
                while fnode & 1 == 0 && fnode != 0 {
                    fnode >>= 1;
                    snode >>= 1;
                }
            }
        } else {
            r = node(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// F1 / F2 / F3 validity (INTERFACES §5).
pub fn is_fork(kind: u8, a: &Checkpoint, b: &Checkpoint, contradiction: Option<&Contradiction>) -> bool {
    match kind {
        KIND_SAME_SIZE => a.size == b.size && a.root != b.root,
        KIND_CONTRADICTION => contradiction.is_some_and(|c| {
            c.index < a.size.min(b.size)
                && c.leaf1 != c.leaf2
                && inclusion_verifies(c.index, a.size, c.leaf1, c.path1, &a.root)
                && inclusion_verifies(c.index, b.size, c.leaf2, c.path2, &b.root)
        }),
        KIND_ROLLBACK => {
            (a.sequence < b.sequence && a.size > b.size)
                || (a.sequence > b.sequence && a.size < b.size)
                || (a.sequence == b.sequence && a.hash != b.hash)
        }
        _ => false,
    }
}

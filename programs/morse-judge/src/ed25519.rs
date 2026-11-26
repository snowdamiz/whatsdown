//! Ed25519 checks by instruction introspection (plan §5.3).
//!
//! The native Ed25519 program verifies every signature listed in its
//! instruction before any other instruction of the transaction runs; if one
//! fails, the whole transaction fails. So an Ed25519 instruction that is
//! present in THIS transaction proves its listed signatures. The judge then
//! only has to make sure the entry it relies on is about exactly the key,
//! message and signature it expects:
//!
//! - the instructions sysvar is the real one (address checked), so the
//!   instruction list is this transaction's own;
//! - the named instruction's program is the Ed25519 program;
//! - the entry's three instruction indexes are all `u16::MAX` ("this
//!   instruction"), so the verified bytes are the Ed25519 instruction's own
//!   data and not bytes of some other instruction;
//! - the public key, message and (when given) signature at the entry's
//!   offsets equal the expected bytes exactly, including length.

use pinocchio::{sysvars::instructions::Instructions, AccountView, Address};

pub const ED25519_ID: Address = Address::from_str_const("Ed25519SigVerify111111111111111111111111111");
const OFFSETS_START: usize = 2;
const OFFSETS_LEN: usize = 14;
const THIS_INSTRUCTION: u16 = u16::MAX;

fn rd(d: &[u8], o: usize) -> usize {
    u16::from_le_bytes([d[o], d[o + 1]]) as usize
}

/// True when instruction `ix_index` of the current transaction is an Ed25519
/// program instruction with a self-contained entry for exactly
/// (`pubkey`, `message`, `signature`). Anything else is `false`: a missing
/// instruction, another program, a fake sysvar, or an entry pointing
/// elsewhere.
pub fn verified(sysvar: &AccountView, ix_index: u8, pubkey: &[u8; 32], message: &[u8], signature: Option<&[u8; 64]>) -> bool {
    let Ok(ixs) = Instructions::try_from(sysvar) else {
        return false;
    };
    let Ok(ix) = ixs.load_instruction_at(ix_index as usize) else {
        return false;
    };
    if ix.get_program_id() != &ED25519_ID {
        return false;
    }
    let d = ix.get_instruction_data();
    if d.len() < OFFSETS_START {
        return false;
    }
    let count = d[0] as usize;
    for k in 0..count {
        let o = OFFSETS_START + k * OFFSETS_LEN;
        if d.len() < o + OFFSETS_LEN {
            return false;
        }
        let (sig_off, pk_off, msg_off, msg_len) = (rd(d, o), rd(d, o + 4), rd(d, o + 8), rd(d, o + 10));
        let here = |p: usize| rd(d, o + p) == THIS_INSTRUCTION as usize;
        if !(here(2) && here(6) && here(12)) {
            continue;
        }
        let pk = d.get(pk_off..pk_off + 32);
        let msg = d.get(msg_off..msg_off + msg_len);
        let sig = d.get(sig_off..sig_off + 64);
        if pk == Some(&pubkey[..]) && msg == Some(message) && signature.is_none_or(|s| sig == Some(&s[..])) {
            return true;
        }
    }
    false
}

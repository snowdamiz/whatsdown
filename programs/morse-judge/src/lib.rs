//! `morse-judge`: anchors Morse transparency-log checkpoints on Solana, holds
//! witness and directory bonds, and slashes them on proof of a fork.
//! Specification: `mesh-private-messenger/protocol/morse-judge-v1.md`.
//!
//! The program has no instruction that moves a vault except `withdraw`
//! (the bond owner, 30 days after `request_unbond`, never after a slash) and
//! the three `prove_*` instructions (a valid fork proof). It becomes
//! immutable after review, so windows and shares are constants (`state.rs`).
#![cfg_attr(target_os = "solana", no_std)]

mod anchor;
mod ed25519;
mod error;
mod frk;
mod governance;
mod proof;
mod state;
mod util;
mod witness;

use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

#[cfg(target_os = "solana")]
mod entry {
    pinocchio::program_entrypoint!(super::process_instruction);
    pinocchio::default_allocator!();
    pinocchio::nostd_panic_handler!();
}

pub fn process_instruction(program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let Some((&ix, rest)) = data.split_first() else {
        return Err(ProgramError::InvalidInstructionData);
    };
    match ix {
        0 => governance::initialize(program_id, accounts, rest),
        1 => governance::propose(program_id, accounts, rest),
        2 => governance::apply(program_id, accounts, rest),
        3 => anchor::register_log(program_id, accounts, rest),
        4 => anchor::set_anchor_authority(program_id, accounts, rest),
        5 => anchor::grow_ring(program_id, accounts, rest),
        6 => anchor::post_anchor(program_id, accounts, rest),
        7 => anchor::cosign(program_id, accounts, rest),
        8 => witness::register_witness(program_id, accounts, rest),
        9 => witness::bond_directory(program_id, accounts, rest),
        10 => witness::bond(program_id, accounts, rest),
        11 => witness::request_unbond(program_id, accounts, rest),
        12 => witness::withdraw(program_id, accounts, rest),
        13 => proof::stage_init(program_id, accounts, rest),
        14 => proof::stage_write(program_id, accounts, rest),
        15 => proof::stage_verify(program_id, accounts, rest),
        16 => proof::stage_close(program_id, accounts, rest),
        17 => proof::prove(program_id, accounts, rest, frk::KIND_SAME_SIZE),
        18 => proof::prove(program_id, accounts, rest, frk::KIND_CONTRADICTION),
        19 => proof::prove(program_id, accounts, rest, frk::KIND_ROLLBACK),
        20 => witness::admit_witness(program_id, accounts, rest),
        21 => anchor::close_log(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

//! Test-only SBF harness for the judge's actual introspection implementation.
//! It has no state, accounts to initialize, custody, or deployment role.
#![no_std]
use morse_judge::checkpoint::{require_ed25519, Checkpoint};
use pinocchio::{error::ProgramError, AccountView, Address, ProgramResult};

pinocchio::program_entrypoint!(process);
pinocchio::no_allocator!();
pinocchio::nostd_panic_handler!();

fn process(_program_id: &Address, accounts: &mut [AccountView], data: &[u8]) -> ProgramResult {
    let [instructions] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };
    if data.len() != 190 {
        return Err(ProgramError::InvalidInstructionData);
    }
    let checkpoint = Checkpoint::parse(&data[2..])?;
    require_ed25519(
        instructions,
        u16::from_le_bytes([data[0], data[1]]),
        &checkpoint.service_key,
        &checkpoint.signature,
        &checkpoint.statement(),
    )
}

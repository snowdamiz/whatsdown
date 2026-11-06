#![cfg_attr(target_os = "solana", no_std)]
#[cfg(target_os = "solana")]
mod entry {
    pinocchio::program_entrypoint!(rewards_core::process_instruction);
    pinocchio::no_allocator!();
    pinocchio::nostd_panic_handler!();
}

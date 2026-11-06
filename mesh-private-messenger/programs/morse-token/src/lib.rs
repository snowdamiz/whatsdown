#![cfg_attr(target_os = "solana", no_std)]
pub mod burn;
pub mod collateral_state;
pub mod judge_binding;
pub mod math;
pub mod oracle;
mod processor;
pub mod reserve;
pub mod reward_state;
pub mod swap;
pub use processor::process_instruction;
pub const SUPPLY: u64 = 1_000_000_000_000_000;
pub const ALLOCATIONS: [u64; 7] = [
    250_000_000_000_000,
    200_000_000_000_000,
    180_000_000_000_000,
    150_000_000_000_000,
    150_000_000_000_000,
    50_000_000_000_000,
    20_000_000_000_000,
];
pub const CONFIG_LEN: usize = 320;
pub const ALLOCATION_LEN: usize = 128;

#![cfg_attr(target_os = "solana", no_std)]

pub mod adjudication;
pub mod attendance;
pub mod checkpoint;
pub mod custody;
pub mod fork;
mod processor;
pub mod stage;
pub mod state;
pub mod token_binding;
pub mod token_custody;
pub mod token_deposit;
pub mod token_exit;
pub mod token_proof;
mod verdict;
pub mod witness;
pub use processor::process_instruction;

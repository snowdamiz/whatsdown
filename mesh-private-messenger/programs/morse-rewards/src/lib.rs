#![cfg_attr(target_os = "solana", no_std)]
mod processor;
pub mod state;
pub use processor::{process_instruction, validate_instruction};

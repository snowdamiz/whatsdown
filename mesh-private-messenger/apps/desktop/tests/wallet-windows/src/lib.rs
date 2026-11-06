#[cfg(not(windows))]
compile_error!("This proof requires a Windows target; use --target x86_64-pc-windows-gnu for compilation only.");

// Compile the production host, not a copy with mock Win32 or credential APIs.
#[cfg(windows)]
#[path = "../../../src-tauri/src/wallet.rs"]
pub mod wallet;

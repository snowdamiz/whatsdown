//! Existing wallet SDK with captured native ownership at its real callbacks.
use super::{native_job::{native_scope, NativeScope}, native_protection::NativeProtection, receiver_scope::PrivateScope};
use std::{ffi::{c_char, c_void, CString}, path::Path, sync::Arc};
use zeroize::Zeroizing;
unsafe extern "C" {
    fn MorseDesktopWalletCall(protection: *mut c_void, scope: NativeScope,
        service: *const c_char, directory: *const c_char, pins: *const u8,
        operation: u32, input: *const u8, length: u64, output: *mut u8, capacity: u64, written: *mut u64) -> i32;
}
pub(crate) fn invoke(native: &NativeProtection, scope: PrivateScope, service: &str, directory: &Path,
    pins: &[u8; 34], operation: u32, input: &[u8]) -> Result<Vec<u8>, String> {
    scope.check().map_err(|error| super::commands::failure(error).to_owned())?;
    let scope=Arc::new(scope);
    let service=CString::new(service).map_err(|_| "invalid_wallet_service")?;
    let directory=CString::new(directory.to_str().ok_or("invalid_wallet_directory")?).map_err(|_| "invalid_wallet_directory")?;
    // Link the unchanged real SDK rather than any fixture replacement.
    std::hint::black_box(morse_wallet_core::morse_wallet_call as *const () as usize);
    let mut output=Zeroizing::new(vec![0; 1232]);let mut written=0;
    let status=unsafe { MorseDesktopWalletCall(native.raw(), native_scope(&scope), service.as_ptr(), directory.as_ptr(), pins.as_ptr(),
        operation, input.as_ptr(), input.len() as u64, output.as_mut_ptr(), output.len() as u64, &mut written) };
    scope.check().map_err(|error| super::commands::failure(error).to_owned())?;
    if status!=0 || written>1232 { return Err(format!("wallet_status_{status}")); }
    output.truncate(written as usize);Ok(output.to_vec())
}

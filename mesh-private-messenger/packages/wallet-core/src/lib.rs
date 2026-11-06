//! Custom local wallet custody and constrained Solana signing only.
mod bounty_transfer;
mod derive;
mod payment;
mod store;

use std::{ffi::c_void, sync::Mutex};

pub type Lock = unsafe extern "C" fn(*mut c_void) -> i32;
pub type Load = unsafe extern "C" fn(*mut c_void, *mut u8, u64, *mut u64) -> i32;
pub type Replace = unsafe extern "C" fn(*mut c_void, *const u8, u64) -> i32;
pub type Authorize = unsafe extern "C" fn(*mut c_void, u32, *const u8, u64) -> i32;

#[repr(C)]
pub struct MorseWalletCallbacksV1 {
    pub abi_version: u32,
    pub struct_size: u32,
    pub context: *mut c_void,
    pub acquire: Option<Lock>,
    pub load: Option<Load>,
    pub replace: Option<Replace>,
    pub release: Option<Lock>,
    pub authorize: Option<Authorize>,
    pub usdc_mint: [u8; 32],
    pub purpose: u8,
    pub reserved: [u8; 7],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(i32)]
enum Error {
    Invalid = 1,
    NotFound = 2,
    Storage = 3,
    Cancelled = 4,
    Exhausted = 5,
    Internal = 6,
    BufferTooSmall = 7,
}
static CALL_LOCK: Mutex<()> = Mutex::new(());

/// See the C header for pointer validity and privileged storage requirements.
/// No callback or context pointer is retained after this synchronous call.
///
/// # Safety
/// Non-null pointers must be aligned and valid for their declared structures
/// or buffer lengths. `written` must be writable and must not overlap any
/// other argument; input and output buffers must not overlap. The callback
/// table, its context and callback implementations must remain valid for the
/// call, honor every supplied capacity, and never unwind across the C ABI.
/// Storage callbacks must enforce the locking and custody contract in the
/// header. A callback may invoke the pure formatter, but must not reenter this
/// serialized wallet operation.
#[no_mangle]
pub unsafe extern "C" fn morse_wallet_call(
    callbacks: *const MorseWalletCallbacksV1,
    operation: u32,
    input: *const u8,
    input_length: u64,
    output: *mut u8,
    output_capacity: u64,
    written: *mut u64,
) -> i32 {
    if written.is_null() {
        return Error::Invalid as i32;
    }
    unsafe {
        written.write(0);
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _call = CALL_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if callbacks.is_null() {
            return Err(Error::Invalid);
        }
        let host = unsafe { &*callbacks };
        if host.abi_version != 1
            || host.struct_size as usize != std::mem::size_of::<MorseWalletCallbacksV1>()
            || host.context.is_null()
            || host.acquire.is_none()
            || host.load.is_none()
            || host.replace.is_none()
            || host.release.is_none()
            || host.authorize.is_none()
            || host.purpose > 1
            || host.reserved != [0; 7]
            || host.usdc_mint == [0; 32]
        {
            return Err(Error::Invalid);
        }
        let required = match operation {
            1 | 2 => 32,
            3 | 5 => 1232,
            4 => 40,
            _ => return Err(Error::Invalid),
        };
        if output.is_null() || output_capacity < required {
            return Err(Error::BufferTooSmall);
        }
        if input_length > 256 || (input_length > 0 && input.is_null()) {
            return Err(Error::Invalid);
        }
        let input = if input_length == 0 {
            &[][..]
        } else {
            unsafe { std::slice::from_raw_parts(input, input_length as usize) }
        };
        if !matches!(operation, 3 | 5) && !input.is_empty() {
            return Err(Error::Invalid);
        }
        match operation {
            1 => store::create(host).map(|key| key.to_vec()),
            2 => store::read(host).map(|record| record.address().to_vec()),
            3 => payment::sign(host, input),
            4 => store::reserve_bounty(host),
            5 => bounty_transfer::sign(host, input),
            _ => unreachable!("validated operation"),
        }
    }));
    match result {
        Ok(Ok(bytes)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), output, bytes.len());
                written.write(bytes.len() as u64)
            };
            0
        }
        Ok(Err(error)) => error as i32,
        Err(_) => Error::Internal as i32,
    }
}

#[cfg(test)]
mod tests;

/// Native-only canonical confirmation text; never authorizes a payment.
///
/// # Safety
/// Non-null input/output pointers must be valid for their declared lengths;
/// `written` must be aligned and writable. These three memory regions must not
/// overlap and must remain valid throughout the call. No pointer is retained.
#[no_mangle]
pub unsafe extern "C" fn morse_wallet_authorization_text(
    operation: u32,
    intent: *const u8,
    length: u64,
    output: *mut u8,
    capacity: u64,
    written: *mut u64,
) -> i32 {
    if written.is_null() {
        return Error::Invalid as i32;
    }
    unsafe {
        written.write(0);
    }
    let result = std::panic::catch_unwind(|| {
        if intent.is_null() || length > 288 {
            return Err(Error::Invalid);
        }
        let intent = unsafe { std::slice::from_raw_parts(intent, length as usize) };
        let text = payment::authorization_text(operation, intent)?;
        if text.len() > 2048 {
            return Err(Error::Internal);
        }
        if output.is_null() || capacity < text.len() as u64 {
            return Err(Error::BufferTooSmall);
        }
        Ok(text)
    });
    match result {
        Ok(Ok(text)) => {
            unsafe {
                std::ptr::copy_nonoverlapping(text.as_ptr(), output, text.len());
                written.write(text.len() as u64);
            }
            0
        }
        Ok(Err(error)) => error as i32,
        Err(_) => Error::Internal as i32,
    }
}

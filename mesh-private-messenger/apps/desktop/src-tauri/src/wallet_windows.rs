use morse_wallet_core::{
    morse_wallet_authorization_text, morse_wallet_call, MorseWalletCallbacksV1,
};
use std::{
    ffi::c_void,
    path::Path,
    ptr,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    time::Duration,
};
use windows_sys::Win32::{
    Foundation::*,
    Security::{
        Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser, TOKEN_QUERY,
        TOKEN_USER,
    },
    System::Threading::*,
    UI::{Accessibility::*, WindowsAndMessaging::*},
};
use zeroize::Zeroizing;

struct Host {
    service: String,
    lock: Option<KernelMutex>,
    parent: isize,
}
fn entry(host: &Host, name: &str) -> Result<keyring::Entry, i32> {
    keyring::Entry::new(&host.service, name).map_err(|_| 3)
}
fn read(host: &Host, name: &str) -> Result<Option<Zeroizing<Vec<u8>>>, i32> {
    match entry(host, name)?.get_secret() {
        Ok(bytes) => Ok(Some(Zeroizing::new(bytes))),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(_) => Err(3),
    }
}
fn put(host: &Host, name: &str, value: &[u8]) -> Result<(), i32> {
    entry(host, name)?.set_secret(value).map_err(|_| 3)
}
// Credential Manager owns the whole record; no app-file snapshot can rewind
// it. The OS lock is independent of replaceable filesystem paths, including
// the first initialization. Its name uses the authenticated OS user SID and
// the global namespace so two sessions of the same user serialize as well.
struct KernelMutex {
    handle: HANDLE,
    held: bool,
}
impl KernelMutex {
    fn release(mut self) -> Result<(), i32> {
        let released = unsafe { ReleaseMutex(self.handle) } != 0;
        self.held = false;
        let closed = unsafe { CloseHandle(self.handle) } != 0;
        self.handle = ptr::null_mut();
        if released && closed {
            Ok(())
        } else {
            Err(3)
        }
    }
}
impl Drop for KernelMutex {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            unsafe {
                if self.held {
                    ReleaseMutex(self.handle);
                }
                CloseHandle(self.handle);
            }
        }
    }
}
fn user_sid() -> Result<String, i32> {
    let mut token = ptr::null_mut();
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
        return Err(3);
    }
    let answer = (|| {
        let mut needed = 0;
        unsafe {
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        }
        if needed == 0 || needed > 65536 {
            return Err(3);
        }
        let mut words = vec![0usize; (needed as usize).div_ceil(std::mem::size_of::<usize>())];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                words.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(3);
        }
        let user = unsafe { &*words.as_ptr().cast::<TOKEN_USER>() };
        let mut text = ptr::null_mut();
        if unsafe { ConvertSidToStringSidW(user.User.Sid, &mut text) } == 0 {
            return Err(3);
        }
        let mut length = 0;
        while length < 185 && unsafe { *text.add(length) } != 0 {
            length += 1;
        }
        let result = if length < 185 {
            String::from_utf16(unsafe { std::slice::from_raw_parts(text, length) }).map_err(|_| 3)
        } else {
            Err(3)
        };
        unsafe {
            LocalFree(text.cast());
        }
        result
    })();
    unsafe {
        CloseHandle(token);
    }
    answer
}
fn kernel_lock(service: &str, timeout: u32) -> Result<KernelMutex, i32> {
    if service.is_empty()
        || !service
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(3);
    }
    let name = format!("Global\\MorseWallet-v1-{}-{}", user_sid()?, service);
    let mut name: Vec<u16> = name.encode_utf16().collect();
    if name.len() > 250 {
        return Err(3);
    }
    name.push(0);
    let handle = unsafe { CreateMutexW(ptr::null(), 0, name.as_ptr()) };
    if handle.is_null() {
        return Err(3);
    }
    let mut guard = KernelMutex {
        handle,
        held: false,
    };
    match unsafe { WaitForSingleObject(handle, timeout) } {
        WAIT_OBJECT_0 | WAIT_ABANDONED => {
            guard.held = true;
            Ok(guard)
        }
        _ => Err(3),
    }
}
unsafe extern "C" fn acquire(context: *mut c_void) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = unsafe { &mut *context.cast::<Host>() };
        if host.lock.is_some() {
            return Err(3);
        }
        host.lock = Some(kernel_lock(&host.service, 30_000)?);
        Ok(())
    }))
    .map_or(3, |result| result.map_or_else(|e| e, |()| 0))
}
unsafe extern "C" fn release(context: *mut c_void) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = unsafe { &mut *context.cast::<Host>() };
        host.lock.take().ok_or(3)?.release()
    }))
    .map_or(3, |result| result.map_or_else(|e| e, |()| 0))
}
unsafe extern "C" fn load(
    context: *mut c_void,
    output: *mut u8,
    capacity: u64,
    written: *mut u64,
) -> i32 {
    if written.is_null() {
        return 3;
    }
    unsafe {
        *written = 0;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = unsafe { &*context.cast::<Host>() };
        if host.lock.is_none() || output.is_null() || capacity < 44 {
            return Err(3);
        }
        match (read(host, "initialized-v1")?, read(host, "record-v1")?) {
            (None, None) => Err(2),
            (Some(marker), Some(bytes)) if marker.as_slice() == [1] && bytes.len() == 44 => {
                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), output, 44);
                    *written = 44;
                }
                Ok(())
            }
            _ => Err(3),
        }
    }))
    .map_or(3, |result| result.map_or_else(|e| e, |()| 0))
}
unsafe extern "C" fn replace(context: *mut c_void, input: *const u8, length: u64) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = unsafe { &*context.cast::<Host>() };
        if host.lock.is_none() || input.is_null() || length != 44 {
            return Err(3);
        }
        let bytes = unsafe { std::slice::from_raw_parts(input, 44) };
        if &bytes[..4] != b"MWL1" {
            return Err(3);
        }
        match (read(host, "initialized-v1")?, read(host, "record-v1")?) {
            (None, None) => {
                put(host, "initialized-v1", &[1])?;
                put(host, "record-v1", bytes)
            }
            (Some(marker), Some(old)) if marker.as_slice() == [1] && old.len() == 44 => {
                put(host, "record-v1", bytes)
            }
            _ => Err(3),
        }
    }))
    .map_or(3, |result| result.map_or_else(|e| e, |()| 0))
}
fn foreground() -> bool {
    let mut process = 0;
    unsafe {
        GetWindowThreadProcessId(GetForegroundWindow(), &mut process);
        process == GetCurrentProcessId()
    }
}
unsafe extern "system" fn close_dialog(window: HWND, _data: LPARAM) -> i32 {
    let mut class = [0u16; 32];
    let length = unsafe { GetClassNameW(window, class.as_mut_ptr(), class.len() as i32) };
    if length > 0 && String::from_utf16_lossy(&class[..length as usize]) == "#32770" {
        unsafe {
            PostMessageW(window, WM_CLOSE, 0, 0);
        }
    }
    1
}
thread_local! {static FOREGROUND_LOSS: std::cell::RefCell<Option<Arc<AtomicBool>>> = const {std::cell::RefCell::new(None)};}
unsafe extern "system" fn foreground_event(
    _hook: HWINEVENTHOOK,
    _event: u32,
    window: HWND,
    _object: i32,
    _child: i32,
    _thread: u32,
    _time: u32,
) {
    let mut process = 0;
    unsafe {
        GetWindowThreadProcessId(window, &mut process);
    }
    if process != unsafe { GetCurrentProcessId() } {
        FOREGROUND_LOSS.with(|state| {
            if let Some(cancelled) = state.borrow().as_ref() {
                cancelled.store(true, Ordering::Release);
            }
        });
    }
}
unsafe extern "C" fn authorize(
    context: *mut c_void,
    operation: u32,
    intent: *const u8,
    length: u64,
) -> i32 {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let host = unsafe { &*context.cast::<Host>() };
        if host.parent == 0 || !foreground() {
            return 4;
        }
        let mut text = [0; 2048];
        let mut written = 0;
        if unsafe {
            morse_wallet_authorization_text(
                operation,
                intent,
                length,
                text.as_mut_ptr(),
                text.len() as u64,
                &mut written,
            )
        } != 0
            || written > 2048
        {
            return 4;
        }
        let Ok(text) = std::str::from_utf8(&text[..written as usize]) else {
            return 4;
        };
        let message: Vec<u16> = text.encode_utf16().chain(Some(0)).collect();
        let title: Vec<u16> = "Morse wallet confirmation"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let ended = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::new(AtomicBool::new(false));
        let thread = unsafe { GetCurrentThreadId() };
        let finished = ended.clone();
        let aborted = cancelled.clone();
        let (ready, started) = std::sync::mpsc::sync_channel(1);
        let monitor = std::thread::spawn(move || {
            FOREGROUND_LOSS.with(|state| *state.borrow_mut() = Some(aborted.clone()));
            let hook = unsafe {
                SetWinEventHook(
                    EVENT_SYSTEM_FOREGROUND,
                    EVENT_SYSTEM_FOREGROUND,
                    ptr::null_mut(),
                    Some(foreground_event),
                    0,
                    0,
                    WINEVENT_OUTOFCONTEXT,
                )
            };
            let okay = !hook.is_null();
            let _ = ready.send(okay);
            if !okay {
                return;
            }
            for tick in 0..12000 {
                if finished.load(Ordering::Acquire) {
                    break;
                }
                let mut message = MSG::default();
                while unsafe { PeekMessageW(&mut message, ptr::null_mut(), 0, 0, PM_REMOVE) } != 0 {
                    unsafe {
                        TranslateMessage(&message);
                        DispatchMessageW(&message);
                    }
                }
                if !foreground() || tick == 11999 {
                    aborted.store(true, Ordering::Release);
                }
                if aborted.load(Ordering::Acquire) {
                    unsafe {
                        EnumThreadWindows(thread, Some(close_dialog), 0);
                    }
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            unsafe {
                UnhookWinEvent(hook);
            }
            FOREGROUND_LOSS.with(|state| *state.borrow_mut() = None);
        });
        if started.recv() != Ok(true) {
            ended.store(true, Ordering::Release);
            let _ = monitor.join();
            return 4;
        }
        let answer = unsafe {
            MessageBoxW(
                host.parent as HWND,
                message.as_ptr(),
                title.as_ptr(),
                MB_OKCANCEL | MB_ICONWARNING | MB_DEFBUTTON2,
            )
        };
        ended.store(true, Ordering::Release);
        let _ = monitor.join();
        if answer == IDOK && !cancelled.load(Ordering::Acquire) && foreground() {
            0
        } else {
            4
        }
    }))
    .unwrap_or(4)
}

pub fn invoke(
    service: &str,
    directory: &Path,
    pins: &[u8; 34],
    parent: isize,
    operation: u32,
    input: &[u8],
) -> Result<Vec<u8>, String> {
    if !directory.is_absolute() {
        return Err("invalid_wallet_directory".into());
    }
    let mut host = Host {
        service: service.to_owned(),
        lock: None,
        parent,
    };
    let callbacks = MorseWalletCallbacksV1 {
        abi_version: 1,
        struct_size: std::mem::size_of::<MorseWalletCallbacksV1>() as u32,
        context: (&mut host as *mut Host).cast(),
        acquire: Some(acquire),
        load: Some(load),
        replace: Some(replace),
        release: Some(release),
        authorize: Some(authorize),
        usdc_mint: pins[2..].try_into().map_err(|_| "wallet_mint_invalid")?,
        purpose: pins[1],
        reserved: [0; 7],
    };
    let mut output = vec![0; 1232];
    let mut written = 0;
    let status = unsafe {
        morse_wallet_call(
            &callbacks,
            operation,
            input.as_ptr(),
            input.len() as u64,
            output.as_mut_ptr(),
            output.len() as u64,
            &mut written,
        )
    };
    if status != 0 || written > 1232 {
        return Err(format!("wallet_status_{status}"));
    }
    output.truncate(written as usize);
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn kernel_lock_serializes_even_without_a_shared_app_file() {
        let service = format!("morse-wallet-disposable-mutex-proof-{}", std::process::id());
        let first = kernel_lock(&service, 1000).unwrap();
        let other = service.clone();
        assert!(std::thread::spawn(move || kernel_lock(&other, 0).is_err())
            .join()
            .unwrap());
        first.release().unwrap();
        assert!(std::thread::spawn(move || kernel_lock(&service, 1000)
            .and_then(|guard| guard.release())
            .is_ok())
        .join()
        .unwrap());
    }
}

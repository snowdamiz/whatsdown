//! Retained exact private lease for native callbacks and owned resources.
use super::receiver_scope::PrivateScope;
use std::{ffi::c_void, sync::Arc};

#[repr(C)]
pub(crate) struct NativeScope {
    context: *const c_void,
    retain: extern "C" fn(*const c_void),
    release: extern "C" fn(*const c_void),
    current: extern "C" fn(*const c_void) -> bool,
    window: u64,
    page: u64,
}
extern "C" fn retain(raw: *const c_void) {
    unsafe { Arc::increment_strong_count(raw.cast::<PrivateScope>()) };
}
extern "C" fn release(raw: *const c_void) {
    unsafe { Arc::decrement_strong_count(raw.cast::<PrivateScope>()) };
}
extern "C" fn current(raw: *const c_void) -> bool {
    match std::panic::catch_unwind(|| unsafe { &*raw.cast::<PrivateScope>() }.check().is_ok()) {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    }
}
pub(crate) fn native_scope(scope: &Arc<PrivateScope>) -> NativeScope {
    let owner = scope.owner();
    NativeScope { context: Arc::as_ptr(scope).cast(), retain, release, current, window: owner.window, page: owner.webview }
}

pub(crate) fn cleanup_scope(scope: &Arc<super::receiver_scope::RetiredCleanup>) -> NativeScope {
    use super::receiver_scope::RetiredCleanup;
    extern "C" fn retain(raw: *const c_void) { unsafe { Arc::increment_strong_count(raw.cast::<RetiredCleanup>()) }; }
    extern "C" fn release(raw: *const c_void) { unsafe { Arc::decrement_strong_count(raw.cast::<RetiredCleanup>()) }; }
    extern "C" fn current(raw: *const c_void) -> bool {
        match std::panic::catch_unwind(|| unsafe { &*raw.cast::<RetiredCleanup>() }.check().is_ok()) {
            Ok(value) => value, Err(_) => std::process::abort(),
        }
    }
    let owner=scope.owner();
    NativeScope { context: Arc::as_ptr(scope).cast(), retain, release, current, window: owner.window, page: owner.webview }
}

//! Retained original receiver and notification-choice revision for OS callbacks.
use super::{controller::Refusal, receiver_scope::{MainThread, PrivateScope}};
use std::{ffi::c_void, sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}}};

pub(crate) struct NotificationActions {
    revision: AtomicU64,
    closed: AtomicBool,
}
#[derive(Clone)]
pub(crate) struct NotificationAction {
    scope: PrivateScope,
    actions: Arc<NotificationActions>,
    revision: u64,
}
impl NotificationActions {
    pub(crate) fn new() -> Self {
        Self { revision: AtomicU64::new(0), closed: AtomicBool::new(false) }
    }
    pub(crate) fn begin(self: &Arc<Self>, _main: &MainThread, scope: PrivateScope,
        changes_choice: bool) -> Result<NotificationAction, Refusal> {
        scope.check()?;
        if self.closed.load(Ordering::Acquire) { return Err(Refusal::Cancelled); }
        let revision = if changes_choice {
            self.revision.try_update(Ordering::AcqRel, Ordering::Acquire, |old| old.checked_add(1))
                .map_err(|_| Refusal::Exhausted)? + 1
        } else { self.revision.load(Ordering::Acquire) };
        let action = NotificationAction { scope, actions: self.clone(), revision };
        action.check()?;
        Ok(action)
    }
    pub(crate) fn close(&self) { self.closed.store(true, Ordering::Release); }
}
impl NotificationAction {
    pub(crate) fn check(&self) -> Result<(), Refusal> {
        self.scope.check()?;
        if self.actions.closed.load(Ordering::Acquire) ||
            self.actions.revision.load(Ordering::Acquire) != self.revision {
            return Err(Refusal::Cancelled);
        }
        Ok(())
    }
    pub(crate) fn scope(&self) -> PrivateScope { self.scope.clone() }
}

// Exact MDPrivateScope layout from PrivateJob.h. The retained context has no
// native-pointer reference, so callback ownership cannot cycle through the port.
#[repr(C)]
pub(crate) struct NativeAuthorizationScope {
    context: *const c_void,
    retain: extern "C" fn(*const c_void),
    release: extern "C" fn(*const c_void),
    current: extern "C" fn(*const c_void) -> bool,
    window: u64,
    page: u64,
}
extern "C" fn retain(raw: *const c_void) {
    unsafe { Arc::increment_strong_count(raw.cast::<NotificationAction>()) };
}
extern "C" fn release(raw: *const c_void) {
    unsafe { Arc::decrement_strong_count(raw.cast::<NotificationAction>()) };
}
extern "C" fn current(raw: *const c_void) -> bool {
    match std::panic::catch_unwind(|| unsafe { &*raw.cast::<NotificationAction>() }.check().is_ok()) {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    }
}
pub(crate) fn native_authorization_scope(action: &Arc<NotificationAction>) -> NativeAuthorizationScope {
    let owner = action.scope.owner();
    NativeAuthorizationScope { context: Arc::as_ptr(action).cast(), retain, release, current,
        window: owner.window, page: owner.webview }
}

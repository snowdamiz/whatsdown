//! Actual native drop/paste ports; original scopes and URL ownership cross the
//! asynchronous boundary together. JS never supplies a path or clipboard key.
use super::{
    controller::Refusal,
    incoming_files::IncomingTicket,
    native_job::{native_scope, NativeScope},
    native_panels::NativeSelection,
    receiver_scope::MainThread,
};
use std::{ffi::c_void, ptr::NonNull, sync::Arc, time::Instant};

#[derive(Clone, Copy)]
pub(crate) enum IncomingHint {
    Sources,
    Dragging(bool),
}
pub(crate) type Wake = Arc<dyn Fn(IncomingTicket, IncomingHint) + Send + Sync>;
struct CallbackState {
    ticket: IncomingTicket,
    wake: Wake,
}
#[repr(C)]
struct Callbacks {
    context: *const c_void,
    retain: extern "C" fn(*const c_void),
    release: extern "C" fn(*const c_void),
    sources: extern "C" fn(*const c_void, *const c_void, u64) -> bool,
    dragging: extern "C" fn(*const c_void, bool),
}
unsafe extern "C" {
    fn MDNativeIncomingSubscribe(
        protection: *mut c_void,
        window: *mut c_void,
        view: *mut c_void,
        scope: NativeScope,
        callbacks: Callbacks,
    ) -> *mut c_void;
    fn MDNativeIncomingClose(token: *mut c_void);
    fn MDNativeIncomingRelease(token: *mut c_void);
}
fn boundary<T>(body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    }
}
extern "C" fn retain(raw: *const c_void) {
    unsafe { Arc::increment_strong_count(raw.cast::<CallbackState>()) };
}
extern "C" fn release(raw: *const c_void) {
    boundary(|| unsafe { Arc::decrement_strong_count(raw.cast::<CallbackState>()) });
}
extern "C" fn sources(raw: *const c_void, rows: *const c_void, count: u64) -> bool {
    boundary(|| {
        let state = unsafe { &*raw.cast::<CallbackState>() };
        let Ok(capture) = state.ticket.capture() else {
            return false;
        };
        let Ok(selected) = (unsafe { NativeSelection::copy_native_rows(rows, count) }) else {
            return false;
        };
        let wake = state.wake.clone();
        // The process-wide four-job reservation spans the real native metadata/
        // FD worker, even after subscription cancellation or context replacement.
        tauri::async_runtime::spawn_blocking(move || {
            let sources = selected
                .into_iter()
                .map(NativeSelection::source)
                .collect::<Result<Vec<_>, _>>();
            if let Ok(sources) = sources {
                if capture.complete(sources, Instant::now()).unwrap_or(false)
                    && capture.ticket().current()
                {
                    wake(capture.ticket().clone(), IncomingHint::Sources);
                }
            }
        });
        true
    })
}
extern "C" fn dragging(raw: *const c_void, value: bool) {
    boundary(|| {
        let state = unsafe { &*raw.cast::<CallbackState>() };
        if state.ticket.dragging_changed(value) {
            (state.wake)(state.ticket.clone(), IncomingHint::Dragging(value));
        }
    });
}
fn callbacks(state: &Arc<CallbackState>) -> Callbacks {
    Callbacks {
        context: Arc::as_ptr(state).cast(),
        retain,
        release,
        sources,
        dragging,
    }
}
pub(crate) struct IncomingToken(NonNull<c_void>);
// Operations are a native atomic close latch and later-Main destruction only.
unsafe impl Send for IncomingToken {}
impl Drop for IncomingToken {
    fn drop(&mut self) {
        unsafe {
            MDNativeIncomingClose(self.0.as_ptr());
            MDNativeIncomingRelease(self.0.as_ptr());
        }
    }
}
pub(crate) unsafe fn subscribe(
    protection: *mut c_void,
    window: *mut c_void,
    view: *mut c_void,
    ticket: IncomingTicket,
    wake: Wake,
) -> Result<IncomingToken, Refusal> {
    MainThread::current()?;
    if !ticket.current() {
        return Err(Refusal::StaleEpoch);
    }
    let scope = Arc::new(ticket.scope());
    let state = Arc::new(CallbackState { ticket, wake });
    NonNull::new(unsafe {
        MDNativeIncomingSubscribe(
            protection,
            window,
            view,
            native_scope(&scope),
            callbacks(&state),
        )
    })
    .map(IncomingToken)
    .ok_or(Refusal::Cancelled)
}

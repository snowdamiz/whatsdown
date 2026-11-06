//! Native original-owner chooser jobs. No path/URL is accepted from or sent to JS.
use super::{
    controller::Refusal,
    native_job::{native_scope, NativeScope},
    native_protection::NativeProtection,
    private_choices::SelectedSource,
    private_destinations::ChosenDestination,
    private_files::{ChosenSource, FileError, NativeFileAccess},
    receiver_scope::{MainThread, PrivateScope},
};
use std::{
    ffi::c_void,
    path::Path,
    ptr::NonNull,
    sync::{Arc, Mutex},
};
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum SourcePurpose {
    Attachment = 0,
    Avatar = 1,
    Backup = 2,
}
#[repr(C)]
struct SelectionRow {
    owner: *mut c_void,
    path: *const u8,
    path_length: u64,
    name: *const u8,
    name_length: u64,
    mime: *const u8,
    mime_length: u64,
}
#[repr(C)]
struct Callbacks {
    context: *const c_void,
    retain: extern "C" fn(*const c_void),
    release: extern "C" fn(*const c_void),
    reply: extern "C" fn(*const c_void, u32, *const SelectionRow, u64),
}
unsafe extern "C" {
    pub(super) fn MDNativeFilePanelsCreate(protection: *mut c_void) -> *mut c_void;
    pub(super) fn MDNativeFilePanelsClose(registry: *mut c_void);
    pub(super) fn MDNativeFilePanelsRelease(registry: *mut c_void);
    fn MDNativeFilePanelsOpen(
        registry: *mut c_void,
        scope: NativeScope,
        purpose: u32,
        callbacks: Callbacks,
    ) -> *mut c_void;
    fn MDNativeFilePanelsSave(
        registry: *mut c_void,
        scope: NativeScope,
        name: *const u8,
        name_length: u64,
        mime: *const u8,
        mime_length: u64,
        callbacks: Callbacks,
    ) -> *mut c_void;
    fn MDNativeFilePanelCancel(token: *mut c_void);
    fn MDNativeFilePanelTokenRelease(token: *mut c_void);
    fn MDNativeFileURLRetain(owner: *mut c_void);
    fn MDNativeFileURLRelease(owner: *mut c_void);
}
fn boundary<T>(body: impl FnOnce() -> T) -> T {
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(body)) {
        Ok(value) => value,
        Err(_) => std::process::abort(),
    }
}
struct URLAccess(NonNull<c_void>);
// Only immutable, retained original NSURL custody crosses threads. Destruction
// is explicitly queued to native main; no AppKit object is accessed by Rust.
unsafe impl Send for URLAccess {}
unsafe impl Sync for URLAccess {}
impl NativeFileAccess for URLAccess {}
impl Drop for URLAccess {
    fn drop(&mut self) {
        unsafe {
            MDNativeFileURLRelease(self.0.as_ptr());
        }
    }
}
pub(crate) struct NativeSelection {
    path: Zeroizing<String>,
    name: Zeroizing<String>,
    mime: Zeroizing<String>,
    access: Arc<URLAccess>,
}
impl NativeSelection {
    pub(crate) unsafe fn copy_native_rows(
        rows: *const c_void,
        count: u64,
    ) -> Result<Vec<Self>, PanelFailure> {
        MainThread::current().map_err(|_| PanelFailure::Unavailable)?;
        let rows = rows.cast::<SelectionRow>();
        if rows.is_null() || count == 0 || count > 10 {
            return Err(PanelFailure::Unavailable);
        }
        let mut selected = Vec::with_capacity(count as usize);
        for row in unsafe { std::slice::from_raw_parts(rows, count as usize) } {
            let owner = NonNull::new(row.owner).ok_or(PanelFailure::Unavailable)?;
            // Retain raw returned ownership before any parsing or async
            // completion fence can refuse. All early paths drop this Arc.
            unsafe {
                MDNativeFileURLRetain(owner.as_ptr());
            }
            let access = Arc::new(URLAccess(owner));
            let path = unsafe { text(row.path, row.path_length, 4096) }
                .ok_or(PanelFailure::Unavailable)?;
            let name =
                unsafe { text(row.name, row.name_length, 255) }.ok_or(PanelFailure::Unavailable)?;
            let mime =
                unsafe { text(row.mime, row.mime_length, 127) }.ok_or(PanelFailure::Unavailable)?;
            if !Path::new(path.as_str()).is_absolute() || path.contains('\0') {
                return Err(PanelFailure::Unavailable);
            }
            selected.push(NativeSelection {
                path,
                name,
                mime,
                access,
            });
        }
        Ok(selected)
    }
    pub(crate) fn source(self) -> Result<SelectedSource, FileError> {
        let source = ChosenSource::open_selected(Path::new(self.path.as_str()), self.access)?;
        SelectedSource::new(&self.name, &self.mime, source)
    }
    pub(crate) fn destination(
        self,
    ) -> Result<ChosenDestination, super::private_exports::ExportError> {
        ChosenDestination::capture_selected(Path::new(self.path.as_str()), self.access)
    }
}
#[derive(Clone, Copy, Debug)]
pub(crate) enum PanelFailure {
    Cancelled,
    Unavailable,
}
pub(crate) type PanelReply = Result<Vec<NativeSelection>, PanelFailure>;
struct PendingState {
    _scope: Arc<PrivateScope>,
    sender: Mutex<Option<tauri::async_runtime::Sender<PanelReply>>>,
}
extern "C" fn retain(raw: *const c_void) {
    unsafe {
        Arc::increment_strong_count(raw.cast::<PendingState>());
    }
}
extern "C" fn release(raw: *const c_void) {
    boundary(|| unsafe {
        Arc::decrement_strong_count(raw.cast::<PendingState>());
    });
}
unsafe fn text(bytes: *const u8, length: u64, maximum: u64) -> Option<Zeroizing<String>> {
    if bytes.is_null() || length == 0 || length > maximum {
        return None;
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(bytes, length as usize) })
        .ok()
        .map(|value| Zeroizing::new(value.to_owned()))
}
extern "C" fn reply(raw: *const c_void, status: u32, rows: *const SelectionRow, count: u64) {
    boundary(|| {
        let state = unsafe { &*raw.cast::<PendingState>() };
        let result = (|| {
            MainThread::current().map_err(|_| PanelFailure::Unavailable)?;
            match status {
                1 if count == 0 => return Err(PanelFailure::Cancelled),
                2 if count == 0 => return Err(PanelFailure::Unavailable),
                0 => {}
                _ => return Err(PanelFailure::Unavailable),
            }
            unsafe { NativeSelection::copy_native_rows(rows.cast(), count) }
        })();
        // Dropping a receiver disposes all untransferred URL owners. Neither
        // callback/resource destruction nor policy checks occur under this lock.
        let sender = { state.sender.lock().unwrap().take() };
        if let Some(sender) = sender {
            let _ = sender.try_send(result);
        }
    });
}
pub(crate) struct PanelRequest(NonNull<c_void>);
// Its only operation is native atomic cancellation of this exact job token.
unsafe impl Send for PanelRequest {}
unsafe impl Sync for PanelRequest {}
impl PanelRequest {
    pub(crate) fn cancel(&self) {
        unsafe {
            MDNativeFilePanelCancel(self.0.as_ptr());
        }
    }
}
impl Drop for PanelRequest {
    fn drop(&mut self) {
        self.cancel();
        unsafe {
            MDNativeFilePanelTokenRelease(self.0.as_ptr());
        }
    }
}
pub(crate) struct PendingPanel {
    pub(crate) request: Arc<PanelRequest>,
    receive: tauri::async_runtime::Receiver<PanelReply>,
}
impl PendingPanel {
    pub(crate) async fn receive(&mut self) -> PanelReply {
        self.receive
            .recv()
            .await
            .unwrap_or(Err(PanelFailure::Unavailable))
    }
}
impl NativeProtection {
    fn start_panel(
        &self,
        scope: PrivateScope,
        source: Option<SourcePurpose>,
        name: &str,
        mime: &str,
    ) -> Result<PendingPanel, Refusal> {
        MainThread::current()?;
        scope.check()?;
        let scope = Arc::new(scope);
        let (send, receive) = tauri::async_runtime::channel(1);
        let state = Arc::new(PendingState {
            _scope: scope.clone(),
            sender: Mutex::new(Some(send)),
        });
        let callbacks = Callbacks {
            context: Arc::as_ptr(&state).cast(),
            retain,
            release,
            reply,
        };
        let raw = match source {
            Some(purpose) => unsafe {
                MDNativeFilePanelsOpen(
                    self.panels_raw(),
                    native_scope(&scope),
                    purpose as u32,
                    callbacks,
                )
            },
            None => unsafe {
                MDNativeFilePanelsSave(
                    self.panels_raw(),
                    native_scope(&scope),
                    name.as_ptr(),
                    name.len() as u64,
                    mime.as_ptr(),
                    mime.len() as u64,
                    callbacks,
                )
            },
        };
        let token = match NonNull::new(raw) {
            Some(token) => token,
            None => {
                scope.check()?;
                return Err(Refusal::Busy);
            }
        };
        // No post-prepare private read: queued OS construction rechecks this
        // exact scope. Register a request-broker on_cancel inside the same main
        // receiving closure before returning PendingPanel. Picker inactivity
        // may then retire this lease. Caller stores its exact ChoiceAnchor
        // result first, then
        // rechecks its original PrivateCall before any JS metadata publication.
        Ok(PendingPanel {
            request: Arc::new(PanelRequest(token)),
            receive,
        })
    }
    pub(crate) fn choose_source_on_main(
        &self,
        scope: PrivateScope,
        purpose: SourcePurpose,
    ) -> Result<PendingPanel, Refusal> {
        self.start_panel(scope, Some(purpose), "", "")
    }
    pub(crate) fn choose_destination_on_main(
        &self,
        scope: PrivateScope,
        name: &str,
        mime: &str,
    ) -> Result<PendingPanel, Refusal> {
        self.start_panel(scope, None, name, mime)
    }
}

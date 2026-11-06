//! Actual macOS registry/cover/lifecycle bridge. No approval IPC exists.
use crate::desktop_lock::controller::*;
use std::collections::HashMap;
use std::ffi::c_void;
use std::ptr::NonNull;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Mutex, OnceLock, Weak,
};
use std::time::Instant;

type Reply = Arc<dyn Fn(AuthReply) + Send + Sync>;
type Publish = dyn Fn(Presentation) + Send + Sync;
type Retire = dyn Fn(Epoch) + Send + Sync;
struct Sink {
    boot: [u8; 16],
    controller: OnceLock<Weak<Controller>>,
    latest: Mutex<Option<Presentation>>,
    replies: Mutex<HashMap<u64, Reply>>,
    retired_through: AtomicU64,
    publish: Box<Publish>,
    retire: Box<Retire>,
}
#[repr(C)]
struct Callbacks {
    context: *const c_void,
    retain: extern "C" fn(*const c_void),
    release: extern "C" fn(*const c_void),
    lifecycle: extern "C" fn(*const c_void, u64, u64, u32),
    auth_reply: extern "C" fn(*const c_void, u64, u32),
    public_action: extern "C" fn(*const c_void, u64, u64, u64, u32),
}
unsafe extern "C" {
    fn MDNativeProtectionCreate(callbacks: Callbacks) -> *mut c_void;
    fn MDNativeProtectionAttach(
        context: *mut c_void,
        window: *mut c_void,
        view: *mut c_void,
        window_id: u64,
        page_id: u64,
    ) -> bool;
    fn MDNativeProtectionReceiver(
        context: *mut c_void,
        window: *mut c_void,
        view: *mut c_void,
        window_id: *mut u64,
        page_id: *mut u64,
    ) -> bool;
    fn MDNativeProtectionPrivateReceiver(context:*mut c_void,view:*mut c_void,window:*mut u64,page:*mut u64)->bool;
    fn MDNativeProtectionRetirePage(context: *mut c_void, window_id: u64, page_id: u64);
    fn MDNativeProtectionReopen(context: *mut c_void) -> bool;
    fn MDNativeProtectionFocusPublic(context: *mut c_void) -> bool;
    fn MDNativeProtectionHide(context: *mut c_void, window: u64, page: u64) -> bool;
    fn MDNativeProtectionForeground(context: *mut c_void) -> bool;
    fn MDNativeProtectionWindowAction(context: *mut c_void, window: u64, page: u64, revision: u64, action: u32) -> bool;
    fn MDNativeAuthenticationAvailable() -> bool;
    fn MDNativeProtectionOpenPayment(context: *mut c_void, scope: super::native_job::NativeScope, url: *const u8, length: u64) -> bool;
    fn MDNativeProtectionCopyText(context: *mut c_void, scope: super::native_job::NativeScope, text: *const u8, length: u64) -> bool;
    fn MDNativeProtectionLegacy(context: *mut c_void, scope: super::native_job::NativeScope,
        key: *const u8, length: u64, read: bool, reply_context: *mut c_void,
        reply: extern "C" fn(*mut c_void,u32,*const u8,u64)) -> bool;
    fn MDNativeProtectionForgetLegacy(context: *mut c_void, scope: super::native_job::NativeScope,
        key: *const u8, length: u64, reply_context: *mut c_void,
        reply: extern "C" fn(*mut c_void,u32,*const u8,u64)) -> bool;
    fn MDNativeProtectionApply(
        context: *mut c_void,
        revision: u64,
        window_id: u64,
        page_id: u64,
        has_owner: bool,
        uncover: bool,
        phase: u32,
        sequence: u64,
        account_generation: u64,
        notice_private_allowed: bool,
    );
    fn MDNativeProtectionBegin(
        context: *mut c_void,
        window_id: u64,
        page_id: u64,
        sequence: u64,
    ) -> bool;
    fn MDNativeProtectionCancel(context: *mut c_void, sequence: u64);
    fn MDNativeProtectionClose(context: *mut c_void);
    fn MDNativeProtectionBootFailed(context: *mut c_void);
    fn MDNativeProtectionRelease(context: *mut c_void);
    fn MDNativeProtectionDeferMain(work:*mut c_void,run:extern "C" fn(*mut c_void));
}
pub(crate) struct LegacyReply { pub(crate) status:u32,pub(crate) bytes:zeroize::Zeroizing<Vec<u8>> }
extern "C" fn legacy_reply(raw:*mut c_void,status:u32,bytes:*const u8,length:u64) {
    boundary(|| {
        // The native registry transfers this sender exactly once, including
        // timeout/close. Its SDK tests exercise duplicate/late completion.
        let sender=unsafe { Box::from_raw(raw.cast::<tauri::async_runtime::Sender<LegacyReply>>()) };
        let valid=status<=4 && length<=16_794_632 && (length==0 || !bytes.is_null()) && (status==0 || length==0);
        let reply=if valid {
            let value=if length==0 { Vec::new() } else { unsafe { std::slice::from_raw_parts(bytes,length as usize) }.to_vec() };
            LegacyReply { status,bytes:zeroize::Zeroizing::new(value) }
        } else { LegacyReply { status:4,bytes:zeroize::Zeroizing::new(Vec::new()) } };
        // A dropped awaiting command drops and wipes the retained raw payload.
        let _=sender.try_send(reply);
    });
}
// Never unwind through an Objective-C/C callback. A broken invariant retires
// the process/window rather than continuing with a private presentation.
fn boundary(work: impl FnOnce()) {
    if std::panic::catch_unwind(std::panic::AssertUnwindSafe(work)).is_err() {
        std::process::abort();
    }
}
extern "C" fn retain(raw: *const c_void) {
    unsafe { Arc::increment_strong_count(raw.cast::<Sink>()) };
}
extern "C" fn release(raw: *const c_void) {
    unsafe { Arc::decrement_strong_count(raw.cast::<Sink>()) };
}
extern "C" fn lifecycle(raw: *const c_void, window: u64, page: u64, event: u32) {
    boundary(|| {
        let sink = unsafe { &*raw.cast::<Sink>() };
        if event == 6 {
            if let Some(controller) = sink.controller.get().and_then(Weak::upgrade) {
                controller.unavailable(Owner { window, webview: page });
            }
            return;
        }
        let event = match event {
            0 => Event::Inactive,
            1 => Event::Active,
            2 => Event::Hidden,
            3 => Event::Minimized,
            4 => Event::SessionLocked,
            5 => Event::Destroyed,
            _ => return,
        };
        if let Some(controller) = sink.controller.get().and_then(Weak::upgrade) {
            controller.lifecycle(
                Owner {
                    window,
                    webview: page,
                },
                event,
            );
        }
    });
}
extern "C" fn auth_reply(raw: *const c_void, sequence: u64, reply: u32) {
    boundary(|| {
        let sink = unsafe { &*raw.cast::<Sink>() };
        let callback = sink.replies.lock().unwrap().remove(&sequence);
        if let Some(callback) = callback {
            callback(match reply {
                0 => AuthReply::Approved,
                1 => AuthReply::Cancelled,
                _ => AuthReply::Failed,
            });
        }
    });
}
extern "C" fn public_action(
    raw: *const c_void,
    window: u64,
    page: u64,
    revision: u64,
    action: u32,
) {
    boundary(|| {
        let sink = unsafe { &*raw.cast::<Sink>() };
        let snapshot = *sink.latest.lock().unwrap();
        let Some(snapshot) = snapshot else {
            return;
        };
        let owner = Owner {
            window,
            webview: page,
        };
        if snapshot.revision != revision || snapshot.owner != Some(owner) {
            return;
        }
        let Some(controller) = sink.controller.get().and_then(Weak::upgrade) else {
            return;
        };
        match action {
            0 if snapshot.phase == Phase::Locked && snapshot.foreground => {
                let _ = controller.request(owner, snapshot.epoch, Intent::Unlock);
            }
            1 => {
                if let Some(request) = snapshot.request {
                    controller.cancel(owner, request);
                }
            }
            _ => {}
        }
    });
}

extern "C" fn run_later(raw:*mut c_void) {
    boundary(||{let work=unsafe{Box::from_raw(raw.cast::<Box<dyn FnOnce()+Send>>())};work();});
}
pub struct NativeProtection {
    context: NonNull<c_void>,
    panels: NonNull<c_void>,
    notices: Option<super::native_notices::NativeNoticePort>,
    sink: Arc<Sink>,
}
// The bridge gates receipts/registry under native locks; every AppKit mutation
// is explicitly main-thread-only or dispatched by the qualified main adapter.
unsafe impl Send for NativeProtection {}
unsafe impl Sync for NativeProtection {}
impl NativeProtection {
    pub(crate) fn defer_main(work:impl FnOnce()+Send+'static) {
        let work:Box<dyn FnOnce()+Send>=Box::new(work);
        unsafe{MDNativeProtectionDeferMain(Box::into_raw(Box::new(work)).cast(),run_later);}
    }
    // Internal native ports retain this NativeProtection for the full call.
    // No raw context value crosses the IPC boundary.
    pub(crate) fn raw(&self) -> *mut c_void { self.context.as_ptr() }
    pub(crate) fn panels_raw(&self)->*mut c_void { self.panels.as_ptr() }
    pub(crate) fn notices(&self)->Option<&super::native_notices::NativeNoticePort>{self.notices.as_ref()}
    pub fn new(
        boot: [u8; 16],
        publish: Box<Publish>,
        retire: Box<Retire>,
        notice_wake: Box<dyn Fn()+Send+Sync>,
    ) -> Result<Self, Refusal> {
        let sink = Arc::new(Sink {
            boot,
            controller: OnceLock::new(),
            latest: Mutex::new(None),
            replies: Mutex::new(HashMap::new()),
            retired_through: AtomicU64::new(0),
            publish,
            retire,
        });
        let raw = Arc::as_ptr(&sink).cast();
        let callbacks = Callbacks {
            context: raw,
            retain,
            release,
            lifecycle,
            auth_reply,
            public_action,
        };
        let context = NonNull::new(unsafe { MDNativeProtectionCreate(callbacks) })
            .ok_or(Refusal::PolicyUnreadable)?;
        let panels=match NonNull::new(unsafe { super::native_panels::MDNativeFilePanelsCreate(context.as_ptr()) }) {
            Some(value)=>value,
            None=>{ unsafe { MDNativeProtectionRelease(context.as_ptr()); }return Err(Refusal::PolicyUnreadable); }
        };
        let notices=match super::native_notices::NativeNoticePort::new_on_main(context.as_ptr(),notice_wake) {
            Ok(value)=>value,
            Err(error)=>{unsafe{super::native_panels::MDNativeFilePanelsRelease(panels.as_ptr());MDNativeProtectionRelease(context.as_ptr());}return Err(error);}
        };
        Ok(Self { context,panels,notices,sink })
    }
    /// Actual WKURLSchemeHandler argument only; no caller pointer or label.
    pub(crate) unsafe fn private_receiver_on_main(&self,view:*mut c_void)->Result<Owner,Refusal> {
        super::receiver_scope::MainThread::current()?;
        let mut window=0;let mut webview=0;
        if !unsafe { MDNativeProtectionPrivateReceiver(self.raw(),view,&mut window,&mut webview) } { return Err(Refusal::StaleOwner); }
        Ok(Owner { window,webview })
    }
    pub fn install_controller(&self, controller: &Arc<Controller>) -> Result<(), Refusal> {
        self.sink
            .controller
            .set(Arc::downgrade(controller))
            .map_err(|_| Refusal::Busy)
    }
    pub fn latest(&self) -> Option<Presentation> {
        *self.sink.latest.lock().unwrap()
    }
    /// Only the native main-thread webview callback may pass actual SDK objects.
    /// Owner IDs are native counters allocated for this window/page generation.
    pub unsafe fn attach(
        &self,
        window: *mut c_void,
        view: *mut c_void,
        owner: Owner,
    ) -> Result<(), Refusal> {
        if unsafe {
            MDNativeProtectionAttach(
                self.context.as_ptr(),
                window,
                view,
                owner.window,
                owner.webview,
            )
        } {
            Ok(())
        } else {
            Err(Refusal::StaleOwner)
        }
    }
    /// Resolves the actual receiving WKWebView; headers cannot choose an Owner.
    pub unsafe fn receiver(
        &self,
        window: *mut c_void,
        view: *mut c_void,
    ) -> Result<Owner, Refusal> {
        let mut window_id = 0;
        let mut page_id = 0;
        if unsafe {
            MDNativeProtectionReceiver(
                self.context.as_ptr(),
                window,
                view,
                &mut window_id,
                &mut page_id,
            )
        } {
            Ok(Owner {
                window: window_id,
                webview: page_id,
            })
        } else {
            Err(Refusal::StaleOwner)
        }
    }
    /// Called on main before page reload/retirement. Exact old IDs cannot retire a successor.
    pub fn retire_page_on_main(&self, owner: Owner) {
        unsafe { MDNativeProtectionRetirePage(self.context.as_ptr(), owner.window, owner.webview) };
    }
    pub fn boot_failed(&self) { unsafe { MDNativeProtectionBootFailed(self.context.as_ptr()) }; }
    pub fn close(&self) {
        if let Some(notices)=self.notices.as_ref(){notices.close();}
        self.sink.retired_through.store(u64::MAX, Ordering::Release);
        self.sink.replies.lock().unwrap().clear();
        unsafe { MDNativeProtectionClose(self.context.as_ptr());super::native_panels::MDNativeFilePanelsClose(self.panels.as_ptr()); };
    }
    pub fn reopen_on_main(&self) -> bool {
        unsafe { MDNativeProtectionReopen(self.context.as_ptr()) }
    }
    pub fn focus_public_on_main(&self) -> bool {
        unsafe { MDNativeProtectionFocusPublic(self.context.as_ptr()) }
    }
    pub fn hide_on_main(&self, owner: Owner) -> bool {
        unsafe { MDNativeProtectionHide(self.context.as_ptr(), owner.window, owner.webview) }
    }
    pub fn window_action_on_main(&self, owner: Owner, revision: u64, action: u32) -> Result<(), Refusal> {
        if unsafe { MDNativeProtectionWindowAction(self.context.as_ptr(), owner.window, owner.webview, revision, action) } {
            Ok(())
        } else {
            Err(Refusal::StaleOwner)
        }
    }
    pub(crate) fn start_legacy_on_main(&self,scope:super::receiver_scope::PrivateScope,key:&str,read:bool)
        ->Result<tauri::async_runtime::Receiver<LegacyReply>,Refusal> {
        scope.check()?;
        let scope=Arc::new(scope);let (send,receive)=tauri::async_runtime::channel(1);
        let sender=Box::into_raw(Box::new(send));
        let accepted=unsafe { MDNativeProtectionLegacy(self.context.as_ptr(),super::native_job::native_scope(&scope),
            key.as_ptr(),key.len() as u64,read,sender.cast(),legacy_reply) };
        if !accepted { unsafe { drop(Box::from_raw(sender)); }return Err(Refusal::Locked); }
        Ok(receive)
    }
    pub(crate) fn forget_legacy_on_main(&self,scope:super::receiver_scope::RetiredCleanup,key:&str)
        ->Result<tauri::async_runtime::Receiver<LegacyReply>,Refusal> {
        scope.check()?;
        let scope=Arc::new(scope);let (send,receive)=tauri::async_runtime::channel(1);
        let sender=Box::into_raw(Box::new(send));
        let accepted=unsafe { MDNativeProtectionForgetLegacy(self.context.as_ptr(),super::native_job::cleanup_scope(&scope),
            key.as_ptr(),key.len() as u64,sender.cast(),legacy_reply) };
        if !accepted { unsafe { drop(Box::from_raw(sender)); }return Err(Refusal::Cancelled); }
        Ok(receive)
    }
    pub(crate) fn authentication_capability() -> super::wire::Capability {
        if unsafe { MDNativeAuthenticationAvailable() } { super::wire::Capability::Available } else { super::wire::Capability::Unavailable }
    }
    pub(crate) fn open_payment_on_main(&self, scope: super::receiver_scope::PrivateScope, url: &str) -> Result<(), Refusal> {
        scope.check()?;
        let scope=Arc::new(scope);
        if unsafe { MDNativeProtectionOpenPayment(self.context.as_ptr(),super::native_job::native_scope(&scope),url.as_ptr(),url.len() as u64) } { Ok(()) } else { Err(Refusal::Cancelled) }
    }
    pub(crate) fn copy_text_on_main(&self, scope: super::receiver_scope::PrivateScope, text: &str) -> Result<(), Refusal> {
        scope.check()?;
        let scope=Arc::new(scope);
        if unsafe { MDNativeProtectionCopyText(self.context.as_ptr(),super::native_job::native_scope(&scope),text.as_ptr(),text.len() as u64) } {
            Ok(())
        } else { Err(Refusal::Locked) }
    }
    pub fn refresh_foreground_on_main(&self, owner: Owner) {
        let active = unsafe { MDNativeProtectionForeground(self.context.as_ptr()) };
        if let Some(controller) = self.sink.controller.get().and_then(Weak::upgrade) {
            controller.lifecycle(
                owner,
                if active {
                    Event::Active
                } else {
                    Event::Inactive
                },
            );
        }
    }
}
impl Authentication for NativeProtection {
    fn begin(
        &self,
        request: AuthRequest,
        reply: Box<dyn Fn(AuthReply) + Send + Sync>,
    ) -> Result<(), Refusal> {
        if request.id.boot() != self.sink.boot {
            return Err(Refusal::StaleEpoch);
        }
        {
            let mut pending = self.sink.replies.lock().unwrap();
            if request.id.sequence() <= self.sink.retired_through.load(Ordering::Acquire) {
                return Err(Refusal::Cancelled);
            }
            pending.insert(request.id.sequence(), Arc::from(reply));
        }
        if unsafe {
            MDNativeProtectionBegin(
                self.context.as_ptr(),
                request.owner.window,
                request.owner.webview,
                request.id.sequence(),
            )
        } {
            Ok(())
        } else {
            self.sink
                .replies
                .lock()
                .unwrap()
                .remove(&request.id.sequence());
            Err(Refusal::StaleOwner)
        }
    }
    fn cancel(&self, request: RequestId) {
        if request.boot() != self.sink.boot {
            return;
        }
        self.sink
            .retired_through
            .fetch_max(request.sequence(), Ordering::AcqRel);
        self.sink
            .replies
            .lock()
            .unwrap()
            .remove(&request.sequence());
        unsafe { MDNativeProtectionCancel(self.context.as_ptr(), request.sequence()) };
    }
}
fn native_phase(phase: Phase) -> u32 {
    match phase {
        Phase::Booting => 0,
        Phase::Disabled => 1,
        Phase::Locked => 2,
        Phase::Authenticating => 3,
        Phase::AwaitingActivation => 4,
        Phase::Activated => 5,
        Phase::Error => 6,
    }
}
impl Cover for NativeProtection {
    fn apply(&self, presentation: Presentation) {
        if presentation.epoch.boot != self.sink.boot {
            return;
        }
        {
            let mut previous = self.sink.latest.lock().unwrap();
            if previous.is_some_and(|value| value.revision >= presentation.revision) {
                return;
            }
            *previous = Some(presentation);
        }
        let owner = presentation.owner.unwrap_or(Owner {
            window: 0,
            webview: 0,
        });
        unsafe {
            MDNativeProtectionApply(
                self.context.as_ptr(),
                presentation.revision,
                owner.window,
                owner.webview,
                presentation.owner.is_some(),
                presentation.uncover,
                native_phase(presentation.phase),
                presentation.request.map_or(0, RequestId::sequence),
                presentation.account_generation,
                presentation.notice_private_allowed,
            )
        };
        (self.sink.publish)(presentation);
    }
    fn retire_private_resources(&self, epoch: Epoch) {
        (self.sink.retire)(epoch);
    }
}
impl Drop for NativeProtection {
    fn drop(&mut self) {
        self.close();
        unsafe {
            super::native_panels::MDNativeFilePanelsRelease(self.panels.as_ptr());
            MDNativeProtectionRelease(self.context.as_ptr());
        }
    }
}
pub struct NativeClock(Instant);
impl Default for NativeClock {
    fn default() -> Self {
        Self(Instant::now())
    }
}
impl Clock for NativeClock {
    fn milliseconds(&self) -> u64 {
        self.0.elapsed().as_millis().try_into().unwrap_or(u64::MAX)
    }
}

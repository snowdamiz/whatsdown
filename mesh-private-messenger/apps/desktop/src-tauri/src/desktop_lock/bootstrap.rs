//! App-lifetime native boot and page ownership. Managed before window creation.
use super::commands::Ready;
use super::controller::{Controller, Executor, Owner, Presentation, Refusal, Work};
use super::native_policy::NativePolicyStore;
use super::native_protection::{NativeClock, NativeProtection};
use super::receiver_scope::{fresh_uuid, MainThread};
use std::sync::{atomic::{AtomicBool, AtomicU64, Ordering}, Arc, Mutex, OnceLock, Weak};
use tauri::{WebviewWindow,Emitter};

struct Worker;
impl Executor for Worker {
    fn post(&self, work: Work) { tauri::async_runtime::spawn_blocking(work); }
}

pub(crate) struct Bootstrap {
    pub(crate) documents: super::document::Documents,
    app: Mutex<Option<tauri::AppHandle>>,
    pub(crate) notifications:Arc<super::notification_commands::NotificationBindings>,
    pub(crate) native: Arc<NativeProtection>,
    boot: [u8; 16],
    generation: Arc<AtomicU64>,
    page: Mutex<Option<Owner>>,
    startup: super::startup::Startup<Ready>,
    loaded: AtomicBool,
    first_presentation: AtomicBool,
    pub(crate) resources: Arc<super::resources::Resources>,
    pub(crate) files: Arc<super::private_files::PrivateFiles>,
    pub(crate) attachments:Arc<super::private_choices::AttachmentChoices>,
    pub(crate) incoming:Arc<super::incoming_files::IncomingFiles>,
    pub(crate) destinations:Arc<super::private_destinations::DestinationChoices>,
    pub(crate) backups:Arc<super::private_backup_choices::BackupChoices>,
    pub(crate) avatars:Arc<super::private_avatar_choices::AvatarChoices>,
    pub(crate) chooser_timer_available:AtomicBool,
    export_directory: Mutex<Option<Arc<super::private_exports::StageDirectory>>>,
}

impl Bootstrap {
    // No policy/Keychain/Core operation runs here. The window does not exist yet.
    pub(crate) fn new(app: tauri::AppHandle) -> Result<Arc<Self>, Refusal> {
        MainThread::current()?;
        let boot = fresh_uuid()?;
        // Actual UN owner construction is Main-only. Native factory refusal
        // remains NotificationBindings::Unavailable, not failed Core boot.
        let notifications=Arc::new(super::notification_commands::NotificationBindings::new_on_main()?);
        let target: Arc<OnceLock<Weak<Self>>> = Arc::new(OnceLock::new());
        let publish_target = target.clone();
        let resources=Arc::new(super::resources::Resources::new(boot));
        let files=super::private_files::PrivateFiles::new(resources.clone());
        let attachments=Arc::new(super::private_choices::AttachmentChoices::new());
        let incoming=super::incoming_files::IncomingFiles::new(resources.clone(),attachments.clone());
        let retire=resources.clone();
        let notice_target=target.clone();
        let native = NativeProtection::new(boot, Box::new(move |snapshot| {
            if let Some(this) = publish_target.get().and_then(Weak::upgrade) { this.publish(snapshot); }
        }), Box::new(move |epoch| retire.retire(epoch)),Box::new(move||{
            if let Some(this)=notice_target.get().and_then(Weak::upgrade){this.wake_notice();}
        }))?;
        let this = Arc::new(Self {
                documents: super::document::Documents::default(),
                app:Mutex::new(Some(app)),
                notifications,
                native: Arc::new(native),
                boot,
                generation: Arc::new(AtomicU64::new(0)),
                page: Mutex::new(None),
                startup: super::startup::Startup::new(),
                loaded: AtomicBool::new(false),
                first_presentation: AtomicBool::new(true),
                resources,
                files,
                attachments,
                incoming,
                destinations:Arc::new(super::private_destinations::DestinationChoices::new()),
                backups:Arc::new(super::private_backup_choices::BackupChoices::new()),
                avatars:Arc::new(super::private_avatar_choices::AvatarChoices::new()),
                chooser_timer_available:AtomicBool::new(false),
                export_directory:Mutex::new(None),
        });
        let _ = target.set(Arc::downgrade(&this));
        Ok(this)
    }

    fn wake_notice(&self) {
        if self.startup.is_closed(){return;}
        let app=self.app.lock().unwrap().clone();
        if let Some(app)=app{let _=app.emit("app-lock-notice-pending",serde_json::json!({"version":1}));}
    }
    pub(crate) fn incoming_wake(self:&Arc<Self>)->super::native_incoming::Wake {
        let weak=Arc::downgrade(self);
        Arc::new(move |ticket,kind| {
            let Some(this)=weak.upgrade() else{return;};
            if this.startup.is_closed() || !ticket.current(){return;}
            let scope=ticket.scope();
            let mut payload=serde_json::json!({"version":1,"owner":scope.owner_token(),"epoch":super::wire::epoch(scope.epoch()),"subscription":ticket.handle().wire()});
            match kind {
                super::native_incoming::IncomingHint::Sources=>{payload["kind"]=serde_json::json!("sources");},
                super::native_incoming::IncomingHint::Dragging(value)=>{payload["kind"]=serde_json::json!("dragging");payload["dragging"]=serde_json::json!(value);},
            }
            let app=this.app.lock().unwrap().clone();
            if let Some(app)=app {if ticket.current(){let _=app.emit("app-lock-files",payload);}}
        })
    }
    fn publish(&self, snapshot: Presentation) {
        let Some(app)=self.app.lock().unwrap().clone() else{return;};
        // NativeProtection has returned from its receipt gate. Scope polling
        // and its deferred final destruction therefore run on a later Main turn.
        let notifications=self.notifications.clone();
        let native=self.native.clone();
        NativeProtection::defer_main(move || {
            let _=notifications.retire_invalid_on_main();
            if let Some(notices)=native.notices(){let _=notices.retire_invalid_on_main();}
        });
        if let Ok(ready) = self.startup.current() { ready.publish(&app, snapshot); }
    }

    fn next_owner(&self) -> Result<Owner, Refusal> {
        let generation = self.generation.try_update(Ordering::AcqRel, Ordering::Acquire,
            |value| value.checked_add(1)).map_err(|_| Refusal::Exhausted)? + 1;
        Ok(Owner { window: 1, webview: generation })
    }

    fn start_choice_timer(self:&Arc<Self>) {
        let weak=Arc::downgrade(self);
        let started=std::thread::Builder::new().name("native-choice-expiry".into()).spawn(move ||loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
            let Some(this)=weak.upgrade() else {break;};
            if this.startup.is_closed() {break;}
            let now=std::time::Instant::now();
            this.attachments.expire(now);this.destinations.expire(now);this.backups.expire(now);this.avatars.expire(now);
            // No authority/descriptor hold survives this iteration's sleep.
        });
        self.chooser_timer_available.store(started.is_ok(),Ordering::Release);
    }
    pub(crate) fn export_directory(&self)->Result<Arc<super::private_exports::StageDirectory>,&'static str> {
        self.export_directory.lock().map_err(|_|"file_unavailable")?.clone().ok_or("file_unavailable")
    }
    pub(crate) fn current(&self) -> Result<Arc<Ready>, &'static str> { self.startup.current() }
    pub(crate) async fn ready(&self) -> Result<Arc<Ready>, &'static str> { self.startup.ready().await }
    // Called by setup after the hidden native primary is built. The actual SDK
    // receiver is attached before page-finished/singleton code can show it.
    pub(crate) fn attach_primary(self: &Arc<Self>, window: WebviewWindow,
        attached: impl FnOnce() + Send + 'static) -> Result<(), &'static str> {
        let this = self.clone();
        let failed = window.clone();
        window.with_webview(move |platform| {
            let result = (|| {
                MainThread::current()?;
                if this.startup.is_closed() { return Err(Refusal::StaleOwner); }
                let owner = this.next_owner()?;
                unsafe { this.native.attach(platform.ns_window(), platform.inner(), owner) }?;
                *this.page.lock().unwrap() = Some(owner);
                Ok(())
            })();
            match result {
                Ok(()) => {
                    if this.loaded.load(Ordering::Acquire) { this.page_finished(failed); }
                    attached();
                }
                Err(_) => { this.fail(); let _ = failed.hide(); }
            }
        }).map_err(|_| "app_lock_unavailable")
    }

    // Native start notification, never a JS-nominated page. Old Page/leases are
    // retired before the same physical WKWebView receives its successor cover.
    pub(crate) fn navigation_started(self: &Arc<Self>, window: WebviewWindow) {
        self.documents.retire();
        self.loaded.store(false, Ordering::Release);
        let this = self.clone();
        let failed = window.clone();
        if window.with_webview(move |platform| {
            let result: Result<(), Refusal> = (|| {
                MainThread::current()?;
                let old = unsafe { this.native.receiver(platform.ns_window(), platform.inner()) }?;
                if let Ok(ready) = this.current() { ready.retire_page(old); }
                this.native.retire_page_on_main(old);
                let owner = this.next_owner()?;
                unsafe { this.native.attach(platform.ns_window(), platform.inner(), owner) }?;
                *this.page.lock().unwrap() = Some(owner);
                Ok(())
            })();
            // An initial Started callback may precede attach_primary. It has no
            // authority to retire; the window remains hidden until attachment.
            if result.is_err() && this.page.lock().unwrap().is_some() {
                this.fail(); let _ = failed.hide();
            }
        }).is_err() { self.fail(); }
    }

    pub(crate) fn reopen(self: &Arc<Self>, window: WebviewWindow) { self.show(window, false, false); }
    pub(crate) fn focus(self: &Arc<Self>, window: WebviewWindow) { self.show(window, true, false); }
    pub(crate) fn hide(self: &Arc<Self>, window: WebviewWindow) {
        let this=self.clone();
        let _=window.with_webview(move |platform| {
            if let Ok(owner)=unsafe { this.native.receiver(platform.ns_window(),platform.inner()) } { this.native.hide_on_main(owner); }
        });
    }
    fn show(self: &Arc<Self>, window: WebviewWindow, focus: bool, first_page: bool) {
        let this = self.clone();
        let _ = window.with_webview(move |platform| {
            let Ok(owner) = (unsafe { this.native.receiver(platform.ns_window(), platform.inner()) }) else { return; };
            if this.startup.is_closed() { return; }
            let focus = focus || (first_page && this.first_presentation.swap(false,Ordering::AcqRel));
            // A late Finished event must not cover an already activated fresh
            // page and manufacture a second focus/authentication transition.
            if !focus && this.native.latest().is_some_and(|snapshot|snapshot.owner == Some(owner) && snapshot.uncover) { return; }
            if focus {
                if !this.native.focus_public_on_main() { return; }
            } else if !this.native.reopen_on_main() {
                return;
            }
            this.native.refresh_foreground_on_main(owner);
        });
    }

    pub(crate) fn page_finished(self: &Arc<Self>, window: WebviewWindow) {
        self.loaded.store(true, Ordering::Release);
        if let Ok(token) = self.documents.issue() {
            // Eval targets the loaded native document; no public command issues grants.
            let script = format!("Object.defineProperty(window,'__MORSE_DOCUMENT__',{{value:{},configurable:false}});window.dispatchEvent(new Event('morse-document-ready'));", serde_json::to_string(&token).unwrap());
            if window.eval(script).is_err() { self.documents.retire(); self.fail(); return; }
        } else { self.fail(); return; }
        self.show(window, false, true);
    }

    // Policy owns the actual cross-process lock before `load_core` is called.
    // The same context is retained by Ready/controller until all work retires.
    pub(crate) fn initialize(self: &Arc<Self>, app: &tauri::AppHandle, directory: &std::path::Path,
        load_core: impl FnOnce() -> Result<(), &'static str>) {
        let result = (|| {
            if self.startup.is_closed() { return Err("app_lock_unavailable"); }
            let policy = Arc::new(NativePolicyStore::open(&app.config().identifier, directory)
                .map_err(|_| "native_policy_unavailable")?);
            if self.startup.is_closed() { return Err("app_lock_unavailable"); }
            // Unknown/unsafe staging is preserved and disables only exports.
            // Ordinary Core/controller boot still proceeds. The exact native
            // process-owner FD, not a shared app-data path, anchors startup.
            let directory=super::stage_startup::prepare(policy.clone()).ok();
            {
                // close marks startup closed before taking this same slot.
                // Whichever acquires the slot first either refuses installation
                // or leaves a value that close subsequently takes and drops.
                let mut slot=self.export_directory.lock().map_err(|_|"file_unavailable")?;
                if self.startup.is_closed() { return Err("app_lock_unavailable"); }
                *slot=directory;
            }
            load_core()?;
            if self.startup.is_closed() { return Err("app_lock_unavailable"); }
            let owner = self.page.lock().unwrap().ok_or("app_lock_unavailable")?;
            let controller = Controller::new(self.boot, owner, policy.clone(), self.native.clone(),
                Arc::new(NativeClock::default()), self.native.clone(), Arc::new(Worker));
            self.native.install_controller(&controller).map_err(|_| "app_lock_unavailable")?;
            self.start_choice_timer();
            Ok(Arc::new(Ready::new(controller, self.native.clone(), policy,
                NativeProtection::authentication_capability(), self.generation.clone())))
        })();
        if let Err(error)=&result { eprintln!("Morse native startup refused: {error}"); self.native.boot_failed(); }
        self.startup.settle(result);
    }

    fn close_notifications(&self) {
        self.notifications.close_admission();
        let notifications=self.notifications.clone();
        NativeProtection::defer_main(move || {let _=notifications.close_on_main();});
    }
    pub(crate) fn fail(&self) {
        self.close_notifications();
        if let Ok(ready) = self.current() { ready.fail_current(); }
        self.native.boot_failed(); self.startup.settle(Err("app_lock_unavailable"));
    }

    pub(crate) fn close(&self) {
        self.documents.retire();
        // Break the app/managed-state lifetime reference before reentrant
        // controller publication. Both broker and presenter captures are weak.
        let app=self.app.lock().unwrap().take();
        self.close_notifications();
        drop(app);
        // Retire captured pages before closing the startup/native ports. A
        // queued caller may already hold Ready; it must not remain admitted.
        if let Ok(ready)=self.current() { ready.close(); }
        self.startup.close();
        self.incoming.close();
        self.attachments.close();self.destinations.close();self.backups.close();self.avatars.close();
        self.resources.close();
        let directory=self.export_directory.lock().unwrap().take();
        drop(directory); // Active exports retain their original directory/flock Arc.
        self.native.close();
    }
}

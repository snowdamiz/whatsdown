use crate::desktop_lock::controller::*;
use crate::desktop_lock::native_policy::NativePolicyStore;
use crate::desktop_lock::receiver_scope::{MainThread,ReceiverScopes};
use crate::desktop_lock::wire::Capability;
use std::collections::VecDeque;
use std::ffi::{c_char,c_void,CString};
use std::path::PathBuf;
use std::sync::{Arc,Mutex};
unsafe extern "C" {
    fn MDTestPolicyFixture(path:*const c_char)->*mut c_void;
    fn MDTestPolicyOpen(fixture:*mut c_void)->*mut c_void;
    fn MDTestPolicyReplaceLock(fixture:*mut c_void)->bool;
    fn MDTestPolicyFixtureRelease(fixture:*mut c_void);
}
struct OwnedRoot { path:PathBuf,raw:*mut c_void }
impl OwnedRoot {
    fn new(name:&str)->Self {
        use std::os::unix::fs::PermissionsExt;
        let path=PathBuf::from(std::env::var_os("MORSE_POLICY_FIXTURE_ROOT").unwrap()).join(name);
        std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();
        let value=CString::new(path.to_str().unwrap()).unwrap();let raw=unsafe { MDTestPolicyFixture(value.as_ptr()) };
        assert!(!raw.is_null());Self { path,raw }
    }
}
impl Drop for OwnedRoot {
    fn drop(&mut self) {
        unsafe { MDTestPolicyFixtureRelease(self.raw) };
        let _=std::fs::remove_file(self.path.join("process-owner.v1"));let _=std::fs::remove_dir(&self.path);
    }
}
#[derive(Default)]
struct Queue(Mutex<VecDeque<Work>>);
impl Executor for Queue { fn post(&self,work:Work) { self.0.lock().unwrap().push_back(work); } }
impl Queue {
    fn drain(&self) { loop { let work=self.0.lock().unwrap().pop_front();if let Some(work)=work { work(); } else { break; } } }
}
#[derive(Default)]
struct Auth(Mutex<Option<Box<dyn Fn(AuthReply)+Send+Sync>>>);
impl Authentication for Auth {
    fn begin(&self,_request:AuthRequest,reply:Box<dyn Fn(AuthReply)+Send+Sync>)->Result<(),Refusal> { *self.0.lock().unwrap()=Some(reply);Ok(()) }
    fn cancel(&self,_request:RequestId) { self.0.lock().unwrap().take(); }
}
struct ClockPort;
impl Clock for ClockPort { fn milliseconds(&self)->u64 { 1 } }
#[derive(Default)]
struct CoverPort(Mutex<Option<Presentation>>);
impl Cover for CoverPort {
    fn apply(&self,value:Presentation) { let mut last=self.0.lock().unwrap();if !last.is_some_and(|p|p.revision>value.revision) { *last=Some(value); } }
    fn retire_private_resources(&self,_epoch:Epoch) {}
}
struct Fixture {
    controller:Arc<Controller>,scopes:ReceiverScopes,_store:Arc<NativePolicyStore>,
    auth:Arc<Auth>,queue:Arc<Queue>,cover:Arc<CoverPort>,token:String,root:OwnedRoot,
}
fn owner(page:u64)->Owner { Owner { window:1,webview:page } }
impl Fixture {
    fn new(name:&str,enabled:bool)->Self {
        let root=OwnedRoot::new(name);let store=Arc::new(unsafe { NativePolicyStore::from_test_context(MDTestPolicyOpen(root.raw)).unwrap() });
        let first=store.read().unwrap();
        if enabled { let pending=store.compare_write(first,Policy::EnablePending).unwrap();store.compare_write(pending,Policy::Enabled).unwrap(); }
        let auth=Arc::new(Auth::default());let queue=Arc::new(Queue::default());let cover=Arc::new(CoverPort::default());
        let controller=Controller::new([7;16],owner(1),store.clone(),auth.clone(),Arc::new(ClockPort),cover.clone(),queue.clone());queue.drain();
        let scopes=ReceiverScopes::new(controller.clone(),store.clone(),Capability::Available);
        let token=scopes.install(&MainThread::deferred_test_dispatch(),owner(1)).unwrap();
        let fixture=Self { controller,scopes,_store:store,auth,queue,cover,token,root };
        fixture.activate(1,&fixture.token);fixture
    }
    fn activate(&self,page:u64,token:&str) {
        if self.controller.policy()==Some(Policy::Enabled) {
            self.controller.request(owner(page),self.controller.epoch(),Intent::Unlock).unwrap();self.queue.drain();
            let callback=self.auth.0.lock().unwrap().take().unwrap();callback(AuthReply::Approved);self.queue.drain();
        }
        self.scopes.receiver(owner(page),token).unwrap().activate(&crate::desktop_lock::wire::epoch(self.controller.epoch())).unwrap();
    }
    fn epoch(&self)->String { crate::desktop_lock::wire::epoch(self.controller.epoch()) }
    fn replace(&self,page:u64)->String { self.scopes.install(&MainThread::deferred_test_dispatch(),owner(page)).unwrap() }
}


use crate::desktop_lock::{
    file_reply::FileReply,
    incoming_files::{IncomingFiles, IncomingHandle},
    private_choices::{AttachmentChoices, SelectedSource},
    private_files::ChosenSource,
    receiver_scope::PrivateScope,
    resources::Resources,
};
use tauri::ipc::IpcResponse;
use serde_json::json;
use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
static INTAKE_TEST_LOCK: Mutex<()> = Mutex::new(());
fn scope(f: &Fixture) -> PrivateScope {
    f.scopes
        .receiver(owner(1), &f.token)
        .unwrap()
        .private(&f.epoch())
        .unwrap()
        .scope()
}
fn setup(f: &Fixture) -> (Arc<Resources>, Arc<AttachmentChoices>, Arc<IncomingFiles>) {
    let resources = Arc::new(Resources::new(f.controller.epoch().boot));
    let choices = Arc::new(AttachmentChoices::new());
    let incoming = IncomingFiles::new(resources.clone(), choices.clone());
    (resources, choices, incoming)
}
struct SelectedTree(PathBuf);
impl SelectedTree {
    fn new(f: &Fixture) -> Self {
        let path = f.root.path.join("sources");
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn source(&self, name: &str) -> SelectedSource {
        let path = self.0.join(name);
        std::fs::write(&path, b"actual-file").unwrap();
        SelectedSource::new(
            name,
            "application/octet-stream",
            ChosenSource::open(&path).unwrap(),
        )
        .unwrap()
    }
}
impl Drop for SelectedTree {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}
#[test]
fn published_subscription_survives_and_unreturned_reply_retires_once() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-reply", false);
    let s = scope(&f);
    let (_, _, incoming) = setup(&f);
    let cancelled = Arc::new(AtomicUsize::new(0));
    let ticket = incoming.subscribe(s.clone()).unwrap();
    let id = ticket.handle();
    let count = cancelled.clone();
    ticket
        .install_native(Box::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }))
        .unwrap();
    let reply = FileReply::incoming(
        incoming.clone(),
        s.clone(),
        id,
        json!({"version":1,"handle":id.wire()}),
    );
    let response = reply.publish().unwrap();
    assert!(
        ticket.current(),
        "published incoming handle must remain usable"
    );
    match response.body().unwrap() {
        tauri::ipc::InvokeResponseBody::Json(value) => assert_eq!(
            serde_json::from_str::<serde_json::Value>(&value).unwrap()["handle"],
            id.wire()
        ),
        _ => panic!("metadata"),
    }
    assert_eq!(cancelled.load(Ordering::SeqCst), 0);
    incoming.unsubscribe(s.owner(), s.epoch(), id);
    assert!(!ticket.current());
    let other = incoming.subscribe(s.clone()).unwrap();
    let count = cancelled.clone();
    other
        .install_native(Box::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }))
        .unwrap();
    drop(FileReply::incoming(
        incoming.clone(),
        s.clone(),
        other.handle(),
        json!({"version":1,"handle":other.handle().wire()}),
    ));
    assert!(!other.current());
    assert_eq!(cancelled.load(Ordering::SeqCst), 2);
    incoming.close();
    assert_eq!(cancelled.load(Ordering::SeqCst), 2);
}
#[test]
fn resources_retirement_stops_original_subscription_and_late_native_install() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-retire", false);
    let s = scope(&f);
    let (resources, _, incoming) = setup(&f);
    let ticket = incoming.subscribe(s.clone()).unwrap();
    resources.retire(s.epoch());
    assert!(
        !ticket.current(),
        "retired resources must stop incoming subscription"
    );
    let cancelled = Arc::new(AtomicUsize::new(0));
    let count = cancelled.clone();
    assert!(ticket
        .install_native(Box::new(move || {
            count.fetch_add(1, Ordering::SeqCst);
        }))
        .is_err());
    assert_eq!(cancelled.load(Ordering::SeqCst), 1);
    assert!(incoming.subscribe(s).is_err());
}
#[test]
fn finite_cleanup_requires_exact_owner_epoch_and_subscription() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-cleanup", false);
    let s = scope(&f);
    let (_, _, incoming) = setup(&f);
    let first = incoming.subscribe(s.clone()).unwrap();
    let second = incoming.subscribe(s.clone()).unwrap();
    incoming.unsubscribe(owner(99), s.epoch(), first.handle());
    incoming.unsubscribe(
        s.owner(),
        Epoch {
            generation: s.epoch().generation + 1,
            ..s.epoch()
        },
        first.handle(),
    );
    let unknown = IncomingHandle::parse("01234567-89ab-4cde-8fab-0123456789ab").unwrap();
    incoming.unsubscribe(s.owner(), s.epoch(), unknown);
    assert!(first.current() && second.current());
    incoming.unsubscribe(s.owner(), s.epoch(), first.handle());
    assert!(!first.current() && second.current());
    incoming.close();
    assert!(!second.current());
}
#[test]
fn intake_fifo_never_substitutes_latest_picker_choice_and_requests_followup() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-fifo", false);
    let tree = SelectedTree::new(&f);
    let s = scope(&f);
    let (_, choices, incoming) = setup(&f);
    let ticket = incoming.subscribe(s.clone()).unwrap();
    let now = Instant::now();
    assert!(ticket.complete(vec![tree.source("first")], now).unwrap());
    assert!(ticket.complete(vec![tree.source("second")], now).unwrap());
    choices
        .remember(
            s.choice_anchor().unwrap(),
            vec![tree.source("explicit-picker")],
            now,
        )
        .unwrap();
    let (first, more) = incoming.take(&s, ticket.handle(), now).unwrap();
    assert_eq!(first.unwrap().files[0].filename.as_str(), "first");
    assert!(more.is_some());
    let (second, more) = incoming.take(&s, ticket.handle(), now).unwrap();
    assert_eq!(second.unwrap().files[0].filename.as_str(), "second");
    assert!(more.is_none());
    assert!(incoming.take(&s, ticket.handle(), now).unwrap().0.is_none());
    assert_eq!(
        choices.pending(&s, now).unwrap().unwrap().files[0]
            .filename
            .as_str(),
        "explicit-picker"
    );
    incoming.close();
    choices.close();
}
#[test]
fn local_unsubscribe_drops_automatic_delivery_but_preserves_explicit_choice() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-local-close", false);
    let tree = SelectedTree::new(&f);
    let s = scope(&f);
    let (_, choices, incoming) = setup(&f);
    let ticket = incoming.subscribe(s.clone()).unwrap();
    let capture = ticket.capture().unwrap();
    incoming.unsubscribe(s.owner(), s.epoch(), ticket.handle());
    let now = Instant::now();
    assert!(!capture
        .complete(vec![tree.source("retained")], now)
        .unwrap());
    let successor = incoming.subscribe(s.clone()).unwrap();
    assert!(incoming
        .take(&s, successor.handle(), now)
        .unwrap()
        .0
        .is_none());
    assert_eq!(
        choices.pending(&s, now).unwrap().unwrap().files[0]
            .filename
            .as_str(),
        "retained"
    );
    incoming.close();
    choices.close();
}
#[test]
fn lock_custody_survives_only_explicit_recovery_and_account_replacement_refuses() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-lock", true);
    let tree = SelectedTree::new(&f);
    let old = scope(&f);
    let (resources, choices, incoming) = setup(&f);
    let ticket = incoming.subscribe(old.clone()).unwrap();
    let capture = ticket.capture().unwrap();
    f.controller.lifecycle(owner(1), Event::Inactive);
    resources.retire(old.epoch());
    let now = Instant::now();
    assert!(!capture.complete(vec![tree.source("locked")], now).unwrap());
    f.controller.lifecycle(owner(1), Event::Active);
    f.activate(1, &f.token);
    let fresh = scope(&f);
    assert!(incoming.take(&fresh, ticket.handle(), now).is_err());
    let metadata = choices.pending(&fresh, now).unwrap().unwrap();
    assert_eq!(metadata.files[0].filename.as_str(), "locked");
    let late = incoming
        .subscribe(fresh.clone())
        .unwrap()
        .capture()
        .unwrap();
    f.controller.account_changed();
    assert!(late
        .complete(vec![tree.source("old-account")], now)
        .is_err());
    f.activate(1, &f.token);
    assert!(choices.pending(&scope(&f), now).unwrap().is_none());
    incoming.close();
    choices.close();
}
#[test]
fn process_budget_includes_retired_inflight_work_across_registry_replacement() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-budget", false);
    let s = scope(&f);
    let (_, choices, incoming) = setup(&f);
    let ticket = incoming.subscribe(s.clone()).unwrap();
    let mut work = (0..4)
        .map(|_| ticket.capture().unwrap())
        .collect::<Vec<_>>();
    assert!(ticket.capture().is_err());
    incoming.close();
    let resources = Arc::new(Resources::new(s.epoch().boot));
    let next = IncomingFiles::new(resources, choices.clone());
    let new = next.subscribe(s.clone()).unwrap();
    assert!(
        new.capture().is_err(),
        "cancelled but draining captures still consume capacity"
    );
    drop(work.pop());
    assert!(new.capture().is_ok());
    drop(work);
    next.close();
    choices.close();
}
#[test]
fn expired_choice_is_skipped_without_losing_next_native_queue_entry() {
    let _serial = INTAKE_TEST_LOCK.lock().unwrap();
    let f = Fixture::new("incoming-expiry", false);
    let tree = SelectedTree::new(&f);
    let s = scope(&f);
    let (_, choices, incoming) = setup(&f);
    let ticket = incoming.subscribe(s.clone()).unwrap();
    let now = Instant::now();
    ticket.complete(vec![tree.source("expired")], now).unwrap();
    ticket
        .complete(vec![tree.source("fresh")], now + Duration::from_secs(60))
        .unwrap();
    assert_eq!(
        incoming
            .take(&s, ticket.handle(), now + Duration::from_secs(121))
            .unwrap()
            .0
            .unwrap()
            .files[0]
            .filename
            .as_str(),
        "fresh"
    );
    incoming.close();
    choices.close();
}

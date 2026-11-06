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

use super::*;
use crate::desktop_lock::{private_choices::SelectedSource,private_files::ChosenSource};
fn scope(f:&Fixture)->PrivateScope { f.scopes.receiver(owner(1),&f.token).unwrap().private(&f.epoch()).unwrap().scope() }
fn source(f:&Fixture)->SelectedSource {
    let path=f.root.path.join("archive");std::fs::write(&path,b"archive").unwrap();
    SelectedSource::new("fixture.morsebackup","application/octet-stream",ChosenSource::open(&path).unwrap()).unwrap()
}
#[test]
fn backup_request_cancel_before_completion_cannot_publish_or_retarget() {
    use std::sync::atomic::{AtomicUsize,Ordering};
    let f=Fixture::new("backup-request-cancel",false);let broker=BackupChoices::new();let scope=scope(&f);let now=Instant::now();
    let first=broker.begin(&scope,BackupPurpose::Source,now).unwrap();
    let ticket=broker.start_source(&scope,&first.wire(),now).unwrap();
    ticket.current(&scope,now).unwrap();
    assert!(broker.start_source(&scope,&first.wire(),now).is_err());
    let cancelled=Arc::new(AtomicUsize::new(0));let count=cancelled.clone();ticket.on_cancel(Box::new(move ||{count.fetch_add(1,Ordering::SeqCst);})).unwrap();
    broker.discard(&scope,BackupPurpose::Source,DiscardBackup::Request(first.wire())).unwrap();
    assert!(ticket.current(&scope,now).is_err());
    assert_eq!(cancelled.load(Ordering::SeqCst),1);
    let next=broker.begin(&scope,BackupPurpose::Source,now).unwrap();assert!(ticket.complete(source(&f),now).is_err());
    let replacement=broker.start_source(&scope,&next.wire(),now).unwrap();let selected=replacement.complete(source(&f),now).unwrap();
    assert!(broker.selection(&scope,BackupPurpose::Source,&first.wire(),&selected.wire(),now).is_err());
    assert!(broker.selection(&scope,BackupPurpose::Source,&next.wire(),&selected.wire(),now).is_ok());
    assert!(matches!(broker.pending(&scope,BackupPurpose::Source,now).unwrap(),Some(BackupMetadata::Source { choice,.. }) if choice==selected.wire()));
    broker.close();std::fs::remove_file(f.root.path.join("archive")).unwrap();
}
#[test]
fn backup_source_survives_lock_but_requires_fresh_original_scope() {
    let f=Fixture::new("backup-source-lock",true);let broker=BackupChoices::new();let old=scope(&f);let now=Instant::now();
    let request=broker.begin(&old,BackupPurpose::Source,now).unwrap();
    assert!(broker.start_destination(&old,&request.wire(),now).is_err());
    let ticket=broker.start_source(&old,&request.wire(),now).unwrap();f.controller.lifecycle(owner(1),Event::Inactive);
    let choice=ticket.complete(source(&f),now).unwrap();assert!(broker.pending(&old,BackupPurpose::Source,now).is_err());
    f.controller.lifecycle(owner(1),Event::Active);f.activate(1,&f.token);let current=scope(&f);
    let Some(BackupMetadata::Source {request:original,choice:id,file})=broker.pending(&current,BackupPurpose::Source,now).unwrap() else {panic!("pending source")};
    assert_eq!(original,request.wire());assert_eq!(id,choice.wire());assert_eq!(file.size,7);
    let taken=broker.claim_source(&current,&id,&file.selection,7,now).unwrap();assert_eq!(taken.size(),7);
    assert!(broker.claim_source(&current,&id,&file.selection,7,now).is_err());assert!(broker.pending(&current,BackupPurpose::Source,now).unwrap().is_none());
    drop(taken);std::fs::remove_file(f.root.path.join("archive")).unwrap();
}
#[test]
fn backup_destination_is_chosen_before_size_and_bound_at_single_claim() {
    use crate::desktop_lock::{private_files::PrivateFiles,private_exports::StageDirectory,resources::Resources};
    use std::os::unix::fs::PermissionsExt;
    let f=Fixture::new("backup-export-choice",false);let broker=BackupChoices::new();let scope=scope(&f);let now=Instant::now();
    let path=f.root.path.join("chosen");std::fs::write(&path,b"previous user file").unwrap();
    let request=broker.begin(&scope,BackupPurpose::Export,now).unwrap();let ticket=broker.start_destination(&scope,&request.wire(),now).unwrap();
    let choice=ticket.complete(ChosenDestination::capture(&path).unwrap(),now).unwrap();assert_eq!(std::fs::read(&path).unwrap(),b"previous user file");
    let context=format!("backup-export/{}/1",wire::epoch(scope.epoch()));
    let selected=broker.claim_export(&scope,&choice.wire(),&context,7,now).unwrap();assert!(broker.claim_export(&scope,&choice.wire(),&context,7,now).is_err());
    let stage=f.root.path.join("stage");std::fs::create_dir(&stage).unwrap();std::fs::set_permissions(&stage,std::fs::Permissions::from_mode(0o700)).unwrap();
    let files=PrivateFiles::new(Arc::new(Resources::new(scope.epoch().boot)));let handle=files.begin_export(&scope,StageDirectory::open(&stage).unwrap(),selected).unwrap();
    files.write_export(&scope,handle,0,b"archive").unwrap();files.commit_export(&scope,handle,||Ok(())).unwrap();assert_eq!(std::fs::read(&path).unwrap(),b"archive");
    std::fs::remove_file(path).unwrap();std::fs::remove_dir(stage).unwrap();
}
#[test]
fn backup_request_capacity_expiry_and_page_retirement_drain_exact_owner() {
    let f=Fixture::new("backup-bounds",false);let broker=BackupChoices::new();let current=scope(&f);let now=Instant::now();
    let first=broker.begin(&current,BackupPurpose::Source,now).unwrap();let ticket=broker.start_source(&current,&first.wire(),now).unwrap();
    for _ in 0..3 {broker.begin(&current,BackupPurpose::Export,now).unwrap();}assert!(broker.begin(&current,BackupPurpose::Source,now).is_err());
    broker.expire(now+Duration::from_secs(120));assert!(ticket.complete(source(&f),now).is_err());
    let request=broker.begin(&current,BackupPurpose::Source,now).unwrap();let ticket=broker.start_source(&current,&request.wire(),now).unwrap();
    f.controller.account_changed();assert!(ticket.complete(source(&f),now).is_err());
    broker.close();assert!(broker.begin(&current,BackupPurpose::Source,now).is_err());std::fs::remove_file(f.root.path.join("archive")).unwrap();
}
#[test]
fn backup_recovery_keeps_latest_choice_after_older_request_is_discarded() {
    let f = Fixture::new("backup-recovery-order", false);
    let broker = BackupChoices::new();
    let current = scope(&f);
    let now = Instant::now();
    let mut requests = Vec::new();
    let mut choices = Vec::new();
    for _ in 0..4 {
        let request = broker.begin(&current, BackupPurpose::Source, now).unwrap();
        let ticket = broker.start_source(&current, &request.wire(), now).unwrap();
        choices.push(ticket.complete(source(&f), now).unwrap());
        requests.push(request);
    }
    broker.discard(&current, BackupPurpose::Source, DiscardBackup::Request(requests[0].wire())).unwrap();
    let Some(BackupMetadata::Source { request, choice, .. }) = broker.pending(&current, BackupPurpose::Source, now).unwrap() else { panic!("pending backup source") };
    assert_eq!(request, requests[3].wire());
    assert_eq!(choice, choices[3].wire());
    broker.close();
    std::fs::remove_file(f.root.path.join("archive")).unwrap();
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

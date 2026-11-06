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
fn image(f:&Fixture,mime:&str,size:u64)->SelectedSource {
    let path=f.root.path.join("image");let file=std::fs::File::create(&path).unwrap();file.set_len(size).unwrap();drop(file);
    SelectedSource::new("photo.jpg",mime,ChosenSource::open(&path).unwrap()).unwrap()
}
#[test]
fn avatar_choice_is_image_only_and_enforces_native_size_bound() {
    let f=Fixture::new("avatar-size",false);let choices=AvatarChoices::new();let scope=scope(&f);let now=Instant::now();
    assert!(choices.remember(scope.choice_anchor().unwrap(),image(&f,"application/octet-stream",7),now).is_err());
    assert!(choices.remember(scope.choice_anchor().unwrap(),image(&f,"image/jpeg",MAX_AVATAR_SOURCE+1),now).is_err());
    choices.remember(scope.choice_anchor().unwrap(),image(&f,"image/jpeg",MAX_AVATAR_SOURCE),now).unwrap();
    choices.close();std::fs::remove_file(f.root.path.join("image")).unwrap();
}
#[test]
fn avatar_choice_survives_lock_and_is_claimed_once_by_fresh_original_scope() {
    let f=Fixture::new("avatar-lock",true);let choices=AvatarChoices::new();let old=scope(&f);let now=Instant::now();let anchor=old.choice_anchor().unwrap();
    f.controller.lifecycle(owner(1),Event::Inactive);
    let choice=choices.remember(anchor,image(&f,"image/jpeg",7),now).unwrap();assert!(choices.pending(&old,now).is_err());assert!(choices.claim(&old,&choice.wire(),now).is_err());
    f.controller.lifecycle(owner(1),Event::Active);f.activate(1,&f.token);let current=scope(&f);
    assert_eq!(choices.pending(&current,now).unwrap().unwrap().wire(),choice.wire());let source=choices.claim(&current,&choice.wire(),now).unwrap();assert_eq!(source.size(),7);
    assert!(choices.claim(&current,&choice.wire(),now).is_err());assert!(choices.pending(&current,now).unwrap().is_none());drop(source);std::fs::remove_file(f.root.path.join("image")).unwrap();
}
#[test]
fn avatar_choices_expire_and_cannot_cross_account_or_page() {
    let f=Fixture::new("avatar-retire",false);let choices=AvatarChoices::new();let current=scope(&f);let now=Instant::now();
    let id=choices.remember(current.choice_anchor().unwrap(),image(&f,"image/jpeg",7),now).unwrap();
    for _ in 0..3 {choices.remember(current.choice_anchor().unwrap(),image(&f,"image/jpeg",7),now).unwrap();}
    assert!(choices.remember(current.choice_anchor().unwrap(),image(&f,"image/jpeg",7),now).is_err());
    choices.expire(now+Duration::from_secs(120));assert!(choices.claim(&current,&id.wire(),now).is_err());
    let id=choices.remember(current.choice_anchor().unwrap(),image(&f,"image/jpeg",7),now).unwrap();f.controller.account_changed();f.activate(1,&f.token);let replacement=scope(&f);
    assert!(choices.claim(&replacement,&id.wire(),now).is_err());assert!(choices.pending(&replacement,now).unwrap().is_none());
    let id=choices.remember(replacement.choice_anchor().unwrap(),image(&f,"image/jpeg",7),now).unwrap();let token=f.replace(2);f.activate(2,&token);
    let next=f.scopes.receiver(owner(2),&token).unwrap().private(&f.epoch()).unwrap().scope();assert!(choices.claim(&next,&id.wire(),now).is_err());
    choices.close();std::fs::remove_file(f.root.path.join("image")).unwrap();
}
#[test]
fn avatar_recovery_keeps_latest_choice_after_older_choice_is_claimed() {
    let f = Fixture::new("avatar-recovery-order", false);
    let choices = AvatarChoices::new();
    let current = scope(&f);
    let now = Instant::now();
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(choices.remember(current.choice_anchor().unwrap(), image(&f, "image/jpeg", 7), now).unwrap());
    }
    drop(choices.claim(&current, &ids[0].wire(), now).unwrap());
    assert_eq!(choices.pending(&current, now).unwrap().unwrap().wire(), ids[3].wire());
    choices.close();
    std::fs::remove_file(f.root.path.join("image")).unwrap();
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

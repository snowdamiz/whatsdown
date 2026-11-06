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


use crate::desktop_lock::{file_reply::FileReply,private_files::{PrivateFiles,ChosenSource,FileHandle,Role},
 private_exports::{ExportContext,StageDirectory},private_destinations::{ChosenDestination,SelectedExport},
 receiver_scope::PrivateScope,resources::Resources};
use tauri::ipc::IpcResponse;
use serde_json::json;
use zeroize::Zeroizing;
use std::os::unix::fs::PermissionsExt;
struct Tree(PathBuf);
impl Tree {
 fn new(f:&Fixture)->Self {let p=f.root.path.join("files");std::fs::create_dir(&p).unwrap();Self(p)}
 fn source(&self)->PathBuf {self.0.join("source")}
 fn target(&self)->PathBuf {self.0.join("target")}
 fn stage(&self)->Arc<StageDirectory> {
  let p=self.0.join("stage");std::fs::create_dir(&p).unwrap();std::fs::set_permissions(&p,std::fs::Permissions::from_mode(0o700)).unwrap();
  StageDirectory::open(&p).unwrap()
 }
}
impl Drop for Tree {fn drop(&mut self) {std::fs::remove_dir_all(&self.0).unwrap();}}
fn scope(f:&Fixture)->PrivateScope {f.scopes.receiver(owner(1),&f.token).unwrap().private(&f.epoch()).unwrap().scope()}
fn mint(files:&Arc<PrivateFiles>,scope:&PrivateScope,tree:&Tree,role:Role)->FileHandle {
 match role {
  Role::Source=>{std::fs::write(tree.source(),b"abc").unwrap();files.claim_source(scope,ChosenSource::open(&tree.source()).unwrap(),3).unwrap()},
  Role::Preview=>files.write_preview(scope,"image/png",Zeroizing::new(b"abc".to_vec())).unwrap(),
  Role::Export=>{
   let selected=SelectedExport::from_choice(scope.choice_anchor().unwrap(),ChosenDestination::capture(&tree.target()).unwrap(),ExportContext::new("fixture/attachment","target","application/octet-stream",3).unwrap());
   files.begin_export(scope,tree.stage(),selected).unwrap()
  }
 }
}
fn usable(files:&Arc<PrivateFiles>,scope:&PrivateScope,role:Role,handle:FileHandle)->bool {
 match role {
  Role::Source=>files.read_source(scope,handle,0,3).is_ok_and(|v|&*v==b"abc"),
  Role::Preview=>files.preview(scope,handle).is_ok_and(|(m,v)|m=="image/png"&&&*v==b"abc"),
  Role::Export=>files.write_export(scope,handle,0,b"abc").is_ok(),
 }
}
fn publication(role:Role,name:&str) {
 let f=Fixture::new(name,false);let tree=Tree::new(&f);let scope=scope(&f);
 let files=PrivateFiles::new(Arc::new(Resources::new(scope.epoch().boot)));
 let handle=mint(&files,&scope,&tree,role);let owners=Arc::strong_count(&files);let policy_owners=Arc::strong_count(&f._store);
 let reply=FileReply::handle(files.clone(),scope.clone(),role,handle,json!({"version":1,"handle":handle.wire()}));
 assert_eq!(Arc::strong_count(&files),owners+1);
 let response=reply.publish().unwrap();
 match response.body().unwrap() {tauri::ipc::InvokeResponseBody::Json(v)=>assert_eq!(serde_json::from_str::<serde_json::Value>(&v).unwrap()["handle"],handle.wire()),_=>panic!("closed metadata reply")}
 assert!(usable(&files,&scope,role,handle),"successfully published handle must remain usable");
 assert_eq!(Arc::strong_count(&files),owners,"published guard must release its own Arc");
 assert_eq!(Arc::strong_count(&f._store),policy_owners,"published guard must release its captured scope");
 if role==Role::Export {files.commit_export(&scope,handle,||Ok(())).unwrap();assert_eq!(std::fs::read(tree.target()).unwrap(),b"abc");}
 files.cleanup(scope.owner(),scope.epoch(),role,handle);
}
#[test]fn published_source_remains_usable(){publication(Role::Source,"reply-source")}
#[test]fn published_preview_remains_usable(){publication(Role::Preview,"reply-preview")}
#[test]fn published_export_remains_usable(){publication(Role::Export,"reply-export")}
#[test]fn rejected_unreturned_reply_retires_each_original_handle(){
 for (role,name) in [(Role::Source,"drop-source"),(Role::Preview,"drop-preview"),(Role::Export,"drop-export")] {
  let f=Fixture::new(name,false);let tree=Tree::new(&f);let scope=scope(&f);let files=PrivateFiles::new(Arc::new(Resources::new(scope.epoch().boot)));
  let handle=mint(&files,&scope,&tree,role);assert!(usable(&files,&scope,role,handle));
  let reply=FileReply::handle(files.clone(),scope.clone(),role,handle,json!({"version":1,"handle":handle.wire()}));
  drop(reply); // The receiving command drops this retained reply when its final admission refuses.
  assert!(!usable(&files,&scope,role,handle),"unreturned reply must retire its original handle");
  assert!(!tree.target().exists());
 }
}

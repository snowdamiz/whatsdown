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

use super::{ChosenSource,FileError,FileHandle,PrivateFiles,Role,MAX_CHUNK};
use crate::desktop_lock::resources::Resources;
use zeroize::Zeroizing;
fn setup(name:&str)->(Fixture,Arc<Resources>,Arc<PrivateFiles>) {
    let f=Fixture::new(name,false);
    let resources=Arc::new(Resources::new(f.controller.epoch().boot));
    let files=PrivateFiles::new(resources.clone());(f,resources,files)
}
fn scope(f:&Fixture)->crate::desktop_lock::receiver_scope::PrivateScope {
    f.scopes.receiver(owner(1),&f.token).unwrap().private(&f.epoch()).unwrap().scope()
}
#[test]
fn source_reads_real_descriptor_in_bounded_ranges_without_reopening_path() {
    let (f,_,files)=setup("file-ranges");let scope=scope(&f);
    let path=f.root.path.join("source");let content=vec![73;MAX_CHUNK+7];std::fs::write(&path,&content).unwrap();
    let chosen=ChosenSource::open(&path).unwrap();let handle=files.claim_source(&scope,chosen,content.len() as u64).unwrap();
    std::fs::rename(&path,f.root.path.join("moved")).unwrap();std::fs::write(&path,b"replacement").unwrap();
    assert_eq!(&*files.read_source(&scope,handle,0,MAX_CHUNK).unwrap(),&content[..MAX_CHUNK]);
    assert_eq!(&*files.read_source(&scope,handle,MAX_CHUNK as u64,7).unwrap(),&content[MAX_CHUNK..]);
    for (offset,length) in [(0,0),(0,MAX_CHUNK+1),(u64::MAX,1),(content.len() as u64,1)] {
        assert!(matches!(files.read_source(&scope,handle,offset,length),Err(FileError::Range)));
    }
    files.cleanup(scope.owner(),scope.epoch(),Role::Source,handle);
    assert!(files.read_source(&scope,handle,0,1).is_err());
    std::fs::remove_file(path).unwrap();std::fs::remove_file(f.root.path.join("moved")).unwrap();
}
#[test]
fn selections_reject_links_special_files_and_mutation_before_claim_or_read() {
    use std::os::unix::fs::symlink;
    let (f,_,files)=setup("file-selection");let scope=scope(&f);let path=f.root.path.join("source");
    std::fs::write(&path,b"original").unwrap();let link=f.root.path.join("link");symlink(&path,&link).unwrap();
    assert!(ChosenSource::open(&link).is_err());assert!(ChosenSource::open(&f.root.path).is_err());
    let fifo=f.root.path.join("fifo");let raw=CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(raw.as_ptr(),0o600) },0);assert!(ChosenSource::open(&fifo).is_err());
    let changed=ChosenSource::open(&path).unwrap();std::fs::write(&path,b"different-size").unwrap();
    assert!(files.claim_source(&scope,changed,8).is_err());
    let chosen=ChosenSource::open(&path).unwrap();let handle=files.claim_source(&scope,chosen,14).unwrap();
    std::fs::write(&path,b"different-SIZE").unwrap();
    assert!(files.read_source(&scope,handle,0,4).is_err());
    files.cleanup(scope.owner(),scope.epoch(),Role::Source,handle);
    for p in [path,link,fifo] { std::fs::remove_file(p).unwrap(); }
}
#[test]
fn preview_uri_is_exact_memory_only_and_strictly_tied_to_owner_epoch_role() {
    let (f,_,files)=setup("file-preview");let old=scope(&f);
    let handle=files.write_preview(&old,"image/png",Zeroizing::new(vec![1,2,3])).unwrap();
    assert_eq!(handle.preview_uri(),format!("morse-private://preview/{}",handle.wire()));
    assert_eq!(FileHandle::parse(&handle.wire()).unwrap(),handle);
    assert!(FileHandle::parse("ABCDEFAB-0000-4000-8000-000000000000").is_err());
    let (mime,bytes)=files.preview(&old,handle).unwrap();assert_eq!(mime,"image/png");assert_eq!(&*bytes,&[1,2,3]);
    assert!(files.read_source(&old,handle,0,1).is_err());
    files.cleanup(owner(99),old.epoch(),Role::Preview,handle);
    files.cleanup(old.owner(),Epoch { generation:old.epoch().generation+1,..old.epoch() },Role::Preview,handle);
    files.cleanup(old.owner(),old.epoch(),Role::Source,handle);
    assert!(files.preview(&old,handle).is_ok());
    let next=f.replace(2);f.activate(2,&next);
    let fresh=f.scopes.receiver(owner(2),&next).unwrap().private(&f.epoch()).unwrap().scope();
    assert!(files.preview(&fresh,handle).is_err());assert!(files.preview(&old,handle).is_err());
    files.cleanup(old.owner(),old.epoch(),Role::Preview,handle);
    assert_eq!(files.state.lock().unwrap().len(),0);
    assert_eq!(std::fs::read_dir(&f.root.path).unwrap().count(),1); // policy lock only
}
#[test]
fn retirement_cleans_registered_resources_and_refuses_late_registration() {
    let (f,resources,files)=setup("file-retire");let scope=scope(&f);
    let handle=files.write_preview(&scope,"image/png",Zeroizing::new(vec![4])).unwrap();
    let held=files.lookup(&scope,Role::Preview,handle).unwrap();
    resources.retire(scope.epoch());assert_eq!(files.state.lock().unwrap().len(),0);
    assert!(held.data.lock().unwrap().is_none());assert!(files.preview(&scope,handle).is_err());
    assert!(files.write_preview(&scope,"image/png",Zeroizing::new(vec![5])).is_err());
    assert_eq!(files.state.lock().unwrap().len(),0);
}
#[test]
fn retirement_does_not_wait_for_active_io_and_suppresses_its_completion() {
    let (f,resources,files)=setup("file-inflight");let scope=scope(&f);
    let handle=files.write_preview(&scope,"image/png",Zeroizing::new(vec![7])).unwrap();
    let held=files.lookup(&scope,Role::Preview,handle).unwrap();
    let (started,wait)=std::sync::mpsc::channel();let (resume,continue_io)=std::sync::mpsc::channel();
    let item=held.clone();let thread_scope=scope.clone();
    let worker=std::thread::spawn(move || item.with_data(&thread_scope,|_| {
        started.send(()).unwrap();continue_io.recv_timeout(std::time::Duration::from_secs(2)).unwrap();Ok(Zeroizing::new(vec![7]))
    }));
    wait.recv_timeout(std::time::Duration::from_secs(2)).unwrap();resources.retire(scope.epoch());
    resume.send(()).unwrap();assert!(worker.join().unwrap().is_err());
    assert!(held.data.lock().unwrap().is_none());assert!(files.state.lock().unwrap().is_empty());
}
#[test]
fn preview_bounds_and_capacity_recover_after_finite_cleanup() {
    let (f,_,files)=setup("file-limits");let scope=scope(&f);
    assert!(files.write_preview(&scope,"text/html",Zeroizing::new(vec![1])).is_err());
    assert!(files.write_preview(&scope,"image/png",Zeroizing::new(vec![])).is_err());
    assert!(files.write_preview(&scope,"image/png",Zeroizing::new(vec![1;16_777_217])).is_err());
    let mut handles=Vec::new();for _ in 0..4 { handles.push(files.write_preview(&scope,"image/png",Zeroizing::new(vec![1])).unwrap()); }
    assert!(files.write_preview(&scope,"image/png",Zeroizing::new(vec![2])).is_err());
    files.cleanup(scope.owner(),scope.epoch(),Role::Preview,handles[0]);
    let next=files.write_preview(&scope,"image/png",Zeroizing::new(vec![3])).unwrap();assert_ne!(next,handles[0]);
    resources_close(&files);assert!(files.state.lock().unwrap().is_empty());
}
fn resources_close(files:&Arc<PrivateFiles>) { files.resources.close(); }

#[test]
fn native_preview_recovery_uses_original_scope_and_retires_inflight_reply() {
    let (f,_,files)=setup("file-native-reply");let scope=scope(&f);
    let handle=files.write_preview(&scope,"image/png",Zeroizing::new(vec![1,2,3])).unwrap();
    assert!(files.preview_for_receiver(owner(99),handle).is_err());
    let reply=files.preview_for_receiver(scope.owner(),handle).unwrap();
    assert_eq!(reply.owner(),scope.owner());assert_eq!(reply.mime(),"image/png");assert_eq!(reply.bytes(),&[1,2,3]);
    reply.check(scope.owner()).unwrap();assert!(reply.check(owner(99)).is_err());
    files.cleanup(scope.owner(),scope.epoch(),Role::Preview,handle);
    assert!(reply.check(scope.owner()).is_err());
    let next=files.write_preview(&scope,"image/png",Zeroizing::new(vec![4])).unwrap();
    let pending=files.preview_for_receiver(scope.owner(),next).unwrap();
    let new=f.replace(2);f.activate(2,&new);
    assert!(pending.check(owner(1)).is_err());assert!(pending.check(owner(2)).is_err());
    assert!(files.preview_for_receiver(owner(2),next).is_err());
}

#[test]
fn encrypted_exports_retire_with_original_native_resources_before_handle_return() {
    use crate::desktop_lock::private_exports::StageDirectory;
    use std::os::unix::fs::PermissionsExt;
    let (f,resources,files)=setup("file-export-retirement");let scope=scope(&f);
    let path=f.root.path.join("stage");std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory=StageDirectory::open(&path).unwrap();
    let handle=files.begin_export(&scope,directory.clone(),selected_export(&f,&scope)).unwrap();files.write_export(&scope,handle,0,b"private").unwrap();
    resources.retire(scope.epoch());assert_eq!(std::fs::read_dir(&path).unwrap().count(),0);
    assert!(files.write_export(&scope,handle,0,b"private").is_err());
    assert!(files.begin_export(&scope,directory.clone(),selected_export(&f,&scope)).is_err());assert_eq!(std::fs::read_dir(&path).unwrap().count(),0);
    drop(directory);std::fs::remove_dir(path).unwrap();
}
#[test]
fn explicit_same_epoch_export_abort_blocks_reentrant_publication_and_spares_successor() {
    use crate::desktop_lock::private_exports::StageDirectory;
    use std::os::unix::fs::PermissionsExt;
    let (f,_,files)=setup("file-export-abort");let scope=scope(&f);
    let path=f.root.path.join("stage");std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory=StageDirectory::open(&path).unwrap();
    let old=files.begin_export(&scope,directory.clone(),selected_export(&f,&scope)).unwrap();files.cleanup(scope.owner(),scope.epoch(),Role::Export,old);
    let handle=files.begin_export(&scope,directory.clone(),selected_export(&f,&scope)).unwrap();files.cleanup(scope.owner(),scope.epoch(),Role::Export,old);
    files.write_export(&scope,handle,0,b"private").unwrap();let target=f.root.path.join("chosen.bin");let mut calls=0;
    let result=files.commit_export(&scope,handle,|| {
        calls+=1;if calls==2 { files.cleanup(scope.owner(),scope.epoch(),Role::Export,handle); }Ok(())
    });
    assert!(result.is_err());assert_eq!(std::fs::metadata(&target).unwrap().len(),0);assert_eq!(std::fs::read_dir(&path).unwrap().count(),0);
    assert!(files.write_export(&scope,handle,0,b"private").is_err());std::fs::remove_file(target).unwrap();drop(directory);std::fs::remove_dir(path).unwrap();
}

fn selected_export(f:&Fixture,scope:&crate::desktop_lock::receiver_scope::PrivateScope)->crate::desktop_lock::private_destinations::SelectedExport {
    use crate::desktop_lock::private_destinations::{ChosenDestination,DestinationChoices};
    use crate::desktop_lock::private_exports::ExportContext;
    let choices=DestinationChoices::new();let now=std::time::Instant::now();
    let context=||ExportContext::new("message/attachment","chosen.bin","image/png",7).unwrap();
    let id=choices.remember(scope.choice_anchor().unwrap(),context(),ChosenDestination::capture(&f.root.path.join("chosen.bin")).unwrap(),now).unwrap();
    choices.claim(scope,&id.wire(),&context(),now).unwrap()
}

#[test]
fn native_selected_export_roundtrips_and_retirement_preserves_existing_destination() {
    use crate::desktop_lock::private_exports::StageDirectory;
    use std::os::unix::fs::PermissionsExt;
    let (f,resources,files)=setup("file-selected-export");let scope=scope(&f);
    let path=f.root.path.join("stage");std::fs::create_dir(&path).unwrap();std::fs::set_permissions(&path,std::fs::Permissions::from_mode(0o700)).unwrap();
    let directory=StageDirectory::open(&path).unwrap();let target=f.root.path.join("chosen.bin");
    std::fs::write(&target,b"existing to preserve").unwrap();
    let handle=files.begin_export(&scope,directory.clone(),selected_export(&f,&scope)).unwrap();
    files.write_export(&scope,handle,0,b"private").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(),b"existing to preserve");
    files.commit_export(&scope,handle,||Ok(())).unwrap();
    assert_eq!(std::fs::read(&target).unwrap(),b"private");
    let handle=files.begin_export(&scope,directory.clone(),selected_export(&f,&scope)).unwrap();
    files.write_export(&scope,handle,0,b"another").unwrap();resources.retire(scope.epoch());
    assert!(files.commit_export(&scope,handle,||Ok(())).is_err());
    assert_eq!(std::fs::read(&target).unwrap(),b"private");
    assert_eq!(std::fs::read_dir(&path).unwrap().count(),0);
    std::fs::remove_file(target).unwrap();drop(directory);std::fs::remove_dir(path).unwrap();
}

struct AccessLifetime(Arc<std::sync::atomic::AtomicUsize>);
impl super::NativeFileAccess for AccessLifetime {}
impl Drop for AccessLifetime { fn drop(&mut self) { self.0.fetch_add(1,std::sync::atomic::Ordering::SeqCst); } }
#[test]
fn native_url_access_lives_through_source_choice_claim_read_and_cleanup() {
    use crate::desktop_lock::private_choices::{AttachmentChoices,SelectedSource};
    use std::{time::Instant,sync::atomic::{AtomicUsize,Ordering}};
    let (f,_,files)=setup("file-native-access");let scope=scope(&f);let path=f.root.path.join("source");std::fs::write(&path,b"private").unwrap();
    let ended=Arc::new(AtomicUsize::new(0));let access=Arc::new(AccessLifetime(ended.clone()));
    let source=ChosenSource::open_selected(&path,access.clone()).unwrap();drop(access);
    let choices=AttachmentChoices::new();let anchor=scope.choice_anchor().unwrap();
    choices.remember(anchor,vec![SelectedSource::new("source","application/octet-stream",source).unwrap()],Instant::now()).unwrap();
    assert_eq!(ended.load(Ordering::SeqCst),0);
    let pending=choices.pending(&scope,Instant::now()).unwrap().unwrap();
    let source=choices.claim(&scope,&pending.choice,&pending.files[0].selection,7,Instant::now()).unwrap();
    let handle=files.claim_source(&scope,source,7).unwrap();assert_eq!(&*files.read_source(&scope,handle,0,7).unwrap(),b"private");assert_eq!(ended.load(Ordering::SeqCst),0);
    files.cleanup(scope.owner(),scope.epoch(),Role::Source,handle);assert_eq!(ended.load(Ordering::SeqCst),1);std::fs::remove_file(path).unwrap();
}

#[test]
fn real_private_scope_refuses_worker_reply_after_lock_before_command_continuation() {
    let f=Fixture::new("command-continuation-lock",true);
    let call=f.scopes.receiver(owner(1),&f.token).unwrap().private(&f.epoch()).unwrap();
    let completion=call.scope();
    let (produced_tx,produced)=std::sync::mpsc::channel();
    let (resume,resume_rx)=std::sync::mpsc::channel();
    let worker=std::thread::spawn(move || {
        let result=call.execute(||Ok(b"core-private-reply".to_vec())).map(Zeroizing::new).map_err(|error|Zeroizing::new(format!("{error:?}")));
        produced_tx.send(()).unwrap();resume_rx.recv().unwrap();
        completion.publish_result(result)
    });
    produced.recv().unwrap();
    f.controller.lifecycle(owner(1),Event::Inactive);
    resume.send(()).unwrap();
    assert_eq!(worker.join().unwrap(),Err("app_lock_stale_epoch".to_owned()));
}
#[test]
fn replaced_page_cannot_publish_a_completed_private_error_or_retire_fresh_scope() {
    let f=Fixture::new("command-continuation-page",false);
    let old=f.scopes.receiver(owner(1),&f.token).unwrap();
    let call=old.clone().private(&f.epoch()).unwrap();
    let completion=call.scope();
    let result=call.execute(||Err("private-account-detail".to_owned())).map(Zeroizing::new).map_err(|_|Zeroizing::new("private-account-detail".to_owned()));
    let token=f.replace(2);f.activate(2,&token);
    old.release();
    assert_eq!(completion.publish_result(result),Err("app_lock_stale_owner".to_owned()));
    assert!(f.scopes.receiver(owner(2),&token).unwrap().check(&f.epoch()).is_ok());
}

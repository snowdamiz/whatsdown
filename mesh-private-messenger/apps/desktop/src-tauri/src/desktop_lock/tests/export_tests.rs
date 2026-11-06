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


use super::{StageDirectory,EncryptedExport,ExportContext,ExportError};
use std::os::unix::fs::{PermissionsExt,FileExt};
use std::fs::OpenOptions;
fn scope(f:&Fixture)->crate::desktop_lock::receiver_scope::PrivateScope {
    f.scopes.receiver(owner(1),&f.token).unwrap().private(&f.epoch()).unwrap().scope()
}
struct Tree(PathBuf);
impl Tree {
    fn new(f:&Fixture)->Self { let p=f.root.path.join("exports");std::fs::create_dir(&p).unwrap();std::fs::create_dir(p.join("stage")).unwrap();std::fs::set_permissions(p.join("stage"),std::fs::Permissions::from_mode(0o700)).unwrap();Self(p) }
    fn stage(&self)->Arc<StageDirectory> { StageDirectory::open(&self.0.join("stage")).unwrap() }
    fn destination(&self)->PathBuf { self.0.join("final.bin") }
}
impl Drop for Tree { fn drop(&mut self) { std::fs::remove_dir_all(&self.0).unwrap(); } }
fn context(size:u64)->ExportContext { ExportContext::new("conversation/message/attachment","final.bin","application/octet-stream",size).unwrap() }
#[test]
fn encrypted_export_never_stages_plaintext_and_roundtrips_real_file() {
    let f=Fixture::new("export-roundtrip",false);let tree=Tree::new(&f);let root=tree.stage();let scope=scope(&f);
    let data=b"private attachment fixture: retain only ciphertext until explicit commit";
    let mut export=EncryptedExport::new(root,&scope,context(data.len() as u64)).unwrap();
    export.write(0,&data[..19]).unwrap();export.write(19,&data[19..]).unwrap();
    let entries=std::fs::read_dir(tree.0.join("stage")).unwrap().map(|e|e.unwrap()).collect::<Vec<_>>();assert_eq!(entries.len(),1);
    let bytes=std::fs::read(entries[0].path()).unwrap();assert!(!bytes.windows(19).any(|v|v==&data[..19]));
    assert_eq!(entries[0].metadata().unwrap().permissions().mode()&0o777,0o600);
    export.commit(||Ok(()),||OpenOptions::new().write(true).create_new(true).open(tree.destination()).map(crate::desktop_lock::private_destinations::DestinationFile::unscoped).map_err(|_|ExportError::Unavailable)).unwrap();
    assert_eq!(std::fs::read(tree.destination()).unwrap(),data);assert_eq!(std::fs::read_dir(tree.0.join("stage")).unwrap().count(),0);
}
#[test]
fn incomplete_abort_bad_ranges_and_invalid_directory_preserve_destination() {
    let f=Fixture::new("export-refusal",false);let tree=Tree::new(&f);let scope=scope(&f);let root=tree.stage();
    std::fs::write(tree.destination(),b"existing").unwrap();let mut export=EncryptedExport::new(root.clone(),&scope,context(8)).unwrap();
    assert!(export.write(1,b"x").is_err());assert!(export.write(0,&[]).is_err());assert!(export.write(0,&vec![1;65537]).is_err());
    export.write(0,b"part").unwrap();let mut opened=false;
    assert!(export.commit(||Ok(()),|| { opened=true;Err(ExportError::Unavailable) }).is_err());assert!(!opened);
    assert_eq!(std::fs::read(tree.destination()).unwrap(),b"existing");
    let mut abandoned=EncryptedExport::new(root,&scope,context(8)).unwrap();abandoned.write(0,b"part").unwrap();drop(abandoned);
    assert_eq!(std::fs::read_dir(tree.0.join("stage")).unwrap().count(),0);
    std::fs::set_permissions(tree.0.join("stage"),std::fs::Permissions::from_mode(0o755)).unwrap();assert!(StageDirectory::open(&tree.0.join("stage")).is_err());
}
#[test]
fn authentication_truncation_and_appended_bytes_fail_before_destination_open() {
    for (name,mode) in [("export-tamper",0),("export-short",1),("export-extra",2)] {
        let f=Fixture::new(name,false);let tree=Tree::new(&f);let scope=scope(&f);let mut export=EncryptedExport::new(tree.stage(),&scope,context(7)).unwrap();export.write(0,b"private").unwrap();
        match mode { 0=>{let mut byte=[0];export.file.read_exact_at(&mut byte,10).unwrap();byte[0]^=1;export.file.write_at(&byte,10).unwrap();},1=>export.file.set_len(30).unwrap(),_=>{export.file.write_at(&[1],31).unwrap();} }
        let mut opened=false;assert!(export.commit(||Ok(()),|| { opened=true;Err(ExportError::Unavailable) }).is_err());assert!(!opened);
        assert_eq!(std::fs::read_dir(tree.0.join("stage")).unwrap().count(),0);
    }
}
#[test]
fn cross_export_ciphertext_is_rejected_and_lock_stops_publication() {
    let f=Fixture::new("export-context",false);let tree=Tree::new(&f);let scope=scope(&f);let root=tree.stage();
    let mut first=EncryptedExport::new(root.clone(),&scope,context(7)).unwrap();first.write(0,b"private").unwrap();
    let mut second=EncryptedExport::new(root,&scope,context(7)).unwrap();second.write(0,b"private").unwrap();
    let mut bytes=vec![0;31];first.file.read_exact_at(&mut bytes,0).unwrap();second.file.write_at(&bytes,0).unwrap();
    let mut opened=false;assert!(second.commit(||Ok(()),|| { opened=true;Err(ExportError::Unavailable) }).is_err());assert!(!opened);
    f.scopes.receiver(owner(1),&f.token).unwrap().release();
    assert!(first.commit(||Ok(()),|| { opened=true;Err(ExportError::Unavailable) }).is_err());assert!(!opened);
}
#[test]
fn revocation_between_chunks_cannot_write_the_next_plaintext_chunk() {
    let f=Fixture::new("export-revoke",false);let tree=Tree::new(&f);let scope=scope(&f);let mut export=EncryptedExport::new(tree.stage(),&scope,context(8)).unwrap();
    export.write(0,b"part").unwrap();export.write(4,b"last").unwrap();let mut publications=0;
    let result=export.commit(|| { publications+=1;if publications==3 { f.scopes.receiver(owner(1),&f.token).unwrap().release(); }Ok(()) },
        ||OpenOptions::new().write(true).create_new(true).open(tree.destination()).map(crate::desktop_lock::private_destinations::DestinationFile::unscoped).map_err(|_|ExportError::Unavailable));
    assert!(result.is_err());assert_eq!(std::fs::read(tree.destination()).unwrap(),b"part");assert_eq!(std::fs::read_dir(tree.0.join("stage")).unwrap().count(),0);
}

#[test]
fn cleanup_does_not_unlink_a_replacement_at_the_original_stage_name() {
    let f=Fixture::new("export-replacement",false);let tree=Tree::new(&f);let scope=scope(&f);
    let mut export=EncryptedExport::new(tree.stage(),&scope,context(7)).unwrap();export.write(0,b"private").unwrap();
    let original=std::fs::read_dir(tree.0.join("stage")).unwrap().next().unwrap().unwrap().path();
    let moved=tree.0.join("stage/renamed.stage");std::fs::rename(&original,&moved).unwrap();std::fs::write(&original,b"replacement must remain").unwrap();
    println!("REAL_STAGE_NAME_REPLACED");drop(export);
    assert_eq!(std::fs::read(&original).ok(),Some(b"replacement must remain".to_vec()),"cleanup must only unlink the original owned file identity");
    assert!(moved.exists());
}

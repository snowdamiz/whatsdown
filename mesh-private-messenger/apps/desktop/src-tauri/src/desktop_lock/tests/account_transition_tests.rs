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


#[test]
fn actual_core_identity_changes_retire_once_and_failed_mutations_keep_admission() {
    const TEST: &str = "desktop_lock::private_commands::tests::actual_core_identity_changes_retire_once_and_failed_mutations_keep_admission";
    if std::env::var("MORSE_DESKTOP_ACCOUNT_CHILD").as_deref() != Ok("1") {
        let proof=std::process::Command::new(std::env::current_exe().unwrap()).args(["--exact",TEST,"--nocapture"])
            .env("MORSE_DESKTOP_ACCOUNT_CHILD","1").output().unwrap();
        assert!(proof.status.success(),"{}\n{}",String::from_utf8_lossy(&proof.stdout),String::from_utf8_lossy(&proof.stderr));
        return;
    }
    let f=Fixture::new("account-transition",true);
    let service=format!("io.morseapp.desktop.tests.{}.account-transition",std::process::id());
    let database=f.root.path.join("core.db").to_string_lossy().into_owned();
    struct Cleanup(String,PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let key=b"mesh/storage-key/v2".iter().map(|byte|format!("{byte:02x}")).collect::<String>();
            let _=keyring::Entry::new(&self.0,&key).unwrap().delete_credential();
            for name in ["core.db","core.db-wal","core.db-shm"] { let _=std::fs::remove_file(self.1.join(name)); }
        }
    }
    let _cleanup=Cleanup(service.clone(),f.root.path.clone());
    let library=crate::mesh::Mesh::load(&PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("native/libmessenger_mobile.dylib"),
        String::new(),String::new(),String::new(),String::new(),String::new(),String::new(),String::new(),String::new(),service).unwrap();
    library.invoke("mesh_messenger_initialize",database.as_bytes(),&database).unwrap();
    assert_eq!(library.invoke("mesh_messenger_load_profile",database.as_bytes(),&database).unwrap_err(), "Mesh 9: local_state_not_found");
    assert_eq!(super::identity(&library,&database).unwrap(),None);
    let original=f.epoch();
    assert!(super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_create_account",b"invalid",&database,|_,_|panic!("failed mutation cannot authorize cleanup")).is_err());
    assert_eq!(f.epoch(),original,"a refused Core mutation must not retire its own admission");
    let vector=|bytes:&[u8]| {let mut frame=(bytes.len() as u32).to_be_bytes().to_vec();frame.extend_from_slice(bytes);frame};
    let mut request=vector(database.as_bytes());request.extend(vector(b"desktopproof"));
    let call=f.scopes.receiver(owner(1),&f.token).unwrap().private(&original).unwrap();
    let outcome=call.execute(||super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_create_account",&request,&database,|_,_|panic!("creation cannot authorize removal"))
        .map(|mut bytes|std::mem::take(&mut *bytes)));
    assert!(matches!(outcome,Err(crate::desktop_lock::receiver_scope::PrivateFailure::Admission(Refusal::StaleEpoch))));
    assert_ne!(f.epoch(),original);
    assert!(super::identity(&library,&database).unwrap().is_some(),"Core committed identity despite refusing the old private completion");
    f.activate(1,&f.token);
    let fresh=f.epoch();
    assert!(super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_create_signup_draft",b"invalid",&database,|_,_|panic!("failed mutation cannot authorize cleanup")).is_err());
    assert_eq!(f.epoch(),fresh);
    assert!(f.scopes.receiver(owner(1),&f.token).unwrap().check(&fresh).is_ok());
    let scope=f.scopes.receiver(owner(1),&f.token).unwrap().private(&fresh).unwrap().scope();
    let expected=super::identity(&library,&database).unwrap().unwrap();
    let removals=crate::desktop_lock::legacy_commands::LegacyRemovals::default();
    let mut successor=String::new();let mut removed=Vec::new();
    let erased=super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_erase_account",database.as_bytes(),&database,|captured,account| {
        assert_eq!(captured,expected);assert_eq!(super::identity(&library,&database).unwrap(),None);
        assert!(scope.check().is_err());
        removals.capture(captured,account,&database)?;
        let result=removals.drain(&library,&f.controller,&scope,&database,|cleanup,key| {
            cleanup.check().unwrap();
            if removed.len()==2 {
                let token=f.replace(2);f.activate(2,&token);successor=token;
                assert!(cleanup.check().is_err(),"old removal may not adopt the replacement document");
                return Err("page_replaced".to_owned());
            }
            removed.push(key.to_owned());Ok(())
        });
        assert_eq!(result,Err("page_replaced".to_owned()));Ok(())
    });
    assert_eq!(erased.unwrap_err(),"app_lock_account_changed");assert_eq!(removed.len(),2);
    let next=f.scopes.receiver(owner(2),&successor).unwrap().private(&f.epoch()).unwrap().scope();
    let mut retried=Vec::new();
    removals.drain(&library,&f.controller,&next,&database,|cleanup,key| {
        cleanup.check().unwrap();retried.push(key.to_owned());Ok(())
    }).unwrap();
    assert_eq!(retried.len(),6,"the replacement page must finish all finite native-owned keys");
    assert!(removed.iter().all(|key|retried.contains(key)));
    removals.drain(&library,&f.controller,&next,&database,|_,_|panic!("completed cleanup must not replay")).unwrap();
    assert!(next.check().is_ok(),"old cleanup must not retire fresh services");
    for symbol in ["mesh_messenger_directory_register","mesh_messenger_devices_renew"] {
        let made=super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_create_account",&request,&database,|_,_|panic!("creation"));
        assert_eq!(made.unwrap_err(),"app_lock_account_changed");f.activate(2,&successor);
        let old=f.scopes.receiver(owner(2),&successor).unwrap().private(&f.epoch()).unwrap().scope();
        let resources=Arc::new(crate::desktop_lock::resources::Resources::new(old.epoch().boot));
        let files=crate::desktop_lock::private_files::PrivateFiles::new(resources.clone());
        let preview=files.write_preview(&old,"image/png",zeroize::Zeroizing::new(b"preview".to_vec())).unwrap();
        // Run the actual Core removal at the external network-operation seam.
        // Verification of HTTP 410 signatures remains Mesh's responsibility.
        let result=super::observe_identity_transition(&library,&f.controller,symbol,&database,
            ||library.invoke("mesh_messenger_erase_account",database.as_bytes(),&database),
            |_,epoch| { assert!(old.check().is_err());assert!(old.retired_cleanup(epoch).check().is_ok());Ok(()) });
        assert_eq!(result.unwrap_err(),"app_lock_account_changed");
        assert!(files.preview(&old,preview).is_err(),"remote removal must revoke retained private files");
        resources.retire(old.epoch());f.activate(2,&successor);
    }
    // The cleanup capability survives lock/unlock for this account, but the
    // original private command must recheck its own epoch before invoking Core.
    removals.capture(expected,f.controller.account_generation(),&database).unwrap();
    let call=f.scopes.receiver(owner(2),&successor).unwrap().private(&f.epoch()).unwrap();
    let (entered_tx,entered)=std::sync::mpsc::channel();let (resume,resume_rx)=std::sync::mpsc::channel();
    let controller=f.controller.clone();let queue=f.queue.clone();let auth=f.auth.clone();let scopes=&f.scopes;let token=successor.clone();
    let mut attempted=false;
    let fresh_epoch=std::thread::scope(|threads| {
        let lifecycle=threads.spawn(move || {
            entered.recv().unwrap();controller.lifecycle(owner(2),Event::Inactive);
            controller.lifecycle(owner(2),Event::Active);
            controller.request(owner(2),controller.epoch(),Intent::Unlock).unwrap();queue.drain();
            auth.0.lock().unwrap().take().unwrap()(AuthReply::Approved);queue.drain();
            let epoch=crate::desktop_lock::wire::epoch(controller.epoch());
            scopes.receiver(owner(2),&token).unwrap().activate(&epoch).unwrap();resume.send(()).unwrap();epoch
        });
        let mut first=true;
        let result=call.execute_checked(|call| {
            super::drain_before_core(call,||removals.drain(&library,&f.controller,&call.scope(),&database,|cleanup,_| {
                if first { first=false;entered_tx.send(()).unwrap();resume_rx.recv().unwrap(); }
                cleanup.check().unwrap();Ok(())
            }))?;
            attempted=true;
            super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_create_account",&request,&database,|_,_|panic!("creation"))
                .map(|mut bytes|std::mem::take(&mut *bytes))
        });
        assert!(result.is_err());lifecycle.join().unwrap()
    });
    assert!(!attempted,"stale Core operation must not run after cleanup resumes");
    assert!(f.scopes.receiver(owner(2),&successor).unwrap().check(&fresh_epoch).is_ok());
    assert_eq!(super::identity(&library,&database).unwrap(),None);
    let _=super::invoke_identity_transition(&library,&f.controller,"mesh_messenger_create_account",&request,&database,|_,_|panic!("creation"));
    f.activate(2,&successor);
    let restored=super::identity(&library,&database).unwrap().unwrap();
    let current=f.scopes.receiver(owner(2),&successor).unwrap().private(&f.epoch()).unwrap().scope();
    removals.capture(restored,f.controller.account_generation(),&database).unwrap();
    removals.drain(&library,&f.controller,&current,&database,|_,_|panic!("cleanup must spare a restored identity's keys")).unwrap();
    assert!(current.check().is_ok());
}

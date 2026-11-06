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


use super::{AttachmentChoices,SelectedSource};
use crate::desktop_lock::private_files::ChosenSource;
use std::time::{Instant,Duration};
fn scope(f:&Fixture)->crate::desktop_lock::receiver_scope::PrivateScope {
    f.scopes.receiver(owner(1),&f.token).unwrap().private(&f.epoch()).unwrap().scope()
}
fn selected(f:&Fixture)->SelectedSource {
    let path=f.root.path.join("selected");std::fs::write(&path,b"choice").unwrap();
    SelectedSource::new("photo.png","image/png",ChosenSource::open(&path).unwrap()).unwrap()
}
#[test]
fn attachment_recovery_keeps_latest_choice_after_older_choice_is_claimed() {
    let f = Fixture::new("attachment-recovery-order", false);
    let choices = AttachmentChoices::new();
    let current = scope(&f);
    let now = Instant::now();
    let mut rows = Vec::new();
    for _ in 0..4 {
        choices.remember(current.choice_anchor().unwrap(), vec![selected(&f)], now).unwrap();
        rows.push(choices.pending(&current, now).unwrap().unwrap());
    }
    drop(choices.claim(&current, &rows[0].choice, &rows[0].files[0].selection, 6, now).unwrap());
    assert_eq!(choices.pending(&current, now).unwrap().unwrap().choice, rows[3].choice);
    choices.close();
    std::fs::remove_file(f.root.path.join("selected")).unwrap();
}
#[test]
fn attachment_recovery_preserves_remaining_native_selection_order() {
    let f = Fixture::new("attachment-selection-order", false);
    let choices = AttachmentChoices::new();
    let current = scope(&f);
    let now = Instant::now();
    choices.remember(current.choice_anchor().unwrap(), vec![selected(&f), selected(&f), selected(&f)], now).unwrap();
    let original = choices.pending(&current, now).unwrap().unwrap();
    drop(choices.claim(&current, &original.choice, &original.files[0].selection, 6, now).unwrap());
    let remaining = choices.pending(&current, now).unwrap().unwrap();
    let actual: Vec<_> = remaining.files.iter().map(|file| &file.selection).collect();
    let expected: Vec<_> = original.files[1..].iter().map(|file| &file.selection).collect();
    assert_eq!(actual, expected);
    choices.close();
    std::fs::remove_file(f.root.path.join("selected")).unwrap();
}
#[test]
fn destination_recovery_keeps_latest_choice_after_older_choice_is_claimed() {
    use crate::desktop_lock::{private_destinations::{ChosenDestination, DestinationChoices}, private_exports::ExportContext};
    let f = Fixture::new("destination-recovery-order", false);
    let choices = DestinationChoices::new();
    let current = scope(&f);
    let now = Instant::now();
    let path = f.root.path.join("chosen");
    let context = || ExportContext::new("message/attachment", "chosen", "text/plain", 7).unwrap();
    let mut ids = Vec::new();
    for _ in 0..4 {
        ids.push(choices.remember(current.choice_anchor().unwrap(), context(), ChosenDestination::capture(&path).unwrap(), now).unwrap());
    }
    drop(choices.claim(&current, &ids[0].wire(), &context(), now).unwrap());
    assert_eq!(choices.pending(&current, &context(), now).unwrap().unwrap().wire(), ids[3].wire());
    choices.close();
    assert!(!path.exists());
}
#[test]
fn picker_choice_survives_lock_but_old_action_cannot_publish_or_claim() {
    let f=Fixture::new("choice-unlock",true);let choices=AttachmentChoices::new();let original=scope(&f);let anchor=original.choice_anchor().unwrap();
    f.controller.lifecycle(owner(1),Event::Inactive);assert!(original.check().is_err());
    let now=Instant::now();let id=choices.remember(anchor,vec![selected(&f)],now).unwrap();
    assert!(choices.pending(&original,now).is_err());
    f.controller.lifecycle(owner(1),Event::Active);f.activate(1,&f.token);let current=scope(&f);
    let pending=choices.pending(&current,now).unwrap().unwrap();assert_eq!(pending.choice,id.wire());assert_eq!(pending.files[0].filename.as_str(),"photo.png");assert_eq!(pending.files[0].mime.as_str(),"image/png");
    let source=choices.claim(&current,&pending.choice,&pending.files[0].selection,6,now).unwrap();assert_eq!(source.size(),6);
    assert!(choices.claim(&current,&pending.choice,&pending.files[0].selection,6,now).is_err());
    assert!(choices.pending(&current,now).unwrap().is_none());std::fs::remove_file(f.root.path.join("selected")).unwrap();
}
#[test]
fn changed_account_or_page_cannot_reclaim_old_choices() {
    let f=Fixture::new("choice-account",false);let choices=AttachmentChoices::new();let original=scope(&f);let now=Instant::now();
    let id=choices.remember(original.choice_anchor().unwrap(),vec![selected(&f)],now).unwrap();
    let summary=choices.pending(&original,now).unwrap().unwrap();
    f.controller.account_changed();f.activate(1,&f.token);let current=scope(&f);
    assert!(choices.claim(&current,&id.wire(),&summary.files[0].selection,6,now).is_err());
    assert!(choices.pending(&current,now).unwrap().is_none());
    let anchor=current.choice_anchor().unwrap();let next=f.replace(2);f.activate(2,&next);
    assert!(choices.remember(anchor,vec![selected(&f)],now).is_err());
    std::fs::remove_file(f.root.path.join("selected")).unwrap();
}
#[test]
fn choice_expiry_bounds_close_and_concurrent_single_claim() {
    let f=Fixture::new("choice-bound",false);let choices=Arc::new(AttachmentChoices::new());let current=scope(&f);let now=Instant::now();
    for _ in 0..4 { choices.remember(current.choice_anchor().unwrap(),vec![selected(&f)],now).unwrap(); }
    assert!(choices.remember(current.choice_anchor().unwrap(),vec![selected(&f)],now).is_err());
    choices.expire(now+Duration::from_secs(121));assert!(choices.pending(&current,now+Duration::from_secs(121)).unwrap().is_none());
    choices.remember(current.choice_anchor().unwrap(),vec![selected(&f)],now).unwrap();let row=choices.pending(&current,now).unwrap().unwrap();
    let barrier=Arc::new(std::sync::Barrier::new(3));let mut workers=vec![];
    for _ in 0..2 { let c=choices.clone();let s=current.clone();let choice=row.choice.clone();let selection=row.files[0].selection.clone();let b=barrier.clone();
        workers.push(std::thread::spawn(move || { b.wait();c.claim(&s,&choice,&selection,6,now).is_ok() })); }
    barrier.wait();assert_eq!(workers.into_iter().map(|w|usize::from(w.join().unwrap())).sum::<usize>(),1);
    choices.close();assert!(choices.remember(current.choice_anchor().unwrap(),vec![selected(&f)],now).is_err());
    std::fs::remove_file(f.root.path.join("selected")).unwrap();
}

#[test]
fn export_choice_requires_fresh_authority_and_exact_original_context() {
    use crate::desktop_lock::{private_destinations::{ChosenDestination, DestinationChoices}, private_exports::ExportContext};
    let f = Fixture::new("destination-authority", true);
    let original = scope(&f);
    let choices = DestinationChoices::new();
    let context = || ExportContext::new("message/attachment", "chosen", "text/plain", 7).unwrap();
    let path = f.root.path.join("chosen");
    std::fs::write(&path, b"existing").unwrap();
    let anchor = original.choice_anchor().unwrap();
    f.controller.lifecycle(owner(1), Event::Inactive);
    let now = Instant::now();
    let id = choices.remember(anchor, context(), ChosenDestination::capture(&path).unwrap(), now).unwrap();
    assert!(choices.claim(&original, &id.wire(), &context(), now).is_err());
    f.controller.lifecycle(owner(1), Event::Active);
    f.activate(1, &f.token);
    let current = scope(&f);
    assert_eq!(choices.pending(&current, &context(), now).unwrap().unwrap().wire(), id.wire());
    let destination = choices.claim(&current, &id.wire(), &context(), now).unwrap();
    assert!(choices.claim(&current, &id.wire(), &context(), now).is_err());
    drop(destination);
    let id = choices.remember(current.choice_anchor().unwrap(), context(), ChosenDestination::capture(&path).unwrap(), now).unwrap();
    let wrong = ExportContext::new("different/message", "chosen", "text/plain", 7).unwrap();
    assert!(choices.claim(&current, &id.wire(), &wrong, now).is_err());
    assert!(choices.claim(&current, &id.wire(), &context(), now).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), b"existing");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn export_choice_expires_and_cannot_cross_account_or_page_replacement() {
    use crate::desktop_lock::{private_destinations::{ChosenDestination, DestinationChoices}, private_exports::ExportContext};
    let f = Fixture::new("destination-owner", false);
    let current = scope(&f);
    let choices = DestinationChoices::new();
    let context = || ExportContext::new("message/attachment", "chosen", "text/plain", 7).unwrap();
    let path = f.root.path.join("chosen");
    let now = Instant::now();
    for _ in 0..4 { choices.remember(current.choice_anchor().unwrap(), context(), ChosenDestination::capture(&path).unwrap(), now).unwrap(); }
    assert!(choices.remember(current.choice_anchor().unwrap(), context(), ChosenDestination::capture(&path).unwrap(), now).is_err());
    choices.expire(now + Duration::from_secs(120));
    assert!(choices.pending(&current, &context(), now).unwrap().is_none());
    let id = choices.remember(current.choice_anchor().unwrap(), context(), ChosenDestination::capture(&path).unwrap(), now).unwrap();
    f.controller.account_changed();
    f.activate(1, &f.token);
    let current = scope(&f);
    assert!(choices.claim(&current, &id.wire(), &context(), now).is_err());
    let anchor = current.choice_anchor().unwrap();
    let token = f.replace(2);
    f.activate(2, &token);
    assert!(choices.remember(anchor, context(), ChosenDestination::capture(&path).unwrap(), now).is_err());
    assert!(!path.exists());
}

struct StageTree(std::path::PathBuf);
impl StageTree {
    fn new(f: &Fixture) -> Self { Self(f.root.path.join("private-exports-v1")) }
}
impl Drop for StageTree {
    fn drop(&mut self) {
        if self.0.exists() { std::fs::remove_dir_all(&self.0).unwrap(); }
    }
}
fn orphan(tree: &StageTree, index: u64) -> std::path::PathBuf {
    use std::os::unix::fs::OpenOptionsExt;
    let path = tree.0.join(format!("00000000-0000-4000-8000-{index:012x}.stage"));
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&path).unwrap();
    std::io::Write::write_all(&mut file, b"owned synthetic opaque stage").unwrap();
    path
}

#[test]
fn startup_retires_old_ciphertext_only_after_last_active_export_releases_owner() {
    use crate::desktop_lock::{private_exports::{EncryptedExport, ExportContext}, stage_startup::prepare};
    let f = Fixture::new("stage-active", false); let tree = StageTree::new(&f);
    let directory = prepare(f._store.clone()).unwrap(); let current = scope(&f);
    let context = ExportContext::new("message/attachment", "chosen", "text/plain", 7).unwrap();
    let mut export = EncryptedExport::new(directory.clone(), &current, context).unwrap();
    export.write(0, b"private").unwrap();
    let path = std::fs::read_dir(&tree.0).unwrap().map(|r| r.unwrap().path()).find(|p| p.extension().is_some_and(|x| x == "stage")).unwrap();
    let encrypted = std::fs::read(&path).unwrap();
    let abandoned = orphan(&tree, 1); std::fs::write(&abandoned, &encrypted).unwrap();
    assert!(prepare(f._store.clone()).is_err());
    assert_eq!(std::fs::read(&path).unwrap(), encrypted);
    drop(directory);
    assert!(prepare(f._store.clone()).is_err()); // Export's Arc still owns the session lock.
    assert!(path.exists());
    drop(export);
    assert!(!path.exists()); assert!(abandoned.exists());
    let next = prepare(f._store.clone()).unwrap();
    assert!(!abandoned.exists());
    assert_eq!(std::fs::read_dir(&tree.0).unwrap().count(), 1); // Only the public session marker.
    drop(next);
}

#[test]
fn startup_inventories_unknown_entries_before_deleting_any_staging() {
    use crate::desktop_lock::stage_startup::prepare;
    let f = Fixture::new("stage-unknown", false); let tree = StageTree::new(&f);
    drop(prepare(f._store.clone()).unwrap());
    let stage = orphan(&tree, 1); let other = tree.0.join("keep.txt");
    std::fs::write(&other, b"preserve unknown entry").unwrap();
    assert!(prepare(f._store.clone()).is_err());
    assert!(stage.exists()); assert_eq!(std::fs::read(&other).unwrap(), b"preserve unknown entry");
    std::fs::remove_file(&other).unwrap();
    use std::os::unix::fs::symlink;
    let link = tree.0.join("00000000-0000-4000-8000-000000000002.stage");
    symlink(&stage, &link).unwrap();
    assert!(prepare(f._store.clone()).is_err()); assert!(stage.exists());
    std::fs::remove_file(&link).unwrap();
    std::fs::hard_link(&stage, &link).unwrap();
    assert!(prepare(f._store.clone()).is_err()); assert!(stage.exists());
}

#[test]
fn startup_rejects_invalid_process_owner_and_preserves_existing_staging() {
    use crate::desktop_lock::stage_startup::prepare;
    let f = Fixture::new("stage-policy-loss", false); let tree = StageTree::new(&f);
    drop(prepare(f._store.clone()).unwrap()); let stage = orphan(&tree, 1);
    assert!(unsafe { MDTestPolicyReplaceLock(f.root.raw) });
    assert!(!f._store.current());
    assert!(prepare(f._store.clone()).is_err()); assert!(stage.exists());
}

#[test]
fn startup_bounds_retirement_and_preserves_unknown_unmarked_directory() {
    use crate::desktop_lock::stage_startup::prepare;
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new("stage-bounds", false); let tree = StageTree::new(&f);
    std::fs::create_dir(&tree.0).unwrap(); std::fs::set_permissions(&tree.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let unknown = tree.0.join("preserve.txt"); std::fs::write(&unknown,b"unrecognized file").unwrap();
    assert!(prepare(f._store.clone()).is_err());
    assert_eq!(std::fs::read_dir(&tree.0).unwrap().count(), 1);
    assert_eq!(std::fs::read(&unknown).unwrap(),b"unrecognized file");
    std::fs::remove_file(unknown).unwrap();
    std::fs::remove_dir(&tree.0).unwrap(); drop(prepare(f._store.clone()).unwrap());
    for index in 0..65 { orphan(&tree, index); }
    assert!(prepare(f._store.clone()).is_err());
    assert_eq!(std::fs::read_dir(&tree.0).unwrap().count(), 66);
    std::fs::remove_file(tree.0.join("00000000-0000-4000-8000-000000000040.stage")).unwrap();
    drop(prepare(f._store.clone()).unwrap());
    assert_eq!(std::fs::read_dir(&tree.0).unwrap().count(), 1);
}

#[test]
fn replacing_stage_marker_refuses_subsequent_private_writes() {
    use crate::desktop_lock::{private_exports::{EncryptedExport, ExportContext}, stage_startup::prepare};
    let f = Fixture::new("stage-replacement", false); let tree = StageTree::new(&f);
    let directory = prepare(f._store.clone()).unwrap(); let current = scope(&f);
    let context = ExportContext::new("message/attachment", "chosen", "text/plain", 7).unwrap();
    let mut export = EncryptedExport::new(directory, &current, context).unwrap();
    let marker = tree.0.join("session.v1");
    std::fs::rename(&marker, tree.0.join("previous-session")).unwrap();
    std::fs::write(&marker, b"replacement must remain").unwrap();
    assert!(export.write(0, b"private").is_err());
    drop(export);
    assert_eq!(std::fs::read(marker).unwrap(), b"replacement must remain");
}

#[test]
fn startup_recovers_empty_owned_directory_after_first_creation_interruption() {
    use crate::desktop_lock::stage_startup::prepare;
    use std::os::unix::fs::PermissionsExt;
    let f = Fixture::new("stage-empty-recovery", false); let tree = StageTree::new(&f);
    std::fs::create_dir(&tree.0).unwrap(); std::fs::set_permissions(&tree.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    eprintln!("REAL_EMPTY_CACHE_AFTER_MKDIR");
    let directory = prepare(f._store.clone()).expect("empty owned cache must recover after interrupted initialization");
    assert_eq!(std::fs::read(tree.0.join("session.v1")).unwrap(),b"Morse encrypted export staging v1\n");
    assert!(prepare(f._store.clone()).is_err()); drop(directory);
}

#[test]
fn startup_completes_partial_public_marker_only_when_no_other_files_exist() {
    use crate::desktop_lock::stage_startup::prepare;
    use std::os::unix::fs::{PermissionsExt, OpenOptionsExt};
    let f = Fixture::new("stage-partial-recovery", false); let tree = StageTree::new(&f);
    std::fs::create_dir(&tree.0).unwrap(); std::fs::set_permissions(&tree.0, std::fs::Permissions::from_mode(0o700)).unwrap();
    let marker = tree.0.join("session.v1");
    let mut file = std::fs::OpenOptions::new().create_new(true).write(true).mode(0o600).open(&marker).unwrap();
    std::io::Write::write_all(&mut file,b"Morse encrypted").unwrap(); drop(file);
    eprintln!("REAL_PARTIAL_PUBLIC_CACHE_MARKER");
    drop(prepare(f._store.clone()).expect("exact partial public marker must recover without data files"));
    assert_eq!(std::fs::read(&marker).unwrap(),b"Morse encrypted export staging v1\n");
    std::fs::write(&marker,b"Morse encrypted").unwrap(); let stage = orphan(&tree, 1);
    assert!(prepare(f._store.clone()).is_err()); assert!(stage.exists());
    assert_eq!(std::fs::read(&marker).unwrap(),b"Morse encrypted");
    std::fs::remove_file(stage).unwrap(); std::fs::write(&marker,b"unknown marker").unwrap();
    assert!(prepare(f._store.clone()).is_err());
    assert_eq!(std::fs::read(&marker).unwrap(),b"unknown marker");
}

#[test]
fn startup_uses_actual_owned_policy_directory_without_changing_shared_appdata_permissions() {
    use crate::desktop_lock::stage_startup::prepare;
    use std::os::unix::fs::PermissionsExt;
    let appdata = OwnedRoot::new("stage-shared-appdata");
    std::fs::set_permissions(&appdata.path,std::fs::Permissions::from_mode(0o755)).unwrap();
    // Matches PolicyBridge.m's production owner-directory layout. The native
    // owner, lock and policy remain actual; only Keychain IO uses fixture ports.
    let owned = OwnedRoot::new("stage-shared-appdata/morse-desktop-app-lock-v1");
    let _cache = StageTree(owned.path.join("private-exports-v1"));
    let policy = Arc::new(unsafe {
        NativePolicyStore::from_test_context(MDTestPolicyOpen(owned.raw)).unwrap()
    });
    assert!(policy.current());
    eprintln!("REAL_0755_APPDATA_WITH_CURRENT_0700_NATIVE_OWNER");
    let directory = prepare(policy).expect("staging must use the actual native-owned directory");
    assert!(owned.path.join("private-exports-v1/session.v1").is_file());
    assert!(!appdata.path.join("private-exports-v1").exists());
    assert_eq!(std::fs::metadata(&appdata.path).unwrap().permissions().mode() & 0o777,0o755);
    drop(directory);
}

#[test]
fn native_selection_mime_is_preserved_and_invalid_metadata_never_enters_a_choice() {
    let f=Fixture::new("choice-mime",false);let path=f.root.path.join("selected");std::fs::write(&path,b"choice").unwrap();
    for mime in ["", "image", "image/", "/png", "image/png/extra", "text/plain;secret=1", "image/png\r\nX-Header: value"] {
        assert!(SelectedSource::new("photo.png",mime,ChosenSource::open(&path).unwrap()).is_err());
    }
    let choices=AttachmentChoices::new();let scope=scope(&f);let now=Instant::now();
    let selected=SelectedSource::new("photo.png","application/vnd.example+json",ChosenSource::open(&path).unwrap()).unwrap();
    choices.remember(scope.choice_anchor().unwrap(),vec![selected],now).unwrap();
    let metadata=choices.pending(&scope,now).unwrap().unwrap();assert_eq!(metadata.files[0].mime.as_str(),"application/vnd.example+json");
    choices.close();std::fs::remove_file(path).unwrap();
}

//! Native page binding and actual private command boundary. Tauri resolves the
//! receiver from PlatformWebview.inner/ns_window; headers only narrow it.
use crate::desktop_lock::controller::{Controller,Epoch,Event,Lease,Owner,Refusal};
use crate::desktop_lock::native_policy::NativePolicyStore;
use crate::desktop_lock::wire::{self,Capability,DesktopEnvelope};
use std::ffi::c_void;
use std::marker::PhantomData;
use std::rc::Rc;
use std::sync::{Arc,Mutex,atomic::{AtomicBool,Ordering}};
use zeroize::Zeroize;

#[link(name="Security",kind="framework")]
unsafe extern "C" {
    fn pthread_main_np()->i32;
    static kSecRandomDefault:*const c_void;
    fn SecRandomCopyBytes(random:*const c_void,count:usize,bytes:*mut u8)->i32;
}
// This token cannot cross threads or come from IPC. Binding transitions run on
// the one native main queue, without holding any policy/Core writer lock.
pub(crate) struct MainThread(PhantomData<Rc<()>>);
impl MainThread {
    #[cfg(test)]
    pub(crate) fn deferred_test_dispatch()->Self { Self(PhantomData) }
    pub(crate) fn current()->Result<Self,Refusal> {
        if unsafe { pthread_main_np() }==1 { Ok(Self(PhantomData)) } else { Err(Refusal::StaleOwner) }
    }
}
pub(crate) fn fill_random(value:&mut [u8])->Result<(),Refusal> {
    if unsafe { SecRandomCopyBytes(kSecRandomDefault,value.len(),value.as_mut_ptr()) }!=0 { return Err(Refusal::PolicyUnreadable); }
    Ok(())
}
pub(crate) fn fresh_uuid()->Result<[u8;16],Refusal> {
    let mut value=[0;16];fill_random(&mut value)?;
    value[6]=(value[6]&0x0f)|0x40;value[8]=(value[8]&0x3f)|0x80;Ok(value)
}
struct Page {
    owner:Owner,
    token:[u8;16],
    open:AtomicBool,
}
struct Pages { current:Option<Arc<Page>>,last_generation:u64,closed:bool }
pub(crate) struct ReceiverScopes {
    pages:Mutex<Pages>,
    controller:Arc<Controller>,
    policy:Arc<NativePolicyStore>,
    capability:Capability,
}
#[derive(Clone)]
pub(crate) struct BoundReceiver {
    page:Arc<Page>,
    controller:Arc<Controller>,
    policy:Arc<NativePolicyStore>,
}
#[derive(Clone)]
pub(crate) struct PrivateScope { bound:BoundReceiver,lease:Lease,epoch:Epoch }
#[derive(Clone)]
pub(crate) struct ChoiceAnchor { bound: BoundReceiver, lease: Lease }
impl ChoiceAnchor {
    pub(crate) fn current(&self) -> Result<(), Refusal> {
        self.bound.require_open()?;
        if !self.bound.controller.choice_is_current(self.lease) { return Err(Refusal::StaleOwner); }
        self.bound.require_open()
    }
    pub(crate) fn matches(&self, scope: &PrivateScope) -> Result<(), Refusal> {
        scope.check()?;
        if !Arc::ptr_eq(&self.bound.page, &scope.bound.page) { return Err(Refusal::StaleOwner); }
        self.current()?;
        scope.check()
    }
}
pub(crate) struct PrivateCall { scope:PrivateScope }
#[derive(Debug,Eq,PartialEq)]
pub(crate) enum PrivateFailure { Admission(Refusal),Operation(String) }
impl ReceiverScopes {
    pub(crate) fn new(controller:Arc<Controller>,policy:Arc<NativePolicyStore>,capability:Capability)->Self {
        Self { pages:Mutex::new(Pages { current:None,last_generation:0,closed:false }),controller,policy,capability }
    }
    // Owner is a new native page generation. Install retires old authority
    // before attachment; the same main callback attaches/refreshes before reply. Even a rebind of the same WKWebView gets a
    // fresh native generation, preventing a delayed A release from retiring B.
    pub(crate) fn install(&self,_main:&MainThread,owner:Owner)->Result<String,Refusal> {
        // Retire the prior authority before *any* fallible bind preparation.
        // A failed attempt cannot revive old queued work when OS state settles.
        {
            let mut pages=self.pages.lock().unwrap();
            if pages.closed || owner.window==0 || owner.webview<=pages.last_generation { return Err(Refusal::StaleOwner); }
            if let Some(previous)=pages.current.take() { previous.open.store(false,Ordering::Release); }
            pages.last_generation=owner.webview;
        }
        self.controller.replace_owner(owner);
        let prepared=(|| {
            if !self.policy.current() { return Err(Refusal::PolicyUnreadable); }
            fresh_uuid()
        })();
        let token=match prepared {
            Ok(token)=>token,
            Err(error)=>{ self.controller.unavailable(owner);return Err(error); }
        };
        let mut pages=self.pages.lock().unwrap();
        if pages.closed { drop(pages);self.controller.unavailable(owner);return Err(Refusal::StaleOwner); }
        pages.current=Some(Arc::new(Page { owner,token,open:AtomicBool::new(true) }));
        Ok(wire::uuid(token))
    }
    pub(crate) fn close(&self) {
        let page={
            let mut pages=self.pages.lock().unwrap();pages.closed=true;
            let page=pages.current.take();
            if let Some(page)=&page { page.open.store(false,Ordering::Release); }
            page
        };
        if let Some(page)=page { self.controller.lifecycle(page.owner,Event::Destroyed); }
    }
    // Finite cleanup validates only actual receiving page + original token.
    // It neither reloads policy nor admits private data or a new operation.
    pub(crate) fn cleanup_epoch(&self,actual:Owner,expected_owner:&str,expected_epoch:&str)->Result<Epoch,Refusal> {
        let token=wire::parse_uuid(expected_owner).ok_or(Refusal::StaleOwner)?;
        let pages=self.pages.lock().unwrap();let page=pages.current.as_ref().ok_or(Refusal::StaleOwner)?;
        if pages.closed || page.owner!=actual || page.token!=token { return Err(Refusal::StaleOwner); }
        let epoch=wire::parse_epoch(expected_epoch)?;
        if epoch.generation==0 || epoch.boot!=self.controller.epoch().boot { return Err(Refusal::StaleEpoch); }
        Ok(epoch)
    }
    pub(crate) fn close_mailbox(&self,resources:&super::resources::Resources,actual:Owner,expected_owner:&str,expected_epoch:&str,ticket:&[u8;32])->Result<(),Refusal> {
        let epoch=self.cleanup_epoch(actual,expected_owner,expected_epoch)?;
        let mut tag=zeroize::Zeroizing::new(vec![0]);tag.extend_from_slice(ticket);
        resources.cancel_one(actual,epoch,&tag);Ok(())
    }
    pub(crate) fn abandon(&self,owner:Owner) {
        let page=self.pages.lock().unwrap().current.clone();
        if let Some(page)=page.filter(|page|page.owner==owner) { page.open.store(false,Ordering::Release); }
        self.controller.unavailable(owner);
    }
    pub(crate) fn receiver(&self,actual:Owner,expected_owner:&str)->Result<BoundReceiver,Refusal> {
        let token=wire::parse_uuid(expected_owner).ok_or(Refusal::StaleOwner)?;
        let page=self.pages.lock().unwrap().current.clone().ok_or(Refusal::StaleOwner)?;
        if page.owner!=actual || page.token!=token { return Err(Refusal::StaleOwner); }
        let bound=BoundReceiver { page,controller:self.controller.clone(),policy:self.policy.clone() };
        bound.require_open()?;Ok(bound)
    }
    // `presentation` is the one complete atomic controller snapshot received by
    // NativeProtection, never a mixture of phase/policy/epoch getters.
    pub(crate) fn envelope(&self,actual:Owner,expected_owner:&str,presentation:crate::desktop_lock::controller::Presentation)->Result<DesktopEnvelope,Refusal> {
        let bound=self.receiver(actual,expected_owner)?;
        if presentation.owner!=Some(actual) { return Err(Refusal::StaleOwner); }
        let result=DesktopEnvelope::new(bound.page.token,presentation.revision,presentation,self.capability);
        bound.require_open()?;Ok(result)
    }
    pub(crate) fn event(&self,presentation:crate::desktop_lock::controller::Presentation)->Option<DesktopEnvelope> {
        let page=self.pages.lock().unwrap().current.clone()?;
        if presentation.owner.is_some_and(|owner|owner!=page.owner) { return None; }
        Some(DesktopEnvelope::new(page.token,presentation.revision,presentation,self.capability))
    }

}
impl BoundReceiver {
    fn require_open(&self)->Result<(),Refusal> {
        if !self.page.open.load(Ordering::Acquire) { return Err(Refusal::StaleOwner); }
        if !self.policy.current() {
            if self.page.open.swap(false,Ordering::AcqRel) { self.controller.lifecycle(self.page.owner,Event::Destroyed); }
            return Err(Refusal::PolicyUnreadable);
        }
        Ok(())
    }
    pub(crate) fn private(self,expected_epoch:&str)->Result<PrivateCall,Refusal> {
        self.require_open()?;let epoch=wire::parse_epoch(expected_epoch)?;
        let lease=self.controller.capture(self.page.owner,epoch)?;
        self.require_open()?;Ok(PrivateCall { scope:PrivateScope { bound:self,lease,epoch } })
    }
    pub(crate) fn check(&self,expected_epoch:&str)->Result<(),Refusal> {
        self.require_open()?;self.controller.capture(self.page.owner,wire::parse_epoch(expected_epoch)?)?;self.require_open()
    }
    pub(crate) fn activate(&self,expected_epoch:&str)->Result<(),Refusal> {
        self.require_open()?;self.controller.activate(self.page.owner,wire::parse_epoch(expected_epoch)?)?;self.require_open()
    }
    pub(crate) fn lock(&self,expected_epoch:&str)->Result<(),Refusal> {
        self.require_open()?;self.controller.lock_for(self.page.owner,wire::parse_epoch(expected_epoch)?)?;self.require_open()
    }
    pub(crate) fn release(&self) {
        if self.page.open.swap(false,Ordering::AcqRel) { self.controller.lifecycle(self.page.owner,Event::Destroyed); }
    }
    pub(crate) fn owner(&self)->Owner { self.page.owner }
    pub(crate) fn current_epoch(&self,expected:&str)->Result<Epoch,Refusal> {
        self.require_open()?;let epoch=wire::parse_epoch(expected)?;
        // Public control admission does not require private Activated state.
        // The controller still verifies exact owner/epoch for each mutation.
        if self.controller.epoch()!=epoch { return Err(Refusal::StaleEpoch); }
        Ok(epoch)
    }
}
impl PrivateScope {
    pub(crate) fn owner_token(&self)->String { wire::uuid(self.bound.page.token) }
    // Called by the receiving command after its worker future resumes. The
    // worker's own completion check does not authorize a later IPC publication.
    pub(crate) fn publish_result(&self, result: Result<zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<String>>) -> Result<Vec<u8>, String> {
        self.check().map_err(|error| super::commands::failure(error).to_owned())?;
        let mut bytes=result.map_err(|error|error.to_string())?;
        Ok(std::mem::take(&mut *bytes))
    }

    pub(crate) fn account_generation(&self) -> Result<u64, Refusal> {
        self.check()?;
        Ok(self.lease.account_generation())
    }
    pub(crate) fn choice_anchor(&self) -> Result<ChoiceAnchor, Refusal> {
        self.check()?;Ok(ChoiceAnchor { bound: self.bound.clone(), lease: self.lease })
    }
    pub(crate) fn check(&self)->Result<(),Refusal> { self.bound.require_open()?;self.bound.controller.check(self.lease)?;self.bound.require_open() }
    pub(crate) fn owner(&self)->Owner { self.bound.page.owner }
    pub(crate) fn epoch(&self)->Epoch { self.epoch }
}
impl PrivateCall {
    pub(crate) fn scope(&self)->PrivateScope { self.scope.clone() }
    pub(crate) fn check(&self)->Result<(),Refusal> { self.scope.check() }
    // Invoke only AFTER the real Core/policy operation lock is acquired. Never
    // replay a mutation, and never publish stale bytes or private error text.
    pub(crate) fn execute(self,operation:impl FnOnce()->Result<Vec<u8>,String>)->Result<Vec<u8>,PrivateFailure> {
        self.execute_checked(|_|operation())
    }
    pub(crate) fn execute_checked(self,operation:impl FnOnce(&Self)->Result<Vec<u8>,String>)->Result<Vec<u8>,PrivateFailure> {
        self.check().map_err(PrivateFailure::Admission)?;
        let mut result=operation(&self);
        if let Err(error)=self.check() {
            match &mut result { Ok(bytes)=>bytes.zeroize(),Err(error)=>error.zeroize() }
            return Err(PrivateFailure::Admission(error));
        }
        result.map_err(PrivateFailure::Operation)
    }
}

// This capability can only remove a captured account's finite legacy keys. It
// cannot invoke Core, read storage, publish bytes, or adopt another page/epoch.
#[derive(Clone)]
pub(crate) struct RetiredCleanup { bound: BoundReceiver, epoch: Epoch }
impl RetiredCleanup {
    pub(crate) fn check(&self) -> Result<(), Refusal> {
        self.bound.require_open()?;
        if self.bound.controller.epoch() != self.epoch { return Err(Refusal::StaleEpoch); }
        self.bound.require_open()
    }
    pub(crate) fn owner(&self) -> Owner { self.bound.page.owner }
}
impl PrivateScope {
    pub(crate) fn retired_cleanup(&self, epoch: Epoch) -> RetiredCleanup {
        RetiredCleanup { bound: self.bound.clone(), epoch }
    }
}

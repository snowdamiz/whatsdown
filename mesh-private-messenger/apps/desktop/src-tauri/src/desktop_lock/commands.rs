//! Actual Tauri receiving-Webview command adapter; no cached JS authority.
use super::controller::{Controller,Intent,Owner,Refusal};
use super::bootstrap::Bootstrap;
use super::native_policy::NativePolicyStore;
use super::native_protection::NativeProtection;
use super::receiver_scope::{BoundReceiver,MainThread,PrivateCall,ReceiverScopes};
use super::wire::{self,Capability,DesktopEnvelope};
use serde::Serialize;
use std::sync::{Arc,atomic::{AtomicU64,Ordering}};
use tauri::{ipc::Request,Emitter,WebviewWindow};

pub(crate) struct Ready {
    pub(crate) controller:Arc<Controller>,
    pub(crate) native:Arc<NativeProtection>,
    scopes:ReceiverScopes,
    next_generation:Arc<AtomicU64>,
}
impl Ready {
    // Caller retains the *same* anchored policy context passed to Controller.
    // Bootstrap must attach the native cover before publishing/showing the page.
    pub(crate) fn new(controller:Arc<Controller>,native:Arc<NativeProtection>,policy:Arc<NativePolicyStore>,capability:Capability,generation:Arc<AtomicU64>)->Self {
        Self { scopes:ReceiverScopes::new(controller.clone(),policy,capability),controller,native,next_generation:generation }
    }
    pub(crate) fn publish(&self,app:&tauri::AppHandle,presentation:super::controller::Presentation) {
        if let Some(envelope)=self.scopes.event(presentation) { let _=app.emit("app-lock-changed",envelope); }
    }
    pub(crate) fn retire_page(&self,owner:Owner) { self.scopes.abandon(owner); }
    pub(crate) fn close(&self) { self.scopes.close(); }
    pub(crate) fn fail_current(&self) {
        if let Some(owner)=self.native.latest().and_then(|snapshot|snapshot.owner) { self.scopes.abandon(owner); }
    }
    fn next_page(&self)->Result<u64,Refusal> {
        self.next_generation.try_update(Ordering::AcqRel,Ordering::Acquire,|value|value.checked_add(1))
            .map(|previous|previous+1).map_err(|_|Refusal::Exhausted)
    }
    pub(crate) fn cleanup_epoch(&self,actual:Owner,owner:&str,epoch:&str)->Result<super::controller::Epoch,Refusal> {
        self.scopes.cleanup_epoch(actual,owner,epoch)
    }
    fn bound(&self,actual:Owner,owner:&str)->Result<BoundReceiver,Refusal> { self.scopes.receiver(actual,owner) }
    fn snapshot(&self,actual:Owner,owner:&str)->Result<DesktopEnvelope,Refusal> {
        self.scopes.envelope(actual,owner,self.native.latest().ok_or(Refusal::Booting)?)
    }
}
pub(crate) fn failure(value:Refusal)->&'static str {
    match value { Refusal::StaleOwner=>"app_lock_stale_owner",Refusal::StaleEpoch=>"app_lock_stale_epoch",
        Refusal::Locked=>"app_lock_locked",Refusal::Cancelled=>"app_lock_cancelled",Refusal::TimedOut=>"app_lock_expired",
        Refusal::Busy=>"app_lock_busy",Refusal::Booting=>"app_lock_booting",_=>"app_lock_unavailable" }
}
fn owner_header(request:&Request<'_>)->Result<String,&'static str> {
    request.headers().get("X-Morse-Lock-Owner").and_then(|value|value.to_str().ok())
        .map(str::to_owned).ok_or("app_lock_stale_owner")
}
fn epoch_header(request:&Request<'_>)->Result<String,&'static str> {
    request.headers().get("X-Morse-Lock-Epoch").and_then(|value|value.to_str().ok())
        .map(str::to_owned).ok_or("app_lock_stale_epoch")
}
pub(crate) async fn receiving<T:Send+'static>(webview:WebviewWindow,ready:Arc<Ready>,body:impl FnOnce(Arc<Ready>,Owner)->Result<T,Refusal>+Send+'static)->Result<T,&'static str> {
    // Navigation policy is also installed on the native primary webview. This
    // boundary additionally refuses a command from any non-app document.
    if !crate::navigation::allowed(&webview.url().map_err(|_|"app_lock_stale_owner")?) { return Err("app_lock_stale_owner"); }
    let (send,mut receive)=tauri::async_runtime::channel(1);
    webview.with_webview(move |platform| {
        let result=(|| {
            MainThread::current()?;
            let actual=unsafe { ready.native.receiver(platform.ns_window(),platform.inner()) }?;
            body(ready,actual)
        })();
        let _=send.try_send(result);
    }).map_err(|_|"app_lock_stale_owner")?;
    receive.recv().await.ok_or("app_lock_stale_owner")?.map_err(failure)
}
#[tauri::command]
pub(crate) async fn app_lock_bind(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<DesktopEnvelope,&'static str> {
    let document=state.documents.capture(crate::header(&request,"X-Morse-Document").ok_or("app_lock_stale_owner")?).map_err(failure)?;
    let ready=state.ready().await?;
    document.check().map_err(failure)?;
    // Receiver validation precedes rebind. A secondary/remote webview cannot
    // nominate itself as the protected primary by calling this public command.
    if !crate::navigation::allowed(&webview.url().map_err(|_|"app_lock_stale_owner")?) { return Err("app_lock_stale_owner"); }
    let (send,mut receive)=tauri::async_runtime::channel(1);
    let failed_window=webview.clone();
    webview.with_webview(move |platform| {
        let result=(|| {
            let main=MainThread::current()?;
            document.check()?;
            let old=unsafe { ready.native.receiver(platform.ns_window(),platform.inner()) }?;
            let actual=Owner { window:old.window,webview:ready.next_page()? };
            let installed=ready.scopes.install(&main,actual);
            // Old work is already retired before native attachment can reenter.
            if let Err(error)=unsafe { ready.native.attach(platform.ns_window(),platform.inner(),actual) } {
                ready.scopes.abandon(actual);
                let _=failed_window.hide();
                return Err(error);
            }
            // Even a failed preparation gets a reachable native Error cover.
            // Successful rebind reloads real durable truth, never cached Disabled.
            if installed.is_ok() { ready.controller.refresh_policy(); }
            ready.native.refresh_foreground_on_main(actual);
            let owner=installed?;
            ready.snapshot(actual,&owner)
        })();let _=send.try_send(result);
    }).map_err(|_|"app_lock_stale_owner")?;
    receive.recv().await.ok_or("app_lock_stale_owner")?.map_err(failure)
}
#[tauri::command]
pub(crate) async fn app_lock_state(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<DesktopEnvelope,&'static str> {
    let owner=owner_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual|ready.snapshot(actual,&owner)).await
}
#[tauri::command]
pub(crate) async fn app_lock_check(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<(),&'static str> {
    let owner=owner_header(&request)?;let epoch=epoch_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual|ready.bound(actual,&owner)?.check(&epoch)).await
}
#[tauri::command]
pub(crate) async fn app_lock_activate(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<(),&'static str> {
    let owner=owner_header(&request)?;let epoch=epoch_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual|ready.bound(actual,&owner)?.activate(&epoch)).await
}
#[tauri::command]
pub(crate) async fn app_lock_lock(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<(),&'static str> {
    let owner=owner_header(&request)?;let epoch=epoch_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual|ready.bound(actual,&owner)?.lock(&epoch)).await
}
#[derive(Serialize)]
pub(crate) struct Started { kind:&'static str }
#[tauri::command]
pub(crate) async fn app_lock_set_enabled(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>,enabled:bool)->Result<Started,&'static str> {
    let owner=owner_header(&request)?;let epoch=epoch_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual| {
        let bound=ready.bound(actual,&owner)?;let epoch=bound.current_epoch(&epoch)?;
        ready.controller.request(bound.owner(),epoch,if enabled { Intent::Enable } else { Intent::Disable })?;
        Ok(Started { kind:"started" })
    }).await
}
#[tauri::command]
pub(crate) async fn app_lock_cancel(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,ipc:Request<'_>,request:String)->Result<(),&'static str> {
    let owner=owner_header(&ipc)?;let challenge=request;
    receiving(webview,state.ready().await?,move |ready,actual| {
        let bound=ready.bound(actual,&owner)?;
        let parsed=wire::parse_epoch(&challenge)?;
        if parsed.generation==0 || parsed.boot!=ready.controller.epoch().boot { return Err(Refusal::Cancelled); }
        let snapshot=ready.native.latest().ok_or(Refusal::Booting)?;
        if let Some(id)=snapshot.request {
            if wire::request(id)!=challenge { return Err(Refusal::Cancelled); }
            ready.controller.cancel(bound.owner(),id);
        }
        Ok(())
    }).await
}
#[tauri::command]
pub(crate) async fn app_lock_release(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<(),&'static str> {
    let owner=owner_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual| { ready.bound(actual,&owner)?.release();Ok(()) }).await
}
#[derive(serde::Deserialize)]
#[serde(rename_all="camelCase")]
pub(crate) enum WindowAction { Minimize, ToggleMaximize, Close, StartDragging }
#[tauri::command]
pub(crate) async fn app_lock_copy_text(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>,text:String)->Result<(),&'static str> {
    let text=zeroize::Zeroizing::new(text);
    if text.len()>1_048_576 { return Err("invalid_clipboard_text"); }
    let ready=state.ready().await?;
    let call=private_call(webview.clone(),ready.clone(),&request).await?;
    // Capture before the second native-main dispatch, then check again at
    // actual execution. A later page cannot repair/retarget this held call.
    receiving(webview,ready,move |ready,actual| {
        if call.scope().owner()!=actual { return Err(Refusal::StaleOwner); }
        call.check()?;
        ready.native.copy_text_on_main(call.scope(),&text)
    }).await
}
#[tauri::command]
pub(crate) async fn app_lock_window_action(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>,action:WindowAction)->Result<(),&'static str> {
    let owner=owner_header(&request)?;let epoch=epoch_header(&request)?;
    receiving(webview,state.ready().await?,move |ready,actual| {
        let call=ready.bound(actual,&owner)?.private(&epoch)?;
        call.check()?;
        let snapshot=ready.native.latest().ok_or(Refusal::Booting)?;
        if snapshot.owner!=Some(actual) || !snapshot.uncover { return Err(Refusal::Locked); }
        let action=match action { WindowAction::Minimize=>0,WindowAction::ToggleMaximize=>1,WindowAction::Close=>2,WindowAction::StartDragging=>3 };
        // The native main-thread operation checks this same receipt before UI
        // mutation. Close/minimize may themselves retire the caller's epoch;
        // no private result is published by this finite chrome command.
        ready.native.window_action_on_main(actual,snapshot.revision,action)
    }).await
}
#[tauri::command]
pub(crate) async fn app_lock_close_mailbox(webview:WebviewWindow,state:tauri::State<'_,Arc<Bootstrap>>,request:Request<'_>)->Result<(),&'static str> {
    let owner=owner_header(&request)?;let epoch=epoch_header(&request)?;
    let bytes=zeroize::Zeroizing::new(crate::request::bounded_binary_body(request.body(),32,32,"invalid_mailbox_ticket").map_err(|_|"invalid_mailbox_ticket")?);
    let ticket=zeroize::Zeroizing::new(<[u8;32]>::try_from(bytes.as_slice()).map_err(|_|"invalid_mailbox_ticket")?);
    let resources=state.resources.clone();
    receiving(webview,state.ready().await?,move |ready,actual| {
        ready.scopes.close_mailbox(&resources,actual,&owner,&epoch,&ticket)
    }).await
}
// Existing private handlers call this before queueing, then PrivateCall.execute
// only after acquiring the real Core operation lock. Captured calls never look
// up/retarget a global latest owner during operation start or completion.
pub(crate) async fn private_call(webview:WebviewWindow,ready:Arc<Ready>,request:&Request<'_>)->Result<PrivateCall,&'static str> {
    let owner=owner_header(request)?;let epoch=epoch_header(request)?;
    receiving(webview,ready,move |ready,actual|ready.bound(actual,&owner)?.private(&epoch)).await
}

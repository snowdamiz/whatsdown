//! Historical WK migration only. Native database and fresh Core identity select
//! the key; request metadata never supplies a storage key, script or path.
use super::{bootstrap::Bootstrap,commands,controller::Refusal,legacy_profile::{LegacyKind,ProfileIdentity},receiver_scope::PrivateScope};
use crate::{Desktop,mesh,request};
use std::sync::{Arc,Mutex};
use tauri::{ipc::Request,State,WebviewWindow};
use zeroize::Zeroizing;

fn current_account(core:&Mutex<mesh::Mesh>,scope:&PrivateScope,database:&str,expected:ProfileIdentity)->Result<(),String> {
    let library=core.lock().map_err(|_|"native_lock_failed")?;
    scope.check().map_err(|value|commands::failure(value).to_owned())?;
    // Keep Core error details private and retain the real operation lock through
    // both the load and its admission check. The result is copied only to the
    // strict identity parser and wiped on every outcome.
    let loaded=library.invoke("mesh_messenger_load_profile",database.as_bytes(),database)
        .map(Zeroizing::new).map_err(Zeroizing::new);
    scope.check().map_err(|value|commands::failure(value).to_owned())?;
    let loaded=loaded.map_err(|_|"account_state_changed")?;
    if ProfileIdentity::parse(&loaded).map_err(|_|"account_state_changed")?!=expected { return Err("account_state_changed".to_owned()); }
    Ok(())
}
#[tauri::command]
pub(crate) async fn app_lock_legacy_preference(webview:WebviewWindow,boot:State<'_,Arc<Bootstrap>>,state:State<'_,Desktop>,request:Request<'_>)->Result<Option<String>,String> {
    let read=match crate::header(&request,"X-Morse-Legacy-Operation") { Some("read")=>true,Some("remove")=>false,_=>return Err("invalid_legacy_operation".to_owned()) };
    let kind=LegacyKind::parse(crate::header(&request,"X-Morse-Legacy-Kind").ok_or("invalid_legacy_kind")?).map_err(str::to_owned)?;
    let profile=Zeroizing::new(request::bounded_binary_body(request.body(),0,36134,"invalid_profile")?);
    let expected=ProfileIdentity::parse(&profile).map_err(str::to_owned)?;
    let ready=boot.ready().await.map_err(str::to_owned)?;
    let call=commands::private_call(webview.clone(),ready.clone(),&request).await.map_err(str::to_owned)?;
    let database=state.database.clone();let mesh=state.mesh.clone();
    let before={let scope=call.scope();let path=database.clone();let core=mesh.clone();
        tauri::async_runtime::spawn_blocking(move || current_account(&core,&scope,&path,expected)).await};
    call.check().map_err(|value|commands::failure(value).to_owned())?;
    before.map_err(|_|"native_task_failed")??;
    let key=Zeroizing::new(expected.legacy_key(&database,kind).map_err(str::to_owned)?);
    let scope=call.scope();
    let mut pending=commands::receiving(webview,ready,move |ready,actual| {
        if scope.owner()!=actual { return Err(Refusal::StaleOwner); }
        scope.check()?;ready.native.start_legacy_on_main(scope,&key,read)
    }).await.map_err(str::to_owned)?;
    let returned=pending.recv().await;
    call.check().map_err(|value|commands::failure(value).to_owned())?;
    let returned=returned.ok_or("legacy_storage_unavailable")?;
    let after={let scope=call.scope();let path=database.clone();let core=mesh.clone();
        tauri::async_runtime::spawn_blocking(move || current_account(&core,&scope,&path,expected)).await};
    call.check().map_err(|value|commands::failure(value).to_owned())?;
    after.map_err(|_|"native_task_failed")??;
    // Every result/error above is fixed or admission-masked. The only private
    // publication is the bounded WK value after both original-scope and fresh
    // account comparisons; Raw reply ownership wipes on every early return.
    match (read,returned.status) {
        (true,0)=>{
            let text=Zeroizing::new(std::str::from_utf8(&returned.bytes).map_err(|_|"invalid_legacy_reply")?.to_owned());
            call.check().map_err(|value|commands::failure(value).to_owned())?;
            Ok(Some(text.to_string()))
        },
        (true,1)|(false,2)=>Ok(None),
        (_,3)=>Err("app_lock_cancelled".to_owned()),
        _=>Err("legacy_storage_unavailable".to_owned()),
    }
}


struct LegacyRemoval {
    identity: ProfileIdentity,
    account: u64,
    keys: Vec<Zeroizing<String>>,
}
#[derive(Default)]
pub(crate) struct LegacyRemovals(Mutex<Option<Arc<LegacyRemoval>>>);
impl LegacyRemovals {
    // One Core writer owns this finite obligation. Every later Core command
    // drains it before mutation, so another erasure cannot overwrite it.
    pub(crate) fn capture(&self, identity:ProfileIdentity, account:u64, database:&str) -> Result<(),String> {
        let mut keys=Vec::new();
        for kind in [LegacyKind::ReadState,LegacyKind::NotificationState,LegacyKind::ReceiptMarks,LegacyKind::ReadReceipts,LegacyKind::NotificationPreview] {
            keys.push(Zeroizing::new(identity.legacy_key(database,kind)?));
        }
        keys.push(Zeroizing::new(identity.notification_key(database)?));
        let mut pending=self.0.lock().unwrap();
        if pending.is_some() { return Err("legacy_cleanup_pending".to_owned()); }
        *pending=Some(Arc::new(LegacyRemoval { identity,account,keys }));Ok(())
    }
    pub(crate) fn drain(&self, library:&mesh::Mesh, controller:&super::controller::Controller,
        scope:&PrivateScope, database:&str,
        mut remove:impl FnMut(super::receiver_scope::RetiredCleanup,&str)->Result<(),String>) -> Result<(),String> {
        let pending=self.0.lock().unwrap().clone();
        let Some(pending)=pending else { return Ok(()); };
        // Native identity/generation, never caller metadata, decides whether a
        // restored account owns these keys again. No old job may delete them.
        let identity=super::private_commands::identity(library,database)?;
        if controller.account_generation()!=pending.account || identity.is_some_and(|current|current.same_account(pending.identity)) {
            self.finish(&pending);return Ok(());
        }
        let cleanup=scope.retired_cleanup(pending.account);
        for key in &pending.keys { cleanup.check().map_err(commands::failure)?;remove(cleanup.clone(),key)?; }
        cleanup.check().map_err(commands::failure)?;
        self.finish(&pending);Ok(())
    }
    fn finish(&self, completed:&Arc<LegacyRemoval>) {
        let mut pending=self.0.lock().unwrap();
        if pending.as_ref().is_some_and(|current|Arc::ptr_eq(current,completed)) { pending.take(); }
    }
}
// The Core worker holds Core's mutex while WebKit removes these exact keys.
// On page replacement/error the obligation stays in Bootstrap for the next
// receiving page. There is no JS cleanup command or private-data capability.
pub(crate) fn remove_legacy_key(native: &Arc<super::native_protection::NativeProtection>,
    scope: super::receiver_scope::RetiredCleanup, key:&str) -> Result<(),String> {
    let native=native.clone();let captured=scope.clone();let key=Zeroizing::new(key.to_owned());
    let (send,receive)=std::sync::mpsc::sync_channel(1);
    super::native_protection::NativeProtection::defer_main(move || {
        let _=send.send(native.forget_legacy_on_main(captured,&key));
    });
    let mut pending=receive.recv().map_err(|_|"legacy_storage_unavailable")?.map_err(commands::failure)?;
    let reply=tauri::async_runtime::block_on(pending.recv());
    scope.check().map_err(commands::failure)?;
    if reply.is_none_or(|reply|reply.status!=2) { return Err("legacy_storage_unavailable".to_owned()); }
    Ok(())
}

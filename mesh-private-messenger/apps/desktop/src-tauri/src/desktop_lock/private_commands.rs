//! Actual macOS receiving-page handlers. Existing non-macOS handlers are separate.
use super::{bootstrap::Bootstrap, commands, private_wallet, receiver_scope::{PrivateCall, PrivateFailure}};
use crate::{bounty, mesh, request, wallet, Desktop};
use std::sync::{Arc, Mutex};
use tauri::{ipc::{Request, Response}, State, WebviewWindow};
use zeroize::Zeroizing;

fn failure(error: PrivateFailure) -> String {
    match error { PrivateFailure::Admission(error)=>commands::failure(error).to_owned(), PrivateFailure::Operation(error)=>error }
}
fn check(call: &PrivateCall) -> Result<(), String> { call.check().map_err(|error|commands::failure(error).to_owned()) }
fn core(mesh: &Mutex<mesh::Mesh>, call: &PrivateCall, symbol: &str, body: &[u8], database: &str) -> Result<Vec<u8>, String> {
    let core=mesh.lock().map_err(|_| "native_lock_failed")?;
    check(call)?;core.invoke(symbol, body, database)
}
fn counted(values: &[&[u8]]) -> Vec<u8> {
    let mut result=(values.len() as u32).to_be_bytes().to_vec();
    for value in values { result.extend_from_slice(&(value.len() as u32).to_be_bytes());result.extend_from_slice(value); } result
}
fn stream_tag(ticket: &[u8]) -> Vec<u8> { let mut tag=vec![0];tag.extend_from_slice(ticket);tag }
fn stream_close_ticket<'a>(body: &'a [u8], database: &str) -> Option<&'a [u8]> {
    let prefix=counted(&[database.as_bytes()]);
    // The count differs; the first path vector must otherwise be byte exact.
    if body.get(..4)? != 2u32.to_be_bytes() || body.get(4..prefix.len())? != &prefix[4..] { return None; }
    let suffix=body.get(prefix.len()..)?;
    if suffix.len()!=36 || suffix[..4]!=32u32.to_be_bytes() { return None; } Some(&suffix[4..])
}

#[tauri::command]
pub(crate) async fn database_path(webview: WebviewWindow, boot: State<'_, Arc<Bootstrap>>, state: State<'_, Desktop>, request: Request<'_>) -> Result<String, String> {
    let call=commands::private_call(webview, boot.ready().await.map_err(str::to_owned)?, &request).await.map_err(str::to_owned)?;
    let database=state.database.clone();
    let bytes=call.execute(|| Ok(database.into_bytes())).map_err(failure)?;
    String::from_utf8(bytes).map_err(|_| "invalid_database_path".to_owned())
}

#[tauri::command]
pub(crate) async fn mesh_invoke(webview: WebviewWindow, boot: State<'_, Arc<Bootstrap>>, state: State<'_, Desktop>, request: Request<'_>) -> Result<Response, String> {
    let symbol=crate::header(&request, "X-Mesh-Symbol").ok_or("invalid_native_request")?.to_owned();
    let body=Zeroizing::new(request::bounded_binary_body(request.body(), 0, request::maximum_request(&symbol), "invalid_native_request")?);
    request::validate_scoped(&symbol, &body, state.database.as_bytes())?;
    let ready=boot.ready().await.map_err(str::to_owned)?;
    let call=commands::private_call(webview, ready.clone(), &request).await.map_err(str::to_owned)?;
    let mesh=state.mesh.clone();let database=state.database.clone();let resources=boot.resources.clone();
    let boot=boot.inner().clone();
    let purpose=state.config.credit_purpose.clone();let mint=state.config.credit_usdc_mint_hex.clone();
    let directory=state.data.clone();let identifier=state.app_identifier.clone();
    let completion_scope=call.scope();
    let result=tauri::async_runtime::spawn_blocking(move || {
        call.execute_checked(|call| {
            if matches!(symbol.as_str(), "mesh_messenger_transparency_fork"|"mesh_messenger_fork_filing") {
                return bounty::invoke_proof(&symbol, database.as_bytes(),
                    |name, frame|core(&mesh, call, name, frame, &database),
                    |operation, payload| {
                        let pins=wallet::pins(&purpose, &mint)?;let service=format!("{identifier}.wallet.v1.{}",pins[1]);
                        private_wallet::invoke(&ready.native,call.scope(),&service,&directory.join(format!("MorseWallet-v1-{}",pins[1])),&pins,operation,payload)
                    });
            }
            let library=mesh.lock().map_err(|_| "native_lock_failed")?;
            check(call)?;
            boot.legacy_removals.drain(&library,&ready.controller,&call.scope(),&database,
                |scope,key|super::legacy_commands::remove_legacy_key(&ready.native,scope,key))?;
            if matches!(symbol.as_str(), "mesh_messenger_mailbox_stream_poll" | "mesh_messenger_mailbox_stream_close") {
                let ticket=stream_close_ticket(&body, &database).ok_or("invalid_mailbox_ticket")?;
                if !resources.owns(call.scope().owner(),call.scope().epoch(),&stream_tag(ticket)) {
                    return Err("app_lock_stale_epoch".to_owned());
                }
            }
            let mut bytes=invoke_identity_transition(&library,&ready.controller,&symbol,&body,&database,|identity,account| {
                boot.legacy_removals.capture(identity,account,&database)?;
                // Failure preserves the obligation; this original private call
                // still refuses. A successor page retries before any Core use.
                boot.legacy_removals.drain(&library,&ready.controller,&call.scope(),&database,
                    |scope,key|super::legacy_commands::remove_legacy_key(&ready.native,scope,key))
            })?;
            if symbol=="mesh_messenger_mailbox_stream_open" {
                if bytes.len()!=32 { use zeroize::Zeroize;bytes.zeroize();return Err("invalid_native_response".to_owned()); }
                let ticket=Zeroizing::new(bytes.to_vec());let tag=stream_tag(&bytes);let mesh=mesh.clone();let path=database.clone();
                resources.register(call.scope().owner(),call.scope().epoch(),tag,Box::new(move || {
                    // Revocation never waits on the Core mutex. Only the exact
                    // already-issued ticket is closed; this grants no read.
                    tauri::async_runtime::spawn_blocking(move || {
                        let frame=Zeroizing::new(counted(&[path.as_bytes(),&ticket]));
                        if let Ok(core)=mesh.lock() { let _=core.invoke("mesh_messenger_mailbox_stream_close", &frame, &path); }
                    });
                })).map_err(|error| commands::failure(error).to_owned())?;
            } else if symbol=="mesh_messenger_mailbox_stream_close" {
                if let Some(ticket)=stream_close_ticket(&body,&database) {
                    let tag=Zeroizing::new(stream_tag(ticket));resources.forget(call.scope().owner(),call.scope().epoch(),&tag);
                }
            }
            Ok(std::mem::take(&mut *bytes))
        }).map(Zeroizing::new).map_err(|error|Zeroizing::new(failure(error)))
    }).await;
    completion_scope.check().map_err(|error|commands::failure(error).to_owned())?;
    completion_scope.publish_result(result.map_err(|_|"native_task_failed")?).map(Response::new)
}

#[tauri::command]
pub(crate) async fn wallet_invoke(webview: WebviewWindow, boot: State<'_, Arc<Bootstrap>>, state: State<'_, Desktop>, request: Request<'_>) -> Result<Response, String> {
    let operation=crate::header(&request,"X-Wallet-Operation").ok_or("invalid_wallet_request")?.parse::<u32>().map_err(|_| "invalid_wallet_request")?;
    let body=Zeroizing::new(crate::raw_body(&request,"invalid_wallet_request")?);
    let pins=if operation==7 && body.as_slice()==[0] { None } else { Some(wallet::pins(&state.config.credit_purpose,&state.config.credit_usdc_mint_hex)?) };
    let ready=boot.ready().await.map_err(str::to_owned)?;
    let call=commands::private_call(webview,ready.clone(),&request).await.map_err(str::to_owned)?;
    let mesh=state.mesh.clone();let database=state.database.clone();let purpose=pins.as_ref().map(|value|value[1]).unwrap_or(0);
    let directory=state.data.join(format!("MorseWallet-v1-{purpose}"));let service=format!("{}.wallet.v1.{purpose}",state.app_identifier);
    let completion_scope=call.scope();
    let result=tauri::async_runtime::spawn_blocking(move || call.execute_checked(|call| {
        let mut sdk=|operation,payload:&[u8]| private_wallet::invoke(&ready.native,call.scope(),&service,&directory,pins.as_ref().ok_or("wallet_pins_missing")?,operation,payload);
        if operation==7 {
            if body.len()!=1 { return Err("invalid_wallet_request".to_owned()); }
            return bounty::set_enabled(database.as_bytes(),body[0],|name,frame|core(&mesh,call,name,frame,&database),&mut sdk);
        }
        if operation==8 { return bounty::movement(&body,database.as_bytes(),|name,frame|core(&mesh,call,name,frame,&database),&mut sdk); }
        if matches!(operation,5|6) { return wallet::network_payment(operation,&body,database.as_bytes(),|name,frame|core(&mesh,call,name,frame,&database),&mut sdk); }
        if matches!(operation,3|4) { return Err("invalid_wallet_request".to_owned()); }
        sdk(operation,&wallet::payload(operation,&body)?)
    }).map(Zeroizing::new).map_err(|error|Zeroizing::new(failure(error)))).await;
    completion_scope.check().map_err(|error|commands::failure(error).to_owned())?;
    completion_scope.publish_result(result.map_err(|_|"wallet_worker_failed")?).map(Response::new)
}

pub(super) fn identity(library: &mesh::Mesh, database: &str) -> Result<Option<super::legacy_profile::ProfileIdentity>, String> {
    match library.invoke("mesh_messenger_load_profile",database.as_bytes(),database).map(Zeroizing::new).map_err(Zeroizing::new) {
        Ok(bytes) => super::legacy_profile::ProfileIdentity::parse(&bytes).map(Some).map_err(str::to_owned),
        Err(error) if error.as_str() == "Mesh 9: local_state_not_found" => Ok(None),
        Err(_) => Err("account_state_unavailable".to_owned()),
    }
}

#[tauri::command]
pub(crate) async fn credit_open_payment(webview: WebviewWindow, boot: State<'_, Arc<Bootstrap>>, state: State<'_, Desktop>, request: Request<'_>) -> Result<(), String> {
    let body=Zeroizing::new(crate::raw_body(&request,"invalid_wallet_request")?);
    let ready=boot.ready().await.map_err(str::to_owned)?;
    let call=commands::private_call(webview.clone(),ready.clone(),&request).await.map_err(str::to_owned)?;
    let scope=call.scope(); let mesh=state.mesh.clone(); let database=state.database.clone();
    let result=tauri::async_runtime::spawn_blocking(move || call.execute_checked(|call| {
        let frame=Zeroizing::new(wallet::journal(&body,database.as_bytes())?);
        core(&mesh,call,"mesh_messenger_credit_payment_handoff",&frame,&database)
    }).map(Zeroizing::new).map_err(|error|Zeroizing::new(failure(error)))).await;
    scope.check().map_err(|error|commands::failure(error).to_owned())?;
    let bytes=result.map_err(|_|"native_task_failed")?.map_err(|error|error.to_string())?;
    let url=Zeroizing::new(std::str::from_utf8(&bytes).map_err(|_|"invalid_payment_url")?.to_owned());
    if !wallet::valid_payment_url(&url) { return Err("invalid_payment_url".to_owned()); }
    commands::receiving(webview,ready,move |ready,actual| {
        if scope.owner()!=actual { return Err(super::controller::Refusal::StaleOwner); }
        ready.native.open_payment_on_main(scope,&url)
    }).await.map_err(str::to_owned)
}

fn invoke_identity_transition(library: &mesh::Mesh, controller: &super::controller::Controller, symbol: &str, body: &[u8], database: &str, removed: impl FnOnce(super::legacy_profile::ProfileIdentity, u64) -> Result<(),String>) -> Result<Zeroizing<Vec<u8>>, String> {
    observe_identity_transition(library,controller,symbol,database,||library.invoke(symbol,body,database),removed)
}
fn observe_identity_transition(library: &mesh::Mesh, controller: &super::controller::Controller, symbol: &str, database: &str,
    invoke: impl FnOnce() -> Result<Vec<u8>,String>,
    removed: impl FnOnce(super::legacy_profile::ProfileIdentity, u64) -> Result<(),String>) -> Result<Zeroizing<Vec<u8>>,String> {
    let transition=matches!(symbol, "mesh_messenger_create_account" | "mesh_messenger_create_signup_draft" |
        "mesh_messenger_complete_device_link" | "mesh_messenger_directory_register" | "mesh_messenger_devices_renew" | "mesh_messenger_account_delete" | "mesh_messenger_account_discard" | "mesh_messenger_erase_account");
    let before=if transition { Some(identity(&library,&database)?) } else { None };
    let result=invoke().map(Zeroizing::new).map_err(Zeroizing::new);
    if let Some(before)=before {
        // Mesh decides whether the identity changed. Old private results
        // then refuse; the root remounts and reloads the committed state.
        // Failed/no-op mutations do not manufacture an account transition.
        let after=identity(&library,&database);
        if after.as_ref().map_or(true, |after| *after != before) {
            controller.account_changed();
            if let (Some(identity), Ok(None))=(before,after) { removed(identity,controller.account_generation())?; }
            return Err("app_lock_account_changed".to_owned());
        }
    }
    result.map_err(|error|error.to_string())
}

#[cfg(all(test, feature = "native-boundary-tests"))]
#[path = "tests/account_transition_tests.rs"]
mod tests;

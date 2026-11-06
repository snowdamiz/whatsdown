//! Captured receiving-page file operations. Native chooser URLs never enter IPC.
use super::{
    avatar_import,
    file_reply::FileReply,
    incoming_files::IncomingHandle,
    bootstrap::Bootstrap,
    commands,
    controller::Refusal,
    native_panels::{PanelFailure, SourcePurpose},
    private_backup_choices::{BackupMetadata, BackupPurpose, DiscardBackup},
    private_choices::SelectionMetadata,
    private_exports::ExportContext,
    private_files::{FileError, FileHandle, PrivateFiles, Role},
    receiver_scope::{PrivateCall, PrivateScope},
    wire,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::{
    sync::{atomic::Ordering, Arc},
    time::Instant,
};
use tauri::{
    ipc::{Request, Response},
    State, WebviewWindow,
};
use zeroize::Zeroizing;

fn failure(error: FileError) -> &'static str {
    match error {
        FileError::Admission(v) => commands::failure(v),
        FileError::Changed => "file_changed",
        FileError::Invalid | FileError::Range => "invalid_file_request",
        _ => "file_unavailable",
    }
}
fn admission(error: FileError) -> Refusal {
    match error {
        FileError::Admission(v) => v,
        _ => Refusal::Cancelled,
    }
}
fn check(call: &PrivateCall) -> Result<(), &'static str> {
    call.check().map_err(commands::failure)
}
fn invalid<T>() -> Result<T, &'static str> {
    Err("invalid_file_request")
}
struct Context(Map<String, Value>);
impl Context {
    fn parse(request: &Request<'_>) -> Result<Self, &'static str> {
        let encoded =
            crate::header(request, "X-Morse-File-Metadata").ok_or("invalid_file_request")?;
        if encoded.len() > 32768 {
            return invalid();
        }
        let bytes = Zeroizing::new(
            STANDARD
                .decode(encoded)
                .map_err(|_| "invalid_file_request")?,
        );
        if bytes.len() > 24576 || STANDARD.encode(bytes.as_slice()) != encoded {
            return invalid();
        }
        let value: Value = serde_json::from_slice(&bytes).map_err(|_| "invalid_file_request")?;
        let Value::Object(value) = value else {
            return invalid();
        };
        if value.get("version").and_then(Value::as_u64) != Some(1) {
            return invalid();
        }
        Ok(Self(value))
    }
    fn keys(&self, allowed: &[&str]) -> Result<(), &'static str> {
        if self
            .0
            .keys()
            .any(|key| key != "version" && !allowed.contains(&key.as_str()))
        {
            return invalid();
        }
        Ok(())
    }
    fn text(&self, key: &str, max: usize) -> Result<&str, &'static str> {
        let value = self
            .0
            .get(key)
            .and_then(Value::as_str)
            .ok_or("invalid_file_request")?;
        if value.is_empty() || value.len() > max || value.contains('\0') {
            return invalid();
        }
        Ok(value)
    }
    fn number(&self, key: &str, max: u64) -> Result<u64, &'static str> {
        self.0
            .get(key)
            .and_then(Value::as_u64)
            .filter(|n| *n <= max)
            .ok_or("invalid_file_request")
    }
    fn handle(&self, key: &str) -> Result<FileHandle, &'static str> {
        FileHandle::parse(self.text(key, 36)?).map_err(failure)
    }
    fn purpose(&self) -> Result<&str, &'static str> {
        self.text("purpose", 20)
    }
    fn export(&self) -> Result<ExportContext, &'static str> {
        ExportContext::new(
            self.text("sourceContext", 4096)?,
            self.text("filename", 255)?,
            self.text("mimeType", 127)?,
            self.number("size", 536870912)?,
        )
        .map_err(|_| "invalid_file_request")
    }
}
fn metadata(file: &SelectionMetadata) -> Value {
    json!({"selectionId":file.selection,"filename":file.filename.as_str(),"mimeType":file.mime.as_str(),"size":file.size})
}
fn backup_metadata(value: BackupMetadata) -> Value {
    match value {
        BackupMetadata::Source {
            request,
            choice,
            file,
        } => json!({"version":1,"requestId":request,"choiceId":choice,"files":[metadata(&file)]}),
        BackupMetadata::Destination { request, choice } => {
            json!({"version":1,"requestId":request,"choiceId":choice})
        }
    }
}
fn backup_purpose(value: &str) -> Result<BackupPurpose, &'static str> {
    match value {
        "backup-source" => Ok(BackupPurpose::Source),
        "backup-export" => Ok(BackupPurpose::Export),
        _ => invalid(),
    }
}
fn counter(scope: &PrivateScope, prefix: &str, value: &str) -> Result<(), &'static str> {
    let prefix = format!("{}/{}/", prefix, wire::epoch(scope.epoch()));
    let value = value.strip_prefix(&prefix).ok_or("invalid_file_request")?;
    if value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
        || !value
            .parse::<u64>()
            .ok()
            .is_some_and(|n| n > 0 && n <= 9_007_199_254_740_991)
    {
        return invalid();
    }
    Ok(())
}
async fn work(
    call: &Arc<PrivateCall>,
    body: impl FnOnce(PrivateScope) -> Result<FileReply, FileError> + Send + 'static,
) -> Result<FileReply, &'static str> {
    let scope = call.scope();
    let run = tauri::async_runtime::spawn_blocking(move || {
        scope.check()?;
        body(scope)
    })
    .await;
    check(call)?;
    run.map_err(|_| "file_unavailable")?.map_err(failure)
}
async fn incoming_subscription(webview:WebviewWindow,boot:&Arc<Bootstrap>,call:&Arc<PrivateCall>)->Result<FileReply,&'static str> {
    let scope=call.scope();
    let ticket=boot.incoming.subscribe(scope.clone()).map_err(failure)?;
    let handle=ticket.handle();
    // Guard ownership before any native dispatch/await. Cancellation or a late
    // result retires only this original subscription, including same-epoch JS disposal.
    let reply=FileReply::incoming(boot.incoming.clone(),scope,handle,json!({"version":1,"handle":handle.wire()}));
    let native=boot.native.clone();let wake=boot.incoming_wake();
    let (sender,mut receiver)=tauri::async_runtime::channel(1);
    webview.with_webview(move |platform| {
        let result=(|| {
            let token=unsafe {super::native_incoming::subscribe(native.raw(),platform.ns_window(),platform.inner(),ticket.clone(),wake)}?;
            ticket.install_native(Box::new(move ||drop(token))).map_err(admission)
        })();
        let _=sender.try_send(result);
    }).map_err(|_|"file_unavailable")?;
    let result=receiver.recv().await;
    check(call)?;
    result.ok_or("file_unavailable")?.map_err(commands::failure)?;
    Ok(reply)
}
async fn source_choice(
    webview: WebviewWindow,
    boot: &Arc<Bootstrap>,
    call: &Arc<PrivateCall>,
    purpose: &str,
    request: Option<String>,
) -> Result<FileReply, &'static str> {
    let ready = boot.ready().await?;
    let scope = call.scope();
    let anchor = scope.choice_anchor().map_err(commands::failure)?;
    if purpose == "backup-source" {
        let request = request.ok_or("invalid_file_request")?;
        let request_for_start = request.clone();
        let broker = boot.backups.clone();
        let source_scope = scope.clone();
        let (ticket, mut pending) = commands::receiving(webview, ready, move |ready, actual| {
            if actual != source_scope.owner() {
                return Err(Refusal::StaleOwner);
            }
            let ticket = broker
                .start_source(&source_scope, &request_for_start, Instant::now())
                .map_err(admission)?;
            ticket
                .current(&source_scope, Instant::now())
                .map_err(admission)?;
            let pending = ready
                .native
                .choose_source_on_main(source_scope, SourcePurpose::Backup)?;
            let cancel = pending.request.clone();
            ticket
                .on_cancel(Box::new(move || cancel.cancel()))
                .map_err(admission)?;
            Ok((ticket, pending))
        })
        .await?;
        let reply = pending.receive().await;
        let rows = match reply {
            Ok(rows) => rows,
            Err(PanelFailure::Cancelled) => {
                check(call)?;
                return Ok(FileReply::json(
                    json!({"version":1,"cancelled":true,"requestId":request}),
                ));
            }
            Err(_) => {
                check(call)?;
                return Err("file_unavailable");
            }
        };
        let saved = tauri::async_runtime::spawn_blocking(move || {
            if rows.len() != 1 {
                return Err(FileError::Invalid);
            }
            ticket.complete(rows.into_iter().next().unwrap().source()?, Instant::now())
        })
        .await;
        check(call)?;
        let id = saved.map_err(|_| "file_unavailable")?.map_err(failure)?;
        let row = boot
            .backups
            .selection(
                &scope,
                BackupPurpose::Source,
                &request,
                &id.wire(),
                Instant::now(),
            )
            .map_err(failure)?;
        return Ok(FileReply::json(backup_metadata(row)));
    }
    let native_purpose = match purpose {
        "attachment" => SourcePurpose::Attachment,
        "avatar" => SourcePurpose::Avatar,
        _ => return invalid(),
    };
    let source_scope = scope.clone();
    let mut pending = commands::receiving(webview, ready, move |ready, actual| {
        if actual != source_scope.owner() {
            return Err(Refusal::StaleOwner);
        }
        ready
            .native
            .choose_source_on_main(source_scope, native_purpose)
    })
    .await?;
    let rows = match pending.receive().await {
        Ok(rows) => rows,
        Err(PanelFailure::Cancelled) => {
            check(call)?;
            return Ok(FileReply::json(json!({"version":1,"cancelled":true})));
        }
        Err(_) => {
            check(call)?;
            return Err("file_unavailable");
        }
    };
    let attachments = boot.attachments.clone();
    let avatars = boot.avatars.clone();
    let avatar = purpose == "avatar";
    let saved = tauri::async_runtime::spawn_blocking(move || -> Result<Value, FileError> {
        anchor.current()?;
        let selections = rows
            .into_iter()
            .map(|row| row.source())
            .collect::<Result<Vec<_>, _>>()?;
        if avatar {
            if selections.len() != 1 {
                return Err(FileError::Invalid);
            }
            let id = avatars.remember(
                anchor,
                selections.into_iter().next().unwrap(),
                Instant::now(),
            )?;
            Ok(json!({"version":1,"choiceId":id.wire()}))
        } else {
            let files = selections
                .iter()
                .map(|value| metadata(&value.metadata()))
                .collect::<Vec<_>>();
            let id = attachments.remember(anchor, selections, Instant::now())?;
            Ok(json!({"version":1,"choiceId":id.wire(),"files":files}))
        }
    })
    .await;
    check(call)?;
    Ok(FileReply::json(
        saved.map_err(|_| "file_unavailable")?.map_err(failure)?,
    ))
}
async fn destination_choice(
    webview: WebviewWindow,
    boot: &Arc<Bootstrap>,
    call: &Arc<PrivateCall>,
    ctx: &Context,
) -> Result<FileReply, &'static str> {
    let ready = boot.ready().await?;
    let scope = call.scope();
    let purpose = ctx.purpose()?;
    if purpose == "backup-export" {
        ctx.keys(&["purpose", "requestId"])?;
        let request = ctx.text("requestId", 36)?.to_owned();
        let request_for_start = request.clone();
        let broker = boot.backups.clone();
        let source_scope = scope.clone();
        let (ticket, mut pending) = commands::receiving(webview, ready, move |ready, actual| {
            if actual != source_scope.owner() {
                return Err(Refusal::StaleOwner);
            }
            let ticket = broker
                .start_destination(&source_scope, &request_for_start, Instant::now())
                .map_err(admission)?;
            ticket
                .current(&source_scope, Instant::now())
                .map_err(admission)?;
            let pending = ready.native.choose_destination_on_main(
                source_scope,
                "morse-backup.morsebackup",
                "application/octet-stream",
            )?;
            let cancel = pending.request.clone();
            ticket
                .on_cancel(Box::new(move || cancel.cancel()))
                .map_err(admission)?;
            Ok((ticket, pending))
        })
        .await?;
        let rows = match pending.receive().await {
            Ok(rows) => rows,
            Err(PanelFailure::Cancelled) => {
                check(call)?;
                return Ok(FileReply::json(
                    json!({"version":1,"requestId":request,"cancelled":true}),
                ));
            }
            Err(_) => {
                check(call)?;
                return Err("file_unavailable");
            }
        };
        let saved = tauri::async_runtime::spawn_blocking(move || {
            if rows.len() != 1 {
                return Err(FileError::Invalid);
            }
            let destination = rows
                .into_iter()
                .next()
                .unwrap()
                .destination()
                .map_err(|_| FileError::Unavailable)?;
            ticket.complete(destination, Instant::now())
        })
        .await;
        check(call)?;
        let id = saved.map_err(|_| "file_unavailable")?.map_err(failure)?;
        return Ok(FileReply::json(backup_metadata(
            boot.backups
                .selection(
                    &scope,
                    BackupPurpose::Export,
                    &request,
                    &id.wire(),
                    Instant::now(),
                )
                .map_err(failure)?,
        )));
    }
    if purpose != "export" {
        return invalid();
    }
    ctx.keys(&["purpose", "filename", "mimeType", "size", "sourceContext"])?;
    let context = ctx.export()?;
    let name = ctx.text("filename", 255)?.to_owned();
    let mime = ctx.text("mimeType", 127)?.to_owned();
    let anchor = scope.choice_anchor().map_err(commands::failure)?;
    let source_scope = scope.clone();
    let mut pending = commands::receiving(webview, ready, move |ready, actual| {
        if actual != source_scope.owner() {
            return Err(Refusal::StaleOwner);
        }
        ready
            .native
            .choose_destination_on_main(source_scope, &name, &mime)
    })
    .await?;
    let rows = match pending.receive().await {
        Ok(rows) => rows,
        Err(PanelFailure::Cancelled) => {
            check(call)?;
            return Ok(FileReply::json(json!({"version":1,"cancelled":true})));
        }
        Err(_) => {
            check(call)?;
            return Err("file_unavailable");
        }
    };
    let broker = boot.destinations.clone();
    let saved = tauri::async_runtime::spawn_blocking(move || {
        anchor.current()?;
        if rows.len() != 1 {
            return Err(super::private_exports::ExportError::Invalid);
        }
        let destination = rows.into_iter().next().unwrap().destination()?;
        broker.remember(anchor, context, destination, Instant::now())
    })
    .await;
    check(call)?;
    let id = saved
        .map_err(|_| "file_unavailable")?
        .map_err(|_| "file_unavailable")?;
    Ok(FileReply::json(json!({"version":1,"choiceId":id.wire()})))
}
#[tauri::command]
pub(crate) async fn app_lock_file(
    webview: WebviewWindow,
    boot: State<'_, Arc<Bootstrap>>,
    request: Request<'_>,
) -> Result<Response, &'static str> {
    let operation = crate::header(&request, "X-Morse-File-Operation")
        .ok_or("invalid_file_request")?
        .to_owned();
    let ctx = Context::parse(&request)?;
    let maximum = match operation.as_str() {
        "writePreview" | "digest" => 16_777_216,
        "writeExport" => 65_536,
        _ => 0,
    };
    let bytes = Zeroizing::new(
        crate::request::bounded_binary_body(request.body(), 0, maximum, "invalid_file_request")
            .map_err(|_| "invalid_file_request")?,
    );
    let call =
        Arc::new(commands::private_call(webview.clone(), boot.ready().await?, &request).await?);
    let scope = call.scope();
    let files = boot.files.clone();
    let result:Result<FileReply,&'static str>=async { match operation.as_str() {
        "subscribeIncoming"=>{ctx.keys(&[])?;if !boot.chooser_timer_available.load(Ordering::Acquire){return Err("file_unavailable");}incoming_subscription(webview,&boot,&call).await},
        "chooseSource"=>{ctx.keys(&["purpose","requestId"])?;if !boot.chooser_timer_available.load(Ordering::Acquire) {return Err("file_unavailable");}
            let purpose=ctx.purpose()?.to_owned();let request=if purpose=="backup-source" {Some(ctx.text("requestId",36)?.to_owned())}else{if ctx.0.contains_key("requestId"){return invalid();}None};
            source_choice(webview,&boot,&call,&purpose,request).await},
        "chooseDestination"=>{if !boot.chooser_timer_available.load(Ordering::Acquire){return Err("file_unavailable");}destination_choice(webview,&boot,&call,&ctx).await},
        "pendingChoice"=>{
            if !boot.chooser_timer_available.load(Ordering::Acquire){return Err("file_unavailable");}
            match ctx.purpose()? {
                "attachment"=>{ctx.keys(&["purpose","subscription"])?;let value=if ctx.0.contains_key("subscription") {
                        let (choice,more)=boot.incoming.take(&scope,IncomingHandle::parse(ctx.text("subscription",36)?).map_err(failure)?,Instant::now()).map_err(failure)?;
                        if let Some(ticket)=more {boot.incoming_wake()(ticket,super::native_incoming::IncomingHint::Sources);}choice
                    }else{boot.attachments.pending(&scope,Instant::now()).map_err(failure)?};
                    Ok(FileReply::json(value.map(|row|json!({"version":1,"choiceId":row.choice,"files":row.files.iter().map(metadata).collect::<Vec<_>>()})).unwrap_or(json!({"version":1}))))},
                "avatar"=>{ctx.keys(&["purpose"])?;Ok(FileReply::json(boot.avatars.pending(&scope,Instant::now()).map_err(failure)?.map(|id|json!({"version":1,"choiceId":id.wire()})).unwrap_or(json!({"version":1}))))},
                "backup-source"|"backup-export"=>{ctx.keys(&["purpose"])?;let purpose=backup_purpose(ctx.purpose()?)?;Ok(FileReply::json(boot.backups.pending(&scope,purpose,Instant::now()).map_err(failure)?.map(backup_metadata).unwrap_or(json!({"version":1}))))},
                "export"=>{ctx.keys(&["purpose","filename","mimeType","size","sourceContext"])?;let context=ctx.export()?;Ok(FileReply::json(boot.destinations.pending(&scope,&context,Instant::now()).map_err(|_|"file_unavailable")?.map(|id|json!({"version":1,"choiceId":id.wire()})).unwrap_or(json!({"version":1}))))},_=>invalid(),
            }
        },
        "beginBackupChoice"=>{ctx.keys(&["purpose"])?;if !boot.chooser_timer_available.load(Ordering::Acquire){return Err("file_unavailable");}
            let id=boot.backups.begin(&scope,backup_purpose(ctx.purpose()?)?,Instant::now()).map_err(failure)?;Ok(FileReply::json(json!({"version":1,"requestId":id.wire()})))},
        "discardBackupChoice"=>{ctx.keys(&["purpose","requestId","choiceId"])?;let purpose=backup_purpose(ctx.purpose()?)?;
            let target=match (ctx.0.contains_key("requestId"),ctx.0.contains_key("choiceId")) {(true,false)=>DiscardBackup::Request(ctx.text("requestId",36)?.to_owned()),(false,true)=>DiscardBackup::Choice(ctx.text("choiceId",36)?.to_owned()),_=>return invalid()};
            boot.backups.discard(&scope,purpose,target).map_err(failure)?;Ok(FileReply::json(json!({"version":1})))},
        "claimSource"=>{let size=ctx.number("size",536_870_912)?;let choice=ctx.text("choiceId",36)?.to_owned();let selected=ctx.text("selectionId",36)?.to_owned();
            let source=if ctx.0.contains_key("purpose") {ctx.keys(&["purpose","sourceContext","choiceId","selectionId","size"])?;
                if ctx.purpose()?!="backup-source" {return invalid();}counter(&scope,"backup-import",ctx.text("sourceContext",4096)?)?;
                boot.backups.claim_source(&scope,&choice,&selected,size,Instant::now()).map_err(failure)?
            }else{ctx.keys(&["choiceId","selectionId","size"])?;boot.attachments.claim(&scope,&choice,&selected,size,Instant::now()).map_err(failure)?};
            work(&call,move |scope|{let h=files.claim_source(&scope,source,size)?;Ok(FileReply::handle(files,scope,Role::Source,h,json!({"version":1,"handle":h.wire(),"size":size})))}).await},
        "readSource"=>{ctx.keys(&["handle","offset","length"])?;let h=ctx.handle("handle")?;let offset=ctx.number("offset",536_870_912)?;let length=ctx.number("length",65_536)? as usize;
            work(&call,move |scope|Ok(FileReply::bytes(files.read_source(&scope,h,offset,length)?))).await},
        "writePreview"=>{ctx.keys(&["key","mimeType"])?;ctx.text("key",256)?;let mime=ctx.text("mimeType",127)?.to_owned();
            work(&call,move |scope|{let h=files.write_preview(&scope,&mime,bytes)?;Ok(FileReply::handle(files,scope,Role::Preview,h,json!({"version":1,"handle":h.wire(),"uri":h.preview_uri()})))}).await},
        "beginExport"=>{ctx.keys(&["purpose","choiceId","filename","mimeType","size","sourceContext"])?;let directory=boot.export_directory()?;let id=ctx.text("choiceId",36)?;
            let selected=match ctx.purpose()? {"backup-export"=>{if ctx.text("filename",255)?!="morse-backup.morsebackup" || ctx.text("mimeType",127)?!="application/octet-stream" {return invalid();}
                boot.backups.claim_export(&scope,id,ctx.text("sourceContext",4096)?,ctx.number("size",16_796_864)?,Instant::now()).map_err(failure)?},
                "export"=>boot.destinations.claim(&scope,id,&ctx.export()?,Instant::now()).map_err(|_|"file_unavailable")?,_=>return invalid()};
            work(&call,move |scope|{let h=files.begin_export(&scope,directory,selected)?;Ok(FileReply::handle(files,scope,Role::Export,h,json!({"version":1,"handle":h.wire()})))}).await},
        "writeExport"=>{ctx.keys(&["handle","offset"])?;let h=ctx.handle("handle")?;let offset=ctx.number("offset",536_870_912)?;
            work(&call,move |scope|{files.write_export(&scope,h,offset,&bytes)?;Ok(FileReply::json(Value::Null))}).await},
        "commitExport"=>{ctx.keys(&["handle"])?;let h=ctx.handle("handle")?;work(&call,move |scope|{files.commit_export(&scope,h,||scope.check().map_err(super::private_exports::ExportError::from))?;Ok(FileReply::json(Value::Null))}).await},
        "importAvatar"=>{ctx.keys(&["purpose","choiceId"])?;if ctx.purpose()?!="avatar" {return invalid();}let source=boot.avatars.claim(&scope,ctx.text("choiceId",36)?,Instant::now()).map_err(failure)?;
            work(&call,move |scope|{let avatar=avatar_import::import(files,scope,source)?;Ok(FileReply::json(json!({"version":1,"avatar":avatar.as_str()})))}).await},
        "digest"=>{ctx.keys(&[])?;work(&call,move |_|{use sha2::{Digest,Sha256};let hash=Sha256::digest(bytes.as_slice());let value=hash.iter().map(|b|format!("{b:02x}")).collect::<String>();Ok(FileReply::json(json!({"version":1,"digest":value})))}).await},
        _=>invalid(),
    }}.await;
    // Every extra asynchronous caller continuation fences both values and
    // failures. A minted file handle remains in FileReply until this succeeds.
    check(&call)?;
    result?.publish()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CleanupContext {
    version: u8,
    handle: String,
}
#[tauri::command]
pub(crate) async fn app_lock_file_cleanup(
    webview: WebviewWindow,
    boot: State<'_, Arc<Bootstrap>>,
    operation: String,
    context: CleanupContext,
    request: Request<'_>,
) -> Result<(), &'static str> {
    if context.version != 1 {
        return invalid();
    }
    if operation=="unsubscribeIncoming" {
        let handle=IncomingHandle::parse(&context.handle).map_err(failure)?;
        let owner=crate::header(&request,"X-Morse-Lock-Owner").ok_or("app_lock_stale_owner")?.to_owned();
        let epoch=crate::header(&request,"X-Morse-Lock-Epoch").ok_or("app_lock_stale_epoch")?.to_owned();
        let incoming=boot.incoming.clone();
        return commands::receiving(webview,boot.ready().await?,move |ready,actual| {
            let epoch=ready.cleanup_epoch(actual,&owner,&epoch)?;incoming.unsubscribe(actual,epoch,handle);Ok(())
        }).await;
    }
    let h = FileHandle::parse(&context.handle).map_err(failure)?;
    let role = match operation.as_str() {
        "closeSource" => Role::Source,
        "abortExport" => Role::Export,
        "releasePreview" => Role::Preview,
        _ => return invalid(),
    };
    let owner = crate::header(&request, "X-Morse-Lock-Owner")
        .ok_or("app_lock_stale_owner")?
        .to_owned();
    let epoch = crate::header(&request, "X-Morse-Lock-Epoch")
        .ok_or("app_lock_stale_epoch")?
        .to_owned();
    let files = boot.files.clone();
    commands::receiving(webview, boot.ready().await?, move |ready, actual| {
        let epoch = ready.cleanup_epoch(actual, &owner, &epoch)?;
        files.cleanup(actual, epoch, role, h);
        Ok(())
    })
    .await
}

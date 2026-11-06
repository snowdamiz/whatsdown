//! Local notification opt-in and actual OS permission under the original call.
use super::{
    bootstrap::Bootstrap,
    commands,
    controller::Refusal,
    legacy_profile::ProfileIdentity,
    native_notices::NativeNoticeIntent,
    notice_wire::{parse_take, PublishNotice},
    notification_actions::{
        native_authorization_scope, NativeAuthorizationScope, NotificationAction,
        NotificationActions,
    },
    receiver_scope::MainThread,
};
use crate::{mesh, request, Desktop};
use std::{
    ffi::c_void,
    ptr::NonNull,
    sync::{Arc, Mutex},
};
use tauri::{
    ipc::{InvokeBody, Request, Response},
    State, WebviewWindow,
};
use zeroize::Zeroizing;

unsafe extern "C" {
    fn MDNativeNotificationsCreate() -> *mut c_void;
    fn MDNativeNotificationsAuthorization(
        context: *mut c_void,
        scope: NativeAuthorizationScope,
        request: bool,
        reply_context: *mut c_void,
        reply: extern "C" fn(*mut c_void, u32),
    ) -> bool;
    fn MDNativeNotificationsRetireInvalid(context: *mut c_void);
    fn MDNativeNotificationsClose(context: *mut c_void);
    fn MDNativeNotificationsRelease(context: *mut c_void);
}

#[derive(Clone, Copy)]
enum Permission {
    Allowed,
    Denied,
    Retired,
    Unavailable,
}
#[derive(Clone, Copy)]
enum PermissionPort {
    Available(NonNull<c_void>),
    Unavailable,
}

pub(crate) struct NotificationBindings {
    port: PermissionPort,
    actions: Arc<NotificationActions>,
}
// The native pointer is only dereferenced on Main. Final release itself queues
// native closure on Main. Rust workers retain only the original typed action.
unsafe impl Send for NotificationBindings {}
unsafe impl Sync for NotificationBindings {}

extern "C" fn permission_reply(raw: *mut c_void, value: u32) {
    if std::panic::catch_unwind(|| {
        let sender =
            unsafe { Box::from_raw(raw.cast::<tauri::async_runtime::Sender<Permission>>()) };
        let permission = match value {
            0 => Permission::Allowed,
            1 => Permission::Denied,
            2 => Permission::Retired,
            _ => Permission::Unavailable,
        };
        let _ = sender.try_send(permission);
    })
    .is_err()
    {
        std::process::abort();
    }
}

impl NotificationBindings {
    pub(crate) fn new_on_main() -> Result<Self, Refusal> {
        MainThread::current()?;
        let port = match NonNull::new(unsafe { MDNativeNotificationsCreate() }) {
            Some(context) => PermissionPort::Available(context),
            None => PermissionPort::Unavailable,
        };
        Ok(Self {
            port,
            actions: Arc::new(NotificationActions::new()),
        })
    }
    fn authorize_on_main(
        &self,
        action: NotificationAction,
        request: bool,
    ) -> Result<tauri::async_runtime::Receiver<Permission>, Refusal> {
        MainThread::current()?;
        action.check()?;
        let (sender, receiver) = tauri::async_runtime::channel(1);
        let PermissionPort::Available(context) = self.port else {
            let _ = sender.try_send(Permission::Unavailable);
            return Ok(receiver);
        };
        let original = Arc::new(action);
        let raw = Box::into_raw(Box::new(sender));
        let accepted = unsafe {
            MDNativeNotificationsAuthorization(
                context.as_ptr(),
                native_authorization_scope(&original),
                request,
                raw.cast(),
                permission_reply,
            )
        };
        if !accepted {
            // The qualified C refusal transfers neither scope nor callback.
            drop(unsafe { Box::from_raw(raw) });
            return Err(Refusal::Busy);
        }
        Ok(receiver)
    }
    pub(crate) fn retire_invalid_on_main(&self) -> Result<(), Refusal> {
        MainThread::current()?;
        if let PermissionPort::Available(context) = self.port {
            unsafe { MDNativeNotificationsRetireInvalid(context.as_ptr()) };
        }
        Ok(())
    }
    // Bootstrap can retire admission from any native thread before it queues
    // the Main-only SDK close. No later OS callback may revive this action.
    pub(crate) fn close_admission(&self) {
        self.actions.close();
    }
    pub(crate) fn close_on_main(&self) -> Result<(), Refusal> {
        MainThread::current()?;
        self.actions.close();
        if let PermissionPort::Available(context) = self.port {
            unsafe { MDNativeNotificationsClose(context.as_ptr()) };
        }
        Ok(())
    }
}
impl Drop for NotificationBindings {
    fn drop(&mut self) {
        self.actions.close();
        if let PermissionPort::Available(context) = self.port {
            unsafe { MDNativeNotificationsRelease(context.as_ptr()) };
        }
    }
}

#[derive(Clone, Copy)]
enum Operation {
    Status,
    Enable,
    Disable,
}
#[derive(Clone, Copy)]
enum Preference {
    Read,
    Set(bool),
    MigrateIfAbsent(bool),
}

fn packet(
    database: &str,
    profile: &[u8],
    value: Option<bool>,
) -> Result<Zeroizing<Vec<u8>>, &'static str> {
    let mut output = Zeroizing::new(Vec::new());
    let mut append = |bytes: &[u8]| -> Result<(), &'static str> {
        let length = u32::try_from(bytes.len()).map_err(|_| "invalid_notification_request")?;
        output.extend_from_slice(&length.to_be_bytes());
        output.extend_from_slice(bytes);
        Ok(())
    };
    append(database.as_bytes())?;
    append(profile)?;
    append(b"preferences/desktop-notifications")?;
    if let Some(enabled) = value {
        append(if enabled { b"on" } else { b"off" })?;
    }
    Ok(output)
}
fn failure(value: Refusal) -> String {
    commands::failure(value).to_owned()
}

fn preference(
    core: &Mutex<mesh::Mesh>,
    action: &NotificationAction,
    database: &str,
    profile: &[u8],
    expected: ProfileIdentity,
    operation: Preference,
) -> Result<Option<bool>, String> {
    let library = core.lock().map_err(|_| "native_lock_failed")?;
    action.check().map_err(failure)?;
    let loaded = library
        .invoke("mesh_messenger_load_profile", database.as_bytes(), database)
        .map(Zeroizing::new)
        .map_err(Zeroizing::new);
    action.check().map_err(failure)?;
    let loaded = loaded.map_err(|_| "account_state_changed")?;
    if ProfileIdentity::parse(&loaded).map_err(|_| "account_state_changed")? != expected {
        return Err("account_state_changed".to_owned());
    }
    let read = packet(database, profile, None)?;
    let returned = library
        .invoke("mesh_messenger_journal_load_bound", &read, database)
        .map(Zeroizing::new)
        .map_err(Zeroizing::new);
    action.check().map_err(failure)?;
    let returned = returned.map_err(|_| "notification_state_unavailable")?;
    let current = match returned.as_slice() {
        b"" => None,
        b"on" => Some(true),
        b"off" => Some(false),
        _ => return Err("notification_state_unavailable".to_owned()),
    };
    let next = match operation {
        Preference::Read => return Ok(current),
        Preference::MigrateIfAbsent(_) if current.is_some() => return Ok(current),
        Preference::Set(value) | Preference::MigrateIfAbsent(value) => value,
    };
    action.check().map_err(failure)?;
    let write = packet(database, profile, Some(next))?;
    let stored = library
        .invoke("mesh_messenger_journal_save_bound", &write, database)
        .map(Zeroizing::new)
        .map_err(Zeroizing::new);
    action.check().map_err(failure)?;
    if !stored
        .map_err(|_| "notification_state_unavailable")?
        .is_empty()
    {
        return Err("notification_state_unavailable".to_owned());
    }
    Ok(Some(next))
}

#[tauri::command]
pub(crate) async fn app_lock_notification_binding(
    webview: WebviewWindow,
    boot: State<'_, Arc<Bootstrap>>,
    state: State<'_, Desktop>,
    notifications: State<'_, Arc<NotificationBindings>>,
    request: Request<'_>,
) -> Result<&'static str, String> {
    let operation = match crate::header(&request, "X-Morse-Notification-Operation") {
        Some("status") => Operation::Status,
        Some("enable") => Operation::Enable,
        Some("disable") => Operation::Disable,
        _ => return Err("invalid_notification_operation".to_owned()),
    };
    let profile = Zeroizing::new(request::bounded_binary_body(
        request.body(),
        0,
        36134,
        "invalid_profile",
    )?);
    let expected = ProfileIdentity::parse(&profile).map_err(str::to_owned)?;
    let ready = boot.ready().await.map_err(str::to_owned)?;
    if !matches!(operation, Operation::Disable) && ready.native.notices().is_none() {
        return Err("notifications_unavailable".to_owned());
    }
    let call = commands::private_call(webview.clone(), ready.clone(), &request)
        .await
        .map_err(str::to_owned)?;
    let bindings = notifications.inner().clone();
    let original = call.scope();
    let owner = bindings.clone();
    let action = commands::receiving(webview.clone(), ready.clone(), move |ready, actual| {
        if original.owner() != actual {
            return Err(Refusal::StaleOwner);
        }
        let changes_choice = !matches!(operation, Operation::Status);
        let action = owner
            .actions
            .begin(&MainThread::current()?, original, changes_choice)?;
        if changes_choice {
            owner.retire_invalid_on_main()?;
            if let Some(notices) = ready.native.notices() {
                notices.retire_invalid_on_main()?;
            }
        }
        Ok(action)
    })
    .await
    .map_err(str::to_owned)?;
    let database = state.database.clone();
    if database.is_empty() || database.len() > 4096 || database.contains('\0') {
        return Err("invalid_database_path".to_owned());
    }
    let core = state.mesh.clone();
    let run_preference = |operation| {
        let core = core.clone();
        let action = action.clone();
        let database = database.clone();
        let profile = profile.clone();
        tauri::async_runtime::spawn_blocking(move || {
            preference(&core, &action, &database, &profile, expected, operation)
        })
    };
    let stored = run_preference(if matches!(operation, Operation::Disable) {
        Preference::Set(false)
    } else {
        Preference::Read
    })
    .await
    .map_err(|_| "native_task_failed")??;
    action.check().map_err(failure)?;
    if matches!(operation, Operation::Disable) {
        return Ok("disabled");
    }

    let opted_in = if matches!(operation, Operation::Status) && stored.is_none() {
        let key = Zeroizing::new(
            expected
                .notification_key(&database)
                .map_err(str::to_owned)?,
        );
        let original = action.clone();
        let scope = original.scope();
        let mut pending =
            commands::receiving(webview.clone(), ready.clone(), move |ready, actual| {
                if scope.owner() != actual {
                    return Err(Refusal::StaleOwner);
                }
                original.check()?;
                ready.native.start_legacy_on_main(scope, &key, true)
            })
            .await
            .map_err(str::to_owned)?;
        let legacy = pending
            .recv()
            .await
            .ok_or("notification_state_unavailable")?;
        action.check().map_err(failure)?;
        let enabled = match legacy.status {
            0 => legacy.bytes.as_slice() == b"true",
            1 => false,
            3 => return Err("app_lock_cancelled".to_owned()),
            _ => return Err("notification_state_unavailable".to_owned()),
        };
        let migrated = run_preference(Preference::MigrateIfAbsent(enabled))
            .await
            .map_err(|_| "native_task_failed")??;
        action.check().map_err(failure)?;
        migrated == Some(true)
    } else {
        stored == Some(true)
    };
    if matches!(operation, Operation::Status) && !opted_in {
        return Ok("disabled");
    }

    let original = action.clone();
    let scope = original.scope();
    let owner = bindings.clone();
    let mut pending = commands::receiving(webview, ready, move |_, actual| {
        if scope.owner() != actual {
            return Err(Refusal::StaleOwner);
        }
        owner.authorize_on_main(original, matches!(operation, Operation::Enable))
    })
    .await
    .map_err(str::to_owned)?;
    let permission = pending
        .recv()
        .await
        .ok_or("notification_state_unavailable")?;
    action.check().map_err(failure)?;
    // This post-prompt Core operation validates the original account again.
    // The revision rejects a permission reply overtaken by a later user action.
    let after = run_preference(
        if matches!(operation, Operation::Enable) && matches!(permission, Permission::Allowed) {
            Preference::Set(true)
        } else {
            Preference::Read
        },
    )
    .await
    .map_err(|_| "native_task_failed")??;
    action.check().map_err(failure)?;
    match permission {
        Permission::Allowed => Ok(if after == Some(true) {
            "enabled"
        } else {
            "disabled"
        }),
        Permission::Denied => Ok("disabled"),
        Permission::Retired => Err("app_lock_cancelled".to_owned()),
        Permission::Unavailable => Err("notifications_unavailable".to_owned()),
    }
}

// A notice has no caller-supplied profile/account authority. Capture the actual
// receiving scope first; read its fresh Core profile and sealed opt-in under the
// Core lock, then release that lock before dispatching to native Main.
fn fresh_notice_preference(
    core: &Mutex<mesh::Mesh>,
    action: &NotificationAction,
    database: &str,
) -> Result<bool, String> {
    let library = core.lock().map_err(|_| "native_lock_failed")?;
    action.check().map_err(failure)?;
    let profile = library
        .invoke("mesh_messenger_load_profile", database.as_bytes(), database)
        .map(Zeroizing::new)
        .map_err(Zeroizing::new);
    action.check().map_err(failure)?;
    let profile = profile.map_err(|_| "account_state_changed")?;
    ProfileIdentity::parse(&profile).map_err(|_| "account_state_changed")?;
    let read = packet(database, &profile, None)?;
    let stored = library
        .invoke("mesh_messenger_journal_load_bound", &read, database)
        .map(Zeroizing::new)
        .map_err(Zeroizing::new);
    action.check().map_err(failure)?;
    match stored
        .map_err(|_| "notification_state_unavailable")?
        .as_slice()
    {
        b"on" => Ok(true),
        b"" | b"off" => Ok(false),
        _ => Err("notification_state_unavailable".to_owned()),
    }
}
fn notice_database(value: &str) -> Result<String, String> {
    if value.is_empty() || value.len() > 4096 || value.contains('\0') {
        return Err("invalid_database_path".to_owned());
    }
    Ok(value.to_owned())
}
async fn notice_action(
    webview: WebviewWindow,
    ready: Arc<commands::Ready>,
    bindings: Arc<NotificationBindings>,
    request: &Request<'_>,
) -> Result<Arc<NotificationAction>, String> {
    if ready.native.notices().is_none() {
        return Err("notifications_unavailable".to_owned());
    }
    let call = commands::private_call(webview.clone(), ready.clone(), request)
        .await
        .map_err(str::to_owned)?;
    let scope = call.scope();
    commands::receiving(webview, ready, move |_, actual| {
        if scope.owner() != actual {
            return Err(Refusal::StaleOwner);
        }
        bindings
            .actions
            .begin(&MainThread::current()?, scope, false)
            .map(Arc::new)
    })
    .await
    .map_err(str::to_owned)
}
fn notice_body<'a>(request: &'a Request<'_>) -> Result<&'a serde_json::Value, String> {
    match request.body() {
        InvokeBody::Json(value) => Ok(value),
        InvokeBody::Raw(_) => Err("invalid_notification_request".to_owned()),
    }
}
#[tauri::command]
pub(crate) async fn app_lock_publish_notice(
    webview: WebviewWindow,
    boot: State<'_, Arc<Bootstrap>>,
    state: State<'_, Desktop>,
    notifications: State<'_, Arc<NotificationBindings>>,
    request: Request<'_>,
) -> Result<(), String> {
    let notice = PublishNotice::parse(notice_body(&request)?).map_err(str::to_owned)?;
    let database = notice_database(&state.database)?;
    let ready = boot.ready().await.map_err(str::to_owned)?;
    let action = notice_action(
        webview.clone(),
        ready.clone(),
        notifications.inner().clone(),
        &request,
    )
    .await?;
    let account = action.scope().account_generation().map_err(failure)?;
    let core = state.mesh.clone();
    let original = action.clone();
    let enabled = tauri::async_runtime::spawn_blocking(move || {
        fresh_notice_preference(&core, &original, &database)
    })
    .await
    .map_err(|_| "native_task_failed")?;
    action.check().map_err(failure)?;
    if !enabled? {
        return Ok(());
    }
    let original = action.clone();
    let result = commands::receiving(webview, ready, move |ready, actual| {
        if original.scope().owner() != actual {
            return Err(Refusal::StaleOwner);
        }
        original.check()?;
        let notices = ready.native.notices().ok_or(Refusal::Cancelled)?;
        if !notices.publish_on_main(
            &original,
            account,
            &notice.title,
            &notice.body,
            &notice.scope,
        )? {
            return Err(Refusal::Busy);
        }
        Ok(())
    })
    .await;
    action.check().map_err(failure)?;
    result.map_err(str::to_owned)
}
#[tauri::command]
pub(crate) async fn app_lock_take_notice_intent(
    webview: WebviewWindow,
    boot: State<'_, Arc<Bootstrap>>,
    state: State<'_, Desktop>,
    notifications: State<'_, Arc<NotificationBindings>>,
    request: Request<'_>,
) -> Result<Response, String> {
    parse_take(notice_body(&request)?).map_err(str::to_owned)?;
    let database = notice_database(&state.database)?;
    let ready = boot.ready().await.map_err(str::to_owned)?;
    let action = notice_action(
        webview.clone(),
        ready.clone(),
        notifications.inner().clone(),
        &request,
    )
    .await?;
    let account = action.scope().account_generation().map_err(failure)?;
    let core = state.mesh.clone();
    let original = action.clone();
    let enabled = tauri::async_runtime::spawn_blocking(move || {
        fresh_notice_preference(&core, &original, &database)
    })
    .await
    .map_err(|_| "native_task_failed")?;
    action.check().map_err(failure)?;
    let enabled = enabled?;
    let original = action.clone();
    let result = commands::receiving(webview, ready, move |ready, actual| {
        if original.scope().owner() != actual {
            return Err(Refusal::StaleOwner);
        }
        original.check()?;
        let intent = if enabled {
            ready
                .native
                .notices()
                .ok_or(Refusal::Cancelled)?
                .consume_on_main(&original, account)?
        } else {
            NativeNoticeIntent::None
        };
        // The typed native port admits only the fixed lowercase chat/group
        // grammar. Encoding is outside Protection's consume gate.
        let encoded = Zeroizing::new(match intent {
            NativeNoticeIntent::None => "{\"version\":1,\"kind\":\"none\"}".to_owned(),
            NativeNoticeIntent::Inbox => "{\"version\":1,\"kind\":\"inbox\"}".to_owned(),
            NativeNoticeIntent::Scope(scope) => format!(
                "{{\"version\":1,\"kind\":\"scope\",\"scope\":\"{}\"}}",
                scope.as_str()
            ),
        });
        original.check()?;
        Ok(encoded)
    })
    .await;
    action.check().map_err(failure)?;
    let mut encoded = result.map_err(str::to_owned)?;
    Ok(Response::new(std::mem::take(&mut *encoded)))
}

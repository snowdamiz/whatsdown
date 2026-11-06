#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(target_os = "macos")]
mod desktop_lock;
mod appearance;
mod attachment_files;
mod bounty;
mod mesh;
mod navigation;
mod request;
mod wallet;

use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tauri::{
    ipc::{InvokeBody, Request, Response},
    Manager,
};
use tauri_plugin_dialog::DialogExt;
use tauri_plugin_updater::{Update, UpdaterExt};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    security_frame: String,
    #[serde(default)]
    network_counter_frame: String,
    #[serde(default)]
    network_frame: String,
    #[serde(default)]
    ohttp_frame: String,
    #[serde(default)]
    credit_purpose: String,
    #[serde(default)]
    credit_usdc_mint_hex: String,
    #[serde(default)]
    lightning_network: String,
    #[serde(default)]
    issuer_tls_root: String,
    development: bool,
}
struct Desktop {
    mesh: Arc<Mutex<mesh::Mesh>>,
    database: String,
    app_identifier: String,
    data: PathBuf,
    config: Config,
    attachment_saves: Arc<attachment_files::AttachmentSaves>,
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
fn database_path(state: tauri::State<Desktop>) -> String {
    state.database.clone()
}

#[tauri::command]
fn appearance(state: tauri::State<Desktop>) -> String {
    appearance::load(&state.data).as_str().to_owned()
}

#[tauri::command]
fn set_appearance(
    app: tauri::AppHandle,
    state: tauri::State<Desktop>,
    appearance: String,
) -> Result<(), String> {
    let choice = appearance::Appearance::parse(&appearance);
    appearance::save(&state.data, choice).map_err(|_| "appearance_not_saved")?;
    if let Some(window) = app.get_webview_window("main") {
        apply_appearance(&window, choice);
    }
    Ok(())
}

// The window's theme drives the web view's `prefers-color-scheme`, and its
// background is what shows before the page paints and behind any gap in it.
fn apply_appearance(window: &tauri::WebviewWindow, choice: appearance::Appearance) {
    let _ = window.set_theme(choice.theme());
    let theme = choice
        .theme()
        .or_else(|| window.theme().ok())
        .unwrap_or(tauri::Theme::Dark);
    let _ = window.set_background_color(Some(appearance::canvas(theme)));
}

// The window is built here rather than from the config alone because its
// buttons differ by macOS and by the SDK Morse links against: macOS 26 draws
// square ones, older systems (and older SDKs on 26) taller ones that sit 4pt
// lower for the same `trafficLightPosition`. Either kind must centre on the
// toolbar strip (desktop-layout.ts).
fn create_main_window(app: &tauri::App) -> tauri::Result<()> {
    let config = app
        .config()
        .app
        .windows
        .iter()
        .find(|window| window.label == "main")
        .expect("the main window is configured")
        .clone();
    let builder = tauri::WebviewWindowBuilder::from_config(app.handle(), &config)?
        .visible(false)
        .on_navigation(navigation::allowed)
        .on_new_window(|_, _| tauri::webview::NewWindowResponse::Deny);
    #[cfg(target_os = "macos")]
    let builder = {
        let boot=app.state::<std::sync::Arc<desktop_lock::bootstrap::Bootstrap>>();
        let configuration=desktop_lock::private_preview::configuration(boot.native.clone(),boot.files.clone())
            .map_err(std::io::Error::other)?;
        builder.with_webview_configuration(configuration)
    };
    #[cfg(target_os = "macos")]
    let builder = match config.traffic_light_position {
        Some(lights) if tall_window_buttons() => {
            builder.traffic_light_position(tauri::LogicalPosition::new(lights.x, lights.y - 4.0))
        }
        _ => builder,
    };
    builder.build()?;
    Ok(())
}

#[cfg(target_os = "macos")]
fn tall_window_buttons() -> bool {
    use objc2_app_kit::{NSWindow, NSWindowButton, NSWindowStyleMask};
    let Some(main_thread) = objc2::MainThreadMarker::new() else {
        return false;
    };
    NSWindow::standardWindowButton_forStyleMask(
        NSWindowButton::CloseButton,
        NSWindowStyleMask::Titled,
        main_thread,
    )
    .is_some_and(|button| {
        let size = button.frame().size;
        size.height > size.width
    })
}

// Binary IPC: postMessage carries exact bounded byte arrays; the native handler
// restores the frame and reads the small string parameters from headers.
fn raw_body(request: &Request<'_>, error: &'static str) -> Result<Vec<u8>, String> {
    request::binary_body(request.body(), error)
}

fn header<'a>(request: &'a Request<'_>, name: &str) -> Option<&'a str> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn mesh_invoke(
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<Response, String> {
    let symbol = header(&request, "X-Mesh-Symbol")
        .ok_or("invalid_native_request")?
        .to_owned();
    let body = request::bounded_binary_body(
        request.body(),
        0,
        request::maximum_request(&symbol),
        "invalid_native_request",
    )?;
    request::validate_public(&symbol, &body, state.database.as_bytes())?;
    let mesh = Arc::clone(&state.mesh);
    let database = state.database.clone();
    let purpose = state.config.credit_purpose.clone();
    let mint = state.config.credit_usdc_mint_hex.clone();
    let directory = state.data.clone();
    let identifier = state.app_identifier.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if matches!(
            symbol.as_str(),
            "mesh_messenger_transparency_fork" | "mesh_messenger_fork_filing"
        ) {
            return bounty::invoke_proof(
                &symbol,
                database.as_bytes(),
                |name, request| {
                    mesh.lock()
                        .map_err(|_| "native_lock_failed")?
                        .invoke(name, request, &database)
                },
                |operation, payload| {
                    let pins = wallet::pins(&purpose, &mint)?;
                    let service = format!("{identifier}.wallet.v1.{}", pins[1]);
                    wallet::invoke(
                        &service,
                        &directory.join(format!("MorseWallet-v1-{}", pins[1])),
                        &pins,
                        0,
                        operation,
                        payload,
                    )
                },
            )
            .map(Response::new);
        }
        mesh.lock()
            .map_err(|_| "native_lock_failed")?
            .invoke(&symbol, &body, &database)
            .map(Response::new)
    })
    .await
    .map_err(|_| "native_task_failed")?
}

// The response is the HTTP status as two big-endian bytes followed by the body.
#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn wallet_invoke(
    app: tauri::AppHandle,
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<Response, String> {
    let operation = header(&request, "X-Wallet-Operation")
        .ok_or("invalid_wallet_request")?
        .parse::<u32>()
        .map_err(|_| "invalid_wallet_request")?;
    let bytes = raw_body(&request, "invalid_wallet_request")?;
    let pins = if operation == 7 && bytes.as_slice() == [0] {
        None
    } else {
        Some(wallet::pins(
            &state.config.credit_purpose,
            &state.config.credit_usdc_mint_hex,
        )?)
    };
    let mesh = state.mesh.clone();
    let database = state.database.clone();
    let purpose = pins.as_ref().map(|value| value[1]).unwrap_or(0);
    let directory = state.data.join(format!("MorseWallet-v1-{purpose}"));
    let service = format!("{}.wallet.v1.{purpose}", app.config().identifier);
    #[cfg(windows)]
    let parent = app
        .get_webview_window("main")
        .ok_or("wallet_window_unavailable")?
        .hwnd()
        .map_err(|_| "wallet_window_unavailable")?
        .0 as isize;
    #[cfg(not(windows))]
    let parent = 0;
    let result = tauri::async_runtime::spawn_blocking(move || {
        if operation == 7 {
            if bytes.len() != 1 {
                return Err("invalid_wallet_request".into());
            }
            return bounty::set_enabled(
                database.as_bytes(),
                bytes[0],
                |name, request| {
                    mesh.lock()
                        .map_err(|_| "mesh_lock_failed")?
                        .invoke(name, request, &database)
                },
                |operation, payload| {
                    let pins = pins.as_ref().ok_or("wallet_pins_missing")?;
                    wallet::invoke(&service, &directory, pins, parent, operation, payload)
                },
            );
        }
        let pins = pins.ok_or("wallet_pins_missing")?;
        if operation == 8 {
            return bounty::movement(
                &bytes,
                database.as_bytes(),
                |name, journal| {
                    mesh.lock()
                        .map_err(|_| "mesh_lock_failed")?
                        .invoke(name, journal, &database)
                },
                |operation, payload| {
                    wallet::invoke(&service, &directory, &pins, parent, operation, payload)
                },
            );
        }
        if operation == 5 || operation == 6 {
            return wallet::network_payment(
                operation,
                &bytes,
                database.as_bytes(),
                |name, journal| {
                    mesh.lock()
                        .map_err(|_| "mesh_lock_failed")?
                        .invoke(name, journal, &database)
                },
                |operation, payload| {
                    wallet::invoke(&service, &directory, &pins, parent, operation, payload)
                },
            );
        }
        if operation == 3 || operation == 4 {
            return Err("invalid_wallet_request".into());
        }
        let payload = wallet::payload(operation, &bytes)?;
        wallet::invoke(&service, &directory, &pins, parent, operation, &payload)
    })
    .await
    .map_err(|_| "wallet_worker_failed")??;
    Ok(Response::new(result))
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn credit_open_payment(
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<(), String> {
    let body = raw_body(&request, "invalid_wallet_request")?;
    let mesh = state.mesh.clone();
    let database = state.database.clone();
    tauri::async_runtime::spawn_blocking(move || {
        let request = wallet::journal(&body, database.as_bytes())?;
        let bytes = mesh.lock().map_err(|_| "mesh_lock_failed")?.invoke(
            "mesh_messenger_credit_payment_handoff",
            &request,
            &database,
        )?;
        let address = String::from_utf8(bytes).map_err(|_| "invalid_payment_url")?;
        wallet::open_payment_url(&address)
    })
    .await
    .map_err(|_| "wallet_worker_failed")?
}

fn attachment_body(body: &InvokeBody) -> Result<Vec<u8>, String> {
    request::bounded_binary_body(body, 1, 16 * 1024 * 1024, "invalid_attachment")
}

// A decrypted attachment leaves the web view only through the system save
// dialog, so the app never needs a filesystem scope of its own.
#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn save_attachment(app: tauri::AppHandle, request: Request<'_>) -> Result<bool, String> {
    let body = attachment_body(request.body())?;
    let name = request::safe_file_name(header(&request, "X-File-Name").unwrap_or_default());
    let dialog = app.dialog().file().set_file_name(name);
    tauri::async_runtime::spawn_blocking(move || match dialog.blocking_save_file() {
        None => Ok(false),
        Some(path) => {
            let path = path.into_path().map_err(|_| "invalid_save_path")?;
            std::fs::write(path, body).map_err(|_| "attachment_not_saved")?;
            Ok(true)
        }
    })
    .await
    .map_err(|_| "native_task_failed")?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn begin_attachment_save(
    app: tauri::AppHandle,
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<Option<u64>, String> {
    let bytes = request::bounded_binary_body(request.body(), 4, 4, "invalid_attachment_size")?;
    let size = u32::from_be_bytes(
        bytes
            .as_slice()
            .try_into()
            .map_err(|_| "invalid_attachment_size")?,
    ) as u64;
    if size == 0 || size > 536_870_912 {
        return Err("invalid_attachment_size".into());
    }
    let name = request::safe_file_name(header(&request, "X-File-Name").unwrap_or_default());
    let dialog = app.dialog().file().set_file_name(name);
    let saves = state.attachment_saves.clone();
    tauri::async_runtime::spawn_blocking(move || match dialog.blocking_save_file() {
        None => Ok(None),
        Some(path) => saves
            .begin(path.into_path().map_err(|_| "invalid_save_path")?, size)
            .map(Some),
    })
    .await
    .map_err(|_| "native_task_failed")?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn write_attachment_range(
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<(), String> {
    let bytes =
        request::bounded_binary_body(request.body(), 1, 65_536, "invalid_attachment_range")?;
    let id = header(&request, "X-Attachment-Id")
        .ok_or("invalid_attachment_range")?
        .parse::<u64>()
        .map_err(|_| "invalid_attachment_range")?;
    let offset = header(&request, "X-Attachment-Offset")
        .ok_or("invalid_attachment_range")?
        .parse::<u64>()
        .map_err(|_| "invalid_attachment_range")?;
    let saves = state.attachment_saves.clone();
    tauri::async_runtime::spawn_blocking(move || saves.write(id, offset, &bytes))
        .await
        .map_err(|_| "native_task_failed")?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn finish_attachment_save(state: tauri::State<'_, Desktop>, id: u64) -> Result<(), String> {
    let saves = state.attachment_saves.clone();
    tauri::async_runtime::spawn_blocking(move || saves.finish(id))
        .await
        .map_err(|_| "native_task_failed")?
}

#[cfg(not(target_os = "macos"))]
#[tauri::command]
async fn abort_attachment_save(state: tauri::State<'_, Desktop>, id: u64) -> Result<(), String> {
    let saves = state.attachment_saves.clone();
    tauri::async_runtime::spawn_blocking(move || saves.abort(id))
        .await
        .map_err(|_| "native_task_failed")?
}

// Updates come from the newest GitHub release and must carry the signature of
// the updater key in tauri.conf.json. A development or preview build would
// replace itself with a release, so it never updates.
async fn pending_update(
    app: &tauri::AppHandle,
    development: bool,
) -> Result<Option<Update>, String> {
    if development {
        return Err("updates_unavailable".into());
    }
    let updater = app.updater().map_err(|_| "update_check_failed")?;
    updater
        .check()
        .await
        .map_err(|_| "update_check_failed".into())
}

#[tauri::command]
async fn check_update(
    app: tauri::AppHandle,
    state: tauri::State<'_, Desktop>,
) -> Result<Option<String>, String> {
    let update = pending_update(&app, state.config.development).await?;
    Ok(update.map(|update| update.version))
}

// Windows exits into the installer, which starts the new version itself.
#[tauri::command]
async fn install_update(
    app: tauri::AppHandle,
    state: tauri::State<'_, Desktop>,
) -> Result<(), String> {
    let update = pending_update(&app, state.config.development)
        .await?
        .ok_or("update_not_found")?;
    update
        .download_and_install(|_, _| {}, || {})
        .await
        .map_err(|_| "update_install_failed")?;
    app.restart()
}

fn load_desktop(app: &tauri::AppHandle, directory: PathBuf, library: PathBuf, config: Config)
    -> Result<Desktop, Box<dyn std::error::Error>> {
    let core = mesh::Mesh::load(&library, config.security_frame.clone(), config.network_counter_frame.clone(),
        config.network_frame.clone(), config.ohttp_frame.clone(), config.credit_purpose.clone(),
        config.credit_usdc_mint_hex.clone(), config.lightning_network.clone(), config.issuer_tls_root.clone(),
        app.config().identifier.clone())?;
    Ok(Desktop {
        mesh: Arc::new(Mutex::new(core)),
        database: directory.join("morse.db").to_string_lossy().into_owned(),
        app_identifier: app.config().identifier.clone(), data: directory, config,
        attachment_saves: Arc::new(attachment_files::AttachmentSaves::default()),
    })
}

fn main() {
    #[cfg(target_os = "macos")]
    let invoke: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![
            desktop_lock::commands::app_lock_bind,
            desktop_lock::commands::app_lock_state,
            desktop_lock::commands::app_lock_check,
            desktop_lock::commands::app_lock_activate,
            desktop_lock::commands::app_lock_lock,
            desktop_lock::commands::app_lock_set_enabled,
            desktop_lock::commands::app_lock_cancel,
            desktop_lock::commands::app_lock_release,
            desktop_lock::commands::app_lock_window_action,
            desktop_lock::commands::app_lock_copy_text,
            desktop_lock::legacy_commands::app_lock_legacy_preference,
            desktop_lock::private_commands::credit_open_payment,
            desktop_lock::file_commands::app_lock_file,
            desktop_lock::file_commands::app_lock_file_cleanup,
            desktop_lock::notification_commands::app_lock_notification_binding,
            desktop_lock::notification_commands::app_lock_publish_notice,
            desktop_lock::notification_commands::app_lock_take_notice_intent,
            desktop_lock::commands::app_lock_close_mailbox,
            desktop_lock::private_commands::database_path,
            appearance,
            set_appearance,
            desktop_lock::private_commands::mesh_invoke,
            desktop_lock::private_commands::wallet_invoke,
            check_update,
            install_update
        ];
    #[cfg(not(target_os = "macos"))]
    let invoke: fn(tauri::ipc::Invoke<tauri::Wry>) -> bool = tauri::generate_handler![appearance, set_appearance, check_update, install_update];
    let builder = tauri::Builder::default().invoke_system(include_str!("ipc-postmessage.js"));
    // Protected macOS has one native UN ownership/delegate path. Preserve
    // the existing plugin on other desktop platforms only.
    #[cfg(not(target_os = "macos"))]
    let builder = builder.plugin(tauri_plugin_notification::init());
    let result = builder
        // The HTML already contains the branded cover. Keep the native
        // window hidden until that document is ready to paint.
        .on_page_load(|webview, payload| {
            if webview.label() != "main" { return; }
            #[cfg(target_os = "macos")]
            {
                let app = webview.app_handle();
                let Some(boot) = app.try_state::<Arc<desktop_lock::bootstrap::Bootstrap>>() else { return; };
                let Some(window) = app.get_webview_window("main") else { return; };
                match payload.event() {
                    tauri::webview::PageLoadEvent::Started => boot.navigation_started(window),
                    tauri::webview::PageLoadEvent::Finished => {
                        let _ = window.set_title_bar_style(tauri::TitleBarStyle::Overlay);
                        boot.page_finished(window);
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                let _ = webview.window().set_decorations(!cfg!(windows));
                let _ = webview.window().show();
            }
        })
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                #[cfg(target_os = "macos")]
                if let Some(boot) = app.try_state::<Arc<desktop_lock::bootstrap::Bootstrap>>() { boot.focus(window); }
                #[cfg(not(target_os = "macos"))]
                let _ = window.set_focus();
            }
        }))
        .on_window_event(|window, event| {
            #[cfg(target_os = "macos")]
            if window.label() == "main" {
                if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                    // Keep the owned primary available to the ordinary Dock or
                    // single-instance reopen path; native Hidden revokes it.
                    api.prevent_close();
                    let app=window.app_handle();
                    if let (Some(boot),Some(primary))=(app.try_state::<Arc<desktop_lock::bootstrap::Bootstrap>>(),app.get_webview_window("main")) { boot.hide(primary); }
                }
            }
        })
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_updater::Builder::new().build())
        .setup(|app| {
            let config: Config = serde_json::from_str(include_str!("../native/config.json"))?;
            if !cfg!(debug_assertions) && (config.development || config.security_frame.is_empty()) {
                return Err("Release binaries require production service configuration".into());
            }
            let directory = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&directory)?;
            let extension = if cfg!(windows) { "dll" } else { "dylib" };
            let library = app.path().resolve(
                format!("native/libmessenger_mobile.{extension}"), tauri::path::BaseDirectory::Resource)?;
            #[cfg(target_os = "macos")]
            {
                let boot = desktop_lock::bootstrap::Bootstrap::new(app.handle().clone())
                    .map_err(|_| "app_lock_unavailable")?;
                app.manage(boot.notifications.clone());
                app.manage(boot.clone());
                create_main_window(app)?;
                let window = app.get_webview_window("main").ok_or("app_lock_unavailable")?;
                apply_appearance(&window, appearance::load(&directory));
                let handle = app.handle().clone();
                let worker = boot.clone();
                boot.attach_primary(window, move || {
                    tauri::async_runtime::spawn_blocking(move || {
                        worker.initialize(&handle, &directory, || {
                            let desktop = load_desktop(&handle, directory.clone(), library, config)
                                .map_err(|_| "native_initialization_failed")?;
                            handle.manage(desktop); Ok(())
                        });
                    });
                })?;
            }
            #[cfg(not(target_os = "macos"))]
            {
                create_main_window(app)?;
                if let Some(window) = app.get_webview_window("main") {
                    apply_appearance(&window, appearance::load(&directory));
                }
                app.manage(load_desktop(app.handle(), directory, library, config)?);
            }
            Ok(())
        })
        .invoke_handler(invoke)
        .build(tauri::generate_context!());
    match result {
        Ok(app) => app.run(|app, event| {
            #[cfg(target_os = "macos")]
            if let Some(boot) = app.try_state::<Arc<desktop_lock::bootstrap::Bootstrap>>() {
                match event {
                    tauri::RunEvent::Reopen { .. } => {
                        if let Some(window) = app.get_webview_window("main") { boot.focus(window); }
                    }
                    tauri::RunEvent::Exit => boot.close(),
                    _ => {}
                }
            }
        }),
        Err(error) => { eprintln!("Morse could not start: {error}"); std::process::exit(1); }
    }
}

#[cfg(test)]
mod attachment_tests {
    use super::*;

    #[test]
    fn downloads_accept_the_full_attachment_limit_and_reject_invalid_bodies() {
        let mut bytes = vec![7; 16 * 1024 * 1024];
        bytes[0] = 1;
        *bytes.last_mut().unwrap() = 9;
        assert_eq!(
            attachment_body(&InvokeBody::Raw(bytes.clone())).unwrap(),
            bytes
        );
        assert!(attachment_body(&InvokeBody::Raw(Vec::new())).is_err());
        assert!(attachment_body(&InvokeBody::Raw(vec![0; 16 * 1024 * 1024 + 1])).is_err());
        assert!(attachment_body(&InvokeBody::Json(serde_json::Value::Null)).is_err());
    }
}

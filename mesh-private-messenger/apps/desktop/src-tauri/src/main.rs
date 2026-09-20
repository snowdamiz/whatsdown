#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod appearance;
mod mesh;
mod request;

use futures_util::StreamExt;
use serde::Deserialize;
use std::{
    collections::HashMap,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};
use tauri::{
    ipc::{Channel, InvokeBody, Request, Response},
    Manager,
};
use tauri_plugin_dialog::DialogExt;
use tokio_tungstenite::tungstenite::{client::IntoClientRequest, http::HeaderValue, Message};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Config {
    base_url: String,
    edge_url: String,
    stream_url: String,
    object_url: String,
    security_frame: String,
    development: bool,
}
struct Desktop {
    mesh: Arc<Mutex<mesh::Mesh>>,
    database: String,
    data: PathBuf,
    config: Config,
    http: reqwest::Client,
    streams: Mutex<HashMap<u32, tokio::task::JoinHandle<()>>>,
}

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

// Binary IPC: the web view sends bytes as the raw request body, with the small
// string parameters in headers, so wire frames never round-trip through JSON.
fn raw_body(request: &Request<'_>, error: &'static str) -> Result<Vec<u8>, String> {
    match request.body() {
        InvokeBody::Raw(bytes) if bytes.len() <= request::MAX_REQUEST => Ok(bytes.clone()),
        _ => Err(error.into()),
    }
}

fn header<'a>(request: &'a Request<'_>, name: &str) -> Option<&'a str> {
    request
        .headers()
        .get(name)
        .and_then(|value| value.to_str().ok())
}

#[tauri::command]
async fn mesh_invoke(
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<Response, String> {
    let body = raw_body(&request, "invalid_native_request")?;
    let symbol = header(&request, "X-Mesh-Symbol")
        .ok_or("invalid_native_request")?
        .to_owned();
    if symbol == "mesh_messenger_prepare_fanout_prekeys" {
        request::validate_prekey_url(&body, &state.config.base_url)?;
    }
    let mesh = Arc::clone(&state.mesh);
    let database = state.database.clone();
    tauri::async_runtime::spawn_blocking(move || {
        mesh.lock()
            .map_err(|_| "native_lock_failed")?
            .invoke(&symbol, &body, &database)
            .map(Response::new)
    })
    .await
    .map_err(|_| "native_task_failed")?
}

// The response is the HTTP status as two big-endian bytes followed by the body.
#[tauri::command]
async fn binary_request(
    state: tauri::State<'_, Desktop>,
    request: Request<'_>,
) -> Result<Response, String> {
    let body = raw_body(&request, "invalid_service_request")?;
    let url = header(&request, "X-Service-Url").unwrap_or_default();
    let method = header(&request, "X-Service-Method").unwrap_or_default();
    let capability = header(&request, "X-Object-Capability");
    let routes = request::Routes {
        base_url: &state.config.base_url,
        edge_url: &state.config.edge_url,
        object_url: &state.config.object_url,
    };
    if !request::allowed_request(&routes, url, method, capability)
        || (method == "GET" && !body.is_empty())
        || (capability.is_some() && body.len() > request::MAX_OBJECT_PART)
    {
        return Err("invalid_service_request".into());
    }
    let mut outgoing = state
        .http
        .request(method.parse().map_err(|_| "invalid_method")?, url)
        .header("Content-Type", "application/octet-stream")
        .body(body);
    if let Some(capability) = capability {
        outgoing = outgoing.header("X-Object-Capability", capability);
    }
    let mut response = outgoing.send().await.map_err(|_| "service_unreachable")?;
    let mut framed = response.status().as_u16().to_be_bytes().to_vec();
    while let Some(chunk) = response.chunk().await.map_err(|_| "service_read_failed")? {
        if framed.len() + chunk.len() > request::MAX_REQUEST + 2 {
            return Err("service_response_too_large".into());
        }
        framed.extend_from_slice(&chunk);
    }
    Ok(Response::new(framed))
}

fn attachment_body(body: &InvokeBody) -> Result<Vec<u8>, String> {
    match body {
        InvokeBody::Raw(bytes) if !bytes.is_empty() && bytes.len() <= 16 * 1024 * 1024 => {
            Ok(bytes.clone())
        }
        _ => Err("invalid_attachment".into()),
    }
}

// A decrypted attachment leaves the web view only through the system save
// dialog, so the app never needs a filesystem scope of its own.
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

#[tauri::command]
async fn mailbox_connect(
    state: tauri::State<'_, Desktop>,
    id: u32,
    authorization: String,
    events: Channel<String>,
) -> Result<(), String> {
    if authorization.len() > 1024
        || !authorization.starts_with("MeshMailbox ")
        || !authorization[12..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid_mailbox_authorization".into());
    }
    let mut streams = state.streams.lock().map_err(|_| "stream_lock_failed")?;
    streams.retain(|_, task| !task.is_finished());
    if streams.len() >= 4 || streams.contains_key(&id) {
        return Err("mailbox_connection_limit".into());
    }
    let url = state.config.stream_url.clone();
    streams.insert(
        id,
        tokio::spawn(async move {
            let result = async {
                let mut request = url.into_client_request().map_err(|_| ())?;
                request.headers_mut().insert(
                    "Authorization",
                    HeaderValue::from_str(&authorization).map_err(|_| ())?,
                );
                let socket_config =
                    tokio_tungstenite::tungstenite::protocol::WebSocketConfig::default()
                        .max_message_size(Some(1024))
                        .max_frame_size(Some(1024));
                let (mut socket, _) = tokio::time::timeout(
                    Duration::from_secs(8),
                    tokio_tungstenite::connect_async_with_config(
                        request,
                        Some(socket_config),
                        false,
                    ),
                )
                .await
                .map_err(|_| ())?
                .map_err(|_| ())?;
                while let Some(message) = socket.next().await {
                    match message.map_err(|_| ())? {
                        Message::Text(text) if text == "ready" || text == "encrypted-wakeup" => {
                            events.send(text.to_string()).map_err(|_| ())?;
                        }
                        Message::Ping(_) | Message::Pong(_) => (),
                        Message::Close(_) => break,
                        _ => return Err(()),
                    }
                }
                Ok::<(), ()>(())
            }
            .await;
            let _ = events.send(if result.is_ok() { "closed" } else { "error" }.into());
        }),
    );
    Ok(())
}

#[tauri::command]
fn mailbox_disconnect(state: tauri::State<Desktop>, id: u32) -> Result<(), String> {
    if let Some(task) = state
        .streams
        .lock()
        .map_err(|_| "stream_lock_failed")?
        .remove(&id)
    {
        task.abort();
    }
    Ok(())
}

fn main() {
    let result = tauri::Builder::default()
        .plugin(tauri_plugin_notification::init())
        // The HTML already contains the branded cover. Keep the native
        // window hidden until that document is ready to paint.
        .on_page_load(|webview, payload| {
            if payload.event() == tauri::webview::PageLoadEvent::Finished {
                // Windows draws its own caption buttons. Reloading also exits
                // the development preview and restores the host's decorations.
                if let Err(error) = webview.window().set_decorations(!cfg!(windows)) {
                    eprintln!("Could not configure window decorations: {error}");
                }
                #[cfg(target_os = "macos")]
                if let Err(error) = webview.window().set_title_bar_style(tauri::TitleBarStyle::Overlay) {
                    eprintln!("Could not restore the overlay title bar: {error}");
                }
                let _ = webview.window().show();
            }
        })
        .plugin(tauri_plugin_single_instance::init(|app, _, _| {
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.set_focus();
            }
        }))
        .plugin(tauri_plugin_dialog::init())
        .setup(|app| {
            let config: Config = serde_json::from_str(include_str!("../native/config.json"))?;
            if !cfg!(debug_assertions) && (config.development || config.security_frame.is_empty()) {
                return Err("Release binaries require production service configuration".into());
            }
            let directory = app.path().app_local_data_dir()?;
            std::fs::create_dir_all(&directory)?;
            let extension = if cfg!(windows) { "dll" } else { "dylib" };
            let library = app.path().resolve(
                format!("native/libmessenger_mobile.{extension}"),
                tauri::path::BaseDirectory::Resource,
            )?;
            // Match the database's app identifier so development never uses release keys.
            let core = mesh::Mesh::load(
                &library,
                config.security_frame.clone(),
                app.config().identifier.clone(),
            )?;
            // The window already exists but has not painted: dress it in the
            // saved scheme now so the first frame is the right one.
            if let Some(window) = app.get_webview_window("main") {
                apply_appearance(&window, appearance::load(&directory));
            }
            app.manage(Desktop {
                mesh: Arc::new(Mutex::new(core)),
                database: directory.join("morse.db").to_string_lossy().into_owned(),
                data: directory,
                config,
                http: reqwest::Client::builder()
                    .redirect(reqwest::redirect::Policy::none())
                    .timeout(Duration::from_secs(8))
                    .build()?,
                streams: Mutex::new(HashMap::new()),
            });
            #[cfg(debug_assertions)]
            if std::env::var_os("MORSE_DEVTOOLS").is_some() {
                if let Some(window) = app.get_webview_window("main") {
                    window.open_devtools();
                }
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            database_path,
            appearance,
            set_appearance,
            mesh_invoke,
            binary_request,
            save_attachment,
            mailbox_connect,
            mailbox_disconnect
        ])
        .run(tauri::generate_context!());
    if let Err(error) = result {
        eprintln!("Morse could not start: {error}");
        std::process::exit(1);
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

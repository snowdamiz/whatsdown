use std::borrow::Cow;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use tauri::{
    ipc::{Request, Response},
    utils::assets::{AssetKey, AssetsIter, CspHash},
    Assets, Runtime,
};

#[allow(dead_code)]
#[path = "../src/navigation.rs"]
mod navigation;
#[allow(dead_code)]
#[path = "../src/request.rs"]
mod request;

#[derive(Default)]
struct ProbeState {
    network_hits: AtomicUsize,
    denied_navigation: AtomicUsize,
    denied_popups: AtomicUsize,
}

struct ProbeAssets;
impl<R: Runtime> Assets<R> for ProbeAssets {
    fn get(&self, _: &AssetKey) -> Option<Cow<'_, [u8]>> {
        Some(Cow::Borrowed(b"<!doctype html><html><head><title>Morse IPC proof</title></head><body>Local native transport proof</body></html>"))
    }
    fn iter(&self) -> Box<AssetsIter<'_>> {
        Box::new(std::iter::empty())
    }
    fn csp_hashes(&self, _: &AssetKey) -> Box<dyn Iterator<Item = CspHash<'_>> + '_> {
        Box::new(std::iter::empty())
    }
}

#[tauri::command]
fn probe_echo(request: Request<'_>) -> Result<Response, String> {
    if request
        .headers()
        .get("X-Morse-Probe")
        .and_then(|h| h.to_str().ok())
        != Some("binary")
    {
        return Err("missing_probe_header".into());
    }
    request::binary_body(request.body(), "invalid_probe_binary").map(Response::new)
}

#[tauri::command]
fn probe_channel(channel: tauri::ipc::Channel<Vec<u8>>) -> Result<(), String> {
    channel
        .send(vec![42; 65_576])
        .map_err(|error| error.to_string())
}

#[tauri::command]
fn probe_finish(state: tauri::State<'_, Arc<ProbeState>>, mut report: serde_json::Value) {
    let hits = state.network_hits.load(Ordering::SeqCst);
    let navigation = state.denied_navigation.load(Ordering::SeqCst);
    report["loopback_network_hits"] = hits.into();
    report["denied_external_navigation"] = navigation.into();
    report["denied_popups"] = state.denied_popups.load(Ordering::SeqCst).into();
    if hits != 0 || navigation == 0 {
        report["result"] = "failed".into();
    }
    let path = std::env::var("MORSE_IPC_REPORT_PATH").expect("isolated proof report path");
    std::fs::write(path, serde_json::to_vec_pretty(&report).unwrap()).unwrap();
    let status = if report["result"] == "passed" { 0 } else { 1 };
    std::process::exit(status);
}

fn main() {
    let state = Arc::new(ProbeState::default());
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let received = state.clone();
    std::thread::spawn(move || {
        for _ in 0..2000 {
            while let Ok((connection, _)) = listener.accept() {
                received.network_hits.fetch_add(1, Ordering::SeqCst);
                drop(connection);
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    });
    let mut context = tauri::generate_context!();
    context.set_assets(Box::new(ProbeAssets));
    tauri::Builder::default()
        .manage(state.clone())
        .invoke_system(include_str!("../src/ipc-postmessage.js"))
        .invoke_handler(tauri::generate_handler![
            probe_echo,
            probe_channel,
            probe_finish
        ])
        .setup(move |app| {
            let navigate = state.clone();
            let popup = state.clone();
            tauri::WebviewWindowBuilder::new(
                app,
                "main",
                tauri::WebviewUrl::App("index.html".into()),
            )
            .visible(false)
            .on_navigation(move |url| {
                let allowed = navigation::allowed(url);
                if !allowed {
                    navigate.denied_navigation.fetch_add(1, Ordering::SeqCst);
                }
                allowed
            })
            .on_new_window(move |_, _| {
                popup.denied_popups.fetch_add(1, Ordering::SeqCst);
                tauri::webview::NewWindowResponse::Deny
            })
            .initialization_script(include_str!("ipc_probe.js").replace(
                "__MORSE_PROBE_ORIGIN__",
                &serde_json::to_string(&origin).unwrap(),
            ))
            .build()?;
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_secs(20));
                std::process::exit(2);
            });
            Ok(())
        })
        .run(context)
        .expect("owned WKWebView proof");
}

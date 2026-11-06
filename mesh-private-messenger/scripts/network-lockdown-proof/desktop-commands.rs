
#[tauri::command]
fn network_probe_echo(request: Request<'_>) -> Result<Response,String> {
 Ok(Response::new(request::bounded_binary_body(request.body(),65537,65537,"bad_probe_bytes")?))
}
#[tauri::command]
fn network_probe_fail() -> Result<(),String> { Err("native_probe_rejected".into()) }
#[tauri::command]
fn network_probe_channel(channel: tauri::ipc::Channel<Vec<u8>>) -> Result<(),String> {
 channel.send(vec![1,2,3]).map_err(|_|"channel_failed")?;
 channel.send(vec![7;8192]).map_err(|_|"channel_failed")?;
 Ok(())
}
#[tauri::command]
fn network_probe_report(app:tauri::AppHandle,report:serde_json::Value) -> Result<(),String> {
 let path=std::env::var("MORSE_NETWORK_PROBE_REPORT").map_err(|_|"missing_probe_path")?;
 std::fs::write(path,serde_json::to_vec_pretty(&report).map_err(|_|"bad_report")?).map_err(|_|"report_failed")?;
 app.exit(if report["passed"]==true {0} else {1}); Ok(())
}

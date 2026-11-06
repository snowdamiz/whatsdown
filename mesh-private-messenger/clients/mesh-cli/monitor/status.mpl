from Monitor.Config import MonitorConfig
from Monitor.State import MonitorState, read_monitor_state

fn cached_status(config :: MonitorConfig, now :: Int) -> Result<(Int, String), String> do
  let state = read_monitor_state(config.path, config.identity)?
  let document = Json.parse(state.report)?
  let checked = Json.as_int(Json.object_get(document, "checked_at_ms")?)?
  let healthy = Json.as_bool(Json.object_get(document, "healthy")?)?
  let stale = now < checked || now - checked > 120000
  let healthy = healthy && !stale && Bytes.length(state.proof) == 0
  Ok((if healthy do
      200
    else
      503
    end,
    "{\"healthy\":#{healthy},\"stale\":#{stale},\"snapshot\":#{state.report}}"))
end

pub fn monitor_status(config :: MonitorConfig, now :: Int) -> (Int, String) do
  case cached_status(config, now) do
    Err(_) -> (503, "{\"healthy\":false,\"stale\":true,\"error\":\"monitor_not_ready\"}")
    Ok(value) -> value
  end
end

pub fn monitor_evidence(config :: MonitorConfig, context :: Bool) -> (Int, Bytes) do
  case read_monitor_state(config.path, config.identity) do
    Err(_) -> (503, Bytes.empty())
    Ok(state) -> do
      let bytes = if context do
        state.proof_context
      else
        state.proof
      end
      if Bytes.length(bytes) == 0 do
        (404, Bytes.empty())
      else
        (200, bytes)
      end
    end
  end
end

fn response(status :: Int, bytes :: Bytes, content_type :: String) -> Response do
  HTTP.response_bytes_with_headers(status,
    bytes,
    Map.new()
      |> Map.put("Content-Type", content_type)
      |> Map.put("Cache-Control", "no-store")
      |> Map.put("X-Content-Type-Options", "nosniff")
      |> Map.put("Content-Security-Policy",
        "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'"))
end

fn page() -> String do
  "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Morse log monitor</title>"
    <> "<style>body{font:17px/1.6 system-ui,sans-serif;max-width:52rem;margin:4rem auto;padding:0 1.5rem;background:#f5f7f8;color:#172b35}h1{line-height:1.2}section{background:white;border:1px solid #ccd6dc;border-radius:12px;padding:1.5rem;margin:1rem 0}pre{overflow:auto;font-size:13px}a{color:#125e82}#health{font-weight:650}li{overflow-wrap:anywhere}</style>"
    <> "<h1>Morse log monitor</h1><p>Independent checks of public checkpoints, witness attendance and registry keys.</p>"
    <> "<section aria-live=\"polite\"><p id=\"health\">Waiting for a cached result…</p><p id=\"log\"></p><p id=\"when\"></p><ul id=\"issues\"></ul><p id=\"attendance\"></p></section>"
    <> "<p><a href=\"/status\">Status JSON</a> · <a href=\"/evidence.frk\" download>Fork evidence</a> · <a href=\"/evidence-context\" download>Observation context</a></p>"
    <> "<p>Fork evidence is retained across restarts. Observation context records this monitor’s RPC view; consumers must independently authenticate chain accounts. Missing proofs and network failures are reported separately from proven forks.</p>"
    <> "<script>async function poll(){const health=document.getElementById('health');try{const r=await fetch('/status',{cache:'no-store'});const data=await r.json();health.textContent=data.healthy?'Healthy':data.stale?'Monitor result unavailable or expired':'Needs attention';const s=data.snapshot||{};document.getElementById('log').textContent=s.log?'Log: '+s.log+' (version '+s.log_version+')':'';document.getElementById('when').textContent=s.checked_at_ms?'Last check: '+new Date(s.checked_at_ms).toISOString():'';const list=document.getElementById('issues');list.replaceChildren();for(const issue of s.issues||[]){const item=document.createElement('li');item.textContent=issue.replaceAll('_',' ');list.append(item)}const a=s.attendance;document.getElementById('attendance').textContent=a?'Witness thresholds: '+a.met+' met, '+a.pending+' waiting, '+a.missed+' missed, '+a.lost+' no longer checkable.':''}catch{health.textContent='Status connection unavailable'}}poll();setInterval(poll,15000)</script></html>"
end

pub fn serve_monitor_status(config :: MonitorConfig, port :: Int) do
  HTTP.router()
    |> HTTP.on_get("/",
      fn(_request :: Request) do response(200,
        Bytes.from_utf8(page()),
        "text/html; charset=utf-8") end)
    |> HTTP.on_get("/status",
      fn(_request :: Request) do
        let (status, body) = monitor_status(config, DateTime.to_unix_ms(DateTime.utc_now()))
        response(status, Bytes.from_utf8(body), "application/json")
      end)
    |> HTTP.on_get("/evidence.frk",
      fn(_request :: Request) do
        let (status, bytes) = monitor_evidence(config, false)
        response(status, bytes, "application/x-morse-fork")
      end)
    |> HTTP.on_get("/evidence-context",
      fn(_request :: Request) do
        let (status, bytes) = monitor_evidence(config, true)
        response(status, bytes, "application/octet-stream")
      end)
    |> HTTP.serve(port)
end

##! The status page: /status.json (written into the state at the end of every
##! cycle) and a small HTML page that renders it.

from Monitor.Chain import (
  ChainLog,
  ChainWitness,
  RingEntry,
  RingHeader,
  monitor_cosigned,
  monitor_decode_entry
)
from Monitor.Flags import MonitorConfig
from Monitor.Mirror import monitor_mirror_size, monitor_mirror_verified
from Monitor.Report import Context
from Security.Config import SecurityConfig, SecurityWitness
from Monitor.Store import (
  Filing,
  Finding,
  StoredEntry,
  monitor_entries_count,
  monitor_entries_counted,
  monitor_filings,
  monitor_findings,
  monitor_kv_get,
  monitor_store_open
)

fn quoted(value :: String) -> String do
  Json.encode_string(value)
end

fn or_null(value :: String) -> String do
  if value == "" do
    "null"
  else
    value
  end
end

fn entry_of(text :: String) -> Option<RingEntry> do
  let parts = String.split(text, ":")
  if List.length(parts) != 2 do
    None
  else
    case (String.to_int(List.get(parts, 0)), Bytes.from_hex(List.get(parts, 1))) do
      (Some(index), Ok(bytes)) -> case monitor_decode_entry(index, bytes) do
        Err(_) -> None
        Ok(entry) -> Some(entry)
      end
      _ -> None
    end
  end
end

fn position_json(text :: String) -> String do
  case entry_of(text) do
    None -> "null"
    Some(entry) -> "{\"ring_index\":#{entry.index},\"sequence\":#{entry.sequence},\"tree_size\":#{entry.tree_size},\"slot\":#{entry.slot},\"timestamp_ms\":#{entry.timestamp_ms},\"evidence\":#{entry.evidence}}"
  end
end

fn header_json(header :: Option<RingHeader>, slot :: Int) -> String do
  case header do
    None -> "null"
    Some(value) -> "{\"head\":#{value.head},\"count\":#{value.count},\"last_sequence\":#{value.last_sequence},\"last_tree_size\":#{value.last_size},\"last_slot\":#{value.last_slot},\"finalized_slot\":#{slot}}"
  end
end

fn decoded(rows :: List<StoredEntry>) -> List<RingEntry> do
  List.flat_map(rows,
    fn row -> case monitor_decode_entry(row.ring_index, row.entry) do
      Err(_) -> List.new()
      Ok(entry) -> [entry]
    end end)
end

fn witness_json(log :: ChainLog, entries :: List<RingEntry>, index :: Int) -> String do
  let count = List.length(List.filter(entries, fn entry -> monitor_cosigned(log, entry, index) end))
  "{\"witness_id\":#{quoted(List.get(log.witnesses, index).witness_id)},\"cosigned\":#{count}}"
end

fn epoch_json(ctx :: Context, epoch :: Int) -> String!String do
  let entries = decoded(monitor_entries_counted(ctx.db, epoch)?)
  let witnesses = for index in 0..List.length(ctx.log.witnesses) do
    witness_json(ctx.log, entries, index)
  end
  let below = List.length(List.filter(monitor_entries_counted(ctx.db, epoch)?,
    fn row -> row.cosign == "below" end))
  Ok("{\"epoch\":#{epoch},\"anchors\":#{List.length(entries)},\"below_threshold\":#{below},\"witnesses\":[#{String.join(witnesses,
    ",")}]}")
end

fn filing_json(value :: Filing) -> String do
  "{\"relay\":#{quoted(value.relay)},\"status\":#{value.status},\"attempts\":#{value.attempts}}"
end

fn finding_json(ctx :: Context, value :: Finding) -> String!String do
  let filed = if value.proof_hash == "" do
    List.new()
  else
    List.map(monitor_filings(ctx.db, value.proof_hash)?, filing_json)
  end
  let proof = if value.proof_hash == "" do
    "null"
  else
    quoted(value.proof_hash)
  end
  Ok("{\"key\":#{quoted(value.key)},\"severity\":#{quoted(value.severity)},\"kind\":#{quoted(value.kind)},\"detail\":#{quoted(value.detail)},\"found_at_ms\":#{value.found_at},\"proof_hash\":#{proof},\"filed\":[#{String.join(filed,
    ",")}]}")
end

fn strings_json(values :: List<String>) -> String do
  "[" <> String.join(List.map(values, quoted), ",") <> "]"
end

fn set_json(ctx :: Context) -> List<String> do
  List.map(ctx.config.sets,
    fn set -> "{\"set_id\":#{quoted(Bytes.to_hex(set.set_id))},\"threshold\":#{set.threshold},\"witnesses\":#{strings_json(List.map(set.witnesses,
      fn witness -> witness.witness_id end))}}" end)
end

# Builds the status document for the end of this cycle. header is None when
# the chain could not be read (two providers did not agree).

pub fn monitor_status_json(ctx :: Context,
  header :: Option<RingHeader>,
  notes :: List<String>) -> String!String do
  let epoch = ctx.now_ms / 1000 / 604800
  let findings = for value in monitor_findings(ctx.db)? do
    finding_json(ctx, value)?
  end
  let epochs = case header do
    None -> List.new()
    Some(_) -> [epoch_json(ctx, epoch)?, epoch_json(ctx, epoch - 1)?]
  end
  let p0 = List.length(List.filter(monitor_findings(ctx.db)?,
    fn value -> value.severity == "P0" end))
  Ok("{\"log\":#{quoted(ctx.config.log_name)},\"judge\":#{quoted(ctx.config.judge)},\"log_account\":#{quoted(ctx.config.log_account)},\"directory\":#{quoted(ctx.config.directory)},\"updated_at_ms\":#{ctx.now_ms},\"ok\":#{p0 == 0},\"inconsistencies\":#{p0},\"service_slashed\":#{ctx.log.service_slashed},\"ring\":#{header_json(header,
    ctx.slot)},\"position\":#{position_json(monitor_kv_get(ctx.db,
    "position")?)},\"last_verified_pair\":#{or_null(monitor_kv_get(ctx.db,
    "last_pair")?)},\"pending_entries\":#{monitor_entries_count(ctx.db,
    "pair = 'pending'")?},\"mirror\":{\"size\":#{monitor_mirror_size(ctx.db)?},\"verified_size\":#{monitor_mirror_verified(ctx.db)?}},\"epochs\":[#{String.join(epochs,
    ",")}],\"sets\":[#{String.join(set_json(ctx),
    ",")}],\"relays\":#{strings_json(ctx.config.relays)},\"findings\":[#{String.join(findings,
    ",")}],\"notes\":#{strings_json(notes)}}")
end

# --- Serving it.

fn page() -> String do
  """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Morse monitor</title>
<style>
:root { color-scheme: light dark; --ink: #1d1d1f; --muted: #6e6e73; --line: #d2d2d7; --bad: #b3261e; --good: #1b7f3a; --paper: #fff; }
@media (prefers-color-scheme: dark) { :root { --ink: #f5f5f7; --muted: #a1a1a6; --line: #3a3a3c; --bad: #ff6b60; --good: #5fd08a; --paper: #111; } }
body { font: 15px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: var(--ink); background: var(--paper); margin: 0 auto; max-width: 960px; padding: 16px; }
h1 { font-size: 22px; margin: 0 0 4px; } h2 { font-size: 16px; margin: 24px 0 8px; }
.muted { color: var(--muted); } .bad { color: var(--bad); font-weight: 600; } .good { color: var(--good); font-weight: 600; }
table { border-collapse: collapse; width: 100%; } td, th { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; }
code { font-size: 13px; word-break: break-all; }
</style>
</head>
<body>
<h1>Morse transparency monitor</h1>
<p id="summary" class="muted">Loading…</p>
<h2>Ring</h2><table id="ring"></table>
<h2>Cosignatures per witness</h2><table id="epochs"></table>
<h2>Findings</h2><table id="findings"></table>
<h2>Notes from the last cycle</h2><ul id="notes"></ul>
<p class="muted">Machine-readable: <a href="status.json">status.json</a></p>
<script>
const text = (value) => String(value == null ? "–" : value);
const cell = (value, tag) => "<" + tag + ">" + value + "</" + tag + ">";
const row = (cells, tag) => "<tr>" + cells.map((value) => cell(value, tag || "td")).join("") + "</tr>";
const escape = (value) => text(value).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" })[c]);
const time = (ms) => (ms ? new Date(ms).toISOString().slice(0, 19).replace("T", " ") + " UTC" : "–");
const bad = (value) => '<span class="bad">' + value + "</span>";
fetch("status.json", { cache: "no-store" }).then((r) => r.json()).then((s) => {
  const state = s.ok ? '<span class="good">No inconsistencies</span>' : bad(s.inconsistencies + (s.inconsistencies === 1 ? " inconsistency" : " inconsistencies"));
  document.getElementById("summary").innerHTML = state + " · log <code>" + escape(s.log) + "</code> · updated " + time(s.updated_at_ms);
  const p = s.position || {}, pair = s.last_verified_pair || {}, ring = s.ring || {};
  document.getElementById("ring").innerHTML = [
    row(["Position", p.ring_index == null ? "–" : "index " + p.ring_index + ", sequence " + p.sequence + ", tree size " + p.tree_size]),
    row(["Anchored", p.slot == null ? "–" : "slot " + p.slot + ", " + time(p.timestamp_ms)]),
    row(["Last verified pair", pair.old_sequence == null ? "–" : pair.old_sequence + " → " + pair.new_sequence + " (tree size " + pair.old_tree_size + " → " + pair.new_tree_size + ")"]),
    row(["Waiting to check", escape(s.pending_entries)]),
    row(["Finalized slot", escape(ring.finalized_slot)]),
    row(["Leaf copy", escape(s.mirror.size) + " leaves, verified to " + escape(s.mirror.verified_size)]),
    row(["Relays", s.relays.length ? s.relays.map(escape).join("<br>") : "none"]),
    row(["Service slashed", s.service_slashed ? bad("yes") : "no"]),
  ].join("");
  document.getElementById("epochs").innerHTML = s.epochs.length === 0 ? row(["–"]) :
    row(["Witness"].concat(s.epochs.map((e) => "Epoch " + e.epoch + " (" + e.anchors + " anchors)")), "th") +
    s.epochs[0].witnesses.map((w, i) => row([escape(w.witness_id)].concat(s.epochs.map((e) => escape(e.witnesses[i] ? e.witnesses[i].cosigned : null))))).join("");
  document.getElementById("findings").innerHTML = s.findings.length === 0 ? row(["None"]) :
    row(["Severity", "Found", "What", "Filed with relays"], "th") +
    s.findings.map((f) => row([
      f.severity === "P0" ? bad(escape(f.severity)) : escape(f.severity),
      time(f.found_at_ms),
      "<strong>" + escape(f.kind) + "</strong><br>" + escape(f.detail) + (f.proof_hash ? "<br><code>" + escape(f.proof_hash) + "</code>" : ""),
      f.filed.map((x) => escape(x.relay) + ": " + escape(x.status)).join("<br>") || "–",
    ])).join("");
  document.getElementById("notes").innerHTML = s.notes.length ? s.notes.map((n) => "<li>" + escape(n) + "</li>").join("") : "<li>none</li>";
}).catch((e) => { document.getElementById("summary").textContent = "Status unavailable: " + e; });
</script>
</body>
</html>
"""
end

fn serve_page(_request :: Request) -> Response do
  HTTP.response_with_headers(200, page(), %{"Content-Type" => "text/html; charset=utf-8"})
end

fn stored_status(path :: String) -> String!String do
  let db = monitor_store_open(path)?
  let value = monitor_kv_get(db, "status")
  Sqlite.close(db)
  value
end

fn serve_status(path :: String) -> Response do
  case stored_status(path) do
    Ok(value) -> if value == "" do
      HTTP.response(503, "{\"error\":\"no cycle has finished yet\"}")
    else
      HTTP.response_with_headers(200,
        value,
        %{"Content-Type" => "application/json", "Cache-Control" => "no-store"})
    end
    Err(_) -> HTTP.response(503, "{\"error\":\"state unavailable\"}")
  end
end

actor status_server(port :: Int, path :: String) do
  HTTP.router()
    |> HTTP.on_get("/", serve_page)
    |> HTTP.on_get("/status.json", fn _request -> serve_status(path) end)
    |> HTTP.serve(port)
end

# Serves the page on port, reading the status the last cycle stored in the
# state at path.

pub fn monitor_serve(port :: Int, path :: String) do
  let _server = spawn(status_server, port, path)
end

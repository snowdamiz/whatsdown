// Alerting for the witness network (plan §12): collect the signals, evaluate
// the plan's thresholds, notify. Dependency-free; runs from the acceptance
// workflow every 5 minutes, and from any host that can see a component's log
// lines (a relay's P0s) on a timer. README.md has the full routing table.
//
//   node ops/acceptance/alerts.mjs --state alert-state.json [--results results.json]
//     [--log FILE[@SOURCE]]... [--contacts contacts.json] [--database-bytes N] [--dry-run]
//
// Severities: warn, page, P0. Recipients: morse (the on-call), operator:<witness
// id>, operators (every operator), relay:<origin>. A Morse-run witness's
// operator is Morse: with no contact for an operator the alert goes to Morse.
import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';

const SOL = 1_000_000_000;
const EPOCH_SECONDS = 604_800;
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const RANK = { warn: 1, page: 2, P0: 3 };
const REPEAT = { warn: DAY, page: HOUR, P0: 30 * MINUTE };

// ---- collection ----

async function fetchJson(http, url) {
  try {
    const response = await http(url, { headers: { Accept: 'application/json' }, signal: AbortSignal.timeout(15_000) });
    if (!response.ok) return { error: `${new URL(url).host} answered ${response.status}`, httpStatus: response.status };
    return await response.json();
  } catch (error) {
    return { error: `${new URL(url).host}: ${String(error.message).slice(0, 200)}` };
  }
}

// logs: [{source, text}], e.g. `docker logs --since 6m morse-relay` as
// relay:https://relay.example. Only P0, PAGE and WARN lines are kept.
export async function collect({ env, http = fetch, now = Date.now(), logs = [], results = [], databaseBytes = null, suppress = [] }) {
  const base = env.MORSE_DIRECTORY_URL;
  const signals = { at: now, lines: [], results, suppress, rewardsConfigured: Boolean(env.MORSE_REWARDS_PROGRAM) };
  if (base) {
    signals.directory = await fetchJson(http, env.MORSE_DIRECTORY_HEALTH_URL ?? `${base}/v1/transparency/health`);
    signals.network = await fetchJson(http, `${base}/v1/network/status.json`);
    try {
      signals.backend = { status: (await http(`${base}/health`, { signal: AbortSignal.timeout(15_000) })).status };
    } catch (error) {
      signals.backend = { status: 0, error: String(error.message).slice(0, 200) };
    }
  }
  if (env.MORSE_MONITOR_STATUS_URL) signals.monitor = await fetchJson(http, env.MORSE_MONITOR_STATUS_URL);
  if (env.MORSE_CREDIT_ISSUER_HEALTH_URL) signals.issuer = await fetchJson(http, env.MORSE_CREDIT_ISSUER_HEALTH_URL);
  if (databaseBytes !== null) signals.database = { bytes: Number(databaseBytes) };
  for (const { source, text } of logs) {
    for (const line of text.split('\n')) if (/^(P0|PAGE|WARN) /.test(line)) signals.lines.push({ source, line: line.trim() });
  }
  return signals;
}

// ---- conditions ----

const hash = text => { let h = 0; for (const c of text) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h.toString(16); };
const field = (line, name) => line.match(new RegExp(`${name}=(\\S+)`))?.[1];
const percentile = (values, p) => { const sorted = [...values].sort((a, b) => a - b); return sorted[Math.max(0, Math.ceil(p * sorted.length) - 1)]; };

// What each log line means (the jobs Worker's, the relay's and the monitor's).
function lineCondition({ source, line }) {
  const [severity, name] = line.split(' ');
  const event = { event: true, summary: `${line} (${source})` };
  if (name === 'fork_evidence_received') return { ...event, key: `fork_evidence:${field(line, 'proof') ?? hash(line)}`, severity: 'P0', recipients: ['morse', 'operators'] };
  if (name === 'relay_finder_mismatch') {
    return { ...event, key: `relay_finder_mismatch:${field(line, 'proof') ?? hash(line)}`, severity: 'P0',
      recipients: [source.startsWith('relay:') ? source : 'morse', 'morse'].filter((r, i, all) => all.indexOf(r) === i) };
  }
  if (name === 'morse-monitor' && severity === 'P0') return { ...event, key: `monitor_finding:${hash(line)}`, severity: 'P0', recipients: ['morse', 'operators'] };
  if (name === 'settle_epoch_late') return { ...event, key: `settle_epoch_late:${field(line, 'epoch')}`, severity: 'warn', recipients: ['morse'] };
  if (name.startsWith('burn_')) return { ...event, key: `burn:${hash(line)}`, severity: 'warn', recipients: ['morse'] };
  return { ...event, key: `line:${name}:${hash(line)}`, severity: severity === 'PAGE' ? 'page' : severity, recipients: ['morse'] };
}

// Every condition active now: {key, severity, recipients, summary, forMs?,
// ageMs?}. forMs: fire once active that long (first seen, from the state);
// ageMs: how long the condition has already lasted, when the source says.
function conditions(s, state, now) {
  const out = [];
  const add = condition => out.push(condition);
  const suppressed = id => (s.suppress ?? []).some(x => x.witness_id === id && x.until_ms > now);
  const d = s.directory;
  const n = s.network;
  const anchoring = n && !n.error && n.operations?.anchor_mode && n.operations.anchor_mode !== 'off';

  if (s.backend?.status === 0) add({ key: 'backend_unreachable', severity: 'page', recipients: ['morse'], forMs: 2 * MINUTE, summary: `backend unreachable: ${s.backend.error}` });
  else if (s.backend?.status >= 500 && !(s.suppress ?? []).some(x => x.until_ms > now)) {
    add({ key: 'backend_health', severity: 'warn', recipients: ['morse'], forMs: 5 * MINUTE, summary: `backend /health answers ${s.backend.status}` });
  }

  if (d?.error) add({ key: 'directory_unreachable', severity: 'page', recipients: ['morse'], forMs: 2 * MINUTE, summary: `directory health: ${d.error}` });
  if (d && !d.error) {
    if (d.checkpoint_sequence !== null && d.threshold_met === false) {
      const signed = (d.witnesses ?? []).filter(w => w.status === 'pinned' && w.signed_current).length;
      add({ key: 'threshold_not_met', severity: 'page', recipients: ['morse'], forMs: 2 * MINUTE,
        summary: `threshold not met for checkpoint ${d.checkpoint_sequence}: ${signed} of ${d.threshold} needed pinned witnesses signed` });
    }
    for (const w of d.witnesses ?? []) {
      if (!['pinned', 'shadow'].includes(w.status) || suppressed(w.witness_id)) continue;
      const key = `witness_silent:${w.witness_id}`;
      const known = w.last_signature_age_seconds;
      const ageMs = known === null ? (state.since?.[key] ? now - state.since[key] : 0) : known * 1000;
      if (known === null || known >= 60) {
        add({ key, severity: 'page', ageMs, forMs: 10 * MINUTE, recipients: ageMs >= 30 * MINUTE ? [`operator:${w.witness_id}`, 'morse'] : [`operator:${w.witness_id}`],
          summary: `${w.status} witness ${w.witness_id} has not signed for ${known === null ? `at least ${Math.round(ageMs / MINUTE)} min (never seen signing)` : `${Math.round(known / 60)} min`}` });
      }
    }
    if (d.last_pruning_day !== undefined) {
      const age = d.last_pruning_day ? now - Date.parse(`${d.last_pruning_day}T00:00:00Z`) : Infinity;
      if (age >= 2 * DAY) add({ key: 'pruning', severity: 'warn', recipients: ['morse'], summary: `pruning last ran ${d.last_pruning_day ?? 'never'}` });
    }
    if (d.tree_size >= 8_000_000) add({ key: 'log_size', severity: 'warn', recipients: ['morse'], summary: `the log holds ${d.tree_size} leaves: plan the G5 tile move before 10 million` });
  }

  if (n?.error) add({ key: 'network_status_unreachable', severity: 'warn', recipients: ['morse'], forMs: 10 * MINUTE, summary: `status.json: ${n.error}` });
  if (anchoring) {
    const time = n.last_public_checkpoint?.time;
    const gapS = time ? (now - Date.parse(time)) / 1000 : d?.last_anchor_age_seconds;
    if (gapS >= 3600 || n.operations.pages?.includes('anchor_gap')) {
      add({ key: 'anchor_gap', severity: 'page', recipients: ['morse'], summary: `no anchor for ${Math.round(gapS / 60)} min` });
    }
    const lamports = Number(n.operations.fee_payer?.lamports ?? NaN);
    if (lamports < 0.05 * SOL) add({ key: 'fee_payer', severity: 'page', recipients: ['morse'], summary: `fee payer holds ${lamports / SOL} SOL (page below 0.05)` });
    else if (lamports < 0.2 * SOL) add({ key: 'fee_payer', severity: 'warn', recipients: ['morse'], summary: `fee payer holds ${lamports / SOL} SOL (warn below 0.2)` });
    if (n.log === 'morse-main') {
      if (n.status === 'unavailable' && n.reason !== 'no_snapshot_yet') add({ key: 'bond_counter', severity: 'warn', recipients: ['morse'], summary: `bond counter unavailable: ${n.reason}` });
      if (n.status === 'ok' && (n.stale || now - Date.parse(n.generated_at) > 5 * MINUTE)) {
        add({ key: 'bond_counter_stale', severity: 'warn', recipients: ['morse'], summary: `bond counter snapshot from ${n.generated_at}` });
      }
    }
    if (s.rewardsConfigured) {
      const due = Math.floor((now / 1000 - 3600) / EPOCH_SECONDS) - 1;
      const settled = n.operations.settled_epoch;
      if (settled === null || settled === undefined || settled < due) {
        add({ key: `settle_epoch_late:${due}`, severity: 'warn', recipients: ['morse'], summary: `settle_epoch has not run for epoch ${due} an hour after its boundary` });
      }
    }
  }

  const m = s.monitor;
  if (m?.error) add({ key: 'monitor_unreachable', severity: 'warn', recipients: ['morse'], forMs: 10 * MINUTE, summary: `monitor status: ${m.error}` });
  if (m && !m.error) {
    const p0 = (m.findings ?? []).filter(f => f.severity === 'P0');
    if (!m.ok || m.inconsistencies > 0 || p0.length) {
      add({ key: 'monitor_inconsistency', severity: 'P0', recipients: ['morse', 'operators'],
        summary: `monitor inconsistency: ${p0.map(f => `${f.kind} ${f.detail ?? ''}`.trim()).join('; ') || `${m.inconsistencies} findings`}` });
    } else if (now - Number(m.updated_at_ms ?? 0) > 10 * MINUTE) {
      add({ key: 'monitor_stuck', severity: 'warn', recipients: ['morse'], summary: `the monitor's last cycle ended ${Math.round((now - m.updated_at_ms) / MINUTE)} min ago` });
    }
  }

  const i = s.issuer;
  if (i?.error) add({ key: 'credits_issuer', severity: 'page', recipients: ['morse'], summary: `credit issuer: ${i.error}` });
  else if (i && i.mode !== 'off' && i.next_key_provisioned === false) {
    add({ key: 'credits_next_key', severity: 'warn', recipients: ['morse'], summary: 'the credit issuer has no key for the next epoch: quotes stop at the boundary' });
  }
  // The last credits drill's redemptions stand until the next drill (weekly).
  const redemptions = state.redemptions ?? [];
  if (redemptions.some(r => r.status === 503)) add({ key: 'credits_spent_set', severity: 'page', recipients: ['morse'], summary: 'a redemption answered 503: the spent set is failing closed' });
  if (redemptions.length && percentile(redemptions.map(r => r.ms), 0.95) > 500) {
    add({ key: 'credits_latency', severity: 'page', recipients: ['morse'], summary: `redemption latency p95 ${percentile(redemptions.map(r => r.ms), 0.95)} ms (over 500)` });
  }

  for (const [id, result] of Object.entries(state.acceptance ?? {})) {
    if (result.status === 'fail') add({ key: `acceptance:${id}`, severity: 'page', recipients: ['morse'], summary: `acceptance check ${id} (${result.name}) failed: ${result.detail}` });
  }
  const growth = state.databaseGrowth;
  if (growth > 0.2) add({ key: 'database_growth', severity: 'warn', recipients: ['morse'], summary: `the directory database grew ${Math.round(growth * 100)}% in a month` });

  for (const line of s.lines ?? []) add(lineCondition(line));
  return out;
}

// Keeps a daily database size sample for 40 days; growth is against the
// newest sample at least 28 days old.
function databaseGrowth(state, bytes, now) {
  const samples = (state.dbSamples ?? []).filter(x => now - x.at <= 40 * DAY);
  if (!samples.length || now - samples.at(-1).at >= 20 * HOUR) samples.push({ at: now, bytes });
  state.dbSamples = samples;
  const old = samples.filter(x => now - x.at >= 28 * DAY).at(-1);
  return old ? (bytes - old.bytes) / old.bytes : 0;
}

// ---- evaluation ----

// {notify, resolved, active, state}: what to send now, what cleared, and the
// state for the next run (first-seen times, what was sent, sticky results).
export function evaluate(signals, { state: previous = {}, now = Date.now() } = {}) {
  const state = structuredClone(previous);
  state.since ??= {};
  state.notified ??= {};
  state.acceptance ??= {};
  for (const result of signals.results ?? []) {
    state.acceptance[result.id] = { status: result.status, name: result.name, detail: result.detail };
    if (result.id === 8) state.redemptions = result.measurements?.redemptions ?? [];
  }
  state.databaseGrowth = signals.database ? databaseGrowth(state, signals.database.bytes, now) : state.databaseGrowth ?? 0;

  const active = conditions(signals, state, now);
  const activeKeys = new Set(active.map(c => c.key));
  for (const key of Object.keys(state.since)) if (!activeKeys.has(key)) delete state.since[key];
  const notify = [];
  for (const condition of active) {
    state.since[condition.key] ??= now;
    const lasted = Math.max(now - state.since[condition.key], condition.ageMs ?? 0);
    if (condition.forMs && lasted < condition.forMs) continue;
    const sent = state.notified[condition.key];
    const escalated = sent && (RANK[condition.severity] > RANK[sent.severity] || condition.recipients.some(r => !sent.recipients.includes(r)));
    const repeat = sent && !condition.event && now - sent.at >= REPEAT[condition.severity];
    if (sent && !escalated && !repeat) continue;
    const { forMs, ageMs, ...alert } = condition;
    notify.push(alert);
    state.notified[condition.key] = { severity: condition.severity, recipients: condition.recipients, summary: condition.summary, at: now, event: Boolean(condition.event) };
  }
  const resolved = [];
  for (const [key, sent] of Object.entries(state.notified)) {
    if (sent.event) {
      if (now - sent.at > 30 * DAY) delete state.notified[key];
      continue;
    }
    if (activeKeys.has(key)) continue;
    resolved.push({ key, severity: sent.severity, recipients: sent.recipients, summary: sent.summary });
    delete state.notified[key];
  }
  return { notify, resolved, active, state };
}

// ---- notifiers ----

// contacts.json: {"morse": [dest], "operators": {"<witness id>": [dest]},
// "relays": {"<origin>": [dest]}}; dest: {"format": "slack" | "discord" |
// "json" | "pagerduty", "url", "routing_key"}. Morse's own webhook may come
// from MORSE_ALERT_WEBHOOK (+ MORSE_ALERT_FORMAT, MORSE_ALERT_ROUTING_KEY).
function morseDestinations(contacts, env) {
  const fromEnv = env.MORSE_ALERT_WEBHOOK || env.MORSE_ALERT_ROUTING_KEY
    ? [{ url: env.MORSE_ALERT_WEBHOOK, format: env.MORSE_ALERT_FORMAT ?? (env.MORSE_ALERT_ROUTING_KEY ? 'pagerduty' : 'json'), routing_key: env.MORSE_ALERT_ROUTING_KEY }]
    : [];
  return [...fromEnv, ...(contacts.morse ?? [])];
}

function destinationsFor(recipient, contacts, env) {
  if (recipient === 'morse') return morseDestinations(contacts, env).map(d => ({ ...d }));
  if (recipient === 'operators') return Object.values(contacts.operators ?? {}).flat();
  const [kind, ...rest] = recipient.split(':');
  const id = rest.join(':');
  const listed = (kind === 'operator' ? contacts.operators?.[id] : kind === 'relay' ? contacts.relays?.[id] : null) ?? [];
  return listed.length ? listed : morseDestinations(contacts, env).map(d => ({ ...d, note: `no contact for ${recipient}` }));
}

function body(destination, alert, resolved) {
  const text = `${resolved ? '[resolved]' : `[${alert.severity}]`} ${alert.summary}${destination.note ? ` (${destination.note})` : ''} [${alert.key}]`;
  if (destination.format === 'slack') return { text };
  if (destination.format === 'discord') return { content: text.slice(0, 2000) };
  if (destination.format === 'pagerduty') {
    return resolved ? { routing_key: destination.routing_key, event_action: 'resolve', dedup_key: alert.key }
      : { routing_key: destination.routing_key, event_action: 'trigger', dedup_key: alert.key,
        payload: { summary: text.slice(0, 1024), source: 'morse-acceptance', severity: { P0: 'critical', page: 'error', warn: 'warning' }[alert.severity] } };
  }
  return { text, alert: { ...alert, resolved } };
}

export async function notify({ notify: alerts = [], resolved = [] }, { contacts = {}, env = {}, http = fetch }) {
  const sent = [];
  for (const [list, isResolved] of [[alerts, false], [resolved, true]]) {
    for (const alert of list) {
      const seen = new Set();
      for (const destination of alert.recipients.flatMap(r => destinationsFor(r, contacts, env))) {
        const url = destination.url ?? (destination.format === 'pagerduty' ? 'https://events.pagerduty.com/v2/enqueue' : null);
        const id = `${url}#${destination.routing_key ?? ''}`;
        if (!url || seen.has(id)) continue;
        seen.add(id);
        try {
          const response = await http(url, { method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body(destination, alert, isResolved)), signal: AbortSignal.timeout(15_000) });
          sent.push({ key: alert.key, host: new URL(url).host, status: response.status });
        } catch (error) {
          sent.push({ key: alert.key, host: new URL(url).host, error: String(error.message) });
        }
      }
    }
  }
  return sent;
}

// ---- CLI ----

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { state: { type: 'string' }, results: { type: 'string' }, log: { type: 'string', multiple: true },
    contacts: { type: 'string' }, 'database-bytes': { type: 'string' }, suppress: { type: 'string' }, 'dry-run': { type: 'boolean' } } });
  if (!values.state) throw new Error('--state FILE is required');
  const read = (file, fallback) => file && existsSync(file) ? JSON.parse(readFileSync(file, 'utf8')) : fallback;
  const env = Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== '')); // unset GitHub variables are ''
  const logs = (values.log ?? []).map(spec => {
    const [file, source = file] = spec.split('@');
    return { source, text: existsSync(file) ? readFileSync(file, 'utf8') : '' };
  });
  const signals = await collect({ env, logs, results: read(values.results, { results: [] }).results,
    databaseBytes: values['database-bytes'] || env.MORSE_DATABASE_BYTES || null, suppress: read(values.suppress, []) });
  const contacts = read(values.contacts ?? env.MORSE_ALERT_CONTACTS, {});
  const out = evaluate(signals, { state: read(values.state, {}), now: signals.at });
  for (const alert of out.notify) console.log(`${alert.severity} ${alert.key}: ${alert.summary} -> ${alert.recipients.join(', ')}`);
  for (const alert of out.resolved) console.log(`resolved ${alert.key}`);
  if (!values['dry-run']) {
    for (const x of await notify(out, { contacts, env })) if (x.error || x.status >= 300) console.error(`notify ${x.key} via ${x.host}: ${x.error ?? x.status}`);
    writeFileSync(values.state, JSON.stringify(out.state, null, 1));
  }
  console.log(`${out.active.length} active, ${out.notify.length} sent, ${out.resolved.length} resolved`);
}

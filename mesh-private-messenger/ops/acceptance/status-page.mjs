// The public status page (plan §12): current profile, pinned set, per-witness
// attendance per epoch, last anchor, burns, bonds and slashes, plus the latest
// acceptance results. A static page and its JSON, rendered from the jobs
// Worker's /v1/network/status.json, the directory's registry, the monitor's
// status and the previous page's JSON, which is how slashes, burns and
// attendance are kept for good even if a source forgets them (§6.17).
//
//   node ops/acceptance/status-page.mjs --out site [--previous FILE|URL] [--results results.json]
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { parseArgs } from 'node:util';
import { fileURLToPath } from 'node:url';
import { parseSecurityConfig, securityFrame } from './config.mjs';

const byNewest = (key, compare) => (a, b) => compare(b[key], a[key]);
const bigCompare = (a, b) => (BigInt(a ?? 0) > BigInt(b ?? 0) ? 1 : BigInt(a ?? 0) < BigInt(b ?? 0) ? -1 : 0);
const textCompare = (a, b) => String(a ?? '').localeCompare(String(b ?? ''));
const union = (older = [], newer = [], id) => [...new Map([...older, ...newer].filter(x => x?.[id]).map(x => [x[id], x])).values()];

export function statusDocument({ frame, registry = null, network = null, monitor = null, results = null, previous = null, now = Date.now() }) {
  const config = parseSecurityConfig(frame);
  const entries = new Map((registry?.witnesses ?? []).map(w => [w.witness_id, w]));
  const ok = network?.status === 'ok';
  const attendance = new Map((previous?.attendance ?? []).map(e => [e.epoch, e]));
  for (const epoch of monitor?.epochs ?? []) {
    attendance.set(epoch.epoch, { epoch: epoch.epoch, anchors: epoch.anchors, below_threshold: epoch.below_threshold,
      witnesses: epoch.witnesses.map(w => ({ witness_id: w.witness_id, cosigned: w.cosigned,
        percent: epoch.anchors ? Math.round((w.cosigned / epoch.anchors) * 1000) / 10 : null })) });
  }
  const acceptance = new Map((previous?.acceptance ?? []).map(r => [r.id, r]));
  for (const r of results ?? []) acceptance.set(r.id, { id: r.id, name: r.name, status: r.status, detail: r.detail, at: r.at });
  return {
    version: 1,
    generated_at: new Date(now).toISOString(),
    profile: { name: config.profile, line: config.profileLine, k: config.k, n: config.witnesses.length, set_id: config.setId },
    pinned: config.witnesses.map(w => ({ witness_id: w.id, operator: w.label, morse_run: w.label === 'Morse', public_key: w.key,
      registry_status: entries.get(w.id)?.status ?? 'not in the registry' })),
    shadow: [...entries.values()].filter(w => w.status === 'shadow').map(w => ({ witness_id: w.witness_id, operator: w.operator, morse_run: w.morse_run })),
    network: network ? { status: network.status, reason: network.reason ?? null, cluster: network.cluster ?? previous?.network?.cluster ?? null,
      log_account: network.log_account ?? previous?.network?.log_account ?? null, generated_at: network.generated_at ?? null } : previous?.network ?? null,
    last_anchor: (ok && network.last_public_checkpoint) || previous?.last_anchor || null,
    bonds: (ok && network.bonded) || previous?.bonds || null,
    slashed: (ok && network.slashed) || previous?.slashed || null,
    slashes: union(previous?.slashes, network?.slash_history, 'proof').sort(byNewest('slot', bigCompare)),
    // ponytail: every burn is kept (about 25 a week); page them if the file ever gets heavy.
    burns: union(previous?.burns, network?.operations?.burns, 'signature').sort(byNewest('at', textCompare)),
    attendance: [...attendance.values()].sort((a, b) => b.epoch - a.epoch),
    acceptance: [...acceptance.values()].sort((a, b) => a.id - b.id),
  };
}

const escape = value => String(value ?? '–').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const link = (url, text) => /^https:\/\//.test(url ?? '') ? `<a href="${escape(url)}">${escape(text)}</a>` : escape(text);
const table = (head, rows) => rows.length
  ? `<table><thead><tr>${head.map(h => `<th>${escape(h)}</th>`).join('')}</tr></thead><tbody>${rows.map(r => `<tr>${r.map(c => `<td>${c}</td>`).join('')}</tr>`).join('')}</tbody></table>`
  : '<p class="muted">None.</p>';

export function renderHtml(doc) {
  const anchor = doc.last_anchor;
  const bonds = doc.bonds;
  const witnessIds = [...new Set(doc.attendance.flatMap(e => e.witnesses.map(w => w.witness_id)))];
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Morse network status</title>
<style>
:root { --bg: #ffffff; --fg: #111418; --muted: #5d6670; --line: #e3e6ea; --ok: #1a7f37; --fail: #c62828; --skip: #8a6d00; --link: #0b62c4; }
@media (prefers-color-scheme: dark) { :root { --bg: #0f1216; --fg: #e8eaed; --muted: #9aa3ad; --line: #262b31; --ok: #4cc26d; --fail: #ff6b6b; --skip: #e0b53a; --link: #7ab4ff; } }
body { margin: 0; background: var(--bg); color: var(--fg); font: 15px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif; }
main { max-width: 960px; margin: 0 auto; padding: 24px 16px 48px; }
h1 { font-size: 24px; margin: 0 0 4px; } h2 { font-size: 17px; margin: 32px 0 8px; }
.profile { font-size: 19px; font-weight: 600; margin: 12px 0 4px; } .muted { color: var(--muted); }
.table-wrap { overflow-x: auto; } table { border-collapse: collapse; width: 100%; font-size: 14px; }
th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid var(--line); vertical-align: top; } th { font-weight: 600; }
a { color: var(--link); } code { font-size: 12px; word-break: break-all; }
.ok { color: var(--ok); } .fail { color: var(--fail); } .skip { color: var(--skip); }
</style>
</head>
<body><main>
<h1>Morse network status</h1>
<p class="muted">Updated ${escape(doc.generated_at)}. Every on-chain number links to its account or transaction. <a href="status.json">status.json</a></p>
<p class="profile">${escape(doc.profile.line)}</p>
<p class="muted">Phones accept a key when ${escape(doc.profile.k)} of these ${escape(doc.profile.n)} witnesses signed it${doc.profile.set_id ? ` (set <code>${escape(doc.profile.set_id.slice(0, 16))}</code>)` : ''}.</p>

<h2>Pinned witnesses</h2>
<div class="table-wrap">${table(['Witness', 'Operator', 'Registry', 'Key'], doc.pinned.map(w => [escape(w.witness_id), escape(w.operator), escape(w.registry_status), `<code>${escape(w.public_key)}</code>`]))}</div>
${doc.shadow.length ? `<p class="muted">In their shadow week: ${doc.shadow.map(w => `${escape(w.witness_id)} (${escape(w.operator)})`).join(', ')}.</p>` : ''}

<h2>Last public checkpoint</h2>
${anchor ? `<p>Sequence ${escape(anchor.sequence)}, tree size ${escape(anchor.tree_size)}, anchored ${escape(anchor.time)} at slot ${link(anchor.link, anchor.slot)}.</p>` : '<p class="muted">Nothing anchored yet.</p>'}
${doc.network?.status && doc.network.status !== 'ok' ? `<p class="skip">The chain reading is unavailable right now (${escape(doc.network.reason)}); these are the last numbers that agreed.</p>` : ''}

<h2>Attendance per epoch</h2>
<div class="table-wrap">${table(['Epoch', 'Anchors', ...witnessIds], doc.attendance.map(e => [escape(e.epoch), escape(e.anchors),
    ...witnessIds.map(id => { const w = e.witnesses.find(x => x.witness_id === id); return w ? `${escape(w.percent)}% (${escape(w.cosigned)})` : '–'; })]))}</div>

<h2>Bonds</h2>
${bonds ? `<div class="table-wrap">${table(['Party', 'Status', 'Bond (USD)'], [
    ['Directory', escape(bonds.directory?.status), link(bonds.directory?.link, bonds.directory?.usd ?? bonds.directory?.amount)],
    ...(bonds.witnesses ?? []).map(w => [escape(w.witness_id), escape(`${w.status}${w.excluded ? ', excluded from pay' : ''}`), link(w.link, w.usd ?? w.amount)])])}</div>` : '<p class="muted">No bonds on-chain yet.</p>'}

<h2>Slashes</h2>
${doc.slashes.length ? `<div class="table-wrap">${table(['Proof', 'Kind', 'Slot', 'Finder paid', 'Transaction'], doc.slashes.map(s => [link(s.account_link, s.proof.slice(0, 16)),
    escape(s.kind), escape(s.slot), `<code>${escape(s.paid_to)}</code>`, link(s.link, s.tx_signature ? s.tx_signature.slice(0, 16) : 'account')]))}</div>`
    : '<p>Never slashed.</p>'}

<h2>Burns</h2>
<div class="table-wrap">${table(['When', 'USDC spent', 'Tokens burned', 'Transaction'], doc.burns.map(b => [escape(b.at), escape(b.spent), escape(b.burned), link(b.link, b.signature?.slice(0, 16))]))}</div>

<h2>Acceptance checks</h2>
<div class="table-wrap">${table(['Check', 'Result', 'Detail', 'Run'], doc.acceptance.map(r => [escape(`${r.id}. ${r.name}`), `<span class="${escape(r.status)}">${escape(r.status)}</span>`,
    escape(r.detail), escape(r.at)]))}</div>
</main></body>
</html>
`;
}

async function readSource(http, location) {
  if (!location) return null;
  if (/^https?:\/\//.test(location)) {
    const response = await http(location, { signal: AbortSignal.timeout(15_000) }).catch(() => null);
    return response?.ok ? response.json() : null;
  }
  return existsSync(location) ? JSON.parse(readFileSync(location, 'utf8')) : null;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { values } = parseArgs({ options: { out: { type: 'string' }, previous: { type: 'string' }, results: { type: 'string' } } });
  if (!values.out) throw new Error('--out DIR is required');
  const env = Object.fromEntries(Object.entries(process.env).filter(([, value]) => value !== '')); // unset GitHub variables are ''
  const frame = securityFrame(env);
  if (!frame) throw new Error('the release security config is required (MORSE_SECURITY_CONFIG or the MESSENGER_* variables)');
  const base = env.MORSE_DIRECTORY_URL;
  const doc = statusDocument({
    frame,
    network: base ? await readSource(fetch, `${base}/v1/network/status.json`) : null,
    registry: base ? await readSource(fetch, `${base}/v1/transparency/registry`) : null,
    monitor: await readSource(fetch, env.MORSE_MONITOR_STATUS_URL),
    results: (await readSource(fetch, values.results))?.results ?? null,
    previous: await readSource(fetch, values.previous),
  });
  mkdirSync(values.out, { recursive: true });
  writeFileSync(join(values.out, 'status.json'), JSON.stringify(doc, null, 1));
  writeFileSync(join(values.out, 'index.html'), renderHtml(doc));
  console.log(`status page: ${doc.profile.line}; ${doc.slashes.length} slashes, ${doc.attendance.length} epochs, ${doc.burns.length} burns`);
}

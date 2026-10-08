// The parts of these pages that aren't static files: the waitlist form posts here, and the network's public
// numbers come through here (below). Each waitlist address is a key in
// KV, so joining twice changes nothing, and its value is only the day it joined. No IP, browser or referrer
// is kept. `wrangler deploy` creates the namespace the first time. To read the list, from this directory:
//   ../../ops/cloudflare/node_modules/.bin/wrangler kv key list --binding WAITLIST --remote
// ponytail: no rate limit; add a `ratelimits` binding if junk starts filling the list.
const looksLikeEmail = /^[^\s@]+@[^\s@.]+(\.[^\s@.]+)+$/;

// ---- The network's public numbers, for witnesses.html's "Current witnesses" and the bond counter
// (WITNESS_NETWORK_PLAN.md §4.4, §6.17). The pages load nothing from third parties, so they ask this origin,
// and this Worker asks the backend (MORSE_BACKEND_URL). Only fields checked here are passed on; anything
// unexpected, too big or unreachable is a 502, and the pages keep the static words they were written with.
// Answers, good or bad, are kept for a minute.
const hex32 = /^[0-9a-f]{64}$/, witnessId = /^[a-z0-9-]{1,64}$/, label = /^[\x21-\x7e](?:[\x20-\x7e]{0,46}[\x21-\x7e])?$/;
// Mainnet only: a devnet link carries ?cluster=devnet, and devnet numbers are rehearsals, not the public record.
const explorer = /^https:\/\/explorer\.solana\.com\/(?:(?:address|tx)\/[1-9A-HJ-NP-Za-km-z]{32,88}|block\/\d{1,20})$/;
const usd = /^\d{1,15}\.\d{2}$/, iso = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/;
const is = (re, v) => typeof v === "string" && re.test(v);
const bad = () => { throw new Error("unexpected shape"); };
const link = (v) => (is(explorer, v) ? v : bad());
// A bond is real once there is money in its vault, priced in dollars.
const bond = (b) => (b.usd === null ? null : is(usd, b.usd) ? (Number(b.usd) > 0 ? { usd: b.usd, link: link(b.link) } : null) : bad());

// GET /v1/transparency/registry → the pinned witnesses and the trust profile they add up to (INTERFACES §4).
function registryView(body) {
  const all = Array.isArray(body?.witnesses) && body.witnesses.length <= 256 ? body.witnesses : bad();
  for (const w of all) {
    if (!(is(witnessId, w?.witness_id) && is(hex32, w.public_key) && is(label, w.operator) && typeof w.morse_run === "boolean"
      && ["shadow", "pinned", "retired"].includes(w.status))) bad();
  }
  if (new Set(all.map((w) => w.witness_id)).size !== all.length) bad();
  const pinned = all.filter((w) => w.status === "pinned");
  if (!pinned.length || pinned.length > 16) bad();
  // Either field saying Morse counts: the page may understate independence, never overstate it (plan I9).
  const witnesses = pinned.map((w) => ({ witness_id: w.witness_id, operator: w.operator, public_key: w.public_key, morse_run: w.morse_run || w.operator === "Morse" }));
  const k = Math.floor(pinned.length / 2) + 1, m = witnesses.filter((w) => w.morse_run).length;
  return { profile: m >= k ? "bootstrap" : m > 1 ? "transitional" : "open", k, witnesses };
}

// GET /v1/network/status.json (ops/cloudflare/network.mjs) → what the bond counter may show. Every number
// comes with its explorer link. A slash stays for good, whatever else the snapshot says.
function statusView(s) {
  if (s?.log !== "morse-main" || !["ok", "unavailable"].includes(s.status) || !Array.isArray(s.slash_history)) bad();
  const out = { state: "none", checkpoint: null, bonded: null, slashed: null, witnesses: {}, slashes: s.slash_history.map((x) => ({ link: link(x?.link) })) };
  const mainnet = s.operations?.anchor_mode === "mainnet";
  if (s.status === "unavailable") {
    // Once the counter has run, it never just disappears: a failed read or a disagreement says so.
    if (mainnet && (["rpc_disagree", "rpc_error"].includes(s.reason) || s.last_good_at)) out.state = "unavailable";
    return out;
  }
  if (s.cluster !== "mainnet-beta") return out;
  if (s.stale) return { ...out, state: "unavailable" };
  const cp = s.last_public_checkpoint;
  if (cp && cp.time !== null) out.checkpoint = { time: is(iso, cp.time) ? cp.time : bad(), link: link(cp.link) };
  out.bonded = bond(s.bonded.directory);
  for (const w of s.bonded.witnesses) {
    const b = bond(w);
    if (b) out.witnesses[is(witnessId, w.witness_id) ? w.witness_id : bad()] = b;
  }
  if (typeof s.slashed?.never !== "boolean") bad();
  out.slashed = { never: s.slashed.never, link: link(s.slashed.link) };
  out.state = "ok";
  return out;
}

const NETWORK = {
  "/network/registry.json": ["/v1/transparency/registry", 64 * 1024, registryView],
  "/network/status.json": ["/v1/network/status.json", 256 * 1024, statusView],
};

async function capped(res, limit) {
  const reader = res.body.getReader(), text = new TextDecoder();
  let out = "", size = 0;
  for (let part; !(part = await reader.read()).done;) {
    if ((size += part.value.length) > limit) { await reader.cancel(); bad(); }
    out += text.decode(part.value, { stream: true });
  }
  return out + text.decode();
}

async function network(request, env, [path, limit, shape]) {
  if (request.method !== "GET") return new Response(null, { status: 405, headers: { allow: "GET" } });
  const key = new URL(request.url);
  key.search = "";
  const cache = globalThis.caches?.default;
  const hit = await cache?.match(new Request(key));
  if (hit) return hit;
  let body = null;
  try {
    const res = await fetch(new URL(path, env.MORSE_BACKEND_URL), { headers: { accept: "application/json" }, signal: AbortSignal.timeout(5000) });
    if (res.ok) body = JSON.stringify(shape(JSON.parse(await capped(res, limit))));
  } catch {}
  const headers = { "cache-control": "public, max-age=60", "x-content-type-options": "nosniff" };
  const res = body ? new Response(body, { headers: { ...headers, "content-type": "application/json" } }) : new Response(null, { status: 502, headers });
  await cache?.put(new Request(key), res.clone());
  return res;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (NETWORK[url.pathname]) return network(request, env, NETWORK[url.pathname]);
    if (url.pathname !== "/waitlist") return new Response("Not found", { status: 404 });
    if (request.method !== "POST") return new Response(null, { status: 405, headers: { allow: "POST" } });

    const form = await request.formData().catch(() => new FormData());
    const email = String(form.get("email") ?? "").trim().toLowerCase();
    if (email.length > 254 || !looksLikeEmail.test(email)) return new Response("That doesn’t look like an email address.", { status: 400 });
    // People never see this field; bots fill in everything. They're told it worked.
    if (!form.get("company")) await env.WAITLIST.put(email, new Date().toISOString().slice(0, 10));

    // The page's script only needs to know it worked. A form posted without script goes back to the page, which
    // then shows it's done.
    if (request.headers.get("sec-fetch-mode") === "navigate") return Response.redirect(new URL("/#joined", url), 303);
    return new Response(null, { status: 204 });
  },
};

// `node --test waitlist.test.mjs` from this directory. KV is a Map here; the Worker only ever puts.
import assert from "node:assert/strict";
import test from "node:test";
import worker from "./waitlist.mjs";

const kv = () => Object.assign(new Map(), { async put(k, v) { this.set(k, v); } });
const post = (fields, headers = {}) => new Request("https://morseapp.io/waitlist", { method: "POST", body: new URLSearchParams(fields), headers });

test("an address joins once, however it's typed", async () => {
  const env = { WAITLIST: kv() };
  assert.equal((await worker.fetch(post({ email: " Ada@Example.com " }), env)).status, 204);
  await worker.fetch(post({ email: "ada@example.com" }), env);
  assert.deepEqual([...env.WAITLIST.keys()], ["ada@example.com"]);
});

test("a form posted without script lands back on the page, saying so", async () => {
  const res = await worker.fetch(post({ email: "ada@example.com" }, { "sec-fetch-mode": "navigate" }), { WAITLIST: kv() });
  assert.equal(res.status, 303);
  assert.equal(res.headers.get("location"), "https://morseapp.io/#joined");
});

test("junk and bots are not kept", async () => {
  const env = { WAITLIST: kv() };
  assert.equal((await worker.fetch(post({ email: "not an email" }), env)).status, 400);
  assert.equal((await worker.fetch(post({ email: `${"a".repeat(250)}@example.com` }), env)).status, 400);
  // The hidden field only a bot fills in: it's told it worked, and nothing is stored.
  assert.equal((await worker.fetch(post({ email: "bot@example.com", company: "Acme" }), env)).status, 204);
  assert.equal(env.WAITLIST.size, 0);
});

test("nothing else is served from here", async () => {
  assert.equal((await worker.fetch(new Request("https://morseapp.io/waitlist"), { WAITLIST: kv() })).status, 405);
  assert.equal((await worker.fetch(new Request("https://morseapp.io/nope", { method: "POST" }), { WAITLIST: kv() })).status, 404);
});

// ---- The network's public numbers. The backend is a mocked `fetch`; its answers are shaped like
// ops/cloudflare's registry route and network.mjs status() (bond-counter.mjs snapshots).
const backend = "https://backend.test";
const EX = "https://explorer.solana.com";
const key = (c) => c.repeat(64);
const witness = (id, operator, status = "pinned", morse_run = operator === "Morse") =>
  ({ witness_id: id, public_key: key(id.at(-1) === "a" ? "a" : "b"), operator, status, software: "mesh", morse_run, c2sp_name: null });
const logAccount = `Log${"1".repeat(41)}`, vault = `Vau${"1".repeat(41)}`, wvault = `WVau${"1".repeat(40)}`, tx = "5".repeat(88);
// Production today: anchoring off, so the jobs never wrote a snapshot.
const today = { log: "morse-main", status: "unavailable", reason: "no_snapshot_yet", slash_history: [], stale: false,
  operations: { anchor_mode: "off", log: "morse-main", last_anchor: null, fee_payer: null, settled_epoch: null, burns: [], pages: [] } };
const live = (over = {}) => ({
  log: "morse-main", status: "ok", generated_at: "2026-09-29T12:00:00.000Z", cluster: "mainnet-beta", judge_program: `Judge${"1".repeat(39)}`,
  log_account: { address: logAccount, link: `${EX}/address/${logAccount}` },
  last_public_checkpoint: { slot: "900", sequence: "41", tree_size: "12", time: "2026-09-29T11:59:20.000Z", age_seconds: 40, link: `${EX}/block/900` },
  bonded: {
    directory: { status: "Active", amount: "50000000000", mint: "USDC", usd: "50000.00", account: vault, link: `${EX}/address/${vault}` },
    witnesses: [{ witness_id: "witness-a", status: "Active", excluded: true, amount: "10000000000", mint: "USDC", usd: "10000.00", account: wvault, vault: wvault, link: `${EX}/address/${wvault}` },
      { witness_id: "witness-b", status: "Registered", excluded: true, amount: "0", mint: null, usd: null, account: wvault, vault: wvault, link: `${EX}/address/${wvault}` }],
  },
  slashed: { service: false, witnesses: 0, never: true, link: `${EX}/address/${logAccount}` },
  slash_history: [], stale: false, operations: { ...today.operations, anchor_mode: "mainnet" }, ...over,
});

// Answers each backend path from `routes` (a value is JSON, a Response is sent as it is) and counts the calls.
function mockBackend(routes) {
  const calls = [];
  const real = globalThis.fetch;
  globalThis.fetch = async (url) => {
    calls.push(String(url));
    const answer = routes[new URL(url).pathname];
    if (answer === undefined) return new Response("Not found", { status: 404 });
    return answer instanceof Response ? answer : new Response(JSON.stringify(answer), { headers: { "content-type": "application/json" } });
  };
  return { calls, restore: () => { globalThis.fetch = real; } };
}
const get = (path, env = { MORSE_BACKEND_URL: backend }) => worker.fetch(new Request(`https://morseapp.io${path}`), env);
async function view(path, routes) {
  const mock = mockBackend(routes);
  try {
    const res = await get(path);
    return { status: res.status, cache: res.headers.get("cache-control"), body: res.status === 200 ? await res.json() : null, calls: mock.calls };
  } finally { mock.restore(); }
}

test("the registry comes through as the pinned witnesses and the trust profile they add up to", async () => {
  const res = await view("/network/registry.json", { "/v1/transparency/registry": { witnesses: [
    witness("witness-a", "Morse"), witness("witness-b", "Morse"), witness("o1-shadow", "Someone", "shadow"), witness("old-c", "Morse", "retired"),
  ] } });
  assert.deepEqual(res.calls, [`${backend}/v1/transparency/registry`]);
  assert.equal(res.cache, "public, max-age=60");
  assert.deepEqual(res.body, { profile: "bootstrap", k: 2, witnesses: [
    { witness_id: "witness-a", operator: "Morse", public_key: key("a"), morse_run: true },
    { witness_id: "witness-b", operator: "Morse", public_key: key("b"), morse_run: true },
  ] });
});

test("the profile follows how many pinned witnesses Morse runs, and a Morse label always counts as Morse's", async () => {
  const set = (morse) => ({ witnesses: ["witness-a", "o1", "o2", "o3", "o4"].map((id, n) => witness(id, n < morse ? "Morse" : `Operator ${n}`)) });
  const profile = async (registry) => (await view("/network/registry.json", { "/v1/transparency/registry": registry })).body;
  assert.equal((await profile(set(3))).profile, "bootstrap");
  assert.equal((await profile(set(2))).profile, "transitional");
  assert.equal((await profile(set(1))).profile, "open");
  // A witness labelled Morse whose morse_run flag is off still counts as Morse's: the page may understate independence, never overstate it.
  const flagged = set(2);
  flagged.witnesses[1].morse_run = false;
  assert.equal((await profile(flagged)).profile, "transitional");
  assert.equal((await profile(flagged)).witnesses[1].morse_run, true);
});

test("the bond counter passes on only mainnet numbers, and only what two providers agreed on", async () => {
  const counter = async (status) => (await view("/network/status.json", { "/v1/network/status.json": status })).body;
  const none = { state: "none", checkpoint: null, bonded: null, slashed: null, witnesses: {}, slashes: [] };
  assert.deepEqual(await counter(today), none);
  assert.deepEqual(await counter(live()), {
    state: "ok", checkpoint: { time: "2026-09-29T11:59:20.000Z", link: `${EX}/block/900` }, bonded: { usd: "50000.00", link: `${EX}/address/${vault}` },
    slashed: { never: true, link: `${EX}/address/${logAccount}` }, witnesses: { "witness-a": { usd: "10000.00", link: `${EX}/address/${wvault}` } }, slashes: [],
  });
  // Before bonds are real (Phase 1), only the checkpoint shows.
  const unbonded = live();
  unbonded.bonded.directory = { ...unbonded.bonded.directory, amount: "0", usd: "0.00" };
  unbonded.bonded.witnesses = [];
  assert.deepEqual(await counter(unbonded), { ...none, state: "ok", checkpoint: { time: "2026-09-29T11:59:20.000Z", link: `${EX}/block/900` }, slashed: { never: true, link: `${EX}/address/${logAccount}` } });
  // Devnet numbers are rehearsals, not the public record.
  assert.deepEqual(await counter(live({ cluster: "devnet", operations: { ...today.operations, anchor_mode: "devnet" } })), none);
  // Providers that disagree, a failed read, or a snapshot the jobs stopped refreshing: no numbers, and the page says so.
  const unavailable = { ...none, state: "unavailable" };
  for (const reason of ["rpc_disagree", "rpc_error"]) {
    assert.deepEqual(await counter({ ...today, reason, last_good_at: null, operations: { ...today.operations, anchor_mode: "mainnet" } }), unavailable);
  }
  assert.deepEqual(await counter(live({ stale: true })), unavailable);
});

test("a slash stays on the counter with its transaction, whatever else the snapshot says", async () => {
  const slash = { proof: `Proof${"1".repeat(39)}`, kind: 1, slot: "950", paid_to: null, tx_signature: tx, link: `${EX}/tx/${tx}`, account_link: `${EX}/address/Proof${"1".repeat(39)}` };
  const res = await view("/network/status.json", { "/v1/network/status.json": { ...today, reason: "rpc_disagree", last_good_at: "2026-09-29T11:00:00.000Z",
    operations: { ...today.operations, anchor_mode: "mainnet" }, slash_history: [slash] } });
  assert.equal(res.body.state, "unavailable");
  assert.deepEqual(res.body.slashes, [{ link: `${EX}/tx/${tx}` }]);
  const after = live({ slashed: { service: true, witnesses: 0, never: false, link: `${EX}/address/${logAccount}` }, slash_history: [slash] });
  after.bonded.directory = { ...after.bonded.directory, status: "Slashed", amount: "0", usd: "0.00" };
  const body = (await view("/network/status.json", { "/v1/network/status.json": after })).body;
  assert.deepEqual([body.bonded, body.slashed, body.slashes], [null, { never: false, link: `${EX}/address/${logAccount}` }, [{ link: `${EX}/tx/${tx}` }]]);
});

test("anything unexpected from the backend is a 502, and the pages keep their own words", async () => {
  const bad = [
    ["/network/registry.json", { witnesses: [witness("witness-a", "M".repeat(49))] }],
    ["/network/registry.json", { witnesses: [{ ...witness("witness-a", "Morse"), witness_id: "Witness A" }] }],
    ["/network/registry.json", { witnesses: [witness("witness-a", "Morse"), witness("witness-a", "Morse")] }],
    ["/network/registry.json", { witnesses: [witness("witness-a", "Morse", "shadow")] }],
    ["/network/registry.json", { witnesses: [{ ...witness("witness-a", "Morse"), morse_run: "yes" }] }],
    ["/network/registry.json", { witnesses: [witness("witness-a", "Morse")], note: "x".repeat(70_000) }],
    ["/network/status.json", live({ log: "morse-canary" })],
    ["/network/status.json", live({ bonded: { ...live().bonded, directory: { ...live().bonded.directory, link: "https://evil.example/address/x" } } })],
    ["/network/status.json", live({ last_public_checkpoint: { ...live().last_public_checkpoint, link: `${EX}/block/900?cluster=devnet` } })],
    ["/network/status.json", live({ slash_history: [{ link: "javascript:alert(1)" }] })],
    ["/network/status.json", live({ bonded: { ...live().bonded, directory: { ...live().bonded.directory, usd: "lots" } } })],
  ];
  for (const [path, answer] of bad) {
    const res = await view(path, { [path === "/network/registry.json" ? "/v1/transparency/registry" : "/v1/network/status.json"]: answer });
    assert.equal(res.status, 502, `${path} passed ${JSON.stringify(answer).slice(0, 120)}`);
  }
  for (const answer of [new Response("{", { status: 200 }), new Response("oops", { status: 500 }), new Response(null, { status: 204 })]) {
    assert.equal((await view("/network/registry.json", { "/v1/transparency/registry": answer })).status, 502);
  }
  // No backend configured, or one that doesn't answer at all.
  assert.equal((await get("/network/status.json", {})).status, 502);
  const mock = mockBackend({});
  globalThis.fetch = async () => { throw new TypeError("connection refused"); };
  try { assert.equal((await get("/network/status.json")).status, 502); } finally { mock.restore(); }
});

test("each answer is kept for a minute, however the address is dressed up", async () => {
  const store = new Map();
  globalThis.caches = { default: { match: async (r) => store.get(r.url)?.clone(), put: async (r, res) => { store.set(r.url, res); } } };
  const mock = mockBackend({ "/v1/network/status.json": today });
  try {
    for (const path of ["/network/status.json", "/network/status.json?fresh=1", "/network/status.json"]) assert.equal((await get(path)).status, 200);
    assert.equal(mock.calls.length, 1);
  } finally { mock.restore(); delete globalThis.caches; }
  assert.equal((await worker.fetch(new Request("https://morseapp.io/network/status.json", { method: "POST" }), {})).status, 405);
});

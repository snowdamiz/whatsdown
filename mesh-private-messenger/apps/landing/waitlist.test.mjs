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

// The one check for the landing pages: `node check.mjs` from this directory.
// It holds each page to what it says about itself (no third-party requests, no
// claims the project can't back) and to working at phone and desktop widths.
// Playwright comes from the mobile app.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "../mobile/node_modules/playwright/index.mjs";
import worker from "./waitlist.mjs";

const here = fileURLToPath(new URL(".", import.meta.url));
// Articles are hardcoded files named blog-<slug>.html, listed by hand on blog.html.
const articles = readdirSync(here).filter((f) => /^blog-[\w-]+\.html$/.test(f));
const pages = ["index.html", "how-it-works.html", "witnesses.html", "blog.html", ...articles];
const problems = [];

// There is no audit and no licence file (SECURITY.md), so the copy can't claim either. The owner also wants no audit
// talk on the page at all, claimed or disclaimed, so the word itself is out.
for (const file of pages) {
  if (!existsSync(new URL(file, import.meta.url))) { problems.push(`${file} is missing`); continue; }
  const copy = readFileSync(new URL(file, import.meta.url), "utf8").replace(/<(style|script)>[\s\S]*?<\/\1>/g, "");
  // The token is sold on what it does, never on what it might be worth: return talk is how a token becomes a security.
  for (const word of [/military.grade/i, /unbreakable/i, /open.source/i, /audit/i, /invest/i, /profit/i, /\byield/i, /\bAPY\b/, /guarantee/i, /\bprice goes/i]) if (word.test(copy)) problems.push(`${file}: copy says ${word}`);
  // Copy that has to wait for the thing it describes (WITNESS_NETWORK_PLAN.md §17). When one ships, delete its line here.
  for (const [claim, until] of [
    [/your phone catches it|you get paid/i, "the phone bounty ships (Phase 4)"],
    [/fool everyone you talk to/i, "checkpoint gossip is in a release (Phase 0.6)"],
    [/\b(messages?|plaintext|what you write)\b[^.]{0,120}\b(compiler?|compiles?|won.t build|doesn.t build)\b|\b(compiler|won.t build|doesn.t build)\b[^.]{0,120}\b(messages?|plaintext)\b/i, "the Phase 6 exit, worded to its limits (§6.18)"],
  ]) if (claim.test(copy)) problems.push(`${file}: copy says ${claim}, which must wait until ${until}`);
  // Link previews fetch the share card from the live site, which serves this directory.
  const card = copy.match(/property="og:image" content="https:\/\/morseapp\.io\/([^"]+)"/)?.[1];
  if (!card || !existsSync(new URL(card, import.meta.url))) problems.push(`${file}: og:image ${card ?? "is missing"} isn't a file here`);
}

// ---- The network's live numbers (network.js). The pages ask their own origin for /network/*.json; here those
// requests go through the real Worker (waitlist.mjs), whose backend answers as ops/cloudflare would in each
// state below. So the page is held to what it shows for each, and the Worker's shape check is held to keeping
// anything unexpected off the page.
const BACKEND = "https://backend.invalid", EX = "https://explorer.solana.com";
const pinned = (witness_id, operator, c) => ({ witness_id, public_key: c.repeat(64), operator, status: "pinned", software: "mesh", morse_run: operator === "Morse", c2sp_name: null });
const off = { log: "morse-main", status: "unavailable", reason: "no_snapshot_yet", slash_history: [], stale: false, operations: { anchor_mode: "off", pages: [] } };
const acct = (c) => c.repeat(44), slash = { proof: acct("P"), kind: 1, slot: "950", link: `${EX}/tx/${"5".repeat(88)}` };
// Production today (plan §4.1, B0): both witnesses are Morse's, and nothing is anchored, bonded or slashed.
// When a release pins a different set, change TODAY and the static words in witnesses.html together: those
// words are what a reader sees whenever the registry can't be read.
const TODAY = { "/v1/transparency/registry": { witnesses: [pinned("witness-a", "Morse", "a"), pinned("witness-b", "Morse", "b")] }, "/v1/network/status.json": off };
const FALLBACK = "Both witnesses are run by Morse today. Independent witnesses join in stages.";
const STATES = {
  today: TODAY,
  down: {},
  // Open, anchored on mainnet and bonded, as it should look once Phase 3 is out.
  live: {
    "/v1/transparency/registry": { witnesses: [pinned("witness-a", "Morse", "a"), ...["Lattice Labs", "Northwind Validators", "Kestrel University", "Ember Foundation"].map((o, n) => pinned(`o${n + 1}-${o.split(" ")[0].toLowerCase()}`, o, "cdef"[n]))] },
    "/v1/network/status.json": () => ({ ...off, status: "ok", cluster: "mainnet-beta", operations: { anchor_mode: "mainnet", pages: [] },
      last_public_checkpoint: { slot: "900", sequence: "41", tree_size: "12", time: new Date(Date.now() - 40_000).toISOString(), link: `${EX}/block/900` },
      bonded: { directory: { status: "Active", usd: "50000.00", link: `${EX}/address/${acct("V")}` }, witnesses: [{ witness_id: "witness-a", usd: "10000.00", link: `${EX}/address/${acct("W")}` }] },
      slashed: { service: false, witnesses: 0, never: true, link: `${EX}/address/${acct("L")}` } }),
  },
  // The two chain providers disagree, after a slash: no numbers, but the slash stays.
  split: { ...TODAY, "/v1/network/status.json": { ...off, reason: "rpc_disagree", last_good_at: "2026-09-29T11:00:00.000Z", slash_history: [slash], operations: { anchor_mode: "mainnet", pages: [] } } },
  // Answers the Worker must refuse: an operator label past 48 characters, and a link off the explorer.
  bad: {
    "/v1/transparency/registry": { witnesses: [pinned("witness-a", "Morse", "a"), pinned("witness-b", "M".repeat(49), "b")] },
    "/v1/network/status.json": { ...off, status: "ok", cluster: "mainnet-beta", operations: { anchor_mode: "mainnet", pages: [] }, last_public_checkpoint: null,
      bonded: { directory: { status: "Active", usd: "50000.00", link: "https://evil.example/x" }, witnesses: [] }, slashed: { never: true, link: `${EX}/address/${acct("L")}` } },
  },
};
let state = STATES.today;
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  if (!String(url).startsWith(BACKEND)) return realFetch(url, init);
  const answer = state[new URL(url).pathname];
  return answer === undefined ? new Response("Not found", { status: 404 }) : Response.json(typeof answer === "function" ? answer() : answer);
};
async function viaWorker(route) {
  const res = await worker.fetch(new Request(`https://morseapp.io/network/${route.request().url().split("/").pop()}`), { MORSE_BACKEND_URL: BACKEND });
  await route.fulfill({ status: res.status, headers: Object.fromEntries(res.headers), body: Buffer.from(await res.arrayBuffer()) });
}

const browser = await chromium.launch();
for (const file of pages.filter((f) => existsSync(new URL(f, import.meta.url)))) {
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    const name = `${file} at ${width}`;
    const page = await browser.newPage({ viewport: { width, height } });
    // A failed /network/*.json is a state the pages are built for (their static words stay), not a page error.
    page.on("console", (m) => ["error", "assert"].includes(m.type()) && !m.location().url.includes("/network/") && problems.push(`${name}: console ${m.type()}: ${m.text()}`));
    page.on("pageerror", (e) => problems.push(`${name}: ${e.message}`));
    // The footer promises this, so anything outside this directory is a failure.
    page.on("request", (r) => decodeURI(r.url()).startsWith(`file://${here}`) || r.url().startsWith("data:") || problems.push(`${name}: third-party request ${r.url()}`));

    await page.route("**/network/*.json", viaWorker);
    await page.goto(new URL(file, import.meta.url).href, { waitUntil: "networkidle" });
    await page.evaluate(() => document.fonts.ready);
    if (!(await page.evaluate(() => document.fonts.check('600 16px "Geist"')))) problems.push(`${name}: Geist did not load`);

    const [doc, win] = await page.evaluate(() => [document.documentElement.scrollWidth, innerWidth]);
    if (doc > win) problems.push(`${name}: page scrolls sideways (${doc} > ${win})`);

    const dead = await page.evaluate(() => [...document.querySelectorAll('a[href^="#"]')].map((a) => a.getAttribute("href")).filter((h) => !document.getElementById(h.slice(1))));
    if (dead.length) problems.push(`${name}: links to nowhere: ${dead.join(" ")}`);
    // Links between the pages must land on a page, and on an id that page has.
    for (const href of await page.evaluate(() => [...document.querySelectorAll("a[href]")].map((a) => a.getAttribute("href")).filter((h) => /^[\w-]+\.html(#|$)/.test(h)))) {
      const [target, id] = href.split("#");
      if (!pages.includes(target)) problems.push(`${name}: links to a page that isn't checked: ${href}`);
      else if (id && !readFileSync(new URL(target, import.meta.url), "utf8").includes(`id="${id}"`)) problems.push(`${name}: links to nowhere: ${href}`);
    }

    await (({ "index.html": home, "how-it-works.html": how, "witnesses.html": witnesses, "blog.html": blog })[file] ?? (() => {}))(page, name);
    if (await page.$("script[src='network.js']")) await network(page, name);

    // Narrow, the nav's links fold behind a menu button, which has to bring every one of them back.
    if (width < 1040) {
      await page.locator(".nav .menu").click({ timeout: 2000 }).catch(() => {});
      const hidden = await page.$$eval(".nav nav a", (as) => as.filter((a) => !a.checkVisibility()).map((a) => a.textContent));
      if (hidden.length || !(await page.$(".nav nav a"))) problems.push(`${name}: the menu doesn't reach the nav's links: ${hidden.join(", ")}`);
    }
    await page.close();
  }
}

async function network(page, name) {
  const look = async (key) => {
    state = STATES[key];
    await page.reload({ waitUntil: "networkidle" });
    const [doc, win] = await page.evaluate(() => [document.documentElement.scrollWidth, innerWidth]);
    if (doc > win) problems.push(`${name} (${key}): page scrolls sideways (${doc} > ${win})`);
    return page.evaluate(() => {
      const all = (s) => [...document.querySelectorAll(s)];
      const shown = (s) => all(s).filter((e) => !e.closest("[hidden]"));
      return {
        profile: shown('[data-net="profile"]').map((e) => e.textContent.trim()),
        outvote: all('[data-net="outvote"]').map((e) => e.textContent.trim()),
        rows: all('[data-net="witnesses"] li').map((li) => [...li.querySelectorAll("b, em")].map((e) => e.textContent).join(" ")),
        bonds: all('[data-net="witnesses"] a').map((a) => a.textContent),
        counter: shown('[data-net="counter"] span').map((e) => e.textContent.trim()),
        next: [...new Set(shown("[data-next]").map((e) => e.dataset.next))].sort(),
        pill: shown("#network .soon").map((e) => e.textContent.trim()),
        links: all("[data-net] a").map((a) => a.href),
        // Every number the counter shows has to link to where it can be checked.
        loose: all('[data-net="counter"] span').flatMap((s) => [...s.childNodes].filter((n) => n.nodeType === 3 && /\d/.test(n.textContent)).map((n) => n.textContent)),
      };
    });
  };
  const file = name.split(" ")[0];
  const says = (key, got, want) => String(got) === String(want) || problems.push(`${name} (${key}): shows ${JSON.stringify(got)}, not ${JSON.stringify(want)}`);
  const seen = {};
  for (const key of ["down", "bad", "today", "live", "split"]) {
    const v = (seen[key] = await look(key));
    for (const href of v.links) if (!href.startsWith(`${EX}/`)) problems.push(`${name} (${key}): links a number to ${href}, not the explorer`);
    if (v.loose.length) problems.push(`${name} (${key}): the counter shows ${v.loose} without a link`);
    // The pill stays until the Phase 3 exit (plan §4.4), whatever the numbers say.
    if (file === "index.html") says(key, v.pill, ["Launching in stages"]);
  }
  // Nothing real to count: no counter at all, and the map still marks the chain and outside witnesses as next.
  for (const key of ["down", "bad", "today"]) {
    says(key, seen[key].counter, []);
    if (file === "how-it-works.html") says(key, seen[key].next, ["anchor", "outside"]);
  }
  says("live", seen.live.counter.map((t) => t.replace(/\d+ seconds/, "N seconds")), ["$50,000 bonded.", "Slashed: never.", "Last public checkpoint: N seconds ago."]);
  says("split", seen.split.counter, ["Slashed: once.", "Live numbers unavailable: two chain providers must agree before we show any."]);
  if (file === "how-it-works.html") says("live", seen.live.next, []);
  if (file === "witnesses.html") {
    // Without the registry the page keeps words true today, and they say the same as the registry does today.
    for (const key of ["down", "bad"]) says(key, seen[key].profile, [FALLBACK]);
    says("today", seen.today.profile, ["Bootstrap: both witnesses are run by Morse. Independent witnesses join in stages."]);
    says("today", seen.today.rows, seen.down.rows);
    says("today", seen.today.outvote, seen.down.outvote);
    if (!/^Today, yes\./.test(seen.down.outvote)) problems.push(`${name}: "Could Morse outvote the witnesses?" doesn't say yes while every witness is Morse's`);
    says("live", seen.live.profile, ["Open: 4 of 5 witnesses are independent. Morse runs one, and phones need 3."]);
    if (!/^No\./.test(seen.live.outvote)) problems.push(`${name} (live): the open network's answer to "Could Morse outvote the witnesses?" isn't no`);
    says("live", seen.live.rows.length, 5);
    says("live", seen.live.bonds, ["$10,000"]);
  }
  state = STATES.today;
  await page.reload({ waitUntil: "networkidle" });
}

async function home(page, name) {
  if (!(await page.$('a[href="how-it-works.html"]'))) problems.push(`${name}: no link to how-it-works.html`);
  if (!(await page.$('a[href="blog.html"]'))) problems.push(`${name}: no link to blog.html`);
  if (!(await page.$('#witness a[href^="witnesses.html"]'))) problems.push(`${name}: the witness section doesn't lead to witnesses.html`);

  // One chat, two views: on our servers every text bubble is the same sealed strip, and it comes back as it was.
  const sizes = () => page.evaluate(() => [...document.querySelectorAll("#demo .msg:not(.file)")].map((m) => `${m.offsetWidth}x${m.offsetHeight}`));
  const before = await sizes();
  // The phone is a device: it keeps its width while the chat on it changes, all the way through the flip.
  const widths = page.evaluate(async () => {
    const seen = new Set();
    for (let t = 0; t < 40; t++) { seen.add(document.querySelector("#demo").getBoundingClientRect().width); await new Promise((r) => setTimeout(r, 50)); }
    return [...seen];
  });
  await page.click('#view button[data-set="server"]');
  if ((await widths).length > 1) problems.push(`${name}: the privacy phone changes width as it flips: ${await widths}`);
  await page.waitForTimeout(1000);
  if ((await page.getAttribute("#demo", "data-view")) !== "server") problems.push(`${name}: server view did not open`);
  if (new Set(await sizes()).size !== 1) problems.push(`${name}: sealed messages differ in size: ${await sizes()}`);
  await page.click('#view button[data-set="device"]');
  await page.waitForTimeout(2000);
  if (String(await sizes()) !== String(before)) problems.push(`${name}: bubbles did not return to their own size`);

  // The hero's incoming messages arrive sealed; once their wipes are over (6s at most), every one must be readable.
  const sealed = await page.evaluate(async () => {
    const words = [...document.querySelectorAll(".hero .seal>span")];
    await Promise.race([Promise.all(words.flatMap((s) => s.getAnimations().map((a) => a.finished))), new Promise((r) => setTimeout(r, 6000))]);
    return words.filter((s) => getComputedStyle(s).maskPosition !== "0% 0px").length;
  });
  if (sealed) problems.push(`${name}: ${sealed} hero messages never unsealed`);

  // At the top of the window the privacy card is fully open, edge to edge, with the nav dark over it.
  await page.evaluate(() => scrollTo(0, document.querySelector(".night").getBoundingClientRect().top + scrollY - 10));
  await page.waitForTimeout(300);
  const open = await page.evaluate(() => {
    const n = document.querySelector(".night");
    return n.style.getPropertyValue("--o") === "1.000" && n.getBoundingClientRect().width === document.documentElement.clientWidth && document.querySelector(".nav").classList.contains("dark");
  });
  if (!open) problems.push(`${name}: privacy card did not open to the window's edges`);
}

// The map is laid out by hand for two shapes, so hold it to what a reader relies on: no part covers another,
// every step lights something, and the packet ends each hop on the part it was sent to. (The page itself
// asserts that every hop runs along a drawn line.)
async function how(page, name) {
  await page.locator("#map").scrollIntoViewIfNeeded();
  const clash = await page.evaluate(() => {
    const stage = document.querySelector(".stage").getBoundingClientRect();
    const boxes = [...document.querySelectorAll(".stage .node")].map((n) => [n.dataset.id, n.getBoundingClientRect()]);
    const out = boxes.filter(([, r]) => r.left < stage.left - 1 || r.top < stage.top - 1 || r.right > stage.right + 1 || r.bottom > stage.bottom + 1).map(([id]) => `${id} outside the map`);
    boxes.forEach(([a, r], i) => boxes.slice(i + 1).forEach(([b, s]) => r.left < s.right && s.left < r.right && r.top < s.bottom && s.top < r.bottom && out.push(`${a} covers ${b}`)));
    return boxes.length ? out : ["the map has no parts"];
  });
  for (const c of clash) problems.push(`${name}: ${c}`);

  for (const tab of await page.$$eval("#journeys [data-journey]", (bs) => bs.map((b) => b.dataset.journey))) {
    await page.click(`#journeys [data-journey="${tab}"]`);
    const steps = await page.$$eval(`ol[data-journey="${tab}"] > li`, (ls) => ls.length);
    for (let n = 0; n < steps; n++) {
      if (n) await page.click("#next");
      const lit = await page.evaluate(async () => {
        await Promise.all(document.getAnimations().filter((a) => a.id === "hop").map((a) => a.finished.catch(() => {})));
        const on = [...document.querySelectorAll(".stage .node.on")];
        const pkt = document.querySelector(".pkt"), end = document.querySelector(".stage").dataset.end;
        if (!pkt || !end || getComputedStyle(pkt).opacity === "0") return { on: on.length };
        const p = pkt.getBoundingClientRect(), r = document.querySelector(`.node[data-id="${end}"]`).getBoundingClientRect();
        const [x, y] = [p.left + p.width / 2, p.top + p.height / 2];
        return { on: on.length, landed: x >= r.left - 2 && x <= r.right + 2 && y >= r.top - 2 && y <= r.bottom + 2, end };
      });
      if (!lit.on) problems.push(`${name}: ${tab} step ${n + 1} lights nothing`);
      if (lit.landed === false) problems.push(`${name}: ${tab} step ${n + 1}'s packet stops short of ${lit.end}`);
    }
  }

  // The parts that come next are wired to nothing yet, so no journey may pass through them.
  const later = await page.$$eval(".stage .node:has([data-next])", (ns) => ns.map((n) => n.dataset.id));
  const used = await page.$$eval("ol[data-journey] > li", (ls) => ls.flatMap((l) => `${l.dataset.at ?? ""} ${l.dataset.path ?? ""}`.split(/[\s|]+/)));
  for (const id of later.filter((id) => used.includes(id))) problems.push(`${name}: a journey runs through ${id}, which the map marks as next`);
  await page.click('.stage .node[data-id="sol"]');
  if (!/Solana\s*Next/.test(await page.locator("#part").textContent().catch(() => ""))) problems.push(`${name}: tapping Solana doesn't say it comes next`);
  await page.keyboard.press("Escape");
  await page.click('.stage .node[data-id="edge"]');
  const card = await page.locator("#part").textContent().catch(() => "");
  if (!/Privacy edge/.test(card) || !/sees/i.test(card)) problems.push(`${name}: tapping the privacy edge did not say what it sees`);
}

// Applying opens a GitHub issue form, which only exists if its template does: a renamed file 404s the button.
async function witnesses(page, name) {
  const forms = await page.$$eval('a[href*="/issues/new?template="]', (as) => as.map((a) => new URL(a.href).searchParams.get("template")));
  if (!forms.length) problems.push(`${name}: no way to apply`);
  for (const t of forms) if (!existsSync(new URL(`../../../.github/ISSUE_TEMPLATE/${t}`, import.meta.url))) problems.push(`${name}: apply links to a missing form: ${t}`);
}

// The index is written by hand, so an article nobody linked would never be found.
async function blog(page, name) {
  const listed = await page.$$eval("main a[href^='blog-']", (as) => as.map((a) => a.getAttribute("href")));
  if (!articles.length) problems.push(`${name}: there are no articles`);
  for (const f of articles) if (!listed.includes(f)) problems.push(`${name}: ${f} isn't listed`);
}

await browser.close();
console.log(problems.length ? problems.join("\n") : "landing pages: ok");
process.exit(problems.length ? 1 : 0);

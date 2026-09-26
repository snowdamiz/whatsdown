// The one check for the landing pages: `node check.mjs` from this directory.
// It holds each page to what it says about itself (no third-party requests, no
// claims the project can't back) and to working at phone and desktop widths.
// Playwright comes from the mobile app.
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "../mobile/node_modules/playwright/index.mjs";

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
  // Link previews fetch the share card from the live site, which serves this directory.
  const card = copy.match(/property="og:image" content="https:\/\/morseapp\.io\/([^"]+)"/)?.[1];
  if (!card || !existsSync(new URL(card, import.meta.url))) problems.push(`${file}: og:image ${card ?? "is missing"} isn't a file here`);
}

const browser = await chromium.launch();
for (const file of pages.filter((f) => existsSync(new URL(f, import.meta.url)))) {
  for (const [width, height] of [[1440, 900], [390, 844]]) {
    const name = `${file} at ${width}`;
    const page = await browser.newPage({ viewport: { width, height } });
    page.on("console", (m) => ["error", "assert"].includes(m.type()) && problems.push(`${name}: console ${m.type()}: ${m.text()}`));
    page.on("pageerror", (e) => problems.push(`${name}: ${e.message}`));
    // The footer promises this, so anything outside this directory is a failure.
    page.on("request", (r) => decodeURI(r.url()).startsWith(`file://${here}`) || r.url().startsWith("data:") || problems.push(`${name}: third-party request ${r.url()}`));

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

    // Narrow, the nav's links fold behind a menu button, which has to bring every one of them back.
    if (width < 1040) {
      await page.locator(".nav .menu").click({ timeout: 2000 }).catch(() => {});
      const hidden = await page.$$eval(".nav nav a", (as) => as.filter((a) => !a.checkVisibility()).map((a) => a.textContent));
      if (hidden.length || !(await page.$(".nav nav a"))) problems.push(`${name}: the menu doesn't reach the nav's links: ${hidden.join(", ")}`);
    }
    await page.close();
  }
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

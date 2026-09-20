// The one check for the landing page: `node check.mjs` from this directory.
// It holds the page to what it says about itself (no third-party requests, no
// claims the project can't back) and to working at phone and desktop widths.
// Playwright comes from the mobile app.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { chromium } from "../mobile/node_modules/playwright/index.mjs";

const page_url = new URL("index.html", import.meta.url).href;
const here = fileURLToPath(new URL(".", import.meta.url));
const problems = [];

// There is no audit and no licence file (SECURITY.md), so the copy can't claim either. The owner also wants no audit
// talk on the page at all, claimed or disclaimed, so the word itself is out.
const copy = readFileSync(new URL("index.html", import.meta.url), "utf8").replace(/<(style|script)>[\s\S]*?<\/\1>/g, "");
for (const word of [/military.grade/i, /unbreakable/i, /open.source/i, /audit/i]) if (word.test(copy)) problems.push(`copy says ${word}`);

const browser = await chromium.launch();
for (const [name, width, height] of [["desktop", 1440, 900], ["phone", 390, 844]]) {
  const page = await browser.newPage({ viewport: { width, height } });
  page.on("console", (m) => ["error", "assert"].includes(m.type()) && problems.push(`${name}: console ${m.type()}: ${m.text()}`));
  page.on("pageerror", (e) => problems.push(`${name}: ${e.message}`));
  // The footer promises this, so anything outside this directory is a failure.
  page.on("request", (r) => decodeURI(r.url()).startsWith(`file://${here}`) || r.url().startsWith("data:") || problems.push(`${name}: third-party request ${r.url()}`));

  await page.goto(page_url, { waitUntil: "networkidle" });
  await page.evaluate(() => document.fonts.ready);
  if (!(await page.evaluate(() => document.fonts.check('600 16px "Geist"')))) problems.push(`${name}: Geist did not load`);

  const [doc, win] = await page.evaluate(() => [document.documentElement.scrollWidth, innerWidth]);
  if (doc > win) problems.push(`${name}: page scrolls sideways (${doc} > ${win})`);

  const dead = await page.evaluate(() => [...document.querySelectorAll('a[href^="#"]')].map((a) => a.getAttribute("href")).filter((h) => !document.getElementById(h.slice(1))));
  if (dead.length) problems.push(`${name}: links to nowhere: ${dead.join(" ")}`);

  // One chat, two views: on our servers every text bubble is the same sealed strip, and it comes back as it was.
  const sizes = () => page.evaluate(() => [...document.querySelectorAll("#demo .msg:not(.file)")].map((m) => `${m.offsetWidth}x${m.offsetHeight}`));
  const before = await sizes();
  await page.click('#view button[data-set="server"]');
  await page.waitForTimeout(1000);
  if ((await page.getAttribute("#demo", "data-view")) !== "server") problems.push(`${name}: server view did not open`);
  if (new Set(await sizes()).size !== 1) problems.push(`${name}: sealed messages differ in size: ${await sizes()}`);
  await page.click('#view button[data-set="device"]');
  await page.waitForTimeout(2000);
  if (String(await sizes()) !== String(before)) problems.push(`${name}: bubbles did not return to their own size`);
  await page.close();
}

await browser.close();
console.log(problems.length ? problems.join("\n") : "landing page: ok");
process.exit(problems.length ? 1 : 0);

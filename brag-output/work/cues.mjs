import { chromium } from "/Volumes/SSK-SSD/whatsdown/mesh-private-messenger/apps/mobile/node_modules/playwright/index.mjs";
const b = await chromium.launch({ channel: "chrome" });
const p = await b.newPage({ viewport: { width: 1920, height: 1080 } });
await p.goto("file://" + new URL(".", import.meta.url).pathname + "video.html");
await p.evaluate(() => window.ready);
console.log(JSON.stringify(await p.evaluate(() => window.cues)));
await b.close();

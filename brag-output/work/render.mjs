// PAGE=v3.html node render.mjs stills 0 1.2 3.5 ...          -> work/stills/<page>-t-<t>.png
// PAGE=v3.html SUB=5 POSTER=19.2 WORKERS=6 node render.mjs video -> work/video-silent.mp4
//   SUB subframes per frame are averaged over a 180° shutter (motion blur); frame 0 shows POSTER.
//   WORKERS browsers each render a slice of frames to their own segment; the segments are joined without re-encoding.
import { chromium } from "/Volumes/SSK-SSD/whatsdown/mesh-private-messenger/apps/mobile/node_modules/playwright/index.mjs";
import { spawn, execFileSync } from "node:child_process";
import { mkdirSync, writeFileSync } from "node:fs";

const here = new URL(".", import.meta.url).pathname;
const [mode, ...args] = process.argv.slice(2);
const FPS = 30, PAGE = process.env.PAGE || "video.html", SUB = +(process.env.SUB || 1), W = +(process.env.WORKERS || 1);

async function open() {
  const browser = await chromium.launch({ channel: "chrome" });
  const page = await browser.newPage({ viewport: { width: 1920, height: 1080 }, deviceScaleFactor: 1 });
  page.on("pageerror", e => console.log("pageerror:", e.message));
  await page.goto("file://" + here + PAGE);
  await page.evaluate(() => window.ready);
  return { browser, page, dur: await page.evaluate(() => window.DURATION) };
}

if (mode === "stills") {
  const { browser, page } = await open();
  mkdirSync(here + "stills", { recursive: true });
  for (const t of args) { await page.evaluate(t => window.render(t), +t); await page.screenshot({ path: `${here}stills/${PAGE.replace(".html", "")}-t-${(+t).toFixed(2)}.png` }); }
  await browser.close();
} else if (mode === "slice") {                       // internal: render frames [a, b) to args[2]
  const [a, b, out] = [+args[0], +args[1], args[2]];
  const { browser, page, dur } = await open();
  const vf = SUB > 1 ? ["-vf", `tmix=frames=${SUB},select='eq(mod(n\\,${SUB})\\,${SUB - 1})',setpts=N/(${FPS}*TB)`, "-r", String(FPS)] : [];
  const ff = spawn("ffmpeg", ["-loglevel", "error", "-y", "-f", "image2pipe", "-framerate", String(FPS * SUB), "-i", "-", ...vf,
    "-c:v", "libx264", "-preset", "slow", "-crf", "16", "-pix_fmt", "yuv420p", out], { stdio: ["pipe", "inherit", "inherit"] });
  for (let f = a; f < b; f++) {
    for (let k = 0; k < SUB; k++) {
      const raw = f === 0 && process.env.POSTER ? +process.env.POSTER : f / FPS + ((k + .5) / SUB - .5) * .5 / FPS;
      const t = ((raw % dur) + dur) % dur;           // the shutter wraps around the loop seam
      await page.evaluate(t => window.render(t), t);
      const buf = await page.screenshot({ type: "png" });
      if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once("drain", r));
    }
    if ((f - a) % 30 === 0) console.log(`[${a}-${b}] frame ${f}`);
  }
  ff.stdin.end(); await new Promise(r => ff.on("close", r));
  await browser.close();
} else {
  const { browser, dur } = await open(); await browser.close();
  const n = Math.round(dur * FPS), per = Math.ceil(n / W), segs = [];
  mkdirSync(here + "segs", { recursive: true });
  await Promise.all(Array.from({ length: W }, (_, i) => {
    const a = i * per, b = Math.min(n, a + per), out = `${here}segs/seg${i}.mp4`; segs.push(out);
    return new Promise(r => spawn("node", [here + "render.mjs", "slice", String(a), String(b), out], { stdio: "inherit", env: process.env }).on("close", r));
  }));
  writeFileSync(here + "segs/list.txt", segs.map(s => `file '${s}'`).join("\n"));
  execFileSync("ffmpeg", ["-loglevel", "error", "-y", "-f", "concat", "-safe", "0", "-i", here + "segs/list.txt", "-c", "copy", "-movflags", "+faststart", here + "video-silent.mp4"]);
  console.log("done", n, "frames");
}

// Run against the real exported app: npm run web --prefix ../desktop first.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';

const dist = new URL('../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    const mime = path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html';
    response.setHeader('Content-Type', mime);
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
let browser;
const url = `http://127.0.0.1:${server.address().port}`;
const screenshots = process.env.MORSE_STARTUP_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  const page = await browser.newPage({ viewport: { width: 1160, height: 800 } });
  await page.route('**/*.js', (route) => route.abort());
  await page.goto(url);
  assert.equal(await page.getByRole('progressbar', { name: 'Opening Morse' }).isVisible(), true,
    'The loading screen must paint even before the JavaScript bundle arrives');
  assert.equal(await page.evaluate(() => getComputedStyle(document.body).backgroundColor), 'rgb(10, 10, 12)');
  console.log('Startup: branded screen visible before JavaScript');
  await page.close();

  for (const scheme of ['light', 'dark']) {
    const page = await browser.newPage({
      viewport: { width: 1160, height: 800 },
      colorScheme: scheme === 'light' ? 'dark' : 'light', // Saved choice wins over the OS.
      reducedMotion: scheme === 'dark' ? 'reduce' : 'no-preference',
    });
    const errors = [];
    page.on('pageerror', (error) => errors.push(error.message));
    // Only the native IPC boundary and font requests are held back; the
    // production bundle, React, styling, and readiness logic all run for real.
    await page.addInitScript((scheme) => {
      const startup = window.startupTest = { calls: [] };
      const shell = new Promise((resolve) => { startup.openStorage = resolve; });
      const profile = new Promise((resolve) => { startup.readProfile = resolve; });
      window.__TAURI_INTERNALS__ = {
        invoke: async (command, args, options) => {
          const symbol = options?.headers?.['X-Mesh-Symbol'];
          startup.calls.push(symbol || command);
          if (command === 'database_path') { await shell; return '/test/morse.db'; }
          if (command === 'appearance') { await shell; return scheme; }
          if (symbol === 'mesh_messenger_load_profile') {
            await profile;
            throw new Error('profile_not_found');
          }
          throw new Error(`Unexpected native call: ${command}`);
        },
      };
    }, scheme);
    let releaseFonts;
    const fonts = new Promise((resolve) => { releaseFonts = resolve; });
    let requestedFont = false;
    await page.route('**/*.ttf', async (route) => { requestedFont = true; await fonts; await route.continue(); });
    await page.goto(url, { waitUntil: 'domcontentloaded' });
    const cover = page.getByRole('progressbar', { name: 'Opening Morse', exact: true });
    await page.waitForFunction(() => window.startupTest.calls.includes('database_path'));
    assert.equal(await cover.isVisible(), true, 'Loading covers the native-storage handshake');
    const mark = cover.locator('svg').first();
    const before = await mark.screenshot({ path: screenshots ? `${screenshots}/gradient-${scheme}-start.png` : undefined });
    // Sample the painted mark at another point in its loading cycle.
    await page.waitForTimeout(1200);
    const after = await mark.screenshot({ path: screenshots ? `${screenshots}/gradient-${scheme}-flow.png` : undefined });
    assert.equal(before.equals(after), scheme === 'dark',
      'The logo gradient flows while loading, but stays still with reduced motion');
    if (scheme === 'light') {
      const positions = await mark.locator('linearGradient').evaluate((gradient) => new Promise((resolve) => {
        const positions = [];
        const start = performance.now();
        const sample = (now) => {
          positions.push({ x: gradient.x1.baseVal.value, y: gradient.y1.baseVal.value });
          if (now - start < 2600) requestAnimationFrame(sample);
          else resolve(positions);
        };
        requestAnimationFrame(sample);
      }));
      assert.ok(positions.every(({ x, y }) => Math.abs(x - y) < 0.0001),
        'The gradient travels diagonally from top left to bottom right');
      const xs = positions.map(({ x }) => x);
      const span = Math.max(...xs) - Math.min(...xs);
      const backwardSteps = xs.slice(1).map((x, i) => x - xs[i]).filter((step) => step < 0);
      assert.ok(backwardSteps.length > 0, 'The gradient repeats its loading cycle');
      assert.ok(backwardSteps.every((step) => step < -span / 2),
        'The gradient moves forward and resets, without sweeping backward');
    }
    assert.equal(await cover.getByRole('progressbar').count(), 0,
      'The logo replaces the separate loading spinner');
    if (screenshots) await page.screenshot({ path: `${screenshots}/loading-${scheme}.png` });
    await page.evaluate(() => window.startupTest.openStorage());
    await page.waitForFunction(() => window.startupTest.calls.includes('mesh_messenger_load_profile'));
    await page.waitForFunction(() => document.fonts.status === 'loading');
    assert.equal(requestedFont, true);
    assert.equal(await cover.evaluate((element) => getComputedStyle(element).opacity), '1');
    await cover.evaluate((element) => {
      window.startupTest.opacities = [];
      const sample = () => {
        if (!element.isConnected) return;
        window.startupTest.opacities.push(Number(getComputedStyle(element).opacity));
        requestAnimationFrame(sample);
      };
      sample();
    });

    if (scheme === 'light') {
      await page.evaluate(() => window.startupTest.readProfile());
      await page.waitForTimeout(100);
      assert.equal(await cover.isVisible(), true, 'Data being ready cannot reveal unloaded fonts');
      assert.equal(await page.getByRole('heading', { name: /Private messaging/ }).count(), 0);
      releaseFonts();
    } else {
      releaseFonts();
      await page.evaluate(() => document.fonts.ready);
      assert.equal(await cover.isVisible(), true, 'Fonts being ready cannot reveal an unresolved account');
      if (screenshots) await page.screenshot({ path: `${screenshots}/loading.png` });
      await page.evaluate(() => window.startupTest.readProfile());
    }
    await cover.waitFor({ state: 'detached' });
    await page.getByRole('heading', { name: /Private messaging/ }).waitFor();
    assert.equal(await page.evaluate(() => document.documentElement.dataset.theme), scheme);
    const faded = await page.evaluate(() => window.startupTest.opacities.some((value) => value > 0 && value < 1));
    assert.equal(faded, scheme === 'light', 'The cover fades only when reduced motion is off');
    assert.deepEqual(errors, []);
    if (screenshots) await page.screenshot({ path: `${screenshots}/ready-${scheme}.png` });
    console.log(`Startup: ${scheme} theme waits for fonts + storage, then reveals${scheme === 'dark' ? ' with reduced motion' : ''}`);
    await page.close();
  }

  const failure = await browser.newPage();
  await failure.goto(url);
  await failure.getByRole('alert', { name: 'Open Morse in the installed desktop app.' }).waitFor();
  assert.equal(await failure.getByRole('progressbar', { name: 'Opening Morse' }).count(), 0);
  console.log('Startup: unavailable native bridge shows a readable error');
  await failure.close();
} finally {
  await browser?.close();
  server.close();
}

import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
const { chromium } = await import(process.env.MORSE_PLAYWRIGHT_MODULE || new URL('../mobile/node_modules/playwright/index.mjs', import.meta.url).href);
const read = name => JSON.parse(fs.readFileSync(new URL(`../../ops/public-chain/fixtures/${name}-history-report.json`, import.meta.url)));

test('static history navigates all65 real identities at phone/desktop widths and marks each independent bank without external requests', { timeout: 30000 }, async () => {
  const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH });
  const observations = [];
  try {
    for (const width of [390, 1440]) {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      const errors = [], requests = []; page.on('pageerror', e => errors.push(e.message)); page.on('request', r => { if (!r.url().startsWith('file:') && !r.url().startsWith('data:')) requests.push(r.url()); });
      await page.goto(new URL('./network.html', import.meta.url).href);
      assert.equal(await page.locator('#report-status').textContent(), 'Awaiting published records');
      assert.match(await page.locator('#history-records').textContent(), /No discovery index is published/);
      const fixture = read('collateral-later'), value = { ...fixture, scope: 'configured-rpc' }, now = Number(value.generated_at_unix);
      const mount = async (report, clock = now) => page.evaluate(({ report, clock }) => globalThis.MorseNetworkReport.mount(document, report, clock), { report, clock });
      await mount(value); assert.equal(await page.locator('#report-status').textContent(), 'Configured snapshot available');
      await page.locator('[data-family="witnesses"]').click();
      const seen = [];
      while (true) {
        seen.push(...await page.locator('.history-record').evaluateAll(cards => cards.map(card => card.dataset.address)));
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
        const next = page.getByRole('button', { name: 'Next', exact: true }); if (await next.isDisabled()) break; await next.click();
      }
      assert.equal(seen.length, 65); assert.equal(new Set(seen).size, 65); assert.deepEqual(seen, value.history.witnesses.records.map(row => row.address));
      assert.match(await page.locator('.history-pages').textContent(), /65–65 of 65/);
      await page.locator('[data-family="proofs"]').click(); assert.equal(await page.locator('.history-record').count(), 1);
      assert.match(await page.locator('.history-record').textContent(), /Unavailable until settlement/);
      assert.match(await page.locator('.history-content').textContent(), /index slot 100000/);
      assert.match(await page.locator('.history-record').textContent(), /Value context slot 100007/);
      const changed = structuredClone(value); changed.history.witnesses.pages[0].values.code_current = false; await mount(changed);
      assert.equal(await page.locator('#report-status').textContent(), 'Code pin changed');
      await page.locator('[data-family="witnesses"]').click(); assert.match(await page.locator('#history-records').textContent(), /code pin changed/);
      const stale = structuredClone(value); stale.history.proofs.source_time_unix = String(now - 901); await mount(stale);
      assert.equal(await page.locator('#report-status').textContent(), 'Snapshot is stale'); await page.locator('[data-family="proofs"]').click(); assert.match(await page.locator('.history-content>h3').textContent(), /stale/);
      stale.history.proofs.source_time_unix = String(now); stale.history.proofs.pages[0].values.source_time_unix = String(now - 901); await mount(stale); await page.locator('[data-family="proofs"]').click();
      assert.match(await page.locator('.history-record .state').textContent(), /stale/);
      const incomplete = structuredClone(value); incomplete.history.proofs.pages[0].values = { availability: 'unavailable' }; incomplete.history.proofs.pages[0].complete = false; incomplete.history.proofs.value_completeness = 'incomplete'; await mount(incomplete); await page.locator('[data-family="proofs"]').click();
      assert.equal(await page.locator('#report-status').textContent(), 'History values are incomplete'); assert.equal(await page.locator('.history-record dl').count(), 0); assert.match(await page.locator('.history-record').textContent(), /remains explicitly indexed/);
      const malformed = structuredClone(value); malformed.history.witnesses.pages.pop(); await mount(malformed); assert.equal(await page.locator('#report-status').textContent(), 'Report unavailable'); assert.equal(await page.locator('.history-record').count(), 0);
      await mount({ ...read('burn'), scope: 'configured-rpc' }, Number(read('burn').generated_at_unix)); assert.equal(await page.locator('.history-record').count(), 4); assert.match(await page.locator('#history-records').textContent(), /230\.000000/);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      observations.push({ width, identities: seen.length, unique: new Set(seen).size, external_requests: requests, page_errors: errors }); assert.deepEqual(errors, []); assert.deepEqual(requests, []); await page.close();
    }
    if (process.env.MORSE_HISTORY_BROWSER_EVIDENCE) fs.writeFileSync(process.env.MORSE_HISTORY_BROWSER_EVIDENCE, JSON.stringify({ observations, captures: false }, null, 2) + '\n', { flag: 'wx' });
  } finally { await browser.close(); }
});

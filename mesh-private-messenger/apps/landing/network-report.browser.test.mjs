import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { chromium } from '../mobile/node_modules/playwright/index.mjs';

const report = JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/legacy-closed-report.json', import.meta.url), 'utf8'));
const proof = process.env.MORSE_PUBLIC_REPORT_PROOF || fileURLToPath(new URL('../../../.morse/witness-proof/public-chain-report-20261022', import.meta.url));

test('public record dogfoods actual Mesh export at phone and desktop widths with truthful failure states', { timeout: 30_000 }, async () => {
  const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH });
  const failures = [];
  try {
    fs.mkdirSync(proof, { recursive: true });
    for (const width of [390, 1440]) {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      page.on('pageerror', error => failures.push(error.message));
      page.on('request', request => { if (!request.url().startsWith('file:') && !request.url().startsWith('data:')) failures.push(`External request: ${request.url()}`); });
      await page.goto(new URL('./network.html', import.meta.url).href);
      await page.evaluate(() => document.fonts.ready);
      assert.equal(await page.locator('#report-status').textContent(), 'Awaiting published records');
      assert.equal(await page.locator('.week').count(), 0);
      assert.equal(await page.evaluate(() => document.fonts.check('600 16px Geist')), true);
      await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), report);
      assert.equal(await page.locator('#report-status').textContent(), 'Local fixture preview');
      assert.match(await page.locator('#report-detail').textContent(), /do not count/);
      assert.match(await page.locator('#burn-records').textContent(), /230\.000000/);
      assert.match(await page.locator('#burn-records').textContent(), /0\.000017/);
      assert.match(await page.locator('#burn-records').textContent(), /0\.000019/);
      assert.equal(await page.locator('.week tbody tr').count(), 24);
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      await page.screenshot({ path: path.join(proof, `fixture-${width}.png`), fullPage: true });
      const current = { ...report, scope: 'configured-rpc', generated_at_unix: report.burns[0].source_time_unix };
      const now = Number(current.generated_at_unix);
      await page.evaluate(({ value, now }) => globalThis.MorseNetworkReport.mount(document, value, now), { value: current, now });
      assert.equal(await page.locator('#report-status').textContent(), 'Configured snapshot available');
      await page.evaluate(({ value, now }) => globalThis.MorseNetworkReport.mount(document, value, now), { value: { ...current, burns: [{ ...current.burns[0], code_current: false }] }, now });
      assert.equal(await page.locator('#report-status').textContent(), 'Code pin changed');
      await page.evaluate(({ value, now }) => globalThis.MorseNetworkReport.mount(document, value, now), { value: current, now: now + 901 });
      assert.equal(await page.locator('#report-status').textContent(), 'Snapshot is stale');
      assert.match(await page.locator('.week .state').textContent(), /stale/);
      for (const availability of ['disagreed', 'unavailable']) {
        await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), { ...report, scope: 'configured-rpc', burns: [{ epoch: '2813', availability }] });
        assert.equal(await page.locator('.week dl').count(), 0, 'no stale amounts survive source failure');
        assert.equal(await page.locator('.week .state').textContent(), availability);
      }
      await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), { ...report, burns: [{ ...report.burns[0], budget_units: '1e6' }] });
      assert.equal(await page.locator('#report-status').textContent(), 'Report unavailable');
      assert.equal(await page.locator('.week').count(), 0);
      await page.close();
    }
    assert.deepEqual(failures, []);
    console.log('MORSE_PUBLIC_CHAIN_BROWSER actual_mesh_export_390_1440_fixture_stale_disagreed_unavailable_exact_units');
  } finally { await browser.close(); }
});

const collateralReport = JSON.parse(fs.readFileSync(new URL('../../ops/public-chain/fixtures/mixed-collateral-report.json', import.meta.url), 'utf8'));
test('public v2 collateral renders actual Mesh output and clears every amount on malformed or failed reads', { timeout: 30_000 }, async () => {
  const browser = await chromium.launch({ executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH });
  try {
    for (const width of [390, 1440]) {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      const errors = []; page.on('pageerror', error => errors.push(error.message));
      await page.goto(new URL('./network.html', import.meta.url).href);
      await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), collateralReport);
      assert.equal(await page.locator('#report-status').textContent(), 'Local fixture preview');
      assert.equal(await page.locator('.bond-record').count(), 3); assert.equal(await page.locator('.slash-record').count(), 1);
      assert.match(await page.locator('#bond-records').textContent(), /Pending liability/);
      assert.match(await page.locator('#bond-records').textContent(), /0\.000007/);
      assert.match(await page.locator('#bond-records').textContent(), /historical/);
      assert.match(await page.locator('#slash-records').textContent(), /600\.000008/);
      assert.match(await page.locator('#slash-records').textContent(), /133\.333358/);
      assert.match(await page.locator('#slash-records').textContent(), /Verified signatures: 6(?:\D|$)/, 'SBF mask63 means six verified bits, not63 signatures');
      assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
      const now = Number(collateralReport.bonds.source_time_unix);
      const changed = { ...collateralReport, scope: 'configured-rpc', bonds: { ...collateralReport.bonds, code_current: false } };
      await page.evaluate(({ report, now }) => globalThis.MorseNetworkReport.mount(document, report, now), { report: changed, now });
      assert.equal(await page.locator('#report-status').textContent(), 'Code pin changed');
      assert.match(await page.locator('.bond-record .state').first().textContent(), /code pin changed/);
      await page.evaluate(({ report, now }) => globalThis.MorseNetworkReport.mount(document, report, now), { report: { ...collateralReport, scope: 'configured-rpc' }, now: now + 901 });
      assert.equal(await page.locator('#report-status').textContent(), 'Snapshot is stale');
      assert.match(await page.locator('.slash-record .state').textContent(), /stale/);
      const prepared = structuredClone(collateralReport); prepared.slashes.receipts[0].status = 'prepared';
      for (const asset of prepared.slashes.receipts[0].assets) for (const field of ['slashed_units', 'finder_units', 'directory_slashed_units']) asset[field] = null;
      for (const row of prepared.slashes.receipts[0].rows) for (const field of ['principal_units', 'slashed_units', 'finder_units']) row[field] = null;
      await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), prepared);
      assert.match(await page.locator('#slash-records').textContent(), /Unavailable until settlement/);
      assert.doesNotMatch(await page.locator('#slash-records').textContent(), /600\.000008/);
      for (const availability of ['disagreed', 'unavailable']) {
        await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), { ...collateralReport, bonds: { availability }, slashes: { availability } });
        assert.equal(await page.locator('.bond-record,.slash-record').count(), 0);
        assert.match(await page.locator('#bond-records').textContent(), /Amounts unavailable/);
        assert.doesNotMatch(await page.locator('#slash-records').textContent(), /600\.000008/);
      }
      const malformed = structuredClone(collateralReport); malformed.slashes.receipts[0].assets[0].slashed_units = '1e6';
      await page.evaluate(value => globalThis.MorseNetworkReport.mount(document, value), malformed);
      assert.equal(await page.locator('#report-status').textContent(), 'Report unavailable');
      assert.equal(await page.locator('.bond-record,.slash-record,.week').count(), 0);
      assert.deepEqual(errors, []); await page.close();
    }
    console.log('MORSE_PUBLIC_COLLATERAL_BROWSER actual_Mesh_v2_output_390_1440 mixed_assets stale_code_warning prepared_null failure_clears_amounts');
  } finally { await browser.close(); }
});

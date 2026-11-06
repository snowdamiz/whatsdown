// Actual exported React onboarding; native authorization/network remain fixtures.
import assert from 'node:assert/strict';
import { mkdir, readFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { chromium } from 'playwright';
import { installCreditFixture } from './credits-fixture.mjs';

const dist = new URL('../../desktop/dist/', import.meta.url);
const server = createServer(async (request, response) => {
  try {
    const path = new URL(request.url, 'http://localhost').pathname;
    response.setHeader('Content-Type', path.endsWith('.js') ? 'text/javascript' : path.endsWith('.ttf') ? 'font/ttf' : 'text/html');
    response.end(await readFile(new URL(`.${path === '/' ? '/index.html' : path}`, dist)));
  } catch { response.writeHead(404).end(); }
});
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
if (process.env.MORSE_CREDITS_SCREENSHOTS) await mkdir(process.env.MORSE_CREDITS_SCREENSHOTS, { recursive: true });
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  for (const mode of (process.env.MORSE_SIGNUP_FLOWS?.split(',') || ['signup', 'signup-pending', 'signup-cancel', 'signup-bad-state', 'signup-free', 'signup-free-conflict'])) {
    const page = await browser.newPage({ viewport: { width: 1160, height: 900 }, reducedMotion: 'reduce' });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(installCreditFixture, { mode });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    if (mode === 'signup-bad-state') {
      await page.getByText('Your saved signup could not be loaded. Retry before continuing.', { exact: true }).waitFor();
      assert.equal(await page.getByRole('button', { name: 'Create account', exact: true }).count(), 0);
      assert.equal(await page.evaluate(() => window.creditsUITest.requests.length), 0);
      await page.evaluate(() => { window.creditsUITest.badDraft = false; localStorage.setItem('signup-proof-readable', '1'); });
      await page.getByRole('button', { name: 'Retry', exact: true }).click();
      await page.getByRole('button', { name: 'Retry saved signup', exact: true }).waitFor();
    }
    if (mode.startsWith('signup-free')) {
      await page.getByRole('button', { name: 'Continue with free signup', exact: true }).click();
      if (mode === 'signup-free-conflict') {
        await page.getByText('That username is taken. Try another.', { exact: true }).waitFor();
        await page.getByRole('textbox', { name: 'Choose your username', exact: true }).fill('alice_free');
        await page.getByRole('button', { name: 'Save username', exact: true }).click();
        await page.getByText('@alice_free', { exact: true }).waitFor();
        assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => call.symbol === 'mesh_messenger_create_signup_draft' || call.symbol === 'mesh_messenger_erase_account').length), 0);
        await page.getByRole('button', { name: 'Continue with free signup', exact: true }).click();
      }
      await page.getByRole('button', { name: 'Settings', exact: true }).waitFor({ timeout: 8000 }).catch(async error => { console.log(await page.locator('body').innerText(), await page.evaluate(() => window.creditsUITest)); throw error; });
      assert.equal(await page.evaluate(() => window.creditsUITest.witnessed), true);
      assert.ok(await page.evaluate(() => window.creditsUITest.calls.some(call => call.symbol === 'mesh_messenger_directory_register')), 'free signup uses the typed native registration');
      assert.equal(await page.evaluate(() => window.creditsUITest.requests.some(request => request.route.endsWith('/v1/devices/register') || request.route.endsWith('/v1/prekeys/one-time/batch'))), false, 'registration and prekey HTTP stay native');
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => call.symbol === 'mesh_messenger_signup_draft_free_complete').length), 1);
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => call.symbol === 'mesh_messenger_credit_signup').length), 0);
      assert.deepEqual(errors, []);
      await page.close();
      console.log(`Rendered ${mode} flow passed`);
      continue;
    }
    if (mode === 'signup') {
      await page.getByRole('button', { name: 'Get started', exact: true }).click();
      await page.getByRole('textbox', { name: 'Choose your username', exact: true }).fill('alice');
      await page.getByRole('button', { name: 'Check signup options', exact: true }).click();
      await page.getByRole('button', { name: 'Set up priority signup', exact: true }).click();
      await page.getByText('Finish signup', { exact: true }).waitFor();
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => call.symbol === 'mesh_messenger_credit_signup').length), 0, 'saving a profile cannot charge');
      await page.getByRole('button', { name: 'Buy credits', exact: true }).click();
      await page.getByText('Test credits', { exact: true }).waitFor();
      await page.getByRole('button', { name: 'Back', exact: true }).click();
      await page.getByText('Finish signup', { exact: true }).waitFor();
      await page.evaluate(() => { window.creditsUITest.balanceAvailable = 0; });
      await page.getByRole('button', { name: 'Refresh balance', exact: true }).click();
      await page.getByText('Available credits: 0', { exact: true }).waitFor();
      await page.getByRole('button', { name: 'Check priority availability', exact: true }).click();
      assert.equal(await page.getByRole('button', { name: 'Spend 20 credits to sign up', exact: true }).isDisabled(), true);
      await page.evaluate(() => { window.creditsUITest.balanceAvailable = 100; });
      await page.getByRole('button', { name: 'Refresh balance', exact: true }).click();
      await page.getByRole('button', { name: 'Spend 20 credits to sign up', exact: true }).click();
      await page.getByRole('button', { name: 'Retry saved signup', exact: true }).waitFor();
    } else await page.getByRole('button', { name: 'Retry saved signup', exact: true }).waitFor();
    assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => ['mesh_messenger_register_request', 'mesh_messenger_directory_register'].includes(call.symbol)).length), 0, 'paid draft must not silently take free registration');
    assert.equal(await page.getByRole('button', { name: 'Continue with free signup', exact: true }).count(), 0, 'pending CAP gates free transition');
    if (process.env.MORSE_CREDITS_SCREENSHOTS) {
      await page.waitForTimeout(500);
      await page.screenshot({ path: `${process.env.MORSE_CREDITS_SCREENSHOTS}/${mode}-pending.png`, fullPage: true });
    }
    if (mode === 'signup-cancel') {
      await page.getByRole('button', { name: 'Recover reserved credits', exact: true }).click();
      await page.getByText('This signup was not used. Your reserved credits are available again.', { exact: true }).waitFor();
      await page.getByRole('button', { name: 'Continue with free signup', exact: true }).waitFor();
      await page.getByRole('textbox', { name: 'Choose your username', exact: true }).fill('alice_again');
      await page.getByRole('button', { name: 'Save username', exact: true }).click();
      await page.getByText('@alice_again', { exact: true }).waitFor();
      assert.equal(await page.getByRole('button', { name: 'Settings', exact: true }).count(), 0, 'signed cancellation is not registration completion');
    } else {
      const first = await page.evaluate(() => window.creditsUITest.requests.filter(request => request.route.endsWith('/signup')).map(request => request.body));
      await page.reload();
      await page.getByRole('button', { name: 'Retry saved signup', exact: true }).waitFor();
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => call.symbol === 'mesh_messenger_credit_signup').length), 0, 'restart must not reserve again');
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => ['mesh_messenger_register_request', 'mesh_messenger_directory_register'].includes(call.symbol)).length), 0);
      await page.evaluate(() => { window.creditsUITest.failSignup = false; });
      await page.getByRole('button', { name: 'Retry saved signup', exact: true }).click();
      await page.getByRole('button', { name: 'Settings', exact: true }).waitFor();
      const retried = await page.evaluate(() => window.creditsUITest.requests.filter(request => request.route.endsWith('/signup')).map(request => request.body));
      assert.deepEqual(retried, [first[0] || [88, 99]]);
    }
    assert.deepEqual(errors, []);
    if (process.env.MORSE_CREDITS_SCREENSHOTS) await page.screenshot({ path: `${process.env.MORSE_CREDITS_SCREENSHOTS}/${mode}.png`, fullPage: true });
    await page.close();
    console.log(`Rendered ${mode} flow passed`);
  }
} finally {
  await browser?.close();
  server.close();
}

// Real exported React/navigation bundle; native IPC and the network are fixtures.
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
const screenshots = process.env.MORSE_CREDITS_SCREENSHOTS;
if (screenshots) await mkdir(screenshots, { recursive: true });
let browser;
try {
  browser = await chromium.launch({ channel: process.env.PLAYWRIGHT_CHANNEL || undefined });
  for (const mode of ['disabled', 'purchase', 'wallet', 'expired', 'lightning', 'lightning-canceled']) {
    const page = await browser.newPage({ viewport: { width: 1160, height: 900 }, reducedMotion: 'reduce' });
    const errors = [];
    page.on('pageerror', error => errors.push(error.message));
    await page.addInitScript(installCreditFixture, { mode });
    await page.goto(`http://127.0.0.1:${server.address().port}`);
    await page.getByRole('button', { name: 'Settings', exact: true }).click({ timeout: 5000 });
    assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(call => call.wallet || (call.symbol?.startsWith('mesh_messenger_credit_') && !call.symbol.includes('signup_policy'))).length), 0, 'free startup must not initialize optional credit or wallet state');
    await page.getByRole('button', { name: 'Credits', exact: true }).click({ timeout: 1500 });
    if (mode === 'disabled') {
      await page.getByText('Credits aren’t enabled in this app release. Your chats still work.', { exact: true }).waitFor();
      assert.equal(await page.getByRole('button', { name: 'Get payment quote', exact: true }).count(), 0);
      await page.getByRole('button', { name: 'Back', exact: true }).click();
      await page.getByText('People you message see this name and photo.', { exact: true }).waitFor();
    } else if (mode === 'purchase') {
      await page.getByText('Test credits', { exact: true }).waitFor();
      assert.equal(await page.evaluate(() => window.creditsUITest.requests.filter(request => request.route.startsWith('https://edge.example/v1/credits/') && !request.route.endsWith('/signup-policy')).length), 0, 'local balance/history must not contact the issuer');
      await page.getByText('Payment is public on Solana.', { exact: false }).waitFor();
      await page.getByRole('radio', { name: 'Credit pack: 500', exact: true }).click();
      await page.getByRole('radio', { name: 'Payment asset: SOL', exact: true }).click();
      await page.getByRole('button', { name: 'Get payment quote', exact: true }).click();
      await page.getByText('Ready to pay', { exact: true }).first().waitFor();
      await page.getByRole('button', { name: 'Open external wallet', exact: true }).click();
      assert.equal((await page.evaluate(() => window.creditsUITest.opened)).length, 1);
      await page.getByRole('textbox', { name: 'Payment signature', exact: true }).fill('canonical-base58-signature');
      await page.getByRole('button', { name: 'Recover payment', exact: true }).click();
      await page.getByText('Payment outcome unknown. Retry this saved purchase; don’t pay again.', { exact: true }).waitFor();
      const before = await page.evaluate(() => window.creditsUITest.requests.filter(value => value.route.endsWith('/issue')));
      assert.equal(before.length, 1);
      await page.reload();
      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await page.getByRole('button', { name: 'Credits', exact: true }).click();
      await page.getByText('Waiting for credits', { exact: true }).first().waitFor();
      assert.equal(await page.getByRole('button', { name: 'Get payment quote', exact: true }).count(), 0);
      await page.evaluate(() => { window.creditsUITest.failIssue = false; });
      await page.getByRole('button', { name: 'Retry saved purchase', exact: true }).click();
      await page.getByText('Purchase complete', { exact: true }).first().waitFor();
      await page.getByText('500', { exact: true }).first().waitFor();
      assert.deepEqual(await page.evaluate(() => window.creditsUITest.requests.filter(value => value.route.endsWith('/issue')).map(value => value.body)), [before[0].body]);
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(value => value.symbol?.endsWith('_prepare')).length), 0);
    } else if (mode.startsWith('lightning')) {
      await page.getByRole('radio', { name: 'Payment asset: Lightning', exact: true }).click();
      await page.getByText('Pay this invoice once with a Lightning wallet.', { exact: false }).waitFor();
      await page.getByRole('button', { name: 'Get payment quote', exact: true }).click();
      await page.getByText('Ready to pay', { exact: true }).first().waitFor();
      assert.equal(await page.getByRole('textbox', { name: 'Payment signature', exact: true }).count(), 0);
      assert.equal(await page.getByRole('button', { name: 'Pay with in-app wallet', exact: true }).count(), 0);
      await page.getByRole('button', { name: 'Open external wallet', exact: true }).click();
      await page.getByText('Waiting for credits', { exact: true }).first().waitFor();
      assert.deepEqual(await page.evaluate(() => window.creditsUITest.opened), ['lightning:lnbcrt1verifiedinvoice']);
      await page.getByRole('button', { name: 'Check Lightning payment', exact: true }).click();
      await page.getByText('Payment outcome unknown. Retry this saved purchase; don’t pay again.', { exact: true }).waitFor();
      await page.reload();
      await page.getByRole('button', { name: 'Settings', exact: true }).click();
      await page.getByRole('button', { name: 'Credits', exact: true }).click();
      await page.getByText('Waiting for credits', { exact: true }).first().waitFor();
      assert.equal(await page.getByRole('button', { name: 'Get payment quote', exact: true }).count(), 0);
      await page.evaluate(() => { window.creditsUITest.failIssue = false; });
      await page.getByRole('button', { name: 'Check Lightning payment', exact: true }).click();
      if (mode === 'lightning-canceled') {
        await page.getByText('Payment canceled', { exact: true }).first().waitFor();
        await page.getByText('This invoice was canceled. No credits were added. You can request a new quote.', { exact: true }).waitFor();
        assert.equal(await page.getByText('Purchase complete', { exact: true }).count(), 0);
        await page.getByRole('button', { name: 'Get payment quote', exact: true }).waitFor();
      } else {
        await page.getByText('Purchase complete', { exact: true }).first().waitFor();
      }
      const attempts = await page.evaluate(() => window.creditsUITest.requests.filter(value => value.route.endsWith('/lightning/issue')));
      assert.equal(attempts.length, 1);
      assert.equal(attempts[0].native, true);
      if (mode === 'lightning-canceled') {
        await page.reload();
        await page.getByRole('button', { name: 'Settings', exact: true }).click();
        await page.getByRole('button', { name: 'Credits', exact: true }).click();
        await page.getByText('Payment canceled', { exact: true }).first().waitFor();
        await page.getByRole('button', { name: 'Get payment quote', exact: true }).click();
        await page.getByText('Ready to pay', { exact: true }).first().waitFor();
      }
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(value => value.symbol?.endsWith('_prepare')).length), mode === 'lightning-canceled' ? 1 : 0);
    } else if (mode === 'wallet') {
      await page.getByRole('button', { name: 'Create in-app wallet', exact: true }).click();
      await page.getByText('4vJ9JU1bJJE96FWSJKvHsmmFADCg4gpZQff4P3bkLKi', { exact: true }).waitFor();
      await page.getByRole('button', { name: 'Get payment quote', exact: true }).click();
      await page.getByRole('button', { name: 'Pay with in-app wallet', exact: true }).click();
      await page.getByText('Payment was not approved. Nothing new was submitted.', { exact: true }).waitFor();
      assert.equal(await page.evaluate(() => window.creditsUITest.requests.filter(value => value.route.endsWith('/issue')).length), 0);
      await page.getByRole('button', { name: 'Pay with in-app wallet', exact: true }).click();
      await page.getByText('Purchase complete', { exact: true }).first().waitFor();
      const calls = await page.evaluate(() => window.creditsUITest.calls.filter(value => value.wallet));
      assert.equal(calls.filter(value => value.wallet === '1').length, 1);
      assert.equal(calls.filter(value => value.wallet === '5').length, 2);
      assert.equal(calls.filter(value => value.wallet === '3').length, 0, 'JS must not supply raw quote/hash to a signer');
      assert.equal(await page.getByRole('button', { name: 'Recover payment', exact: true }).count(), 0);
    } else {
      await page.getByText('Quote expired', { exact: true }).first().waitFor();
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(value => value.symbol?.endsWith('_prepare_again')).length), 0);
      await page.getByText('The old quote stays in your local history for payment recovery.', { exact: false }).waitFor();
      await page.getByRole('button', { name: 'Buy again with a new quote', exact: true }).click();
      await page.getByText('Ready to pay', { exact: true }).first().waitFor();
      assert.equal(await page.evaluate(() => window.creditsUITest.calls.filter(value => value.symbol?.endsWith('_prepare_again')).length), 1);
    }
    if (screenshots) {
      if (mode !== 'disabled') await page.getByText('Test credits', { exact: true }).evaluate(element => {
        for (let parent = element.parentElement; parent; parent = parent.parentElement) {
          if (['auto', 'scroll'].includes(getComputedStyle(parent).overflowY)) { parent.scrollTop = 0; break; }
        }
      });
      // Native-style enter animation outlives the accessibility node.
      await page.waitForTimeout(500);
      await page.screenshot({ path: `${screenshots}/${mode}.png`, fullPage: true });
    }
    if (mode === 'wallet') {
      const languages = [
        ['es', 'Ajustes', 'Créditos', 'Créditos de prueba'],
        ['pt', 'Configurações', 'Créditos', 'Créditos de teste'],
        ['fr', 'Paramètres', 'Crédits', 'Crédits de test'],
        ['de', 'Einstellungen', 'Credits', 'Test-Credits'],
        ['ru', 'Настройки', 'Кредиты', 'Тестовые кредиты'],
      ];
      for (const [language, settings, credits, available] of languages) {
        await page.evaluate(language => localStorage.setItem('morse.language', language), language);
        await page.reload();
        await page.getByRole('button', { name: settings, exact: true }).click();
        await page.getByRole('button', { name: credits, exact: true }).click();
        await page.getByText(available, { exact: true }).waitFor();
        if (screenshots) {
          await page.waitForTimeout(500);
          await page.screenshot({ path: `${screenshots}/locale-${language}.png`, fullPage: true });
        }
        console.log(`Credits UI language: ${language}`);
      }
    }
    assert.deepEqual(errors, []);
    console.log(`Credits UI: ${mode}`);
    await page.close();
  }
} finally {
  await browser?.close();
  await new Promise(resolve => server.close(resolve));
}

import assert from 'node:assert/strict';
import test from 'node:test';
import { chromium } from '../mobile/node_modules/playwright/index.mjs';

test('witness recruitment shows Bootstrap limitations before its future network examples', async () => {
  const browser = await chromium.launch(process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH
    ? { executablePath: process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH } : {});
  try {
    for (const width of [390, 1440]) {
      const page = await browser.newPage({ viewport: { width, height: 900 } });
      try {
        await page.goto(new URL('./witnesses.html', import.meta.url).href);
        const current = page.locator('#current-witnesses');
        assert.equal(await current.count(), 1, 'missing current trust profile');
        const profile = await current.innerText();
        assert.match(profile, /Bootstrap/);
        assert.match(profile, /witness-a[\s\S]*witness-b/);
        assert.match(profile, /same operator/);
        assert.match(profile, /No outside signature is required/);
        assert.equal(await page.locator('a[href="#current-witnesses"]').count() > 0, true);
        const faq = page.locator('details').filter({ hasText: 'Could Morse outvote the witnesses?' });
        await faq.locator('summary').click();
        await faq.locator('p').first().waitFor({ state: 'visible' });
        const answer = await faq.innerText();
        assert.match(answer, /Bootstrap/);
        assert.match(answer, /Open profile/);
        assert.doesNotMatch(answer, /No\. Morse runs exactly one witness/);
        const implementation = page.locator('details').filter({ hasText: 'Do I have to run Morse’s software?' });
        assert.doesNotMatch(await implementation.textContent(), /at least one pinned witness runs software Morse didn’t write/);
        assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
      } finally { await page.close(); }
    }
  } finally { await browser.close(); }
});

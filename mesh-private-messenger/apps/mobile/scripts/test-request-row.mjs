import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { createServer } from 'node:http';
import { readFile, writeFile, mkdtemp, mkdir, rm } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';

// Run after installing mobile dependencies: node scripts/test-request-row.mjs
// An optional MORSE_ROW_TEST_OUTPUT keeps the bundle and result for inspection.
const app = fileURLToPath(new URL('../', import.meta.url));
const keep = process.env.MORSE_ROW_TEST_OUTPUT;
const output = keep ? resolve(keep) : await mkdtemp(join(tmpdir(), 'morse-request-row-'));
if (keep) await mkdir(output);
const { chromium } = createRequire(join(app, 'package.json'))('playwright');
const result = { scope: 'Actual React/RNWeb RequestRow and Tap; distinct open and accept actions', cases: [], pageErrors: [] };
const server = createServer(async (request, response) => {
  if (request.url === '/') {
    response.setHeader('Content-Type', 'text/html');
    response.end('<!doctype html><html><body><div id="root"></div><script src="/rendered.js"></script></body></html>');
  } else if (request.url === '/rendered.js') {
    response.setHeader('Content-Type', 'text/javascript');
    response.end(await readFile(join(output, 'rendered.js')));
  } else response.writeHead(404).end();
});
let browser;
try {
  const build = spawnSync(process.execPath, [join(app, 'node_modules/expo/bin/cli'), 'export:embed',
    '--platform', 'web', '--entry-file', 'tests/request-row.tsx',
    '--bundle-output', join(output, 'rendered.js'), '--assets-dest', join(output, 'assets'),
    '--dev', 'false', '--minify', 'false', '--max-workers', '1'], {
    cwd: app, env: { ...process.env, CI: '1', EXPO_NO_DOTENV: '1', EXPO_NO_TELEMETRY: '1' },
    encoding: 'utf8', timeout: 120000, maxBuffer: 8 * 1024 * 1024,
  });
  await writeFile(join(output, 'build.log'), (build.stdout ?? '') + (build.stderr ?? ''));
  assert.equal(build.status, 0, `Request-row test bundle failed: ${build.error?.message ?? build.stderr}`);
  await new Promise((ok, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', ok); });
  browser = await chromium.launch({ channel: 'chrome', headless: true });
  result.browser = browser.version();
  for (const width of [420, 1160]) {
    for (const kind of ['open-enter', 'open-click', 'accept-enter', 'accept-click', 'separate-actions']) {
      const page = await browser.newPage({ viewport: { width, height: 800 }, reducedMotion: 'reduce' });
      page.on('pageerror', error => result.pageErrors.push(error.message));
      const record = { width, kind, status: 'failed' };
      try {
        await page.goto(`http://127.0.0.1:${server.address().port}`);
        const control = page.getByRole('button', { name: 'Conversation with @carol', exact: true });
        await control.press('Enter');
        await page.getByText('Control: 1', { exact: true }).waitFor({ timeout: 2000 });
        const open = page.getByRole('button', { name: 'Conversation with @bob, message request pending, 2 unread messages', exact: true });
        const accept = page.getByRole('button', { name: 'Accept request from @bob', exact: true });
        assert.equal(await open.count(), 1);
        assert.equal(await accept.count(), 1);
        assert.equal(await page.getByText('Can we talk about the project?', { exact: true }).isVisible(), true);
        if (kind === 'separate-actions') {
          assert.equal(await open.getByRole('button').count(), 0, 'open action cannot contain another button');
          assert.equal(await accept.locator('xpath=ancestor::*[@role="button"]').count(), 0, 'accept action cannot be nested in a button');
          assert.equal(await open.evaluate(element => element.tabIndex), 0, 'open action must be keyboard focusable');
          record.open = await open.ariaSnapshot(); record.accept = await accept.ariaSnapshot();
        } else {
          const action = kind.startsWith('open') ? open : accept;
          if (kind.endsWith('enter')) await action.press('Enter');
          else await action.click({ timeout: 2000 });
          await page.getByText(kind.startsWith('open') ? 'Opened: 1; accepted: 0' : 'Opened: 0; accepted: 1', { exact: true }).waitFor({ timeout: 2000 });
          // A second direct activation proves both controls stay independently usable.
          const other = kind.startsWith('open') ? accept : open;
          await other.click({ timeout: 2000 });
          await page.getByText('Opened: 1; accepted: 1', { exact: true }).waitFor({ timeout: 2000 });
        }
        record.status = 'passed';
      } catch (error) { record.error = error.message; }
      finally { await page.close(); result.cases.push(record); }
    }
  }
  assert.deepEqual(result.pageErrors, []);
  assert.equal(result.cases.filter(item => item.status === 'passed').length, 10, 'all direct row action cases pass');
  result.status = 'passed';
} catch (error) { result.status = 'failed'; result.error = error.message; process.exitCode = 1; }
finally {
  await browser?.close();
  if (server.listening) await new Promise(ok => server.close(ok));
  await writeFile(join(output, 'result.json'), JSON.stringify(result, null, 2) + '\n');
  console.log(JSON.stringify({ status: result.status, passed: result.cases.filter(item => item.status === 'passed').length, cases: result.cases.length, ...(keep ? { output } : {}) }));
  if (!keep) await rm(output, { recursive: true, force: true });
}

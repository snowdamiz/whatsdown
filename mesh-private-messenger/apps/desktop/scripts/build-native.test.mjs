import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, copyFileSync, writeFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';

test('desktop preserves its installed library and config unless the disclosure report matches',
  { skip: process.platform !== 'darwin' }, () => {
    const root = mkdtempSync(join(tmpdir(), 'morse-desktop-disclosures-'));
    try {
      const product = join(root, 'mesh-private-messenger');
      const scripts = join(product, 'apps/desktop/scripts');
      const native = join(product, 'apps/desktop/src-tauri/native');
      for (const path of [scripts, native, join(product, 'ops/plaintext'), join(product, 'protocol'), join(root, 'bin')]) {
        mkdirSync(path, { recursive: true });
      }
      copyFileSync(new URL('./build-native.mjs', import.meta.url), join(scripts, 'build-native.mjs'));
      copyFileSync(new URL('../../../ops/plaintext/report.mjs', import.meta.url), join(product, 'ops/plaintext/report.mjs'));
      // Configuration has separate tests; this gate tests installation order.
      writeFileSync(join(scripts, 'config.mjs'), 'export const desktopConfig = () => ({ fixture: true, ohttpFrame: \"synthetic-companion-serialization-fixture\" });\n');
      writeFileSync(join(native, '../tauri.conf.json'), JSON.stringify({ bundle: { macOS: { minimumSystemVersion: '12.0' } } }));
      const site = { kind: 'display', reason: 'synthetic desktop fixture', start: 1, end: 20, line: 1, column: 1 };
      const report = { schema_version: 1, policy: 'plaintext-v1', compiler_version: 'test',
        modules: [{ module: 'MobileCore', file: 'mobile_core.mpl', source_sha256: 'ab'.repeat(32), sites: [site] }] };
      writeFileSync(join(root, 'report.json'), JSON.stringify(report));
      writeFileSync(join(product, 'protocol/plaintext-disclosures.json'), JSON.stringify({ schema_version: 1, policy: 'plaintext-v1',
        sites: [{ module: 'MobileCore', file: 'mobile_core.mpl', ...site }] }));
      const compiler = join(root, 'bin/meshc');
      writeFileSync(compiler, `#!/usr/bin/env node
const fs = require('node:fs');
const output = process.argv[process.argv.indexOf('--output') + 1];
fs.writeFileSync(output, 'new library');
if (process.env.REPORT_MODE !== 'missing') {
  const report = JSON.parse(fs.readFileSync(process.env.FIXTURE_REPORT, 'utf8'));
  if (process.env.REPORT_MODE === 'changed') report.modules[0].sites[0].reason = 'unreviewed';
  fs.writeFileSync(output + '.plaintext.json', JSON.stringify(report));
}
`, { mode: 0o755 });
      writeFileSync(join(root, 'bin/otool'), '#!/bin/sh\nprintf "minos 12.0\\n"\n', { mode: 0o755 });
      const extension = process.platform === 'win32' ? 'dll' : 'dylib';
      const library = join(native, `libmessenger_mobile.${extension}`);
      writeFileSync(library, 'installed library');
      writeFileSync(join(native, 'config.json'), 'installed config');
      const run = mode => spawnSync(process.execPath, [join(scripts, 'build-native.mjs'), '--development'], {
        encoding: 'utf8', env: { ...process.env, MESHC: compiler, REPORT_MODE: mode,
          FIXTURE_REPORT: join(root, 'report.json'), PATH: `${join(root, 'bin')}:${process.env.PATH}` },
      });
      for (const mode of ['missing', 'changed']) {
        const result = run(mode);
        assert.notEqual(result.status, 0, `${mode}: unreviewed native library was installed`);
        assert.equal(readFileSync(library, 'utf8'), 'installed library');
        assert.equal(readFileSync(join(native, 'config.json'), 'utf8'), 'installed config');
      }
      const result = run('valid');
      assert.equal(result.status, 0, result.stderr);
      assert.equal(readFileSync(library, 'utf8'), 'new library');
      assert.equal(JSON.parse(readFileSync(join(native, 'config.json'), 'utf8')).ohttpFrame, 'synthetic-companion-serialization-fixture');
      const evidence = JSON.parse(readFileSync(`${library}.plaintext-evidence.json`, 'utf8'));
      assert.equal(evidence.disclosure_count, 1);
      assert.equal(readFileSync(`${library}.plaintext.json`, 'utf8'), JSON.stringify(report));
    } finally { rmSync(root, { recursive: true, force: true }); }
  });

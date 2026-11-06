import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const app = fileURLToPath(new URL('..', import.meta.url));
const cli = fileURLToPath(new URL('../node_modules/expo/bin/cli', import.meta.url));
const output = mkdtempSync(join(tmpdir(), 'morse-preview-bundles-'));
// Metro writes an indexed map, one section per module group, as often as a flat one.
const mapSources = (map) => map.sections ? map.sections.flatMap((section) => mapSources(section.map)) : map.sources ?? [];
try {
  for (const build of [
    { name: 'release', platforms: ['ios', 'android', 'web'], desktop: 'false', dev: false, fixtures: false },
    { name: 'desktop-dev', platforms: ['web'], desktop: 'true', dev: false, fixtures: true },
    { name: 'mobile-dev', platforms: ['ios', 'android'], desktop: 'false', dev: true, fixtures: true },
  ]) {
    const directory = join(output, build.name);
    const result = spawnSync(process.execPath, [
      cli, 'export', '--clear', '--no-bytecode', '--source-maps', '--output-dir', directory,
      ...build.platforms.flatMap((platform) => ['--platform', platform]), ...(build.dev ? ['--dev'] : []),
    ], {
      cwd: app, encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
      env: { ...process.env, EXPO_PUBLIC_DESKTOP_DEVELOPMENT: build.desktop },
    });
    assert.equal(result.status, 0, result.error?.message ?? result.stdout + result.stderr);
    for (const platform of build.platforms) {
      const bundles = join(directory, '_expo', 'static', 'js', platform);
      const maps = readdirSync(bundles).filter((file) => file.endsWith('.map'));
      assert.ok(maps.length, `${build.name}/${platform}: missing source maps`);
      const hasFixtures = maps.some((file) => mapSources(JSON.parse(readFileSync(join(bundles, file), 'utf8')))
        .some((source) => /(^|\/)dev-preview\.ts$/.test(source.replaceAll('\\', '/'))));
      assert.equal(hasFixtures, build.fixtures, `${build.name}/${platform}: unexpected fixture module inclusion`);
      console.log(`${build.name}/${platform}: fixtures ${hasFixtures ? 'included' : 'excluded'}`);
    }
  }
} finally {
  rmSync(output, { recursive: true, force: true });
}

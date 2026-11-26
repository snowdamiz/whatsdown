// Writes the latest.json that installed apps read to find an update:
//   node updater-manifest.mjs <installers dir> <version>
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

export const releases = 'https://github.com/snowdamiz/whatsdown/releases';

// The updater picks its entry by `<os>-<arch>`. The release job gives the Mac
// archives these names; Tauri names the Windows installer itself.
const bundles = {
  'darwin-aarch64': (version) => `Morse_${version}_aarch64.app.tar.gz`,
  'darwin-x86_64': (version) => `Morse_${version}_x64.app.tar.gz`,
  'windows-x86_64': (version) => `Morse_${version}_x64-setup.exe`,
};

export function updaterManifest(dir, version) {
  const platforms = {};
  for (const [platform, bundle] of Object.entries(bundles)) {
    const file = bundle(version);
    platforms[platform] = {
      signature: readFileSync(join(dir, `${file}.sig`), 'utf8').trim(),
      url: `${releases}/download/desktop-v${version}/${file}`,
    };
  }
  return { version, platforms };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const [dir, version] = process.argv.slice(2);
  writeFileSync(join(dir, 'latest.json'), `${JSON.stringify(updaterManifest(dir, version), null, 2)}\n`);
}

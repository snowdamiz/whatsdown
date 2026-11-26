import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';

// Cargo runs this after linking, including every Tauri development rebuild.
const identity = (process.env.MORSE_DEV_SIGNING_IDENTITY || process.env.APPLE_SIGNING_IDENTITY || 'Apple Development').trim();
if (!identity || identity === '-') throw new Error('Use a signing certificate for MORSE_DEV_SIGNING_IDENTITY, not ad-hoc signing');
const [executable, ...args] = process.argv.slice(2);
if (!executable) throw new Error('Expected the Cargo executable path');
const binary = resolve(executable);
const { identifier } = JSON.parse(readFileSync(new URL('../src-tauri/tauri.dev.conf.json', import.meta.url)));
const signed = spawnSync('codesign', ['--force', '--timestamp=none', '--sign', identity,
  '--identifier', identifier, binary], { stdio: 'inherit' });
if (signed.error) throw signed.error;
if (signed.status !== 0) throw new Error('Install a signing certificate or set MORSE_DEV_SIGNING_IDENTITY to its name');

// Replace the runner so Tauri can stop/restart the actual app without orphaning it.
process.execve(binary, [binary, ...args], process.env);

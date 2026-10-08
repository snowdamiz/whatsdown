import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../../../..', import.meta.url));
const macOnly = { skip: process.platform !== 'darwin' && 'the stand-ins are shell scripts; Windows builds run in CI' };

// cargo and meshc are stand-ins that log their calls; the compiler then fails,
// so nothing is installed into src-tauri/native.
function nativeBuild(...options) {
  const bin = mkdtempSync(join(tmpdir(), 'morse-desktop-native-test-'));
  try {
    const log = join(bin, 'calls.log');
    for (const [name, status] of [['cargo', 0], ['meshc', 1]]) {
      writeFileSync(join(bin, name), `#!/bin/sh\necho "${name} runtime=\${MESH_RT_LIB_PATH:-default} $*" >> "${log}"\nexit ${status}\n`);
      chmodSync(join(bin, name), 0o755);
    }
    const env = { ...process.env, PATH: `${bin}:${process.env.PATH}`, MESHC: join(bin, 'meshc') };
    delete env.MESH_RT_LIB_PATH;
    delete env.CARGO_TARGET_DIR;
    const result = spawnSync(process.execPath, [fileURLToPath(new URL('./build-native.mjs', import.meta.url)),
      '--development', ...options], { encoding: 'utf8', env });
    assert.match(result.stderr, /Mesh native build failed/);
    return readFileSync(log, 'utf8').trim().split('\n');
  } finally {
    rmSync(bin, { recursive: true, force: true });
  }
}

test('release libraries link the release runtime into an optimised core', macOnly, () => {
  const [cargo, meshc] = nativeBuild('--release');
  assert.equal(cargo, `cargo runtime=default build --locked --release -p mesh-rt --lib --manifest-path ${join(root, 'mesh-lang/Cargo.toml')}`);
  assert.ok(meshc.startsWith(`meshc runtime=${join(root, 'mesh-lang/target/release/libmesh_rt.a')} build `), meshc);
  assert.match(meshc, / --opt-level 2( |$)/);
});

test('development libraries keep the compiler\'s own runtime and optimisation level', macOnly, () => {
  const calls = nativeBuild();
  assert.equal(calls.length, 1, calls.join('\n'));
  assert.ok(calls[0].startsWith('meshc runtime=default build '), calls[0]);
  assert.doesNotMatch(calls[0], /--opt-level/);
});

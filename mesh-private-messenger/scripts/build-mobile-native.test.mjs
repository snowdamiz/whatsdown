import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { chmodSync, copyFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

// Runs the script in a scratch checkout, with cargo, rustup and meshc replaced
// by stand-ins that log how they were called.
function buildAndroid(...options) {
  const root = realpathSync(mkdtempSync(join(tmpdir(), 'morse-native-test-')));
  try {
    const messenger = join(root, 'mesh-private-messenger');
    const generated = join(messenger, 'apps/mobile/modules/mesh-messenger/generated');
    const bin = join(root, 'bin');
    const log = join(root, 'calls.log');
    for (const directory of ['scripts', 'packages/mobile-core', 'packages/wallet-core/include']) {
      mkdirSync(join(messenger, directory), { recursive: true });
    }
    for (const directory of [generated, bin, join(root, 'ndk')]) mkdirSync(directory, { recursive: true });
    copyFileSync(new URL('./build-mobile-native.sh', import.meta.url), join(messenger, 'scripts/build-mobile-native.sh'));
    for (const extension of ['h', 'swift', 'kt', 'jni.c', 'ts']) {
      writeFileSync(join(generated, `libmessenger_mobile.${extension}`), extension);
    }
    for (const header of [join(generated, 'morse_wallet.h'), join(messenger, 'packages/wallet-core/include/morse_wallet.h')]) {
      writeFileSync(header, 'wallet');
    }
    const tool = (name, body) => {
      writeFileSync(join(bin, name), `#!/bin/sh\n${body}\n`);
      chmodSync(join(bin, name), 0o755);
    };
    tool('rustup', `echo "${bin}/cargo"`);
    tool('cargo', `echo "cargo $*" >> "${log}"
while [ $# -gt 1 ]; do case $1 in --target) t=$2 ;; --target-dir) d=$2 ;; esac; shift; done
if [ -n "$d" ]; then mkdir -p "$d/$t/release" && : > "$d/$t/release/libmorse_wallet_core.a"; fi`);
    tool('meshc', `echo "meshc runtime=\${MESH_RT_LIB_PATH:-default} $*" >> "${log}"
while [ $# -gt 1 ]; do if [ "$1" = --output ]; then out=$2; fi; shift; done
: > "$out"
for extension in h swift kt jni.c ts; do cp "${generated}/libmessenger_mobile.$extension" "\${out%.a}.$extension"; done`);
    const result = spawnSync('bash', [join(messenger, 'scripts/build-mobile-native.sh'), ...options, 'android'], {
      encoding: 'utf8',
      env: {
        ...process.env, PATH: `${bin}:${process.env.PATH}`, MESHC: join(bin, 'meshc'),
        CARGO_TARGET_DIR: join(root, 'target'), ANDROID_NDK_HOME: join(root, 'ndk'),
      },
    });
    assert.equal(result.status, 0, result.stderr);
    return { root, calls: readFileSync(log, 'utf8').trim().split('\n') };
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

test('release archives link each target\'s release runtime into an optimised core', () => {
  const { root, calls } = buildAndroid('--release');
  for (const target of ['aarch64-linux-android', 'x86_64-linux-android']) {
    assert.ok(calls.includes(`cargo build --locked --release --manifest-path ${root}/mesh-lang/Cargo.toml -p mesh-rt --lib --target ${target}`), calls.join('\n'));
    const core = calls.find(call => call.startsWith('meshc') && call.includes(`--target ${target}`));
    assert.ok(core.startsWith(`meshc runtime=${root}/target/${target}/release/libmesh_rt.a build `), core);
    assert.ok(core.includes(' --opt-level 2 '), core);
  }
});

test('development archives keep the compiler\'s own runtime and optimisation level', () => {
  const { calls } = buildAndroid();
  assert.equal(calls.filter(call => /mesh-rt|--opt-level|runtime=(?!default)/.test(call)).length, 0, calls.join('\n'));
});

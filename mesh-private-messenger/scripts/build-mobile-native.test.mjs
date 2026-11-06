import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, copyFileSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { createHash } from 'node:crypto';

test('native installation preserves old artifacts on failure and refreshes Android ABI and bindings on success', async () => {
  const root = mkdtempSync(join(tmpdir(), 'morse-native-build-test-'));
  try {
    const scripts = join(root, 'mesh-private-messenger/scripts');
    const appScripts = join(root, 'mesh-private-messenger/apps/mobile/scripts');
    const module = join(root, 'mesh-private-messenger/apps/mobile/modules/mesh-messenger');
    const framework = join(module, 'native/ios/MeshMessengerCore.xcframework');
    const walletFramework = join(module, 'native/ios/MorseWalletCore.xcframework');
    const walletPackage = join(root, 'mesh-private-messenger/packages/wallet-core');
    const plaintext = join(root, 'mesh-private-messenger/ops/plaintext');
    const protocol = join(root, 'mesh-private-messenger/protocol');
    const ndk = join(root, 'ndk');
    for (const path of [scripts, appScripts, plaintext, protocol, join(walletPackage, 'include'), walletFramework, join(module, 'generated'), framework, join(root, 'bin'), join(root, 'temp')]) mkdirSync(path, { recursive: true });
    copyFileSync(new URL('./build-mobile-native.sh', import.meta.url), join(scripts, 'build-mobile-native.sh'));
    copyFileSync(new URL('../apps/mobile/scripts/generate-scoped-bindings.mjs', import.meta.url), join(appScripts, 'generate-scoped-bindings.mjs'));
    const rawBindings = readFileSync(new URL('../apps/mobile/scripts/fixtures/scoped-bindings/mobile.ts', import.meta.url), 'utf8');
    const abi = JSON.parse(readFileSync(new URL('../apps/mobile/scripts/fixtures/scoped-bindings/native-mobile.abi.json', import.meta.url), 'utf8'));
    const { generate } = await import('../apps/mobile/scripts/generate-scoped-bindings.mjs');
    const scoped = generate(rawBindings, abi);
    writeFileSync(join(module, 'scoped.ts'), scoped);
    writeFileSync(join(root, 'bindings.ts'), rawBindings);
    for (const target of ['host', 'aarch64-apple-ios', 'aarch64-apple-ios-sim', 'aarch64-linux-android', 'x86_64-linux-android']) {
      writeFileSync(join(root, `abi-${target}.json`), JSON.stringify({ ...abi, target }));
    }

    copyFileSync(new URL('../ops/plaintext/report.mjs', import.meta.url), join(plaintext, 'report.mjs'));
    const disclosure = { module: 'MobileCore', file: 'mobile_core.mpl', kind: 'display',
      reason: 'synthetic public native build fixture', start: 1, end: 20, line: 1, column: 1 };
    writeFileSync(join(protocol, 'plaintext-disclosures.json'), JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: [disclosure] }));
    const { module: moduleName, file, ...site } = disclosure;
    writeFileSync(join(root, 'report.json'), JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', compiler_version: 'test',
      modules: [{ module: moduleName, file, source_sha256: 'ab'.repeat(32), sites: [site] }] }));
    writeFileSync(join(root, 'changed-report.json'), JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', compiler_version: 'test',
      modules: [{ module: moduleName, file, source_sha256: 'ab'.repeat(32), sites: [{ ...site, reason: 'unreviewed disclosure' }] }] }));
    writeFileSync(join(framework, 'version'), 'installed');
    writeFileSync(join(walletFramework, 'version'), 'installed-wallet');
    writeFileSync(join(walletPackage, 'include/morse_wallet_core.h'), 'wallet-header');
    for (const ext of ['h', 'swift', 'kt', 'jni.c', 'ts']) writeFileSync(join(module, 'generated', `libmessenger_mobile.${ext}`), ext === 'ts' ? rawBindings : 'binding');
    const executable = (name, lines) => writeFileSync(join(root, 'bin', name), ['#!/bin/bash', 'set -euo pipefail', ...lines, ''].join('\n'), { mode: 0o755 });
    executable('uname', ['echo Darwin']);
    mkdirSync(join(ndk, 'toolchains/llvm/prebuilt/darwin-x86_64/bin'), { recursive: true });
    for (const target of ['aarch64-linux-android', 'x86_64-linux-android']) writeFileSync(join(ndk, `toolchains/llvm/prebuilt/darwin-x86_64/bin/${target}26-clang`), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
    for (const abi of ['arm64-v8a', 'x86_64']) {
      mkdirSync(join(module, 'native/android', abi), { recursive: true });
      writeFileSync(join(module, 'native/android', abi, 'libmessenger_mobile.a'), 'installed-android');
      writeFileSync(join(module, 'native/android', abi, 'libmorse_wallet_core.a'), 'installed-wallet-android');
      for (const ext of ['abi.json', 'h', 'swift', 'kt', 'jni.c', 'ts']) {
        writeFileSync(join(module, 'native/android', abi, `libmessenger_mobile.${ext}`), ext === 'abi.json' ? JSON.stringify({ target: `installed-${abi}` }) : `installed-${abi}-${ext}`);
      }
    }
    executable('meshc', [
      'target=; output=',
      'while [[ $# -gt 0 ]]; do',
      '  case "$1" in --target) target=$2; shift;; --output) output=$2; shift;; esac',
      '  shift', 'done',
      'if [[ -n "$target" && "${FAIL_TARGET:-}" == "$target" ]]; then exit 41; fi',
      'mkdir -p "$(dirname "$output")"',
      'printf library > "$output"',
      'for ext in h swift kt jni.c ts; do printf binding > "${output%.a}.$ext"; done',
      'cp "$FIXTURE_ROOT/bindings.ts" "${output%.a}.ts"',
      'cp "$FIXTURE_ROOT/abi-${target:-host}.json" "${output%.a}.abi.json"',
      'if [[ "${FAIL_REPORT_TARGET:-never}" == "${target:-host}" ]]; then',
      '  if [[ "${REPORT_MODE:-}" != missing ]]; then cp "$FIXTURE_ROOT/changed-report.json" "$output.plaintext.json"; fi',
      'else cp "$FIXTURE_ROOT/report.json" "$output.plaintext.json"; fi',
    ]);
    executable('cargo', [
      'target=; output=',
      'while [[ $# -gt 0 ]]; do',
      ' case "$1" in --target) target=$2; shift;; --target-dir) output=$2; shift;; esac',
      ' shift', 'done',
      'if [[ "${FAIL_WALLET_TARGET:-}" == "$target" ]]; then exit 43; fi',
      'mkdir -p "$output/$target/release"',
      'printf wallet > "$output/$target/release/libmorse_wallet_core.a"',
    ]);
    executable('xcodebuild', [
      'while [[ $# -gt 0 ]]; do',
      '  if [[ "$1" == -output ]]; then mkdir -p "$2"; printf rebuilt > "$2/version"; exit 0; fi',
      '  shift', 'done', 'exit 42',
    ]);
    const run = (fail, walletFail = '', platform = 'ios', reportTarget = 'never', reportMode = '') => spawnSync('bash', [join(scripts, 'build-mobile-native.sh'), platform], {
      encoding: 'utf8', env: { ...process.env, PATH: `${join(root, 'bin')}:${process.env.PATH}`,
        MESHC: join(root, 'bin/meshc'), TMPDIR: join(root, 'temp'), FAIL_TARGET: fail, FAIL_WALLET_TARGET: walletFail, ANDROID_NDK_HOME: ndk,
        FIXTURE_ROOT: root, FAIL_REPORT_TARGET: reportTarget, REPORT_MODE: reportMode },
    });
    const failed = run('aarch64-apple-ios-sim');
    assert.equal(failed.status, 41, failed.stderr);
    assert.equal(readFileSync(join(framework, 'version'), 'utf8'), 'installed');
    const walletFailed = run('', 'aarch64-apple-ios-sim');
    assert.equal(walletFailed.status, 43, walletFailed.stderr);
    assert.equal(readFileSync(join(framework, 'version'), 'utf8'), 'installed');
    assert.equal(readFileSync(join(walletFramework, 'version'), 'utf8'), 'installed-wallet');
    const assertInstalledAndroid = () => {
      for (const abi of ['arm64-v8a', 'x86_64']) {
        assert.equal(readFileSync(join(module, 'native/android', abi, 'libmessenger_mobile.a'), 'utf8'), 'installed-android');
        assert.equal(readFileSync(join(module, 'native/android', abi, 'libmorse_wallet_core.a'), 'utf8'), 'installed-wallet-android');
        for (const ext of ['abi.json', 'h', 'swift', 'kt', 'jni.c', 'ts']) {
          assert.equal(readFileSync(join(module, 'native/android', abi, `libmessenger_mobile.${ext}`), 'utf8'), ext === 'abi.json' ? JSON.stringify({ target: `installed-${abi}` }) : `installed-${abi}-${ext}`);
        }
      }
    };
    const androidCompilerFailed = run('x86_64-linux-android', '', 'android');
    assert.equal(androidCompilerFailed.status, 41, androidCompilerFailed.stderr);
    assertInstalledAndroid();
    const androidFailed = run('', 'x86_64-linux-android', 'android');
    assert.equal(androidFailed.status, 43, androidFailed.stderr);
    assertInstalledAndroid();
    assert.equal(readFileSync(join(module, 'native/android/arm64-v8a/libmessenger_mobile.a'), 'utf8'), 'installed-android');
    assert.equal(readFileSync(join(module, 'native/android/arm64-v8a/libmorse_wallet_core.a'), 'utf8'), 'installed-wallet-android');
    for (const [platform, target, mode] of [['ios', 'host', 'missing'], ['ios', 'aarch64-apple-ios-sim', 'changed'],
      ['android', 'x86_64-linux-android', 'changed']]) {
      const invalidReport = run('', '', platform, target, mode);
      assert.notEqual(invalidReport.status, 0, `${target}: an unreviewed or absent disclosure report was installed`);
      assert.equal(readFileSync(join(framework, 'version'), 'utf8'), 'installed');
      assert.equal(readFileSync(join(walletFramework, 'version'), 'utf8'), 'installed-wallet');
      assert.equal(readFileSync(join(module, 'native/android/arm64-v8a/libmessenger_mobile.a'), 'utf8'), 'installed-android');
      assert.equal(readFileSync(join(module, 'native/android/arm64-v8a/libmorse_wallet_core.a'), 'utf8'), 'installed-wallet-android');
    }
    // Host policy check must refuse stale JS authority before any target installation.
    writeFileSync(join(module, 'scoped.ts'), scoped + '// stale facade\n');
    const staleFacade = run('', '', 'android');
    assert.notEqual(staleFacade.status, 0, 'a stale scoped facade was installed');
    assert.match(staleFacade.stderr, /scoped_bindings_stale/);
    assertInstalledAndroid();
    assert.equal(readFileSync(join(framework, 'version'), 'utf8'), 'installed');
    writeFileSync(join(module, 'scoped.ts'), scoped);
    const success = run('');
    assert.equal(success.status, 0, success.stderr);
    assert.equal(readFileSync(join(framework, 'version'), 'utf8'), 'rebuilt');
    assert.equal(readFileSync(join(walletFramework, 'version'), 'utf8'), 'rebuilt');
    assert.equal(readFileSync(join(module, 'native/include/morse_wallet_core.h'), 'utf8'), 'wallet-header');
    const androidSuccess = run('', '', 'android');
    assert.equal(androidSuccess.status, 0, androidSuccess.stderr);
    for (const [abi, target] of [['arm64-v8a', 'aarch64-linux-android'], ['x86_64', 'x86_64-linux-android']]) {
      assert.deepEqual(JSON.parse(readFileSync(join(module, 'native/android', abi, 'libmessenger_mobile.abi.json'), 'utf8')), { ...JSON.parse(readFileSync(join(root, `abi-${target}.json`), 'utf8')) }, `${abi}: successful build must replace stale ABI metadata`);
      for (const ext of ['h', 'swift', 'kt', 'jni.c', 'ts']) {
        assert.equal(readFileSync(join(module, 'native/android', abi, `libmessenger_mobile.${ext}`), 'utf8'), ext === 'ts' ? rawBindings : 'binding', `${abi}: successful build must replace stale ${ext} binding`);
      }
    }

    for (const target of ['aarch64-apple-ios', 'aarch64-apple-ios-sim', 'android-arm64-v8a', 'android-x86_64']) {
      const evidence = JSON.parse(readFileSync(join(module, 'native/plaintext', target, 'evidence.json'), 'utf8'));
      assert.equal(evidence.disclosure_count, 1);
      assert.equal(evidence.artifact_sha256, createHash('sha256').update('library').digest('hex'));
      assert.equal(readFileSync(join(module, 'native/plaintext', target, 'report.json'), 'utf8'), readFileSync(join(root, 'report.json'), 'utf8'));
    }
  } finally { rmSync(root, { recursive: true, force: true }); }
});

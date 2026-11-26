import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const runner = fileURLToPath(new URL('./run-signed.mjs', import.meta.url));

test('development refuses ad-hoc signing instead of launching with unstable Keychain access', () => {
  const result = spawnSync(process.execPath, [runner, 'unused'], {
    env: { ...process.env, MORSE_DEV_SIGNING_IDENTITY: '-' }, encoding: 'utf8',
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /certificate.*MORSE_DEV_SIGNING_IDENTITY/);
});

test('signed development retains private Keychain access across launches and rebuilds', (t) => {
  if (process.platform !== 'darwin') return t.skip('Requires macOS Keychain');
  const identity = process.env.MORSE_DEV_SIGNING_IDENTITY || process.env.APPLE_SIGNING_IDENTITY || 'Apple Development';
  const identities = spawnSync('security', ['find-identity', '-v', '-p', 'codesigning'], { encoding: 'utf8' });
  if (!identities.stdout.includes(identity)) return t.skip('Requires a local development signing certificate');
  const directory = mkdtempSync(join(tmpdir(), 'morse-signing-'));
  const binary = join(directory, 'probe');
  const source = join(directory, 'probe.swift');
  const service = `io.morseapp.desktop.tests.${randomUUID()}`;
  const env = { ...process.env, MORSE_DEV_SIGNING_IDENTITY: identity };
  const run = (command, args, options = {}) => {
    const result = spawnSync(command, args, { encoding: 'utf8', env, ...options });
    assert.equal(result.status, 0, result.stderr || result.error?.message);
    return result;
  };
  const probe = `
import Foundation
import Security
SecKeychainSetUserInteractionAllowed(false)
let service = "${service}"
let action = CommandLine.arguments[1]
for account in ["storage-key", "storage-counter"] {
    let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service, kSecAttrAccount as String: account]
    var status: OSStatus
    if action == "create" {
        var item = query
        item[kSecValueData as String] = Data([0, 255, 17, 0, 42])
        status = SecItemAdd(item as CFDictionary, nil)
    } else if action == "delete" {
        status = SecItemDelete(query as CFDictionary)
    } else {
        var search = query
        search[kSecReturnData as String] = true
        var result: CFTypeRef?
        status = SecItemCopyMatching(search as CFDictionary, &result)
        if status == errSecSuccess && result as? Data != Data([0, 255, 17, 0, 42]) { exit(2) }
    }
    if status != errSecSuccess { fputs("Keychain status: \\(status)\\n", stderr); exit(1) }
}
`;
  try {
    writeFileSync(source, probe + '\nprint("first build")\n');
    run('swiftc', [source, '-o', binary]);
    run(process.execPath, [runner, binary, 'create']);
    run(process.execPath, [runner, binary, 'read']);
    const firstSignature = run('codesign', ['-d', '-r-', binary]);
    const first = firstSignature.stdout + firstSignature.stderr;
    writeFileSync(source, probe + '\nprint("rebuilt executable")\n');
    run('swiftc', [source, '-o', binary]);
    const untrusted = spawnSync(binary, ['read'], { encoding: 'utf8', env });
    assert.notEqual(untrusted.status, 0, 'An untrusted executable must not read the existing secrets');
    assert.match(untrusted.stderr, /Keychain status:/);
    run(process.execPath, [runner, binary, 'read']);
    const secondSignature = run('codesign', ['-d', '-r-', binary]);
    const second = secondSignature.stdout + secondSignature.stderr;
    assert.equal(first, second, 'Rebuilding must preserve the designated requirement');
    const config = JSON.parse(readFileSync(new URL('../src-tauri/tauri.dev.conf.json', import.meta.url)));
    assert.match(second, new RegExp(`identifier "${config.identifier.replaceAll('.', '\\.')}"`));
    assert.doesNotMatch(second, /cdhash/);
  } finally {
    spawnSync(process.execPath, [runner, binary, 'delete'], { env, stdio: 'pipe' });
    rmSync(directory, { recursive: true, force: true });
  }
});

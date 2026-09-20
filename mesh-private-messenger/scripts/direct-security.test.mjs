import assert from 'node:assert/strict';
import { cpSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';
import test from 'node:test';

const root = fileURLToPath(new URL('../..', import.meta.url));
const protocol = join(root, 'mesh-private-messenger/packages/messenger-protocol');
const proofs = join(root, 'mesh-private-messenger/tests/direct-security');
const fixtures = join(root, 'mesh-private-messenger/tests/fixtures');
const vectors = {
  OUTER: 'm1/outer-envelope-v1', CREDENTIAL: 'm1/device-credential-v1',
  OUTER_OVERSIZED: 'm1/outer-envelope-v1-oversized-vector', CREDENTIAL_OVERSIZED: 'm1/device-credential-v1-oversized-vector',
  ACCOUNT: 'm5/account-identity-v1', PREKEY: 'm5/prekey-bundle-v1', INNER: 'm5/inner-envelope-v1',
  TRANSCRIPT: 'm5/handshake-transcript-v1', TRANSCRIPT_HASH: 'm5/handshake-transcript-hash-v1',
};
const expected = JSON.parse(readFileSync(join(proofs, 'expected.json'), 'utf8'));
for (const [name, stdout] of Object.entries(expected)) {
  test(`C2 C3 C7 direct ${name} golden and hostile traces`, { timeout: 120_000 }, t => {
    const project = mkdtempSync(join(tmpdir(), 'morse-direct-proof-'));
    t.after(() => rmSync(project, { recursive: true, force: true }));
    const packages = join(project, '.mesh/packages');
    mkdirSync(packages, { recursive: true });
    cpSync(protocol, join(packages, 'messenger-protocol@0.1.0'), { recursive: true });
    cpSync(join(root, 'mesh-lang/packages/mesh-binary'), join(packages, 'mesh-binary@0.1.0'), { recursive: true });
    let source = readFileSync(join(proofs, `${name}.mpl`), 'utf8').replace(/__(\w+)_HEX__/g, (_, key) => readFileSync(join(fixtures, `${vectors[key]}.hex`), 'utf8').trim());
    writeFileSync(join(project, 'mesh.toml'), '[package]\nname = "direct-security-proof"\nversion = "0.1.0"\n');
    writeFileSync(join(project, 'main.mpl'), source);
    const binary = join(project, 'proof');
    const compiled = spawnSync(process.env.MESHC ?? join(root, 'mesh-lang/target/debug/meshc'), ['build', project, '--output', binary], { encoding: 'utf8', timeout: 80_000, maxBuffer: 8 * 1024 * 1024 });
    assert.equal(compiled.status, 0, compiled.stderr);
    const result = spawnSync(binary, [], { encoding: 'utf8', timeout: 20_000 });
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, stdout);
    assert.equal(result.stderr, '');
  });
}

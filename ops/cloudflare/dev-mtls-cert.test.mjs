import assert from 'node:assert/strict';
import test from 'node:test';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { X509Certificate } from 'node:crypto';
import { existsSync, mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { certificatePins } from './edge.mjs';

const run = promisify(execFile);
const script = fileURLToPath(new URL('./dev-mtls-cert.mjs', import.meta.url));

test('M2 the dev script writes a CA and an edge client certificate outside the repository, and prints the backend pins', async () => {
  const parent = mkdtempSync(join(tmpdir(), 'morse-mtls-'));
  const out = join(parent, 'certs');
  try {
    const { stdout } = await run(process.execPath, [script, out]);
    assert.equal(statSync(out).mode & 0o777, 0o700);
    for (const name of ['ca.key', 'client.key']) assert.equal(statSync(join(out, name)).mode & 0o077, 0, `${name} is private`);
    assert.doesNotMatch(stdout, /PRIVATE KEY/);

    const ca = new X509Certificate(readFileSync(join(out, 'ca.pem')));
    const client = new X509Certificate(readFileSync(join(out, 'client.pem')));
    assert.equal(ca.ca, true);
    assert.equal(client.ca, false);
    assert.ok(client.checkIssued(ca) && client.verify(ca.publicKey));
    assert.deepEqual(client.keyUsage, ['1.3.6.1.5.5.7.3.2'], 'client authentication only');
    assert.ok(existsSync(join(out, 'client.csr')), 'the CSR is kept for a Cloudflare-managed CA');

    const fingerprint = client.fingerprint256.replaceAll(':', '').toLowerCase();
    assert.match(stdout, new RegExp(`^MORSE_INGRESS_CLIENT_CERT_SHA256=${fingerprint}$`, 'm'));
    assert.deepEqual(certificatePins(stdout.match(/^MORSE_INGRESS_CLIENT_CERT_SHA256=(.*)$/m)[1]), [fingerprint]);
    assert.match(stdout, /^MORSE_INGRESS_CLIENT_CERT_ISSUER=CN=Morse edge ingress dev CA$/m);

    // Never overwrites an existing key.
    const key = readFileSync(join(out, 'client.key'));
    await assert.rejects(run(process.execPath, [script, out]), /not empty/);
    assert.deepEqual(readFileSync(join(out, 'client.key')), key);
  } finally {
    rmSync(parent, { recursive: true, force: true });
  }
});

test('M2 the dev script refuses to write keys into the repository', async () => {
  const inside = fileURLToPath(new URL('./.mtls-dev-refused', import.meta.url));
  await assert.rejects(run(process.execPath, [script, inside]), /outside the repository/);
  assert.equal(existsSync(inside), false);
  await assert.rejects(run(process.execPath, [script]), /Usage/);
});

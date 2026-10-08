// Development CA and edge client certificate for the sealed ingress (§22 M2).
//
//   node dev-mtls-cert.mjs <directory outside the repository>
//
// Writes ca.key, ca.pem, client.key, client.csr and client.pem (keys 0600,
// directory 0700) and prints the values the backend pins. client.csr can
// instead be signed by the zone's Cloudflare-managed CA (README, "Sealed
// ingress edge credential"). Never writes into the repository and never overwrites a key.
import { execFileSync } from 'node:child_process';
import { X509Certificate, randomBytes } from 'node:crypto';
import { readFileSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { privateOutput } from './private-output.mjs';

const out = privateOutput(process.argv[2], 'Usage: node dev-mtls-cert.mjs <output directory outside the repository>');
const openssl = (...args) => execFileSync('openssl', args, { cwd: out, stdio: ['ignore', 'pipe', 'pipe'] }).toString();

openssl('req', '-x509', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'ca.key', '-out', 'ca.pem', '-days', '825',
  '-subj', '/CN=Morse edge ingress dev CA',
  '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign,cRLSign');
openssl('req', '-new', '-newkey', 'rsa:2048', '-nodes', '-keyout', 'client.key', '-out', 'client.csr', '-subj', '/CN=morse-privacy-edge');
writeFileSync(join(out, 'client.ext'), 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=clientAuth\n');
try {
  openssl('x509', '-req', '-in', 'client.csr', '-CA', 'ca.pem', '-CAkey', 'ca.key', '-set_serial', `0x${randomBytes(16).toString('hex')}`,
    '-days', '397', '-extfile', 'client.ext', '-out', 'client.pem');
} finally {
  rmSync(join(out, 'client.ext'));
}

const fingerprint = new X509Certificate(readFileSync(join(out, 'client.pem'))).fingerprint256.replaceAll(':', '').toLowerCase();
const issuer = openssl('x509', '-in', 'client.pem', '-noout', '-issuer', '-nameopt', 'RFC2253').trim().replace(/^issuer=\s*/, '');
console.log(`Wrote ${out}: ca.pem, ca.key, client.csr, client.pem, client.key

Backend (morse-backend) build variables:
MORSE_INGRESS_CLIENT_CERT_SHA256=${fingerprint}
MORSE_INGRESS_CLIENT_CERT_ISSUER=${issuer}

Edge account (its own credentials), then deploy the edge with the printed ID as MORSE_EDGE_CLIENT_CERT_ID:
npx wrangler mtls-certificate upload --cert ${join(out, 'client.pem')} --key ${join(out, 'client.key')} --name morse-edge-ingress`);

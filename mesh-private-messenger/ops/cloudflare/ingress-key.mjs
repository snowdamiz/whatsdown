// The Ed25519 key the edge signs sealed-ingress requests with (§22 M2).
//
//   node ingress-key.mjs <directory outside the repository>
//
// Writes edge-ingress-signing-key.hex (the 32-byte seed as hex, 0600) and prints
// the public key the backend pins and the command that stores the private key
// as the edge's Worker secret. Never writes into the repository or over a key.
import { generateKeyPairSync } from 'node:crypto';
import { writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { privateOutput } from './private-output.mjs';

const out = privateOutput(process.argv[2], 'Usage: node ingress-key.mjs <output directory outside the repository>');
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const hex = value => Buffer.from(value, 'base64url').toString('hex');
const path = join(out, 'edge-ingress-signing-key.hex');
writeFileSync(path, hex(privateKey.export({ format: 'jwk' }).d), { mode: 0o600 });
console.log(`Wrote ${path}

Backend (morse-backend) build variable:
MORSE_EDGE_INGRESS_PUBLIC_KEY=${hex(publicKey.export({ format: 'jwk' }).x)}

Edge Worker secret, with the edge's own credentials; then delete the file:
npx wrangler secret put MORSE_EDGE_INGRESS_SIGNING_KEY --name morse-privacy-edge < ${path}`);

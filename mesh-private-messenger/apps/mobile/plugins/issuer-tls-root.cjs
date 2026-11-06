const fs = require('node:fs');
const path = require('node:path');
const { X509Certificate } = require('node:crypto');
const MAX_PEM = 65536;
const ASSET = 'app/src/main/assets/morse-issuer-tls-root-v1.bin';

function issuerTLSRoot(environment) {
  const file = environment.MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE;
  if (file === undefined) return null;
  const origin = environment.MESSENGER_CREDIT_ISSUER_ORIGIN;
  if (typeof origin !== 'string' || origin.length > 2048 || !/^[\x21-\x7e]+$/.test(origin) ||
      /[\\@?#]/.test(origin) || new URL(origin).protocol !== 'https:' || new URL(origin).origin !== origin) {
    throw new Error('Issuer TLS roots require the exact canonical native HTTPS issuer origin');
  }
  if (typeof file !== 'string' || !file) throw new Error('Provide a build-only issuer CA PEM file');
  const descriptor = fs.openSync(file, fs.constants.O_RDONLY | fs.constants.O_NONBLOCK);
  let pem;
  try {
    if (!fs.fstatSync(descriptor).isFile()) throw new Error('Issuer CA PEM must be a regular file');
    const bounded = Buffer.alloc(MAX_PEM + 1);
    let length = 0;
    while (length < bounded.length) {
      const count = fs.readSync(descriptor, bounded, length, bounded.length - length, null);
      if (!count) break;
      length += count;
    }
    if (length < 1 || length > MAX_PEM) throw new Error('Issuer CA PEM exceeds 65536 bytes');
    pem = bounded.subarray(0, length);
  } finally { fs.closeSync(descriptor); }
  if (pem.some(byte => byte > 127)) throw new Error('Issuer CA PEM must be ASCII');
  let remainder = pem.toString('ascii').trim();
  let count = 0;
  while (remainder) {
    const match = /^-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/.exec(remainder);
    if (!match || ++count > 8) throw new Error('Provide only 1–8 PEM CA certificates');
    const certificate = new X509Certificate(match[0]);
    if (!certificate.ca) throw new Error('Issuer trust roots must be CA certificates');
    remainder = remainder.slice(match[0].length).trim();
  }
  if (!count) throw new Error('Provide 1–8 PEM CA certificates');
  const name = Buffer.from(origin, 'ascii');
  const prefix = Buffer.alloc(3); prefix[0] = 1; prefix.writeUInt16BE(name.length, 1);
  const length = Buffer.alloc(4); length.writeUInt32BE(pem.length);
  return Buffer.concat([prefix, name, length, pem]);
}

issuerTLSRoot.writeAndroid = function writeAndroid(platformRoot, environment) {
  const target = path.join(platformRoot, ASSET);
  const wire = issuerTLSRoot(environment);
  if (wire) {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, wire);
  } else fs.rmSync(target, { force: true });
};
module.exports = issuerTLSRoot;

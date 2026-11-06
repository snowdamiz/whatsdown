const fs = require('node:fs');
const path = require('node:path');
const { readCaPEM } = require('./tls-root-files.cjs');
const ASSET = 'app/src/main/assets/morse-issuer-tls-root-v1.bin';

function issuerTLSRoot(environment) {
  const file = environment.MORSE_CREDIT_ISSUER_TLS_ROOT_PEM_FILE;
  if (file === undefined) return null;
  const origin = environment.MESSENGER_CREDIT_ISSUER_ORIGIN;
  if (typeof origin !== 'string' || origin.length > 2048 || !/^[\x21-\x7e]+$/.test(origin) ||
      /[\\@?#]/.test(origin) || new URL(origin).protocol !== 'https:' || new URL(origin).origin !== origin) {
    throw new Error('Issuer TLS roots require the exact canonical native HTTPS issuer origin');
  }
  const pem = readCaPEM(file);
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

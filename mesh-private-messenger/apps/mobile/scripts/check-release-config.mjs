import assert from 'node:assert/strict';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { X509Certificate } from 'node:crypto';

const require = createRequire(import.meta.url);
const { getConfig } = require('expo/config');
const securityConfig = require('../plugins/security-config.cjs');
const env = process.env;

assert.match(env.EXPO_PROJECT_ID ?? '', /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/, 'Set EXPO_PROJECT_ID');
assert.ok(env.MORSE_OTA_CERTIFICATE, 'Set MORSE_OTA_CERTIFICATE to the public OTA signing certificate');
const certificate = new X509Certificate(readFileSync(env.MORSE_OTA_CERTIFICATE));
assert.equal(certificate.publicKey.asymmetricKeyType, 'rsa', 'OTA signing requires an RSA certificate');
assert.ok(certificate.publicKey.asymmetricKeyDetails.modulusLength >= 2048, 'OTA signing requires at least 2048-bit RSA');
assert.ok(Date.parse(certificate.validFrom) <= Date.now() && Date.parse(certificate.validTo) > Date.now(), 'OTA signing certificate is outside its validity period');
for (const name of ['EXPO_PUBLIC_MESSENGER_BASE_URL', 'EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL']) {
  assert.equal(new URL(env[name]).protocol, 'https:', `${name} must use HTTPS`);
}
if (env.EXPO_PUBLIC_MESSENGER_STREAM_URL) {
  assert.equal(new URL(env.EXPO_PUBLIC_MESSENGER_STREAM_URL).protocol, 'wss:', 'The stream URL must use WSS');
}
if (env.EXPO_PUBLIC_MESSENGER_OBJECT_URL) {
  assert.equal(new URL(env.EXPO_PUBLIC_MESSENGER_OBJECT_URL).protocol, 'https:', 'The object URL must use HTTPS');
}
if (env.EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY) {
  assert.match(env.EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY, /^(?:[1-9]|1[0-9]|2[0-4])$/,
    'EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY must be a canonical integer 1–24');
}
// A release carries a valid v2 security frame; securityConfig refuses anything the core would.
const securityFrame = securityConfig(env);
assert.ok(securityFrame, 'Set the MESSENGER security pins in the EAS production environment');
// Stateless requests go through the privacy edge as OHTTP (protocol/ohttp-v1.md); only a
// development build may send them directly.
assert.ok(env.MESSENGER_OHTTP_KEY, 'Set MESSENGER_OHTTP_KEY to the OHTTP gateway key (<key id>:<public key hex>)');
assert.equal(env.MESSENGER_OHTTP_RELAY, new URL(env.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL).origin,
  'MESSENGER_OHTTP_RELAY must be the privacy edge origin');
// Reuse the native plugin's paired push-pin validation.
getConfig(process.cwd());
const { setId, profile, k, n } = securityConfig.witnessSet(securityFrame);
console.log(`Release environment is configured. Witness set_id ${setId}, ${profile}, ${k} of ${n}.`);

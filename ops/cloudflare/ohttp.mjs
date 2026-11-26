// Oblivious HTTP client (RFC 9458) for operator checks, from the RFC text with
// Node's crypto: HPKE base mode (RFC 9180) with DHKEM(X25519, HKDF-SHA256),
// HKDF-SHA256 and ChaCha20-Poly1305 (AES-128-GCM only for the RFC's own
// example), and known-length Binary HTTP (RFC 9292). Phones use the Mesh
// implementation (packages/messenger-protocol/privacy/ohttp.mpl); both answer
// the same vectors (ohttp.test.mjs, tests/fixtures/ohttp/kat.mjs).
import crypto from 'node:crypto';

export const hex = (text) => Buffer.from(text.replace(/\s+/g, ''), 'hex');
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const privateKey = (raw) => crypto.createPrivateKey({ key: Buffer.concat([hex('302e020100300506032b656e04220420'), raw]), format: 'der', type: 'pkcs8' });
export const x25519Public = (raw) => crypto.createPublicKey(privateKey(raw)).export({ format: 'der', type: 'spki' }).subarray(-32);
const publicKey = (raw) => crypto.createPublicKey({ key: Buffer.concat([hex('302a300506032b656e032100'), raw]), format: 'der', type: 'spki' });
const dh = (secret, peer) => crypto.diffieHellman({ privateKey: privateKey(secret), publicKey: publicKey(peer) });
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const expand = (prk, info, length) => {
  let block = Buffer.alloc(0), output = Buffer.alloc(0);
  for (let counter = 1; output.length < length; counter += 1) {
    block = hmac(prk, Buffer.concat([block, info, Buffer.from([counter])]));
    output = Buffer.concat([output, block]);
  }
  return output.subarray(0, length);
};

const AEADS = { 1: { name: 'aes-128-gcm', nk: 16, nn: 12 }, 3: { name: 'chacha20-poly1305', nk: 32, nn: 12 } };
function seal(aead, key, nonce, plaintext) {
  const cipher = crypto.createCipheriv(AEADS[aead].name, key, nonce, { authTagLength: 16 });
  cipher.setAAD(Buffer.alloc(0), { plaintextLength: plaintext.length });
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}
function open(aead, key, nonce, sealed) {
  if (sealed.length < 16) throw new Error('ohttp_response_invalid');
  const decipher = crypto.createDecipheriv(AEADS[aead].name, key, nonce, { authTagLength: 16 });
  decipher.setAAD(Buffer.alloc(0), { plaintextLength: sealed.length - 16 });
  decipher.setAuthTag(sealed.subarray(-16));
  return Buffer.concat([decipher.update(sealed.subarray(0, -16)), decipher.final()]);
}

// RFC 9180 key schedule for one suite.
export function hpke(aead) {
  const kemId = Buffer.concat([Buffer.from('KEM'), u16(0x20)]);
  const suiteId = Buffer.concat([Buffer.from('HPKE'), u16(0x20), u16(1), u16(aead)]);
  const extract = (id, salt, label, ikm) =>
    hmac(salt.length ? salt : Buffer.alloc(32), Buffer.concat([Buffer.from('HPKE-v1'), id, Buffer.from(label), ikm]));
  const labeled = (id, prk, label, info, length) =>
    expand(prk, Buffer.concat([u16(length), Buffer.from('HPKE-v1'), id, Buffer.from(label), info]), length);
  const context = (dhValue, enc, pkR, info) => {
    const eae = extract(kemId, Buffer.alloc(0), 'eae_prk', dhValue);
    const sharedSecret = labeled(kemId, eae, 'shared_secret', Buffer.concat([enc, pkR]), 32);
    const schedule = Buffer.concat([Buffer.from([0]), extract(suiteId, Buffer.alloc(0), 'psk_id_hash', Buffer.alloc(0)),
      extract(suiteId, Buffer.alloc(0), 'info_hash', info)]);
    const secret = extract(suiteId, sharedSecret, 'secret', Buffer.alloc(0));
    const exporterSecret = labeled(suiteId, secret, 'exp', schedule, 32);
    return {
      enc, sharedSecret, exporterSecret,
      key: labeled(suiteId, secret, 'key', schedule, AEADS[aead].nk),
      baseNonce: labeled(suiteId, secret, 'base_nonce', schedule, AEADS[aead].nn),
      export: (exporterContext, length) => labeled(suiteId, exporterSecret, 'sec', exporterContext, length),
    };
  };
  return {
    deriveKeyPair: (ikm) => labeled(kemId, extract(kemId, Buffer.alloc(0), 'dkp_prk', ikm), 'sk', Buffer.alloc(0), 32),
    setupSender: (skE, pkR, info) => context(dh(skE, pkR), x25519Public(skE), pkR, info),
    setupReceiver: (skR, enc, info) => context(dh(skR, enc), enc, x25519Public(skR), info),
  };
}

// RFC 9458 section 3.1, one key configuration: { keyId, publicKey, suites }.
export function decodeKeyConfig(bytes) {
  const config = Buffer.from(bytes);
  if (config.length < 41 || config.readUInt16BE(1) !== 0x20) throw new Error('ohttp_invalid_key_config');
  const length = config.readUInt16BE(35);
  if (length < 4 || length % 4 || 37 + length !== config.length) throw new Error('ohttp_invalid_key_config');
  const suites = [];
  for (let at = 37; at < config.length; at += 4) suites.push([config.readUInt16BE(at), config.readUInt16BE(at + 2)]);
  return { keyId: config[0], publicKey: config.subarray(3, 35), suites };
}

// application/ohttp-keys (section 3.2): u16-length-prefixed configurations.
export function decodeKeys(bytes) {
  const list = Buffer.from(bytes), configs = [];
  for (let at = 0; at < list.length;) {
    if (at + 2 > list.length) throw new Error('ohttp_invalid_keys');
    const length = list.readUInt16BE(at);
    if (at + 2 + length > list.length) throw new Error('ohttp_invalid_keys');
    configs.push(list.subarray(at + 2, at + 2 + length));
    at += 2 + length;
  }
  return configs;
}

// Section 4.3. `ephemeral` (a raw X25519 secret) is for known answers only.
export function encapsulateRequest(config, request, { aead = 3, ephemeral = crypto.randomBytes(32) } = {}) {
  const header = Buffer.concat([Buffer.from([config.keyId]), u16(0x20), u16(1), u16(aead)]);
  const info = Buffer.concat([Buffer.from('message/bhttp request'), Buffer.from([0]), header]);
  const sender = hpke(aead).setupSender(ephemeral, Buffer.from(config.publicKey), info);
  return {
    encapsulated: Buffer.concat([header, sender.enc, seal(aead, sender.key, sender.baseNonce, Buffer.from(request))]),
    context: { aead, enc: sender.enc, export: sender.export },
  };
}

// Section 4.4, from either end's context.
function responseKeys(context, nonce) {
  const { nk, nn } = AEADS[context.aead];
  const secret = context.export(Buffer.from('message/bhttp response'), Math.max(nk, nn));
  const prk = hmac(Buffer.concat([context.enc, nonce]), secret);
  return [expand(prk, Buffer.from('key'), nk), expand(prk, Buffer.from('nonce'), nn)];
}
export function encapsulateResponse(context, response, nonce = crypto.randomBytes(Math.max(AEADS[context.aead].nk, AEADS[context.aead].nn))) {
  return Buffer.concat([nonce, seal(context.aead, ...responseKeys(context, nonce), Buffer.from(response))]);
}
export function decapsulateResponse(context, encapsulated) {
  const length = Math.max(AEADS[context.aead].nk, AEADS[context.aead].nn);
  const bytes = Buffer.from(encapsulated);
  if (bytes.length < length + 16) throw new Error('ohttp_response_invalid');
  const nonce = bytes.subarray(0, length);
  return open(context.aead, ...responseKeys(context, nonce), bytes.subarray(length));
}

// Binary HTTP, known length: QUIC variable-length integers.
function varint(value) {
  if (value < 64) return Buffer.from([value]);
  if (value < 16384) return Buffer.from([0x40 | (value >> 8), value & 0xff]);
  const b = Buffer.alloc(4); b.writeUInt32BE(value); b[0] |= 0x80; return b;
}
const prefixed = (bytes) => Buffer.concat([varint(bytes.length), bytes]);
export function encodeRequest(method, path, content = Buffer.alloc(0), length = 256) {
  const message = Buffer.concat([varint(0), ...[method, 'https', '', path].map(text => prefixed(Buffer.from(text))),
    varint(0), prefixed(Buffer.from(content))]);
  return Buffer.concat([message, Buffer.alloc(Math.max(0, length - message.length))]);
}
function readVarint(bytes, at) {
  const length = 1 << (bytes[at] >> 6);
  let value = bytes[at] & 0x3f;
  for (let i = 1; i < length; i += 1) value = value * 256 + bytes[at + i];
  return [value, at + length];
}
// { status, content } of a final response; informational ones are skipped.
export function decodeResponse(bytes) {
  const message = Buffer.from(bytes);
  let [framing, at] = readVarint(message, 0);
  if (framing !== 1) throw new Error('bhttp_invalid');
  let status;
  for (;;) {
    [status, at] = readVarint(message, at);
    if (status < 100 || status > 599) throw new Error('bhttp_invalid');
    const [fields, next] = at < message.length ? readVarint(message, at) : [0, at];
    at = at < message.length ? next + fields : at;
    if (status >= 200) break;
  }
  const [length, start] = at < message.length ? readVarint(message, at) : [0, at];
  if (start + length > message.length) throw new Error('bhttp_invalid');
  return { status, content: message.subarray(start, start + length) };
}

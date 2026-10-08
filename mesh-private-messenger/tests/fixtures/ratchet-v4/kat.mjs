// Independent derivation (OpenSSL through Node) of the ratchet message 4 known
// answers in packages/messenger-protocol/tests/ratchet_v4.test.mpl: X25519 from
// fixed seeds, HKDF-SHA256 with the protocol labels, ChaCha20-Poly1305 probes.
// Run: node kat.mjs
import crypto from 'node:crypto';
const seed = (start) => Buffer.from(Array.from({ length: 32 }, (_, i) => start + i));
const priv = (s) => crypto.createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b656e04220420', 'hex'), s]), format: 'der', type: 'pkcs8' });
const pub = (s) => crypto.createPublicKey(priv(s)).export({ format: 'der', type: 'spki' }).subarray(-32);
const dh = (a, b) => crypto.diffieHellman({ privateKey: priv(a), publicKey: crypto.createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b656e032100', 'hex'), pub(b)]), format: 'der', type: 'spki' }) });
const hkdf = (ikm, salt, info, len = 32) => Buffer.from(crypto.hkdfSync('sha256', ikm, salt, info, len));
const seal = (key, nonce, aad, pt) => { const c = crypto.createCipheriv('chacha20-poly1305', key, nonce, { authTagLength: 16 }); c.setAAD(aad, { plaintextLength: pt.length }); return Buffer.concat([c.update(pt), c.final(), c.getAuthTag()]); };
const probe = (key) => seal(key, Buffer.alloc(12), Buffer.alloc(0), Buffer.from('morse-kat')).toString('hex');
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u16 = (n) => { const b = Buffer.alloc(2); b.writeUInt16BE(n); return b; };
const [A, B, C, D, E, F] = [0x00, 0x20, 0x40, 0x60, 0x80, 0xa0].map(seed);
const root = dh(A, B), shared = dh(C, D), pq = dh(E, F);
const sid = Buffer.alloc(32, 0x11), rpub = pub(C);
function rootV2(root, shared, mix) {
  const old = hkdf(root, sid, Buffer.concat([Buffer.from('mesh-msg/v2/root-mix'), rpub]));
  const comb = Buffer.concat([old, shared]);
  const suffix = Buffer.concat([rpub, u32(mix)]);
  return ['ratchet-root', 'ratchet-chain', 'header-key'].map((l) => hkdf(comb, sid, Buffer.concat([Buffer.from('mesh-msg/v2/' + l), suffix])));
}
const out = {};
out.classical = rootV2(root, shared, 0).map(probe);
out.hybrid = rootV2(root, Buffer.concat([shared, pq]), 3).map(probe);
out.upgrade = ['first', 'second'].map((l) => probe(hkdf(root, sid, Buffer.from('mesh-msg/v2/header-key/upgrade/' + l))));
const header = Buffer.concat([u16(2), sid, rpub, u32(7), u32(9), u32(0), u32(1), Buffer.from([1, 36, 1]), Buffer.alloc(32, 0xab)]);
const hnonce = Buffer.from(Array.from({ length: 12 }, (_, i) => i));
const hkey = hkdf(shared, Buffer.alloc(0), Buffer.from('mesh-msg/v2/header-seal'));
out.header_plain = header.toString('hex');
out.header_blob = Buffer.concat([hnonce, seal(hkey, hnonce, Buffer.from('mesh-msg/v2/ratchet-header'), header)]).toString('hex');
out.rpub = rpub.toString('hex');
console.log(JSON.stringify(out, null, 1));

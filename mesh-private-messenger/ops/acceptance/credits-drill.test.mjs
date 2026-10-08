import assert from 'node:assert/strict';
import { constants, createHash, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import test from 'node:test';
import { addressFrom, memoryChain } from '../cloudflare/judge.mjs';
import { blind, creditsDrill, decodeQuote, encodeQuoteRequest, finalize, tokenChallenge } from './credits-drill.mjs';

// RFC 9578 Appendix A.2, the first Issuance Protocol 2 vector (public values only).
const VECTOR = {
  pkI:
    '30820152303d06092a864886f70d01010a3030a00d300b0609608648016503040202a11a301806092a864886f70d010108300b060960864801650304' +
    '0202a2030201300382010f003082010a0282010100cb1aed6b6a95f5b1ce013a4cfcab25b94b2e64a23034e4250a7eab43c0df3a8c12993af12b1119' +
    '08d4b471bec31d4b6c9ad9cdda90612a2ee903523e6de5a224d6b02f09e5c374d0cfe01d8f529c500a78a2f67908fa682b5a2b430c81eaf1af72d7b5' +
    'e794fc98a3139276879757ce453b526ef9bf6ceb99979b8423b90f4461a22af37aab0cf5733f7597abe44d31c732db68a181c6cbbe607d8c0e52e065' +
    '5fd9996dc584eca0be87afbcd78a337d17b1dba9e828bbd81e291317144e7ff89f55619709b096cbb9ea474cead264c2073fe49740c01f00e1091060' +
    '66983d21e5f83f086e2e823c879cd43cef700d2a352a9babd612d03cad02db134b7e225a5f0203010001',
  token_challenge:
    '0002000e6973737565722e6578616d706c65208e7acc900e393381e8810b7c9e4a68b5163f1f880ab6688a6ffe780923609e88000e6f726967696e2e' +
    '6578616d706c65',
  nonce:
    'aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f05',
  blind:
    '425421de54c7381864ce36473abfb988c454fe6c27de863de702a6a2adca153fa2de47bd8fcd62734caa8ce1f920b77d980ab58c32d16dde54873f28' +
    'ca968e8c125b8363514be68972f553655bcc7f80a284cc327e47e804a47333c5b3cdf773312cc7ad9fda748aed0baa7e19c5a2d1dafda718f086d7fc' +
    '0a4bc02d488e0f20812daee335af7177b7a8369bd617066aed7a58f659f295c36b418827f679725b81ca14ea16fb82df21ad76da1ac38dcf24bf6252' +
    'f8510e2308608ac9197f6cb54fdcb19db17837302a2b87d659c5605f35f3709a130f0c3d50e172f0cae36cbc9467f9914895a215a9e32443bcafff79' +
    '5273ccf8965a7eaa8c0b2184763e3e5c',
  salt:
    '3d980852fa570c064204feb8d107098db976ef8c2137e8641d234bbd88a986fdb306a7af220cfadede08f51e1ef61766',
  token_request:
    '0002086a95be84b63cfed0993bb579194a72a95057e1548ac463a9a5b33b011f2b2011d59487f01862f1d8e4d5ea42e73a660fbc3d010b944a54da3a' +
    '4e0942f8894c0884589b438cb902e9a34278970f33c16f351f7dae58d273c3ab66ef368da36f785e89e24d1d983d5c34311cd21f290f9e89e8646ab0' +
    'd0a48988fcd46230de5e7603cd12cc95c7ec5002e5e26737aa7eb69c626476e6c8d46510ee404a3d7daf3a23b7c66735d363ca13676925c6ed0117f6' +
    '0d165ce1f8ba616d041b6384baf6da3e2f757cb18e879a4f8595c2dc895ddf1f4279c75768d108b5c47f95f94e81e2d8b9c8b74476924ab3b7c45243' +
    'fc99ac5466e8a3680ad37fa15c96010b274094',
  token_response:
    '675d84b751d9e593330ec4b6d7ab69c9a61517e98971f4b736150508174b4335761464f237be2d72bbae4b94dffc6143413f6351f1aa4efde6c32d4d' +
    '6d9392a008290d56d1222f9b77a1336213e01934f7d972f3bf9ea5a5786c321352f103b3667e605379a55f0fb925fbb09b8a9f85e7dd4b388a3b49d0' +
    '6fd70ba28f6a780e3bc8f6421554fd6c38b63ef19f84ccfcf14709dd0b4d72213c1f060893854eba0ea1a147e275da320db5e9849882d5f9179efa8a' +
    '2d8d3b803f9d1445ef5c1f660be08883ce9b29a0a992fc035d2938cbb61c440044438dbb8b3ce7158a8f9827d230482f622d291406ab236b32b12262' +
    '7ae0fd36bd0d6b7607b8044ace404d44',
  token:
    '0002aa72019d1f951df197021ce63876fe8b0a02dc1c31a12b0a2dd1508d07827f055969f643b4cfda5196d4aa86aeb5368834f4f06de46950ed435b' +
    '3b81bd036d44ca572f8982a9ca248a3056186322d93ca147266121ddeb5632c07f1f71cd2708bc6a21b533d07294b5e900faf5537dd3eb33cee4e08c' +
    '9670d1e5358fd184b0e00c637174f5206b14c7bb0e724ebf6b56271e5aa2ed94c051c4a433d302b23bc52460810d489fb050f9de5c868c6c1b06e384' +
    '9fd087629f704cc724bc0d0984d5c339686fcdd75f9a9cdd25f37f855f6f4c584d84f716864f546b696d620c5bd41a811498de84ff9740ba3003ba24' +
    '22d26b91eb745c084758974642a42078201543246ddb58030ea8e722376aa82484dca9610a8fb7e018e396165462e17a03e40ea7e128c090a911ecc7' +
    '08066cb201833010c1ebd4e910fc8e27a1be467f78671836a508257123a45e4e0ae2180a434bd1037713466347a8ebe46439d3da1970',
};

const hex = value => Buffer.from(value, 'hex');
const sha256 = (...parts) => createHash('sha256').update(Buffer.concat(parts)).digest();
const u16 = n => Buffer.from([n >> 8, n & 255]);
const u32 = n => { const b = Buffer.alloc(4); b.writeUInt32BE(n); return b; };
const u64 = n => { const b = Buffer.alloc(8); b.writeBigUInt64BE(BigInt(n)); return b; };
const vec = b => Buffer.concat([u32(b.length), b]);
const big = b => BigInt(`0x${Buffer.from(b).toString('hex')}`);
const bytes = (n, length) => Buffer.from(n.toString(16).padStart(length * 2, '0'), 'hex');

test('blind RSA client: RFC 9578 type 2 vector, blinded message and finished token', () => {
  const keyId = sha256(hex(VECTOR.pkI));
  const input = Buffer.concat([u16(2), hex(VECTOR.nonce), sha256(hex(VECTOR.token_challenge)), keyId]);
  const { blinded, inv } = blind(hex(VECTOR.pkI), input, { salt: hex(VECTOR.salt), r: big(hex(VECTOR.blind)) });
  assert.equal(Buffer.from(blinded).toString('hex'), VECTOR.token_request.slice(6));
  const authenticator = finalize(hex(VECTOR.pkI), input, hex(VECTOR.token_response), inv);
  assert.equal(Buffer.concat([input, authenticator]).toString('hex'), VECTOR.token);
  const tampered = hex(VECTOR.token_response);
  tampered[10] ^= 1;
  assert.throws(() => finalize(hex(VECTOR.pkI), input, tampered, inv), /does not verify/);
});

test('frames: the quote request and the Morse token challenge', () => {
  assert.deepEqual([...encodeQuoteRequest(1, 1)], [1, 0x43, 0x51, 0x52, 1, 1]);
  assert.equal(Buffer.from(tokenChallenge('credits.morseapp.io')).toString('hex'),
    `00020013${Buffer.from('credits.morseapp.io').toString('hex')}00000b${Buffer.from('morseapp.io').toString('hex')}`);
});

// A fake issuer holding a fresh key, reached through a fake edge, with its key
// in the directory's listing; a fake chain for the payment.
function issuerFixture() {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const jwk = privateKey.export({ format: 'jwk' });
  const n = big(Buffer.from(jwk.n, 'base64url'));
  // The RFC 9578 SPKI layout (RSASSA-PSS, SHA-384) around this key's modulus.
  const spki = hex(VECTOR.pkI);
  bytes(n, 256).copy(spki, spki.length - 5 - 256);
  const keyId = sha256(spki);
  const iky = Buffer.concat([Buffer.from([1]), Buffer.from('IKY'), Buffer.from([1]), vec(Buffer.from('credits.test')), u32(683),
    u64(683n * 2_592_000_000n), u64(685n * 2_592_000_000n), spki]);
  const kte = Buffer.concat([Buffer.from([2]), Buffer.from('KTE'), vec(iky), ...Array(5).fill(vec(Buffer.alloc(0)))]);
  const listing = Buffer.concat([Buffer.from([1]), Buffer.from('CIK'), Buffer.from([1]), vec(kte)]);
  const deposit = addressFrom(new Uint8Array(32).fill(8));
  const mint = addressFrom(new Uint8Array(32).fill(9));
  const reference = addressFrom(new Uint8Array(32).fill(10));
  const quoteId = Buffer.alloc(32, 7);
  const quote = Buffer.concat([Buffer.from([1]), Buffer.from('CQT'), quoteId, Buffer.from([1, 1]), u16(100), u64(5_000_000), u64(Date.now() + 900_000), keyId,
    vec(Buffer.from(`solana:${deposit}?amount=5&spl-token=${mint}&reference=${reference}&label=Morse&message=100%20Morse%20credits`))]);
  let issueCalls = 0;
  const calls = [];
  const http = async (url, init = {}) => {
    calls.push(String(url));
    if (String(url) === 'https://dir.test/v1/credits/issuer-keys') return new Response(listing);
    if (String(url) === 'https://edge.test/v1/credits/quote') {
      // PWR(CQR) at the pinned difficulty (8 here), label mesh-msg/v1/work/credit-quote.
      const body = Buffer.from(init.body);
      const payload = body.subarray(20);
      const digest = sha256(Buffer.from('mesh-msg/v1/work/credit-quote'), body.subarray(4, 16), sha256(payload));
      const fresh = Number(body.readBigUInt64BE(4)) > Date.now() && Number(body.readBigUInt64BE(4)) <= Date.now() + 300_000;
      const ok = body.subarray(0, 4).toString('latin1') === '\x01PWR' && body.readUInt32BE(16) === payload.length && fresh && digest[0] === 0
        && payload.equals(Buffer.from([1, 0x43, 0x51, 0x52, 1, 1]));
      return new Response(ok ? quote : null, { status: ok ? 201 : 429 });
    }
    if (String(url) === 'https://edge.test/v1/credits/issue') {
      if (issueCalls++ === 0) return new Response(null, { status: 202 });
      const body = Buffer.from(init.body);
      const count = body.readUInt16BE(4 + 32 + 4 + body.readUInt32BE(36) + 32);
      const start = 4 + 32 + 4 + body.readUInt32BE(36) + 32 + 2;
      // Blind signing is raw RSA: blinded^d mod n.
      const signatures = Array.from({ length: count }, (_, i) =>
        privateDecrypt({ key: privateKey, padding: constants.RSA_NO_PADDING }, body.subarray(start + 256 * i, start + 256 * (i + 1))));
      return new Response(Buffer.concat([Buffer.from([1]), Buffer.from('CIS'), quoteId, keyId, u16(count), ...signatures]));
    }
    return new Response(null, { status: 404 });
  };
  const chain = memoryChain();
  return { http, chain, calls, deposit, mint, reference, keyId };
}

const drillEnv = buyer => ({ MORSE_DIRECTORY_URL: 'https://dir.test', MORSE_CREDITS_EDGE_URL: 'https://edge.test', MORSE_CREDITS_RPC: 'https://rpc.test',
  MORSE_CREDITS_BUYER_KEYPAIR: buyer });
// What the drill device (canary-device, role extras) reports when every extra works.
const deviceLines = (overrides = {}) => [
  { kind: 'extra', extra: 'signup', surge: false, work_status: 200, difficulty: 16, base: 16, status: 201, ...overrides.signup },
  { kind: 'extra', extra: 'postage', policy_status: 201, unpaid_status: 402, policy_returned: true, status: 202, ms: 90, ...overrides.postage },
  { kind: 'extra', extra: 'storage', status: 201, retention_days: 60, ms: 120, ...overrides.storage },
  { kind: 'extra', extra: 'cleanup', account: 'morse-drill-0a1b2c3d', status: 204, ...overrides.cleanup },
];
const drill = (f, lines, seen = []) => creditsDrill({ issuer: 'https://credits.test', difficulty: 8, http: f.http, chainFor: () => f.chain, sleep: async () => {},
  env: drillEnv('[]'), buyerKey: async () => ({ address: addressFrom(new Uint8Array(32).fill(3)) }),
  device: async ({ tokens }) => { seen.push(tokens); return lines; } });

test('credits drill: buys a pack with work, pays the quote with its reference, verifies every token, then drives each extra', async () => {
  const f = issuerFixture();
  const seen = [];
  const report = await drill(f, deviceLines(), seen);
  assert.equal(report.ok, true, report.detail);
  assert.match(report.detail, /100 credits issued and verified/);
  assert.match(report.detail, /postage: 402 unpaid, 202 with 1 credit/);
  assert.match(report.detail, /storage: 60 days/);
  assert.match(report.detail, /signup: no surge/);
  assert.match(report.detail, /large-file: large-file extra not deployed/);
  assert.equal(seen[0].length, 31, '20 for sign-up, 1 for postage, 10 for storage');
  assert.ok(seen[0].every(token => token.length === 354));
  assert.deepEqual(report.redemptions.map(r => [r.extra, r.status, r.ms]), [['postage', 202, 90], ['storage', 201, 120]]);
  const [payment] = f.chain.sent;
  const transfer = payment.instructions.at(-1);
  assert.ok(transfer.accounts.some(a => a.address === f.reference), 'the Solana Pay reference rides on the transfer');
  assert.equal(Buffer.from(transfer.data).readBigUInt64LE(1), 5_000_000n);
});

test('credits drill: each extra is judged by what it must answer', async () => {
  const f = issuerFixture();
  const run = async overrides => drill(f, deviceLines(overrides));
  let report = await run({ postage: { unpaid_status: 202 } });
  assert.equal(report.ok, false);
  assert.match(report.detail, /postage: an unpaid envelope to a priced inbox answered 202/);
  report = await run({ postage: { policy_returned: false } });
  assert.match(report.detail, /postage: the 402 did not carry the signed policy/);
  report = await run({ storage: { status: 503, retention_days: -1 } });
  assert.equal(report.ok, false);
  assert.deepEqual(report.redemptions.find(r => r.extra === 'storage').status, 503, 'the alerts see the spent set failing');
  report = await run({ signup: { surge: true, difficulty: 19, status: 201, ms: 300 } });
  assert.equal(report.ok, true, report.detail);
  assert.match(report.detail, /signup: priority sign-up at difficulty 16 during a surge \(19\)/);
  assert.equal(report.redemptions.find(r => r.extra === 'signup').ms, 300);
  report = await run({ signup: { work_status: 404, difficulty: -1 } });
  assert.match(report.detail, /signup: GET \/v1\/devices\/register\/work answered 404/);
  report = await run({ cleanup: { status: 500 } });
  assert.equal(report.ok, false);
  assert.match(report.detail, /morse-drill-0a1b2c3d was not deleted/);
  report = await drill(f, [{ kind: 'error', error: 'the drill account\'s registration answered 429' }]);
  assert.equal(report.ok, false);
  assert.match(report.detail, /registration answered 429/);
});

test('credits drill: a quote for a key the log does not hold is refused before paying', async () => {
  const f = issuerFixture();
  const http = async (url, init) => String(url).endsWith('/issuer-keys') ? new Response(Buffer.from([1, 0x43, 0x49, 0x4b, 0])) : f.http(url, init);
  const report = await creditsDrill({ issuer: 'https://credits.test', difficulty: 8, http, chainFor: () => f.chain, sleep: async () => {},
    env: { MORSE_DIRECTORY_URL: 'https://dir.test', MORSE_CREDITS_EDGE_URL: 'https://edge.test', MORSE_CREDITS_RPC: 'https://rpc.test', MORSE_CREDITS_BUYER_KEYPAIR: '[]' },
    buyerKey: async () => ({ address: addressFrom(new Uint8Array(32).fill(3)) }) });
  assert.equal(report.ok, false);
  assert.match(report.detail, /not in the log/);
  assert.equal(f.chain.sent.length, 0);
  assert.equal(decodeQuote(Buffer.concat([Buffer.from([1]), Buffer.from('CQT'), Buffer.alloc(32), Buffer.from([1, 1]), u16(100), u64(1), u64(2), Buffer.alloc(32), vec(Buffer.from('x'))])).batch, 100);
});

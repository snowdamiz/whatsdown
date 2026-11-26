// The weekly credits drill (plan §4.3 check 8, §11.3): buy the smallest pack
// with the canary buyer wallet through the privacy edge, get it issued, finish
// and verify every token, then spend one on each extra. Frames are
// protocol/credits-v1.md; the blind RSA client is RFC 9474
// RSABSSA-SHA384-PSS-Deterministic, as Privacy Pass token type 2 (RFC 9578).
//
// Checked here: the issuer's quote names a live key the directory lists, the
// payment is the quote's, every blind signature finishes into a token that
// verifies. Phones also verify each key's log evidence (mobile-core); the drill
// tests the purchase pipeline, not that proof again.
import { constants, createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { address, ata, createAtaIdempotent, loadKeypair, solanaChain, token } from '../cloudflare/judge.mjs';

const MORSE_ORIGIN_INFO = 'morseapp.io';
const PACK_SMALLEST = 1; // 100 credits, $5: the smallest pack there is
const ASSET_USDC = 1;
const text = value => new TextEncoder().encode(value);
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0)); let at = 0; for (const p of parts) { out.set(p, at); at += p.length; } return out; };
const u16 = n => Uint8Array.of(n >> 8, n & 255);
const u32 = n => Uint8Array.of(n >>> 24, (n >>> 16) & 255, (n >>> 8) & 255, n & 255);
const vec = value => concat(u32(value.length), value);
const sha = (name, ...parts) => new Uint8Array(createHash(name).update(concat(...parts)).digest());
const equal = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

function reader(bytes, magic, version = 1) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let at = 0;
  const need = n => { if (at + n > bytes.length) throw new Error(`truncated ${magic} frame`); };
  const r = {
    take: n => { need(n); at += n; return bytes.subarray(at - n, at); },
    u8: () => r.take(1)[0], u16: () => { need(2); at += 2; return view.getUint16(at - 2); },
    u32: () => { need(4); at += 4; return view.getUint32(at - 4); }, u64: () => { need(8); at += 8; return view.getBigUint64(at - 8); },
    vec: () => r.take(r.u32()), done: () => { if (at !== bytes.length) throw new Error(`trailing bytes after ${magic}`); },
  };
  if (r.u8() !== version) throw new Error(`not a ${magic} frame`);
  if (new TextDecoder().decode(r.take(3)) !== magic) throw new Error(`not a ${magic} frame`);
  return r;
}

// ---- frames ----

export const encodeQuoteRequest = (pack, asset) => concat(Uint8Array.of(1), text('CQR'), Uint8Array.of(pack, asset));

export function decodeQuote(bytes) {
  const r = reader(bytes, 'CQT');
  const quote = { quoteId: r.take(32), pack: r.u8(), asset: r.u8(), batch: r.u16(), amount: r.u64(), expiresAtMs: r.u64(), keyId: r.take(32),
    paymentRequest: new TextDecoder().decode(r.vec()) };
  r.done();
  return quote;
}

const encodeIssueRequest = ({ quoteId, payment, keyId, blinded }) =>
  concat(Uint8Array.of(1), text('CIR'), quoteId, vec(text(payment)), keyId, u16(blinded.length), ...blinded);

function decodeIssueResponse(bytes) {
  const r = reader(bytes, 'CIS');
  const out = { quoteId: r.take(32), keyId: r.take(32), signatures: [] };
  for (let count = r.u16(); count > 0; count--) out.signatures.push(r.take(256));
  r.done();
  return out;
}

// CIK: the live issuer keys the directory lists, each as its IKY leaf.
function decodeIssuerKeys(bytes) {
  const r = reader(bytes, 'CIK');
  const keys = [];
  for (let count = r.u8(); count > 0; count--) {
    const kte = reader(r.vec(), 'KTE', 2);
    const iky = reader(kte.vec(), 'IKY');
    const purpose = iky.u8();
    const issuerName = new TextDecoder().decode(iky.vec());
    const epoch = iky.u32();
    iky.u64();
    iky.u64();
    const spki = iky.take(342);
    iky.done();
    keys.push({ purpose, issuerName, epoch, spki, keyId: sha('sha256', spki) });
  }
  r.done();
  return keys;
}

// RFC 9577 TokenChallenge, token type 2, empty redemption context.
export const tokenChallenge = issuerName =>
  concat(u16(2), u16(text(issuerName).length), text(issuerName), Uint8Array.of(0), u16(MORSE_ORIGIN_INFO.length), text(MORSE_ORIGIN_INFO));

// ---- RFC 9474 blind RSA, client side ----

const toBig = bytes => BigInt(`0x${Buffer.from(bytes).toString('hex') || '0'}`);
const toBytes = (n, length) => Uint8Array.from(Buffer.from(n.toString(16).padStart(length * 2, '0'), 'hex'));
const modpow = (base, exponent, modulus) => {
  let result = 1n;
  for (let b = base % modulus, e = exponent; e > 0n; e >>= 1n, b = (b * b) % modulus) if (e & 1n) result = (result * b) % modulus;
  return result;
};
const gcd = (a, b) => { while (b) [a, b] = [b, a % b]; return a; };
const inverse = (a, m) => {
  let [r0, r1, t0, t1] = [m, a % m, 0n, 1n];
  while (r1) { const q = r0 / r1; [r0, r1, t0, t1] = [r1, r0 - q * r1, t1, t0 - q * t1]; }
  if (r0 !== 1n) throw new Error('not invertible');
  return ((t0 % m) + m) % m;
};

// n and e from an SPKI (the RSAPublicKey inside the BIT STRING), by a minimal DER walk.
function publicNumbers(spki) {
  const tlv = (bytes, at) => {
    let length = bytes[at + 1];
    let head = 2;
    if (length & 0x80) { const n = length & 0x7f; length = 0; for (let i = 0; i < n; i++) length = length * 256 + bytes[at + 2 + i]; head += n; }
    return { tag: bytes[at], start: at + head, end: at + head + length };
  };
  const outer = tlv(spki, 0);
  const algorithm = tlv(spki, outer.start);
  const bits = tlv(spki, algorithm.end);
  const key = tlv(spki, bits.start + 1);
  const n = tlv(spki, key.start);
  const e = tlv(spki, n.end);
  if (outer.tag !== 0x30 || bits.tag !== 0x03 || key.tag !== 0x30 || n.tag !== 0x02 || e.tag !== 0x02) throw new Error('not an RSA SPKI');
  return { n: toBig(spki.subarray(n.start, n.end)), e: toBig(spki.subarray(e.start, e.end)) };
}

const mgf1 = (seed, length) => {
  const parts = [];
  for (let counter = 0; parts.length * 48 < length; counter++) parts.push(sha('sha384', seed, u32(counter)));
  return concat(...parts).subarray(0, length);
};

// EMSA-PSS-ENCODE (RFC 8017 §9.1.1), SHA-384, MGF1-SHA-384, 48-byte salt.
function pssEncode(message, emBits, salt) {
  const emLength = Math.ceil(emBits / 8);
  const h = sha('sha384', new Uint8Array(8), sha('sha384', message), salt);
  const db = concat(new Uint8Array(emLength - salt.length - 48 - 2), Uint8Array.of(1), salt);
  const mask = mgf1(h, db.length);
  const masked = db.map((x, i) => x ^ mask[i]);
  masked[0] &= 0xff >> (8 * emLength - emBits);
  return concat(masked, h, Uint8Array.of(0xbc));
}

// Blind(pk, msg): {blinded, inv}. `salt` and `r` are for test vectors only.
export function blind(spki, message, { salt = randomBytes(48), r = null } = {}) {
  const { n, e } = publicNumbers(spki);
  const length = Math.ceil(n.toString(2).length / 8);
  const m = toBig(pssEncode(message, n.toString(2).length - 1, Uint8Array.from(salt)));
  if (gcd(m, n) !== 1n) throw new Error('message not coprime with the modulus');
  let factor = r;
  while (factor === null) {
    const candidate = toBig(randomBytes(length)); // uniform in [2, n): rejection, never a reduction
    if (candidate > 1n && candidate < n && gcd(candidate, n) === 1n) factor = candidate;
  }
  return { blinded: toBytes((m * modpow(factor, e, n)) % n, length), inv: inverse(factor, n) };
}

// Finalize: unblind and verify (RSASSA-PSS, SHA-384, 48-byte salt); throws on a bad signature.
export function finalize(spki, message, blindSignature, inv) {
  const { n } = publicNumbers(spki);
  const length = Math.ceil(n.toString(2).length / 8);
  const signature = toBytes((toBig(blindSignature) * inv) % n, length);
  const key = createPublicKey({ key: Buffer.from(spki), format: 'der', type: 'spki' });
  if (!verify('sha384', message, { key, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 48 }, signature)) {
    throw new Error('blind signature does not verify');
  }
  return signature;
}

// ---- extras ----

// The extras credits buy (protocol/credits-v1.md "Extras"), in the order the
// drill device spends them: the tokens it gets, and how to judge what it
// reported. A verdict is {status, ms} for a spend (the alerts read it), plus
// ok or problem; or {skipped}.
const verdict = (line, problem, note) => ({ status: line.status, ms: line.ms, ok: !problem, problem, note });

export const EXTRAS = {
  // Priority sign-up: 20 tokens skip a surge's extra work. Without a surge
  // nothing is spent: the work route must answer, and the account registers
  // at the pinned base.
  signup: {
    credits: 20,
    judge: line => {
      if (!line.surge) {
        if (line.work_status !== 200) return { skipped: `GET /v1/devices/register/work answered ${line.work_status}`, problem: true };
        return { skipped: `no surge (registration asks the pinned difficulty ${line.base})` };
      }
      return verdict(line, line.status === 201 ? null : `priority sign-up answered ${line.status}`,
        `priority sign-up at difficulty ${line.base} during a surge (${line.difficulty})`);
    },
  },
  // Postage: the drill account prices its inbox at 1 credit; a stranger's
  // envelope without credits must get 402 and the signed policy, with a token 202.
  postage: {
    credits: 1,
    judge: line => verdict(line,
      line.policy_status !== 201 ? `PUT /v1/mailbox/policy answered ${line.policy_status}`
        : line.unpaid_status !== 402 ? `an unpaid envelope to a priced inbox answered ${line.unpaid_status}`
          : !line.policy_returned ? 'the 402 did not carry the signed policy'
            : line.status !== 202 ? `the envelope with 1 credit answered ${line.status}` : null,
      '402 unpaid, 202 with 1 credit'),
  },
  // Longer storage: 10 tokens buy one 30-day period.
  storage: {
    credits: 10,
    judge: line => verdict(line,
      line.status !== 201 ? `POST /v1/mailbox/retention answered ${line.status}`
        : line.retention_days !== 60 ? `the mailbox kept ${line.retention_days} days, not 60` : null,
      `${line.retention_days} days`),
  },
  // Large files (an object-store grant with CRD above 16 MiB): its workstream
  // replaces this entry with the grant request once the object store serves it.
  'large-file': { credits: 0, judge: () => ({ skipped: 'large-file extra not deployed' }) },
};

// ---- the drill ----

const pause = ms => new Promise(resolve => setTimeout(resolve, ms));

function paymentRequest(url) {
  const parsed = new URL(url);
  if (parsed.protocol !== 'solana:') throw new Error('the quote is not a Solana Pay request');
  return { recipient: parsed.pathname, mint: parsed.searchParams.get('spl-token'), reference: parsed.searchParams.get('reference') };
}

// PWR (sealed-delivery-v1.md "Stamped directory requests"): SHA-256(label ||
// expires_at_ms || nonce || SHA-256(payload)) with `difficulty` leading zero bits.
export function stampRequest(label, payload, difficulty, nowMs = Date.now()) {
  const expires = new Uint8Array(8);
  new DataView(expires.buffer).setBigUint64(0, BigInt(nowMs + 240_000));
  const inner = sha('sha256', payload);
  const zeros = hash => { let bits = 0; for (const byte of hash) { if (byte) return bits + Math.clz32(byte) - 24; bits += 8; } return bits; };
  for (let nonce = 0; nonce < 2 ** 32; nonce++) {
    if (zeros(sha('sha256', text(label), expires, u32(nonce), inner)) >= difficulty) {
      return concat(Uint8Array.of(1), text('PWR'), expires, u32(nonce), vec(payload));
    }
  }
  throw new Error('no stamp found');
}

// device({tokens}): runs the drill device (canary-device, role extras) with
// the tokens the extras spend and returns the lines it reported.
export async function creditsDrill({ issuer, difficulty, env, device, http = fetch, chainFor = url => solanaChain({ url }), sleep = pause,
  now = Date.now, buyerKey = () => loadKeypair(env.MORSE_CREDITS_BUYER_KEYPAIR), extras = EXTRAS }) {
  const fail = detail => ({ ok: false, detail });
  for (const name of ['MORSE_DIRECTORY_URL', 'MORSE_CREDITS_EDGE_URL', 'MORSE_CREDITS_RPC', 'MORSE_CREDITS_BUYER_KEYPAIR']) {
    if (!env[name]) return fail(`missing ${name}`);
  }
  const issuerName = new URL(issuer).host;
  const post = async (path, body) => http(`${env.MORSE_CREDITS_EDGE_URL}${path}`, { method: 'POST', body,
    headers: { 'Content-Type': 'application/octet-stream' }, signal: AbortSignal.timeout(30_000) });

  const listing = await http(`${env.MORSE_DIRECTORY_URL}/v1/credits/issuer-keys`, { signal: AbortSignal.timeout(30_000) });
  if (!listing.ok) return fail(`issuer keys answered ${listing.status}`);
  const keys = decodeIssuerKeys(new Uint8Array(await listing.arrayBuffer())).filter(k => k.purpose === 1 && k.issuerName === issuerName);

  const started = now();
  const quoted = await post('/v1/credits/quote', stampRequest('mesh-msg/v1/work/credit-quote', encodeQuoteRequest(PACK_SMALLEST, ASSET_USDC), difficulty, now()));
  if (quoted.status !== 201) return fail(`quote answered ${quoted.status}`);
  const quote = decodeQuote(new Uint8Array(await quoted.arrayBuffer()));
  const key = keys.find(k => equal(k.keyId, quote.keyId));
  if (!key) return fail('the quote names an issuer key that is not in the log');
  const pay = paymentRequest(quote.paymentRequest);
  if (!pay.mint || !pay.reference) return fail('the quote asks for no USDC mint or reference');

  const buyer = await buyerKey();
  const chain = chainFor(env.MORSE_CREDITS_RPC);
  const transfer = await token.transfer({ owner: buyer.address, mint: address(pay.mint), to: await ata(pay.recipient, pay.mint), amount: quote.amount });
  // Solana Pay: the reference rides on the transfer as a read-only account (role 0).
  transfer.accounts = [...transfer.accounts, { address: address(pay.reference), role: 0 }];
  const { signature } = await chain.send([await createAtaIdempotent(buyer.address, pay.recipient, pay.mint), transfer], { payer: buyer });

  const challengeDigest = sha('sha256', tokenChallenge(issuerName));
  const inputs = Array.from({ length: quote.batch }, () => concat(u16(2), randomBytes(32), challengeDigest, key.keyId));
  const blinds = inputs.map(input => blind(key.spki, input));
  const request = encodeIssueRequest({ quoteId: quote.quoteId, payment: signature, keyId: key.keyId, blinded: blinds.map(b => b.blinded) });
  let issued = null;
  for (let attempt = 0; attempt < 120 && !issued; attempt++) {
    const answer = await post('/v1/credits/issue', request);
    if (answer.status === 200) issued = decodeIssueResponse(new Uint8Array(await answer.arrayBuffer()));
    else if (answer.status === 202) await sleep(5000);
    else return fail(`issue answered ${answer.status} (payment ${signature})`);
  }
  if (!issued) return fail(`the payment ${signature} was not final within 10 minutes`);
  if (!equal(issued.quoteId, quote.quoteId) || !equal(issued.keyId, key.keyId) || issued.signatures.length !== inputs.length) {
    return fail('the issue response does not match the request');
  }
  const tokens = inputs.map((input, i) => concat(input, finalize(key.spki, input, issued.signatures[i], blinds[i].inv)));
  const purchaseMs = now() - started;

  const spending = Object.entries(extras).filter(([, extra]) => extra.credits > 0);
  const needed = spending.reduce((total, [, extra]) => total + extra.credits, 0);
  const lines = await device({ tokens: tokens.slice(0, needed) });
  const deviceError = lines.find(line => line.kind === 'error')?.error;
  const problems = deviceError ? [`drill device: ${deviceError}`] : [];
  const notes = [];
  const redemptions = [];
  for (const [name, extra] of Object.entries(extras)) {
    const line = lines.find(x => x.kind === 'extra' && x.extra === name);
    if (!line && extra.credits > 0) {
      if (!deviceError) problems.push(`${name}: the drill device reported nothing`);
      continue;
    }
    const result = extra.judge(line ?? {});
    if (result.skipped) {
      notes.push(`${name}: ${result.skipped}`);
      if (result.problem) problems.push(`${name}: ${result.skipped}`);
      continue;
    }
    redemptions.push({ extra: name, status: result.status, ms: result.ms });
    if (result.problem) problems.push(`${name}: ${result.problem}`);
    else notes.push(`${name}: ${result.note}`);
  }
  const cleanup = lines.find(x => x.extra === 'cleanup');
  if (cleanup && cleanup.status !== 204) problems.push(`the drill account ${cleanup.account} was not deleted (${cleanup.status})`);
  return { ok: problems.length === 0, redemptions,
    detail: `${tokens.length} credits issued and verified for payment ${signature} in ${Math.round(purchaseMs / 1000)} s; ` +
      `${[...problems, ...notes].join('; ')}` };
}

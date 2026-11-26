import assert from 'node:assert/strict';
import test from 'node:test';
import { pushC2sp } from './c2sp-push.mjs';

const note = 'morseapp.io/log/main\n9\nROOT=\nmorse-checkpoint KTK=\n\n— morseapp.io/log/main AAAA\n';
const hash = n => new Uint8Array(32).fill(n);
const witness = (id, extra = {}) => ({ witness_id: id, public_key: '1'.repeat(64), operator: 'Acme', status: 'shadow',
  software: 'c2sp', morse_run: false, c2sp_name: `${id}.example/w`, push_url: `https://${id}.example/w`, ...extra });

// A directory serving the note and RFC 6962 consistency proofs, recording what
// it was asked and which cosignatures it received.
function fakeDirectory({ proofLength = 3 } = {}) {
  const seen = { queries: [], cosignatures: [] };
  const env = { MESSENGER_DELIVERY_INTERNAL_TOKEN: 't', DIRECTORY: { getByName: () => ({ fetch: async (url, init = {}) => {
    const path = new URL(url).pathname;
    if (path === '/v1/transparency/checkpoint.note') return new Response(note);
    if (path === '/v1/transparency/consistency') {
      const q = new Uint8Array(init.body);
      const view = new DataView(q.buffer);
      seen.queries.push([view.getBigUint64(4), view.getBigUint64(12), q[20]]);
      const out = new Uint8Array(21 + 32 * proofLength);
      out.set([2, 75, 84, 67]); out.set(q.subarray(4, 20), 4); out[20] = proofLength;
      for (let i = 0; i < proofLength; i++) out.set(hash(i + 1), 21 + 32 * i);
      return new Response(out);
    }
    if (path === '/v1/transparency/witnesses' && init.method === 'POST') {
      seen.cosignatures.push([init.headers['Content-Type'], init.body]);
      return new Response(null, { status: 201 });
    }
    return new Response(null, { status: 404 });
  } }) } };
  return { env, seen };
}
const memory = () => { const m = new Map(); return { get: k => m.get(k), set: (k, v) => m.set(k, v), m }; };

test('C2SP push is off by default and an empty push list makes no requests', async () => {
  const { env, seen } = fakeDirectory();
  let calls = 0;
  const fetcher = async () => { calls++; return new Response(null, { status: 500 }); };
  assert.deepEqual(await pushC2sp(env, { state: memory(), fetcher, witnesses: [witness('acme')] }), []);
  env.MORSE_C2SP_PUSH = 'on';
  assert.deepEqual(await pushC2sp(env, { state: memory(), fetcher, witnesses: [witness('witness-a', { software: 'mesh', morse_run: true })] }), []);
  assert.equal(calls, 0);
  assert.deepEqual(seen.queries, []);
});

test('C2SP push sends add-checkpoint, follows a 409 to the witness size, and forwards the cosignature', async () => {
  const { env, seen } = fakeDirectory();
  env.MORSE_C2SP_PUSH = 'on';
  const state = memory();
  const bodies = [];
  const fetcher = async (url, init) => {
    bodies.push([String(url), init.body]);
    if (init.body.startsWith('old 0\n')) return new Response('5\n', { status: 409, headers: { 'Content-Type': 'text/x.tlog.size' } });
    return new Response('— acme.example/w Zm9v\n— other.example/w YmFy\n');
  };
  const results = await pushC2sp(env, { state, fetcher, witnesses: [witness('acme')] });
  assert.deepEqual(results, [{ witness_id: 'acme', status: 'cosigned', size: '9' }]);
  assert.equal(bodies[0][0], 'https://acme.example/w/add-checkpoint');
  assert.equal(bodies[0][1], `old 0\n\n${note}`, 'no proof lines from size 0');
  assert.deepEqual(seen.queries, [[5n, 9n, 2]], 'an RFC 6962 (tree 2) proof from the witness size');
  const lines = [1, 2, 3].map(n => Buffer.from(hash(n)).toString('base64'));
  assert.equal(bodies[1][1], `old 5\n${lines.join('\n')}\n\n${note}`);
  assert.deepEqual(seen.cosignatures, [['text/x-c2sp-cosignature', '— acme.example/w Zm9v\n']]);
  assert.equal(state.get('c2sp:acme'), '9');
  // The next push starts from the size the witness cosigned.
  await pushC2sp(env, { state, fetcher, witnesses: [witness('acme')] });
  assert.match(bodies.at(-1)[1], /^old 9\n\n/);
});

test('a failing or over-long push is reported per witness and never blocks the others', async () => {
  const { env } = fakeDirectory({ proofLength: 64 });
  env.MORSE_C2SP_PUSH = 'on';
  const state = memory();
  state.set('c2sp:far', '1');
  const fetcher = async url => String(url).includes('down') ? new Response(null, { status: 503 }) : new Response('— ok.example/w Zm9v\n');
  const results = await pushC2sp(env, { state, fetcher, witnesses: [witness('down'), witness('far'), witness('ok')] });
  assert.deepEqual(results.map(x => [x.witness_id, x.status]), [['down', 'failed'], ['far', 'failed'], ['ok', 'cosigned']]);
  assert.match(results[1].error, /63/);
});

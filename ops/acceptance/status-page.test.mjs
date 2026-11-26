import assert from 'node:assert/strict';
import test from 'node:test';
import { renderHtml, statusDocument } from './status-page.mjs';

const key = n => n.toString(16).padStart(2, '0').repeat(32);
const frame = ['2', key(1), key(2), '16', '2', '3', `witness-a ${key(10)} Morse`, `witness-b ${key(11)} Morse`, `witness-c ${key(12)} Morse`,
  '-', '0', '0', '-', 'morseapp.io/log/main', '2'].join('\n');
const registry = { witnesses: [
  { witness_id: 'witness-a', operator: 'Morse', status: 'pinned', morse_run: true },
  { witness_id: 'witness-b', operator: 'Morse', status: 'pinned', morse_run: true },
  { witness_id: 'witness-c', operator: 'Morse', status: 'pinned', morse_run: true },
  { witness_id: 'acme-1', operator: 'Acme <b>Labs</b>', status: 'shadow', morse_run: false },
] };
const slash = (proof, slot) => ({ proof, kind: 1, slot: String(slot), paid_to: 'Finder111', tx_signature: `tx-${proof}`, link: `https://explorer/tx-${proof}`,
  account_link: `https://explorer/${proof}` });
const network = extra => ({ log: 'morse-main', status: 'ok', cluster: 'mainnet-beta', generated_at: '2026-09-29T11:59:00.000Z',
  log_account: { address: 'Log111', link: 'https://explorer/Log111' },
  last_public_checkpoint: { slot: '900', sequence: '41', tree_size: '1200', time: '2026-09-29T11:50:00.000Z', age_seconds: 600, link: 'https://explorer/block/900' },
  bonded: { directory: { status: 'Active', amount: '50000000000', usd: '50000.00', link: 'https://explorer/dv' },
    witnesses: [{ witness_id: 'witness-a', status: 'Active', excluded: true, amount: '10000000000', usd: '10000.00', link: 'https://explorer/wa' }] },
  slashed: { service: false, witnesses: 0, never: true }, slash_history: [], operations: { burns: [] }, ...extra });
const NOW = Date.UTC(2026, 8, 29, 12);

test('status page: the profile line and pinned set phones hold', () => {
  const doc = statusDocument({ frame, registry, network: network(), now: NOW });
  assert.equal(doc.profile.line, 'Bootstrap: all 3 witnesses are run by Morse');
  assert.deepEqual(doc.pinned.map(w => [w.witness_id, w.operator, w.registry_status]),
    [['witness-a', 'Morse', 'pinned'], ['witness-b', 'Morse', 'pinned'], ['witness-c', 'Morse', 'pinned']]);
  assert.deepEqual(doc.shadow.map(w => w.witness_id), ['acme-1']);
  assert.equal(doc.last_anchor.sequence, '41');
});

test('status page: slashes stay forever, even when status.json forgets one', () => {
  const first = statusDocument({ frame, registry, network: network({ slash_history: [slash('aa', 10)] }), now: NOW });
  const second = statusDocument({ frame, registry, network: network({ slash_history: [slash('bb', 20)] }), previous: first, now: NOW + 60_000 });
  assert.deepEqual(second.slashes.map(s => s.proof), ['bb', 'aa']);
  const third = statusDocument({ frame, registry, network: { status: 'unavailable', reason: 'rpc_disagree', slash_history: [] }, previous: second, now: NOW + 120_000 });
  assert.deepEqual(third.slashes.map(s => s.proof), ['bb', 'aa']);
  assert.equal(third.network.status, 'unavailable');
  assert.equal(third.last_anchor.sequence, '41', 'the last known anchor is kept while the counter is unavailable');
});

test('status page: attendance per epoch accumulates from the monitor, burns by transaction', () => {
  const monitor = epochs => ({ epochs });
  const first = statusDocument({ frame, registry, network: network({ operations: { burns: [{ signature: 's1', burned: '5', at: 'x' }] } }),
    monitor: monitor([{ epoch: 2939, anchors: 10, below_threshold: 0, witnesses: [{ witness_id: 'witness-a', cosigned: 10 }, { witness_id: 'witness-b', cosigned: 9 }] }]), now: NOW });
  const second = statusDocument({ frame, registry, network: network({ operations: { burns: [{ signature: 's2', burned: '7', at: 'y' }] } }),
    monitor: monitor([{ epoch: 2940, anchors: 4, below_threshold: 0, witnesses: [{ witness_id: 'witness-a', cosigned: 4 }] },
      { epoch: 2939, anchors: 12, below_threshold: 0, witnesses: [{ witness_id: 'witness-a', cosigned: 12 }, { witness_id: 'witness-b', cosigned: 11 }] }]),
    previous: first, now: NOW + 60_000 });
  assert.deepEqual(second.attendance.map(e => [e.epoch, e.anchors]), [[2940, 4], [2939, 12]]);
  assert.equal(second.attendance[1].witnesses.find(w => w.witness_id === 'witness-b').percent, 91.7);
  assert.deepEqual(second.burns.map(b => b.signature), ['s2', 's1']);
});

test('status page: HTML escapes everything it did not write and links every number', () => {
  const doc = statusDocument({ frame, registry, network: network({ slash_history: [slash('aa', 10)] }), now: NOW,
    results: [{ id: 1, name: 'lookup', status: 'fail', detail: '<img src=x onerror=alert(1)>', at: '2026-09-29T11:00:00.000Z' }] });
  const html = renderHtml(doc);
  assert.match(html, /<title>Morse network status<\/title>/);
  assert.match(html, /Bootstrap: all 3 witnesses are run by Morse/);
  assert.doesNotMatch(html, /<b>Labs<\/b>/);
  assert.match(html, /Acme &lt;b&gt;Labs&lt;\/b&gt;/);
  assert.doesNotMatch(html, /<img src=x/);
  assert.match(html, /href="https:\/\/explorer\/block\/900"/);
  assert.match(html, /href="https:\/\/explorer\/tx-aa"/);
  assert.doesNotMatch(renderHtml({ ...doc, last_anchor: { ...doc.last_anchor, link: 'javascript:alert(1)' } }), /href="javascript:/);
});

import assert from 'node:assert/strict';
import test from 'node:test';

import { base58 } from './base58.ts';
import { bountyNotice, bountyProof, formatUnits } from './bounty-notice.ts';
import type { FiledProof, TrustDetails } from './public-record.ts';

const finder = new Uint8Array(32).fill(7);
const other = new Uint8Array(32).fill(8);
const proof = (changes: Partial<FiledProof>): FiledProof => ({
  bytes: new Uint8Array(37),
  forkKind: 2,
  proofHash: new Uint8Array(32),
  finder,
  complete: true,
  landed: false,
  paidTo: null,
  paidElsewhere: false,
  relays: [{ url: 'https://relay-a.test', status: 'sent' }],
  ...changes,
});
const alarm = (proofs: FiledProof[], raisedAt = 1): TrustDetails =>
  ({ kind: 'anchor_mismatch', active: true, raisedAt, yours: null, other: null, proofs });

test('the bounty notice is about a proof that named this wallet and reached a relay', () => {
  assert.equal(bountyProof([]), null);
  // With the setting off the finder is zero: no bounty to announce.
  assert.equal(bountyProof([alarm([proof({ finder: null })])]), null);
  // Not filed yet: every relay still pending.
  assert.equal(bountyProof([alarm([proof({ relays: [{ url: 'https://relay-a.test', status: 'pending' }] })])]), null);
  const newest = proof({ forkKind: 3 });
  assert.equal(bountyProof([alarm([proof({})], 1), alarm([newest], 2)]), newest);
});

test('filed, then landed with the amount and transaction, or paid to another address', () => {
  assert.deepEqual(bountyNotice(proof({}), null), {
    text: 'Your phone caught a forked key log. The proof was filed; the bounty is on its way to your wallet.',
    details: null,
    transaction: null,
  });
  const landed = proof({ landed: true, paidTo: finder });
  // Landed, but the payout isn't read from the chain yet.
  assert.equal(bountyNotice(landed, null).text, 'Your phone caught a forked key log. The proof was filed; the bounty is on its way to your wallet.');
  assert.deepEqual(bountyNotice(landed, { amount: 1_250_500_000n, signature: 'sig' }), {
    text: 'Your phone caught a forked key log. The proof was filed, and the bounty landed in your wallet: 1,250.5 USDC.',
    details: null,
    transaction: 'https://explorer.solana.com/tx/sig',
  });
  const elsewhere = bountyNotice(proof({ landed: true, paidTo: other, paidElsewhere: true }), null);
  assert.equal(elsewhere.text, 'Your phone caught a forked key log. The proof was filed.');
  assert.match(elsewhere.details!, new RegExp(`paid ${base58(other)}, not your wallet`));
});

test('amounts print in whole units with the digits the asset has', () => {
  assert.equal(formatUnits(0n, 6), '0');
  assert.equal(formatUnits(1n, 9), '0.000000001');
  assert.equal(formatUnits(2_500_000n, 9), '0.0025');
  assert.equal(formatUnits(1_234_567_000_000n, 6), '1,234,567');
});

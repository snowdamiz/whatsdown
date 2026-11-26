import assert from 'node:assert/strict';
import test from 'node:test';

import {
  answerBountyOffer,
  confirmsPhrase,
  defaultWalletSettings,
  finderAddress,
  offerBounties,
  parseWalletSettings,
  pickConfirmation,
  setCollectBounties,
  walletMessage,
} from './wallet-settings.ts';

const bountyKey = new Uint8Array(32).fill(0xba);

test('collecting fork bounties is off until the person turns it on, and needs the wallet', () => {
  assert.equal(defaultWalletSettings.collectBounties, false);
  assert.deepEqual(parseWalletSettings(null), defaultWalletSettings);
  assert.deepEqual(parseWalletSettings('{"settings":"nonsense"}'), defaultWalletSettings);
  assert.throws(() => setCollectBounties(defaultWalletSettings, false, true), /wallet_required/);
  const on = setCollectBounties(defaultWalletSettings, true, true);
  assert.equal(on.collectBounties, true);
  // Turning it off never needs anything.
  assert.equal(setCollectBounties(on, false, false).collectBounties, false);
  assert.deepEqual(parseWalletSettings(JSON.stringify({ settings: on })), on);
});

test('the offer is made once, when a wallet is set up, whatever the answer', () => {
  assert.equal(offerBounties(defaultWalletSettings, false), false);
  assert.equal(offerBounties(defaultWalletSettings, true), true);
  const declined = answerBountyOffer(defaultWalletSettings, false);
  assert.deepEqual([declined.bountiesOffered, declined.collectBounties], [true, false]);
  assert.equal(offerBounties(declined, true), false);
  const accepted = answerBountyOffer(defaultWalletSettings, true);
  assert.deepEqual([accepted.bountiesOffered, accepted.collectBounties], [true, true]);
  assert.equal(offerBounties(accepted, true), false);
});

test('a fork proof names a fresh bounty address only with the setting on and a wallet', async () => {
  let handedOut = 0;
  const next = async () => { handedOut += 1; return bountyKey; };
  assert.equal(await finderAddress(defaultWalletSettings, true, next), null);
  const on = { ...defaultWalletSettings, collectBounties: true };
  assert.equal(await finderAddress(on, false, next), null);
  assert.equal(handedOut, 0);
  assert.equal(await finderAddress(on, true, next), bountyKey);
  assert.equal(handedOut, 1);
  // A wallet that can't answer (locked, gone) names no address; the proof is filed anyway.
  assert.equal(await finderAddress(on, true, async () => { throw new Error('wallet_locked'); }), null);
});

test('the recovery phrase is confirmed by typing two of its words back', () => {
  const words = 'legal winner thank year wave sausage worth useful legal winner thank yellow'.split(' ');
  const asked = pickConfirmation(words.length, () => 0.99);
  assert.equal(asked[0] < asked[1], true);
  assert.equal(asked[1] < words.length, true);
  const [first, second] = asked;
  assert.equal(confirmsPhrase(words, asked, [` ${words[first]!.toUpperCase()} `, words[second]!]), true);
  assert.equal(confirmsPhrase(words, asked, [words[second]!, words[first]!]), words[first] === words[second]);
  assert.equal(confirmsPhrase(words, asked, ['', '']), false);
  const [low, high] = pickConfirmation(12, () => 0);
  assert.notEqual(low, high);
});

test('wallet errors read as sentences, and unknown ones still say something', () => {
  assert.equal(walletMessage(new Error('bad_mnemonic')), 'That isn’t a valid recovery phrase. Check each word.');
  assert.equal(walletMessage(new Error('Call rejected → Caused by: bounty_not_issued')), 'Bounty not issued.');
  assert.equal(walletMessage(new Error('rpc_error: insufficient lamports')), 'Not enough SOL to pay the network fee.');
});

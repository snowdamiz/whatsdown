import assert from 'node:assert/strict';
import test from 'node:test';

import { utf8, vector } from './codec.ts';
import { keyCheckedLine, parseNetworkStatus, profileLine, witnessNote } from './witnesses.ts';

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};

// What mobile-core's network status export writes.
function status(
  profile: string,
  threshold: number,
  witnesses: [string, string][],
  sections: [number, Uint8Array][] = [],
): Uint8Array {
  const morse = witnesses.filter(([, label]) => label === 'Morse').length;
  return concat(
    Uint8Array.of(1), utf8('NST'), vector(utf8(profile)),
    Uint8Array.of(threshold, witnesses.length, morse), new Uint8Array(32).fill(9),
    ...witnesses.map(([id, label]) => concat(vector(utf8(id)), vector(utf8(label)), Uint8Array.of(label === 'Morse' ? 1 : 0))),
    Uint8Array.of(sections.length),
    ...sections.map(([tag, body]) => concat(Uint8Array.of(tag >> 8, tag & 255), vector(body))),
  );
}

test('network status reads the pinned set and says which profile it is in', () => {
  const bootstrap = parseNetworkStatus(status('bootstrap', 2, [['witness-a', 'Morse'], ['witness-b', 'Morse'], ['witness-c', 'Morse']]));
  assert.equal(bootstrap.threshold, 2);
  assert.equal(bootstrap.updateRequired, false);
  assert.deepEqual(bootstrap.setId, new Uint8Array(32).fill(9));
  assert.equal(profileLine(bootstrap), 'Bootstrap: all 3 witnesses are run by Morse');
  assert.equal(keyCheckedLine(bootstrap), 'Key checked by 2 of 3 witnesses');

  const open = parseNetworkStatus(status('open', 3, [
    ['a', 'Morse'], ['b', 'Acme Labs'], ['c', 'Witness Guild'], ['d', 'Kestrel'], ['e', 'Open Relay Co'],
  ]));
  assert.equal(profileLine(open), 'Open: 4 of 5 witnesses are independent');
  assert.equal(keyCheckedLine(open), 'Key checked by 3 of 5 witnesses');
  assert.deepEqual(open.witnesses.map(witnessNote), ['Run by Morse', 'Acme Labs', 'Witness Guild', 'Kestrel', 'Open Relay Co']);

  const mixed = parseNetworkStatus(status('bootstrap', 3, [['a', 'Morse'], ['b', 'Morse'], ['c', 'Morse'], ['d', 'X'], ['e', 'Y']]));
  assert.equal(profileLine(mixed), 'Bootstrap: 3 of 5 witnesses are run by Morse');
  const transitional = parseNetworkStatus(status('transitional', 3, [['a', 'Morse'], ['b', 'Morse'], ['c', 'X'], ['d', 'Y'], ['e', 'Z']]));
  assert.equal(profileLine(transitional), 'Transitional: 3 of 5 witnesses are independent');
});

test('network status sections: update required is read and unknown tags are skipped', () => {
  const witnesses: [string, string][] = [['witness-a', 'Morse'], ['witness-b', 'Morse']];
  assert.equal(parseNetworkStatus(status('bootstrap', 2, witnesses, [[7, utf8('later')], [1, Uint8Array.of(1)]])).updateRequired, true);
  assert.equal(parseNetworkStatus(status('bootstrap', 2, witnesses, [[7, utf8('later')]])).updateRequired, false);
});

test('network status refuses frames that do not add up', () => {
  const witnesses: [string, string][] = [['witness-a', 'Morse'], ['witness-b', 'Morse']];
  const good = status('bootstrap', 2, witnesses);
  assert.throws(() => parseNetworkStatus(good.subarray(0, good.length - 1)));
  assert.throws(() => parseNetworkStatus(concat(good, Uint8Array.of(0))));
  assert.throws(() => parseNetworkStatus(status('closed', 2, witnesses)));
  assert.throws(() => parseNetworkStatus(status('bootstrap', 3, witnesses)));
  const lying = status('bootstrap', 2, witnesses);
  lying[4 + 4 + 9 + 2] = 1; // Morse-run count
  assert.throws(() => parseNetworkStatus(lying));
  assert.throws(() => parseNetworkStatus(concat(Uint8Array.of(2), good.subarray(1))));
});

import assert from 'node:assert/strict';
import test from 'node:test';
import securityConfig from '../plugins/security-config.cjs';

const pins = [
  { id: 'witness-c', publicKey: '03'.repeat(32), operator: 'Outside Two' },
  { id: 'witness-a', publicKey: '01'.repeat(32), operator: 'Morse' },
  { id: 'witness-b', publicKey: '02'.repeat(32), operator: 'Outside One' },
];
const environment = {
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '22'.repeat(32),
  MESSENGER_ABUSE_DIFFICULTY: '16',
  MESSENGER_WITNESS_SET_JSON: JSON.stringify(pins),
  MESSENGER_WITNESS_THRESHOLD: '2',
};

test('native writers produce a sorted, canonical majority frame', () => {
  assert.equal(securityConfig(environment), [
    '2', '11'.repeat(32), '22'.repeat(32), '16', '2', '3',
    `witness-a ${'01'.repeat(32)} Morse`,
    `witness-b ${'02'.repeat(32)} Outside One`,
    `witness-c ${'03'.repeat(32)} Outside Two`, '-', '0', '-',
  ].join('\n'));
});

test('native writers reject ambiguous sets, insufficient majorities, and invalid endpoints', () => {
  for (const update of [
    { MESSENGER_WITNESS_THRESHOLD: '1' },
    { MESSENGER_WITNESS_THRESHOLD: '3' },
    { MESSENGER_WITNESS_THRESHOLD: '02' },
    { MESSENGER_WITNESS_SET_JSON: JSON.stringify([pins[0], pins[0], pins[2]]) },
    { MESSENGER_WITNESS_SET_JSON: JSON.stringify([pins[0], { ...pins[1], publicKey: pins[0].publicKey }, pins[2]]) },
    { MESSENGER_WITNESS_SET_JSON: JSON.stringify([{ ...pins[0], id: 'Upper' }, pins[1], pins[2]]) },
    { MESSENGER_WITNESS_SET_JSON: JSON.stringify([{ ...pins[0], operator: ' trailing ' }, pins[1], pins[2]]) },
    { MESSENGER_ANCHOR_RING_ADDRESS: 'bad-base58' },
    { MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example']) },
    { MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example', 'https://one.example', 'https://three.example']) },
    { MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example/rpc-a', 'https://one.example/rpc-b', 'https://three.example']) },
    { MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://[broken' },
    { MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://credits.example/path' },
    { MESSENGER_CREDIT_ISSUER_ORIGIN: 'http://credits.example' },
    { MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://user@credits.example' },
  ]) assert.throws(() => securityConfig({ ...environment, ...update }));
  assert.throws(() => securityConfig({ MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://credits.example' }));
});

test('anchor and issuer pins remain in the native frame', () => {
  const rpcs = ['https://one.example/rpc', 'https://two.example/rpc', 'https://three.example/rpc'];
  const result = securityConfig({
    ...environment,
    MESSENGER_ANCHOR_RING_ADDRESS: '1'.repeat(32),
    MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(rpcs),
    MESSENGER_CREDIT_ISSUER_ORIGIN: 'https://credits.example',
  });
  assert.equal(result.split('\n').slice(-6).join('\n'), ['1'.repeat(32), '3', ...rpcs, 'https://credits.example'].join('\n'));
});

const migrationEnvironment = {
  ...environment,
  MESSENGER_TRANSPARENCY_LOG_VERSION: '2',
  MESSENGER_LEGACY_WITNESS_THRESHOLD: '2',
  MESSENGER_LEGACY_WITNESS_SET_JSON: JSON.stringify(pins.slice(1)),
};

test('RFC native config pins the new log and a separate immutable legacy seal policy', () => {
  const expected = securityConfig(environment).split('\n'); expected[0] = '3';
  expected.push('2', '2', '2', `witness-a ${'01'.repeat(32)} Morse`, `witness-b ${'02'.repeat(32)} Outside One`);
  assert.equal(securityConfig(migrationEnvironment), expected.join('\n'));
  // Operators may retire a legacy key from the current set without losing the
  // policy needed by a returning client to authenticate its historical bridge.
  const changed = securityConfig({ ...migrationEnvironment,
    MESSENGER_WITNESS_SET_JSON: JSON.stringify(pins.map(pin => ({ ...pin, publicKey: 'a' + pin.publicKey.slice(1) }))),
  });
  assert.equal(changed.split('\n').slice(-5).join('\n'), expected.slice(-5).join('\n'));
});

test('a native RFC release cannot omit, weaken or ambiguously select its legacy policy', () => {
  for (const update of [
    { MESSENGER_TRANSPARENCY_LOG_VERSION: '02' },
    { MESSENGER_TRANSPARENCY_LOG_VERSION: '3' },
    { MESSENGER_TRANSPARENCY_LOG_VERSION: undefined },
    { MESSENGER_LEGACY_WITNESS_THRESHOLD: undefined },
    { MESSENGER_LEGACY_WITNESS_THRESHOLD: '1' },
    { MESSENGER_LEGACY_WITNESS_SET_JSON: undefined },
    { MESSENGER_LEGACY_WITNESS_SET_JSON: '[]' },
    { MESSENGER_LEGACY_WITNESS_SET_JSON: JSON.stringify([pins[0], pins[0]]) },
  ]) assert.throws(() => securityConfig({ ...migrationEnvironment, ...update }));
});

const anchorEnvironment = {
  ...migrationEnvironment,
  MESSENGER_ANCHOR_RING_ADDRESS: '5yn5bTAXsACqkiwrJxVuSZVtCmam6uPVcNS4oYHt6Vtb',
  MESSENGER_ANCHOR_PROGRAM_ADDRESS: '1'.repeat(32),
  MESSENGER_ANCHOR_LOG_NAME: 'morse-main',
  MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(['https://one.example', 'https://two.example', 'https://three.example']),
};

test('native v4 carries explicit judge and log pins beside both witness policies', () => {
  const expected = securityConfig({ ...anchorEnvironment,
    MESSENGER_ANCHOR_PROGRAM_ADDRESS: undefined, MESSENGER_ANCHOR_LOG_NAME: undefined }).split('\n');
  expected[0] = '4'; expected.push('1'.repeat(32), 'morse-main');
  assert.equal(securityConfig(anchorEnvironment), expected.join('\n'));
  for (const update of [
    { MESSENGER_ANCHOR_PROGRAM_ADDRESS: undefined },
    { MESSENGER_ANCHOR_PROGRAM_ADDRESS: 'invalid' },
    { MESSENGER_ANCHOR_LOG_NAME: undefined },
    { MESSENGER_ANCHOR_LOG_NAME: 'Main' },
    { MESSENGER_ANCHOR_LOG_NAME: 'a'.repeat(33) },
    { MESSENGER_ANCHOR_RING_ADDRESS: '-' },
    { MESSENGER_ANCHOR_PROGRAM_ADDRESS: '-' },
    { MESSENGER_ANCHOR_LOG_NAME: '-' },
    { MESSENGER_TRANSPARENCY_LOG_VERSION: undefined },
  ]) assert.throws(() => securityConfig({ ...anchorEnvironment, ...update }));
  const disabled = securityConfig({ ...anchorEnvironment, MESSENGER_ANCHOR_RING_ADDRESS: '-',
    MESSENGER_ANCHOR_PROGRAM_ADDRESS: '-', MESSENGER_ANCHOR_LOG_NAME: '-' });
  assert.ok(disabled.startsWith('4\n'));
  assert.ok(disabled.endsWith('\n-\n-'));
});

test('production native writers never pin the canary log', () => {
  const canary = { ...anchorEnvironment, MESSENGER_ANCHOR_LOG_NAME: 'morse-canary' };
  assert.throws(() => securityConfig(canary), /morse-main/);
  assert.ok(securityConfig(canary, { development: true }).endsWith('\nmorse-canary'));
});

const relayEnvironment = { ...anchorEnvironment,
  MESSENGER_SLASH_MINT_ADDRESS: 'cGfHiC6Kgg3FpFZvgwGcswsCRtp4aBP2fzuXRQPizuN',
  MESSENGER_RELAY_URLS: JSON.stringify(['https://relay-one.example', 'https://relay-two.example:8443']),
};

test('native v5 release pins relay origins and receipt mint alongside existing log identity', () => {
  const expected = securityConfig(anchorEnvironment).split('\n'); expected[0] = '5';
  expected.push(relayEnvironment.MESSENGER_SLASH_MINT_ADDRESS, '2', 'https://relay-one.example', 'https://relay-two.example:8443');
  assert.equal(securityConfig(relayEnvironment), expected.join('\n'));
  const disabled = securityConfig({ ...anchorEnvironment, MESSENGER_SLASH_MINT_ADDRESS: '-', MESSENGER_RELAY_URLS: '[]' });
  assert.ok(disabled.startsWith('5\n')); assert.ok(disabled.endsWith('\n-\n0'));
  const maximum = Array.from({ length: 8 }, (_, i) => `https://relay-${i}.example`);
  assert.ok(securityConfig({ ...relayEnvironment, MESSENGER_RELAY_URLS: JSON.stringify(maximum) }).endsWith('\n8\n' + maximum.join('\n')));
});

test('relay pins cannot select untrusted endpoints, disappear on missing prerequisites or exceed bounds', () => {
  for (const update of [
    { MESSENGER_SLASH_MINT_ADDRESS: undefined }, { MESSENGER_SLASH_MINT_ADDRESS: '-' },
    { MESSENGER_SLASH_MINT_ADDRESS: 'bad' }, { MESSENGER_SLASH_MINT_ADDRESS: '1'.repeat(32) },
    { MESSENGER_ANCHOR_RING_ADDRESS: '-', MESSENGER_ANCHOR_PROGRAM_ADDRESS: '-', MESSENGER_ANCHOR_LOG_NAME: '-' },
    { MESSENGER_ANCHOR_PROGRAM_ADDRESS: undefined }, { MESSENGER_TRANSPARENCY_LOG_VERSION: undefined },
    ...['null', '{}', JSON.stringify(['https://relay.example', 'https://relay.example']),
      JSON.stringify(Array.from({ length: 9 }, (_, i) => `https://relay-${i}.example`)),
      ...['http://relay.example', 'https://relay.example/', 'https://relay.example/path',
        'https://relay.example?query', 'https://relay.example#fragment', 'https://user@relay.example',
        'https://Relay.example', 'https://relay.example:443'].map(url => JSON.stringify([url])),
    ].map(MESSENGER_RELAY_URLS => ({ MESSENGER_RELAY_URLS })),
  ]) assert.throws(() => securityConfig({ ...relayEnvironment, ...update }));
  assert.throws(() => securityConfig({ MESSENGER_RELAY_URLS: '[]' }));
});


const classicalRelease = {
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32),
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: '01'.repeat(32),
  MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: '02'.repeat(32),
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '22'.repeat(32),
  MESSENGER_ABUSE_DIFFICULTY: '16',
};

test('explicit suite floors wrap exact existing feature profiles; absent floor preserves old bytes', () => {
  for (const [index, release] of [classicalRelease, environment, migrationEnvironment, anchorEnvironment, relayEnvironment].entries()) {
    const old = securityConfig(release);
    assert.equal(old.split('\n')[0], String(index + 1));
    assert.equal(securityConfig({ ...release, MESSENGER_MINIMUM_SESSION_SUITE: undefined }), old);
    for (const minimum of ['1', '2']) {
      assert.equal(securityConfig({ ...release, MESSENGER_MINIMUM_SESSION_SUITE: minimum }), `6\n${minimum}\n${old}`);
    }
  }
});

test('suite floor never substitutes for valid security pins or accepts an ambiguous minimum', () => {
  for (const minimum of ['', '0', '3', '-1', '+2', '02', '2.0', '2e0', ' 2', '2 ', '2\n', 2, null]) {
    assert.throws(() => securityConfig({ ...environment, MESSENGER_MINIMUM_SESSION_SUITE: minimum }), String(minimum));
  }
  for (const minimum of ['1', '2']) {
    assert.throws(() => securityConfig({ MESSENGER_MINIMUM_SESSION_SUITE: minimum }));
    assert.throws(() => securityConfig({ MESSENGER_MINIMUM_SESSION_SUITE: minimum,
      MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: '11'.repeat(32) }));
  }
});

function releaseWithFrameSize(bytes) {
  const rpcs = Array.from({ length: 4 }, (_, i) => `https://rpc-${i}.example/`);
  const release = { ...migrationEnvironment, MESSENGER_ANCHOR_RPC_URLS: JSON.stringify(rpcs) };
  let remaining = bytes - Buffer.byteLength(securityConfig(release));
  assert.ok(remaining >= 0);
  for (let i = 0; i < rpcs.length && remaining > 0; i++) {
    const grow = Math.min(remaining, 2048 - rpcs[i].length);
    rpcs[i] += 'a'.repeat(grow); remaining -= grow;
  }
  assert.equal(remaining, 0);
  release.MESSENGER_ANCHOR_RPC_URLS = JSON.stringify(rpcs);
  assert.equal(Buffer.byteLength(securityConfig(release)), bytes);
  return release;
}

test('v6 complete-wire bound includes its envelope and retains old profile bounds', () => {
  const atLimit = releaseWithFrameSize(8188);
  const beyondLimit = releaseWithFrameSize(8189);
  assert.equal(Buffer.byteLength(securityConfig({ ...atLimit, MESSENGER_MINIMUM_SESSION_SUITE: '2' })), 8192);
  assert.throws(() => securityConfig({ ...beyondLimit, MESSENGER_MINIMUM_SESSION_SUITE: '2' }));
  assert.equal(Buffer.byteLength(securityConfig(releaseWithFrameSize(8192))), 8192);
});

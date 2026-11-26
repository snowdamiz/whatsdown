import assert from 'node:assert/strict';
import test from 'node:test';
import securityConfig from '../plugins/security-config.cjs';

const [service, a, b, delivery, c] = ['11', '22', '33', '44', '55'].map((byte) => byte.repeat(32));
const legacy = {
  MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: service,
  MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: a,
  MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: b,
  MESSENGER_DELIVERY_PUBLIC_KEY_HEX: delivery,
  MESSENGER_ABUSE_DIFFICULTY: '16',
};
const program = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA';
const log = '11111111111111111111111111111111';
const rpcs = ['https://rpc-1.example', 'https://rpc-2.example/key', 'https://rpc-3.example:8899'];
const full = {
  ...legacy,
  MESSENGER_WITNESSES: `witness-b:${b}:Morse;acme-1:${c}:Acme Labs;witness-a:${a}:Morse`,
  MESSENGER_ANCHOR: `${program} ${log}`,
  MESSENGER_RPC_URLS: rpcs.join(','),
  MESSENGER_RELAY_URLS: 'https://relay.example',
  MESSENGER_CREDIT_ISSUER: 'https://credits.example',
  MESSENGER_LOG_ORIGIN: 'morseapp.io/log/main',
  MESSENGER_MINIMUM_SUITE: '2',
};

test('rollout step 1: the legacy witness pins become a v2 frame for today\'s set', () => {
  const frame = securityConfig(legacy);
  assert.equal(frame, [
    '2', service, delivery, '16', '2', '2',
    `witness-a ${a} Morse`, `witness-b ${b} Morse`,
    '-', '0', '0', '-', '-', '1',
  ].join('\n'));
  // Independently: printf '%s' "morse-witness-set-v12\n2\nwitness-a … Morse\nwitness-b … Morse" | shasum -a 256
  assert.deepEqual(securityConfig.witnessSet(frame), {
    setId: 'b51e1e61e569d854d3efa8f247b328e3ad6e0074d5a8b7c18757188cc01b83b0',
    profile: 'Bootstrap', k: 2, n: 2,
  });
  assert.equal(securityConfig(Object.fromEntries(Object.keys(legacy).map((name) => [name, undefined]))), undefined);
});

test('a pinned set is sorted, gets a computed majority threshold and carries every v2 field', () => {
  const frame = securityConfig(full);
  assert.equal(frame, [
    '2', service, delivery, '16', '2', '3',
    `acme-1 ${c} Acme Labs`, `witness-a ${a} Morse`, `witness-b ${b} Morse`,
    `${program} ${log}`, '3', ...rpcs, '1', 'https://relay.example',
    'https://credits.example', 'morseapp.io/log/main', '2',
  ].join('\n'));
  assert.equal(securityConfig.witnessSet(frame).setId,
    '4167a85c60510f477026a8e4db7232ac7f613a7676a0e5be655894bb48f6b9ac');
  // Empty values (unset GitHub variables) mean "not configured".
  assert.equal(securityConfig({ ...legacy, MESSENGER_WITNESSES: '', MESSENGER_ANCHOR: '', MESSENGER_RPC_URLS: '' }),
    securityConfig(legacy));
});

test('the trust profile counts witnesses labelled exactly Morse against the threshold', () => {
  const witnesses = (labels) => ({
    ...legacy,
    MESSENGER_WITNESSES: labels.map((label, index) => `w${index}:${String(index + 1).padStart(2, '0').repeat(32)}:${label}`).join(';'),
  });
  const profile = (labels) => securityConfig.witnessSet(securityConfig(witnesses(labels))).profile;
  assert.equal(profile(['Morse', 'Morse', 'Morse', 'Ann', 'Bo']), 'Bootstrap');
  assert.equal(profile(['Morse', 'Morse', 'Ann', 'Bo', 'Cy']), 'Transitional');
  assert.equal(profile(['Morse', 'morse', 'Ann']), 'Open');
  assert.equal(securityConfig.witnessSet(securityConfig(witnesses(['Ann']))).k, 1);
});

test('frames the core would reject are refused with the variable at fault', () => {
  const witness = (id, key, label = 'Morse') => `${id}:${key}:${label}`;
  const many = (count, label = 'L'.repeat(48)) => Array.from({ length: count }, (_, index) =>
    witness(`${'w'.repeat(62)}${String(index).padStart(2, '0')}`, index.toString(16).padStart(64, '0').replace(/^0/, 'a'), label)).join(';');
  for (const [changes, pattern] of [
    [{ MESSENGER_DELIVERY_PUBLIC_KEY_HEX: '00'.repeat(32) }, /MESSENGER_DELIVERY_PUBLIC_KEY_HEX/],
    [{ MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: 'AB'.repeat(32) }, /MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX/],
    [{ MESSENGER_ABUSE_DIFFICULTY: '08' }, /MESSENGER_ABUSE_DIFFICULTY/],
    [{ MESSENGER_WITNESSES: undefined, MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: a }, /MESSENGER_WITNESS/],
    [{ MESSENGER_WITNESSES: undefined, MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: undefined }, /MESSENGER_WITNESS_A_PUBLIC_KEY_HEX/],
    [{ MESSENGER_WITNESSES: `${witness('a', a)};${witness('a', b)}` }, /MESSENGER_WITNESSES.*unique/],
    [{ MESSENGER_WITNESSES: `${witness('a', a)};${witness('b', a)}` }, /MESSENGER_WITNESSES.*unique/],
    [{ MESSENGER_WITNESSES: witness('Witness-A', a) }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_WITNESSES: witness('a'.repeat(65), a) }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_WITNESSES: witness('a', a, ' Morse') }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_WITNESSES: witness('a', a, 'Mörse') }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_WITNESSES: witness('a', a, 'L'.repeat(49)) }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_WITNESSES: `${witness('a', a)};` }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_WITNESSES: many(17, 'L') }, /MESSENGER_WITNESSES/],
    [{ MESSENGER_ANCHOR: `${program} ${log.replace('1', '0')}` }, /MESSENGER_ANCHOR/],
    [{ MESSENGER_ANCHOR: `${program} 1111` }, /MESSENGER_ANCHOR/],
    [{ MESSENGER_ANCHOR: `${program}  ${log}` }, /MESSENGER_ANCHOR/],
    [{ MESSENGER_RPC_URLS: '' }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: rpcs.slice(0, 2).join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: Array.from({ length: 9 }, (_, index) => `https://rpc-${index}.example`).join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: [...rpcs, rpcs[0]].join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_ANCHOR: '-' }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: [...rpcs, 'http://rpc-4.example'].join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: [...rpcs, 'https://user@rpc-4.example'].join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: [...rpcs, 'https://rpc-4.example/?key=1'].join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RPC_URLS: [...rpcs, 'https://rpc-4.example/#x'].join(',') }, /MESSENGER_RPC_URLS/],
    [{ MESSENGER_RELAY_URLS: 'https://relay.example/path' }, /MESSENGER_RELAY_URLS/],
    [{ MESSENGER_RELAY_URLS: Array.from({ length: 9 }, (_, index) => `https://r${index}.example`).join(',') }, /MESSENGER_RELAY_URLS/],
    [{ MESSENGER_CREDIT_ISSUER: 'https://Credits.example' }, /MESSENGER_CREDIT_ISSUER/],
    [{ MESSENGER_LOG_ORIGIN: 'morseapp.io/log main' }, /MESSENGER_LOG_ORIGIN/],
    [{ MESSENGER_MINIMUM_SUITE: '3' }, /MESSENGER_MINIMUM_SUITE/],
    [{ MESSENGER_WITNESSES: many(16), MESSENGER_RPC_URLS: Array.from({ length: 8 }, (_, index) =>
      `https://rpc-${index}.example/${'p'.repeat(200)}`).join(',') }, /4,096/],
  ]) {
    assert.throws(() => securityConfig({ ...full, ...changes }), pattern, JSON.stringify(changes));
  }
  assert.ok(Buffer.byteLength(securityConfig({ ...full, MESSENGER_WITNESSES: many(16) })) <= 4096);
});

// §22 M3 (protocol/ohttp-v1.md): the OHTTP gateway key and the relay a build
// sends its stateless requests through, as one last line.
test('the OHTTP gateway key and relay are pinned as an RFC 9458 key configuration and an origin', () => {
  const gateway = '31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155';
  const frame = securityConfig({ ...full, MESSENGER_OHTTP_KEY: `1:${gateway}`, MESSENGER_OHTTP_RELAY: 'https://edge.example' });
  assert.equal(frame.split('\n').at(-1), `010020${gateway}000400010003 https://edge.example`);
  assert.equal(frame, `${securityConfig(full)}\n010020${gateway}000400010003 https://edge.example`);
  // Development builds may pin the edge on a loopback or private address.
  assert.match(securityConfig({ ...full, MESSENGER_OHTTP_KEY: `7:${gateway}`, MESSENGER_OHTTP_RELAY: 'http://10.0.2.2:18087' }),
    /\n070020[0-9a-f]{64}000400010003 http:\/\/10\.0\.2\.2:18087$/);
  for (const [changes, pattern] of [
    [{ MESSENGER_OHTTP_KEY: `1:${gateway}` }, /MESSENGER_OHTTP_RELAY/],
    [{ MESSENGER_OHTTP_RELAY: 'https://edge.example' }, /MESSENGER_OHTTP_KEY/],
    [{ MESSENGER_OHTTP_KEY: `256:${gateway}`, MESSENGER_OHTTP_RELAY: 'https://edge.example' }, /MESSENGER_OHTTP_KEY/],
    [{ MESSENGER_OHTTP_KEY: `01:${gateway}`, MESSENGER_OHTTP_RELAY: 'https://edge.example' }, /MESSENGER_OHTTP_KEY/],
    [{ MESSENGER_OHTTP_KEY: `1:${'00'.repeat(32)}`, MESSENGER_OHTTP_RELAY: 'https://edge.example' }, /MESSENGER_OHTTP_KEY/],
    [{ MESSENGER_OHTTP_KEY: `1:${gateway}`, MESSENGER_OHTTP_RELAY: 'https://edge.example/v1/ohttp' }, /MESSENGER_OHTTP_RELAY/],
    [{ MESSENGER_OHTTP_KEY: `1:${gateway}`, MESSENGER_OHTTP_RELAY: 'http://edge.example' }, /MESSENGER_OHTTP_RELAY/],
  ]) {
    assert.throws(() => securityConfig({ ...full, ...changes }), pattern, JSON.stringify(changes));
  }
});

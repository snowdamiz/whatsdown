import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import configure from '../plugins/ohttp-config.cjs';

const network = '2\n0\nhttps://core.example\nhttps://edge.example\nhttps://objects.example\nwss://stream.example/v1/mailbox/stream\n16';
const security = 'synthetic canonical native security bytes';
const key1 = '31e1f05a740102751261153ed490fd94a675258c3b8e30b373beaabfba281550';
const key2 = '8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a';
const digest = value => createHash('sha256').update(value).digest('hex');
const pin = (key_id = 1, public_key = key1) => ({ key_id, public_key, not_before_ms: '0', not_after_ms: '18446744073709551615' });
const config = () => ({ schema_version: 1, mode: 'required', revision: '18446744073709551615', keys: [pin()] });
const encode = value => configure({ MESSENGER_OHTTP_CONFIG: JSON.stringify(value) }, network, security);

test('unconfigured builds remain unconfigured; configured default-off binds both exact parents', () => {
  assert.equal(configure({}, undefined, undefined), undefined);
  const expected = ['1', digest(network), digest(security), '1', 'off', '0'].join('\n');
  assert.equal(configure({}, network, security), expected);
  assert.equal(encode({ schema_version: 1, mode: 'off', revision: '7', keys: [] }).split('\n').slice(3).join('\n'), '7\noff\n0');
  for (const parents of [[network, undefined], [undefined, security], ['', security], [network, '']]) {
    assert.throws(() => configure({}, ...parents));
  }
  assert.throws(() => configure({ MESSENGER_OHTTP_CONFIG: JSON.stringify(config()) }, undefined, undefined));
  assert.notEqual(configure({}, network + ' ', security), expected);
  assert.notEqual(configure({}, network, security + ' '), expected);
});

test('required release pins preserve current/overlap order and exact standard single-suite wire', () => {
  const value = config(); value.keys.push(pin(255, key2));
  const rows = encode(value).split('\n');
  assert.deepEqual(rows.slice(0, 6), ['1', digest(network), digest(security), value.revision, 'required', '2']);
  const first = Buffer.from('010020' + key1 + '000400010003', 'hex').toString('base64');
  const second = Buffer.from('ff0020' + key2 + '000400010003', 'hex').toString('base64');
  assert.equal(rows[6], '0 18446744073709551615 ' + first);
  assert.equal(rows[7], '0 18446744073709551615 ' + second);
  assert.equal(Buffer.from(rows[6].split(' ')[2], 'base64').length, 41);
  assert.equal(Buffer.from(encode({ ...config(), keys: [pin(0)] }).split('\n')[6].split(' ')[2], 'base64')[0], 0);
});

test('integers and validity windows are exact canonical bounded values', () => {
  for (const revision of ['0', '', '01', '-1', '+1', '1.0', '1e3', ' 1', '1\n', '18446744073709551616', 1, null]) {
    assert.throws(() => encode({ ...config(), revision }), String(revision));
  }
  for (const bad of ['', '01', '-1', '+1', '1.0', '1e3', ' 1', '18446744073709551616', 1, null]) {
    for (const field of ['not_before_ms', 'not_after_ms']) assert.throws(() => encode({ ...config(), keys: [{ ...pin(), [field]: bad }] }));
  }
  for (const [start, end] of [['0', '0'], ['2', '1'], ['18446744073709551615', '18446744073709551615']]) {
    assert.throws(() => encode({ ...config(), keys: [{ ...pin(), not_before_ms: start, not_after_ms: end }] }));
  }
  assert.doesNotThrow(() => encode({ ...config(), keys: [{ ...pin(), not_before_ms: '18446744073709551614' }] }));
});

test('whole collection validation refuses duplicates, unsupported shapes and invalid public encodings', () => {
  for (const keys of [[], [pin(), pin(1, key2)], [pin(), pin(2, key1)], [pin(), pin(2, key2), pin(3)], null, {}]) {
    assert.throws(() => encode({ ...config(), keys }));
  }
  for (const key_id of [-1, 256, 1.5, '1', null]) assert.throws(() => encode({ ...config(), keys: [pin(key_id)] }));
  for (const public_key of ['', '00'.repeat(32), key1.toUpperCase(), key1.slice(2), key1 + '00', 'gg'.repeat(32), null]) {
    assert.throws(() => encode({ ...config(), keys: [pin(1, public_key)] }));
  }
  for (const value of [null, [], {}, { ...config(), schema_version: 2 }, { ...config(), mode: 'fallback' },
    { ...config(), mode: 'off' }, { ...config(), origin: 'https://evil.example' },
    { ...config(), keys: [{ ...pin(), private_key: 'unused' }] },
    { ...config(), keys: [pin(), { ...pin(2, key2), extra: true }] }]) assert.throws(() => encode(value));
});

test('configuration and parent bounds refuse before unbounded parsing or output', () => {
  for (const input of ['{', ' '.repeat(4097), {}, 1, null]) {
    assert.throws(() => configure({ MESSENGER_OHTTP_CONFIG: input }, network, security));
  }
  assert.throws(() => configure({}, 'n'.repeat(8245), security));
  assert.throws(() => configure({}, network, 's'.repeat(8193)));
  assert.throws(() => configure({}, Buffer.from(network), security));
  assert.throws(() => configure({}, network, Buffer.from(security)));
  assert.ok(Buffer.byteLength(encode({ ...config(), keys: [pin(), pin(255, key2)] })) <= 600);
});


test('OHTTP companion binds the whole floor envelope, not only the embedded old profile', () => {
  const wrapped = `6\n2\n${security}`;
  const previous = configure({}, network, security).split('\n');
  const next = configure({}, network, wrapped).split('\n');
  assert.equal(next[1], previous[1]);
  assert.equal(next[2], digest(wrapped));
  assert.notEqual(next[2], previous[2]);
  assert.deepEqual(next.slice(3), previous.slice(3));
});

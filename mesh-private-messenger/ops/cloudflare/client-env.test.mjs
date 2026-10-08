import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const hex = (byte) => byte.repeat(32);
const seeds = [hex('a1'), hex('a2'), hex('a3'), hex('a4')];

test('client.env gets the witness set pins from public keys only, and sources back exactly', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'morse-client-env-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'client.env');
  const original = [
    '# Public deployment configuration. Source before building a native client.',
    'export EXPO_PUBLIC_MESSENGER_BASE_URL=https://messenger.example',
    'export MESSENGER_ABUSE_DIFFICULTY=16',
    `export MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX=${hex('10')}`,
    `export MESSENGER_WITNESS_A_PUBLIC_KEY_HEX=${hex('22')}`,
    `export MESSENGER_WITNESS_B_PUBLIC_KEY_HEX=${hex('33')}`,
    `export MESSENGER_DELIVERY_PUBLIC_KEY_HEX=${hex('44')}`,
    '',
    '# Push additionally requires MESSENGER_EXPO_PROJECT_ID and this public key:',
    '',
  ].join('\n');
  writeFileSync(file, original);
  const secrets = join(dir, 'secrets.json');
  writeFileSync(secrets, JSON.stringify({
    MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX: seeds[0],
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: hex('11'),
    MESSENGER_WITNESS_A_SIGNING_SEED_HEX: seeds[1],
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: hex('22'),
    MESSENGER_WITNESS_B_SIGNING_SEED_HEX: seeds[2],
    MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: hex('33'),
    MESSENGER_DELIVERY_SEALING_SEED_HEX: seeds[3],
    MESSENGER_DELIVERY_PUBLIC_KEY_HEX: hex('44'),
  }));
  const outside = join(dir, 'outside.json');
  writeFileSync(outside, JSON.stringify({ MESSENGER_ACME_1_PUBLIC_KEY_HEX: hex('55') }));
  const run = (...args) => spawnSync(process.execPath,
    [fileURLToPath(new URL('client-env.mjs', import.meta.url)), '--env', file, '--keys', secrets, '--keys', outside, ...args],
    { encoding: 'utf8' });
  const sourced = (name) => spawnSync('sh', ['-c', `. "${file}" && printf %s "$${name}"`], { encoding: 'utf8' }).stdout;

  const first = run('witness-a:Morse', 'witness-b:Morse');
  assert.equal(first.status, 0, first.stderr);
  // The bootstrap set of rollout step 1 (set_id hand-computed in apps/mobile/scripts/security-config.test.mjs
  // for keys 22…/33…).
  assert.match(first.stdout, /set_id b51e1e61e569d854d3efa8f247b328e3ad6e0074d5a8b7c18757188cc01b83b0, Bootstrap, 2 of 2/);
  assert.equal(sourced('MESSENGER_WITNESSES'), `witness-a:${hex('22')}:Morse;witness-b:${hex('33')}:Morse`);
  assert.equal(sourced('MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX'), hex('11'));

  const second = run('witness-a:Morse', 'witness-b:Morse', "acme-1:Acme's Lab");
  assert.equal(second.status, 0, second.stderr);
  assert.match(second.stdout, /Bootstrap, 2 of 3/);
  assert.equal(sourced('MESSENGER_WITNESSES'),
    `witness-a:${hex('22')}:Morse;witness-b:${hex('33')}:Morse;acme-1:${hex('55')}:Acme's Lab`);
  const written = readFileSync(file, 'utf8');
  assert.equal(written.match(/MESSENGER_WITNESSES=/g).length, 1);
  assert.ok(written.startsWith(original.split('\n')[0]) && written.includes('# Push additionally requires'));
  for (const seed of seeds) {
    assert.ok(![written, first.stdout, first.stderr, second.stdout, second.stderr].some((text) => text.includes(seed)));
  }

  for (const args of [['witness-a:Morse', 'witness-z:Morse'], ['witness-a:Morse', 'witness-a:Other'], ['witness-a:']]) {
    const refused = run(...args);
    assert.notEqual(refused.status, 0, args.join(' '));
    assert.equal(readFileSync(file, 'utf8'), written);
  }
});

test('client.env pins the OHTTP gateway key from its public half and the edge as the relay', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'morse-client-env-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const file = join(dir, 'client.env');
  writeFileSync(file, [
    'export EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL=https://edge.example/',
    'export MESSENGER_ABUSE_DIFFICULTY=16',
    `export MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX=${hex('10')}`,
    `export MESSENGER_DELIVERY_PUBLIC_KEY_HEX=${hex('44')}`,
  ].join('\n'));
  const gateway = '31e1f05a740102115220e9af918f738674aec95f54db6e04eb705aae8e798155';
  const secrets = join(dir, 'secrets.json');
  writeFileSync(secrets, JSON.stringify({
    MESSENGER_WITNESS_A_PUBLIC_KEY_HEX: hex('22'), MESSENGER_WITNESS_B_PUBLIC_KEY_HEX: hex('33'),
    MESSENGER_OHTTP_GATEWAY_KEY_ID: '2', MESSENGER_OHTTP_GATEWAY_SEED_HEX: seeds[0],
    MESSENGER_OHTTP_GATEWAY_PUBLIC_KEY_HEX: gateway,
  }));
  const result = spawnSync(process.execPath,
    [fileURLToPath(new URL('client-env.mjs', import.meta.url)), '--env', file, '--keys', secrets, 'witness-a:Morse', 'witness-b:Morse'],
    { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  const sourced = (name) => spawnSync('sh', ['-c', `. "${file}" && printf %s "$${name}"`], { encoding: 'utf8' }).stdout;
  assert.equal(sourced('MESSENGER_OHTTP_KEY'), `2:${gateway}`);
  assert.equal(sourced('MESSENGER_OHTTP_RELAY'), 'https://edge.example');
  assert.ok(!readFileSync(file, 'utf8').includes(seeds[0]) && !result.stdout.includes(seeds[0]));
});

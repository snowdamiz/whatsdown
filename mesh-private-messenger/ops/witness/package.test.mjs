import assert from 'node:assert/strict';
import test from 'node:test';
import { packageArguments, relayArchiveArguments, verifyImageRevisions, verifyServicesImage } from './package.mjs';
const config = { MORSE_SERVICES_IMAGE: `ghcr.io/example/morse@sha256:${'a'.repeat(64)}`,
  MORSE_REVISION: 'b'.repeat(40), MESH_LANG_REVISION: 'c'.repeat(40), SOURCE_DATE_EPOCH: '1791490000' };
test('witness packaging requires immutable inputs and a reproducible creation time', () => {
  const args = packageArguments(config, '/proof/witness');
  assert.ok(args.includes(`MORSE_SERVICES_IMAGE=${config.MORSE_SERVICES_IMAGE}`));
  assert.ok(args.includes(`SOURCE_DATE_EPOCH=${config.SOURCE_DATE_EPOCH}`));
  for (const [key, value] of [['MORSE_SERVICES_IMAGE', 'ghcr.io/example/morse:latest'],
    ['MORSE_REVISION', 'main'], ['MESH_LANG_REVISION', 'latest'], ['SOURCE_DATE_EPOCH', 'now']]) {
    assert.throws(() => packageArguments({ ...config, [key]: value }, '/proof/witness'));
  }
});

test('a witness package cannot relabel another service image as the reviewed revision', () => {
  const labels = { 'org.opencontainers.image.revision': config.MORSE_REVISION, 'org.morse.mesh-revision': config.MESH_LANG_REVISION };
  verifyImageRevisions(labels, config);
  assert.throws(() => verifyImageRevisions({ ...labels, 'org.morse.mesh-revision': 'd'.repeat(40) }, config));
  assert.throws(() => verifyImageRevisions({}, config));
});

test('revision verification inspects the packaged platform even when the host variant has matching labels', () => {
  const wanted = { 'org.opencontainers.image.revision': config.MORSE_REVISION, 'org.morse.mesh-revision': config.MESH_LANG_REVISION };
  const inspect = (command, args) => {
    assert.equal(command, 'docker');
    assert.equal(args.at(-1), config.MORSE_SERVICES_IMAGE);
    return JSON.stringify(args[args.indexOf('--platform') + 1] === 'linux/amd64'
      ? { ...wanted, 'org.morse.mesh-revision': 'd'.repeat(40) } : wanted);
  };
  assert.throws(() => verifyServicesImage(config, inspect), /does not match/);
  verifyServicesImage(config, () => JSON.stringify(wanted));
});


test('the relay archive comes from the same immutable image without starting a networked signer',()=>{
  const args=relayArchiveArguments(config);
  assert.equal(args[0],'run');assert.ok(args.includes('--read-only'));assert.ok(args.includes('--network=none'));
  assert.ok(args.includes('--cap-drop=ALL'));assert.ok(args.includes('--security-opt=no-new-privileges'));
  assert.equal(args[args.indexOf('--entrypoint')+1],'/bin/tar');assert.ok(args.includes(config.MORSE_SERVICES_IMAGE));
  assert.ok(args.includes(`--mtime=@${config.SOURCE_DATE_EPOCH}`));assert.ok(args.includes('--sort=name'));assert.ok(args.includes('--owner=0'));
  assert.deepEqual(args.slice(-2),['morse-relay','morse-fork-verifier']);
  assert.throws(()=>relayArchiveArguments({...config,MORSE_SERVICES_IMAGE:'unreviewed:latest'}),/digest/);
});

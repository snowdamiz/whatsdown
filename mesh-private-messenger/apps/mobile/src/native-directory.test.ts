import assert from 'node:assert/strict';
import test from 'node:test';
import { registerNativeDirectory, synchronizeNativePrekeys, parseDirectoryRegistration, isDirectoryRegistrationRefused, resolveNativeDirectory } from './native-directory.ts';
const registered = Uint8Array.of(1, 68, 82, 71, 0, 64, 0);
test('directory and prekey adapters pass only the native database path', async () => {
  const seen: Uint8Array[] = [];
  const invoke = async (bytes: Uint8Array) => { seen.push(bytes); return registered; };
  assert.deepEqual(await registerNativeDirectory('/native/мorse.db', invoke), { activePrekeys: 64, removalKind: 0 });
  assert.deepEqual(seen, [new TextEncoder().encode('/native/мorse.db')]);
  assert.equal(await synchronizeNativePrekeys('/native/morse.db', async bytes => {
    assert.deepEqual(bytes, new TextEncoder().encode('/native/morse.db'));
    return Uint8Array.of(1, 68, 80, 75, 0, 64);
  }), 64);
});
test('directory status accepts only exact version/count and verified removal combinations', () => {
  for (const kind of [1, 2, 3]) assert.deepEqual(parseDirectoryRegistration(Uint8Array.of(1,68,82,71,0,0,kind)), { activePrekeys: 0, removalKind: kind });
  for (const bad of [registered.slice(0,6), new Uint8Array([...registered,0]), Uint8Array.of(2,68,82,71,0,64,0),
    Uint8Array.of(1,68,82,71,0,63,0), Uint8Array.of(1,68,82,71,0,64,1), Uint8Array.of(1,68,82,71,0,0,4)]) {
    assert.throws(() => parseDirectoryRegistration(bad), /invalid_directory_status/);
  }
});
test('prekey failures and malformed native replies cannot be treated as completed refill', async () => {
  for (const bad of [Uint8Array.of(1,68,80,75,0,63), Uint8Array.of(2,68,80,75,0,64), new Uint8Array(5)]) {
    await assert.rejects(synchronizeNativePrekeys('/native/morse.db', async () => bad), /invalid_prekey_status/);
  }
  await assert.rejects(registerNativeDirectory('/native/morse.db', async () => { throw new Error('untrusted_credit_signup_policy'); }), /untrusted_credit_signup_policy/);
  await assert.rejects(synchronizeNativePrekeys('/native/morse.db', async () => { throw new Error('prekey_http_503'); }), /prekey_http_503/);
});
test('registration refusal survives native error framing without matching other failures', () => {
  for (const error of [new Error('registration_refused'), new Error('Error: registration_refused'), 'Error: Error: registration_refused']) {
    assert.equal(isDirectoryRegistrationRefused(error), true);
  }
  for (const error of [new Error('directory_http_503'), 'registration_refused_extra', 'server registration_refused', null]) {
    assert.equal(isDirectoryRegistrationRefused(error), false);
  }
});

test('resolution passes only lookup input and accepts only bounded native authenticated output', async () => {
  assert.deepEqual(await resolveNativeDirectory('/native/morse.db', '@' + '01'.repeat(32), async input => {
    const expected = new TextEncoder().encode('/native/morse.db');
    const lookup = new TextEncoder().encode('@' + '01'.repeat(32));
    const frame = (bytes: Uint8Array) => [0,0,0,bytes.length,...bytes];
    assert.deepEqual(input, Uint8Array.from([...frame(expected), ...frame(lookup)]));
    return Uint8Array.of(1,2,3);
  }), Uint8Array.of(1,2,3));
  for (const size of [0,305261]) {
    await assert.rejects(resolveNativeDirectory('/native/morse.db','alice', async () => new Uint8Array(size)), /invalid_directory_device_set/);
  }
  await assert.rejects(resolveNativeDirectory('/native/morse.db','alice', async () => { throw Error('transparency_stale'); }), /transparency_stale/);
});

test('onboarding refusal recognizes only canonical native application-error envelopes', async () => {
  const { isDirectoryRegistrationRefused } = await import('./native-directory.ts');
  for (const message of ['registration_refused', 'Error: registration_refused', 'Mesh 9: registration_refused', 'Mesh library call failed (status=9): registration_refused']) {
    assert.equal(isDirectoryRegistrationRefused(new Error(message)), true, message);
  }
  for (const message of ['Mesh 4: registration_refused', 'registration_refused: unavailable', 'not registration_refused']) {
    assert.equal(isDirectoryRegistrationRefused(new Error(message)), false, message);
  }
});

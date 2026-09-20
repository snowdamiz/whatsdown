import assert from 'node:assert/strict';

// Values come from the same run's reusable CI job, never a branch's latest run.
const env = process.env;
assert.equal(env.VERIFICATION_RESULT, 'success', 'Candidate verification must succeed');
for (const [candidate, verified] of [
  ['GITHUB_SHA', 'VERIFIED_MORSE_REVISION'],
  ['MESH_LANG_REVISION', 'VERIFIED_MESH_REVISION'],
]) {
  assert.match(env[candidate] ?? '', /^[a-f0-9]{40}$/, `${candidate} must be a full commit SHA`);
  assert.equal(env[verified], env[candidate], `${candidate} was not verified`);
}
console.log(`C8 verified Morse ${env.GITHUB_SHA}, Mesh ${env.MESH_LANG_REVISION}`);

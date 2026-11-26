import assert from 'node:assert/strict';
import test from 'node:test';
import { latestReleaseTag, tagCommit } from './mesh-release.mjs';

const redirectedTo = (url, ok = true) => async () => ({ ok, url });

test('the latest Mesh release is where GitHub redirects releases/latest', async () => {
  assert.equal(
    await latestReleaseTag(redirectedTo('https://github.com/snowdamiz/mesh-lang/releases/tag/v0.1.3')),
    'v0.1.3',
  );
  // With no published release GitHub lands on the release list instead.
  await assert.rejects(
    latestReleaseTag(redirectedTo('https://github.com/snowdamiz/mesh-lang/releases')),
    /No published Mesh release/,
  );
  await assert.rejects(
    latestReleaseTag(redirectedTo('https://github.com/snowdamiz/mesh-lang/releases/tag/v0.1.3', false)),
    /No published Mesh release/,
  );
});

test("a release commit is an annotated tag's target, or a lightweight tag itself", () => {
  const annotated = `${'a'.repeat(40)}\trefs/tags/v0.1.3\n${'b'.repeat(40)}\trefs/tags/v0.1.3^{}\n`;
  assert.equal(tagCommit(annotated, 'v0.1.3'), 'b'.repeat(40));
  assert.equal(tagCommit(`${'c'.repeat(40)}\trefs/tags/v0.1.3\n`, 'v0.1.3'), 'c'.repeat(40));
  assert.throws(() => tagCommit('', 'v0.1.3'), /has no commit/);
  assert.throws(() => tagCommit(`${'d'.repeat(40)}\trefs/tags/v0.1.30\n`, 'v0.1.3'), /has no commit/);
});

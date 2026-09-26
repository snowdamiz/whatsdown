import assert from 'node:assert/strict';
import test from 'node:test';
import { changed } from './release-changes.mjs';

const only = (...names) => ({
  backend: names.includes('backend'),
  landing: names.includes('landing'),
  mobile: names.includes('mobile'),
  desktop: names.includes('desktop'),
});

test('a landing page change deploys only the landing page', () => {
  assert.deepEqual(changed(['mesh-private-messenger/apps/landing/index.html']), only('landing'));
});

test('documentation deploys nothing, even inside a deployed directory', () => {
  assert.deepEqual(
    changed(['README.md', 'mesh-private-messenger/protocol/witness-network-v1.md', 'mesh-private-messenger/apps/mobile/README.md']),
    only(),
  );
});

test('the shared protocol package rebuilds everything that embeds it', () => {
  assert.deepEqual(
    changed(['mesh-private-messenger/packages/messenger-protocol/src/wire.mpl']),
    only('backend', 'mobile', 'desktop'),
  );
  // Every build compiles with the Mesh release this script resolves.
  assert.deepEqual(changed(['mesh-private-messenger/scripts/mesh-release.mjs']), only('backend', 'mobile', 'desktop'));
});

test('the mobile app is also the desktop app', () => {
  assert.deepEqual(changed(['mesh-private-messenger/apps/mobile/src/App.tsx']), only('mobile', 'desktop'));
  assert.deepEqual(changed(['mesh-private-messenger/scripts/eas-build-native.sh']), only('mobile'));
  assert.deepEqual(changed(['mesh-private-messenger/apps/desktop/src-tauri/src/main.rs']), only('desktop'));
});

test('backend services and their deploy tooling deploy the backend', () => {
  assert.deepEqual(
    changed(['mesh-private-messenger/services/privacy-edge/main.mpl', 'mesh-private-messenger/ops/cloudflare/worker.mjs']),
    only('backend'),
  );
  assert.deepEqual(changed(['mesh-private-messenger/packages/service-jobs/jobs.mpl']), only('backend'));
});

test('a release workflow change alone deploys nothing; run it by hand to redeploy', () => {
  assert.deepEqual(
    changed(['.github/workflows/backend-release.yml', '.github/workflows/mobile-release.yml', '.github/workflows/desktop-release.yml']),
    only(),
  );
  // The landing page links to the witness application form.
  assert.deepEqual(changed(['.github/ISSUE_TEMPLATE/witness-application.yml']), only('landing'));
});

test('a prefix match is a whole directory, not a name that starts the same', () => {
  assert.deepEqual(changed(['mesh-private-messenger/apps/landing-old/index.html']), only());
});

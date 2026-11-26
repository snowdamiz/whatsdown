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
  assert.deepEqual(changed(['apps/landing/index.html']), only('landing'));
});

test('documentation deploys nothing, even inside a deployed directory', () => {
  assert.deepEqual(
    changed(['README.md', 'protocol/witness-network-v1.md', 'apps/mobile/README.md']),
    only(),
  );
});

test('the shared protocol package rebuilds everything that embeds it', () => {
  assert.deepEqual(
    changed(['packages/messenger-protocol/src/wire.mpl']),
    only('backend', 'mobile', 'desktop'),
  );
  // Every build compiles with the Mesh release this script resolves.
  assert.deepEqual(changed(['scripts/mesh-release.mjs']), only('backend', 'mobile', 'desktop'));
});

test('the mobile app is also the desktop app', () => {
  assert.deepEqual(changed(['apps/mobile/src/App.tsx']), only('mobile', 'desktop'));
  assert.deepEqual(changed(['scripts/eas-build-native.sh']), only('mobile'));
  assert.deepEqual(changed(['apps/desktop/src-tauri/src/main.rs']), only('desktop'));
});

test('the wallet core is linked into both apps', () => {
  assert.deepEqual(changed(['packages/wallet-core/src/tx.rs']), only('mobile', 'desktop'));
  assert.deepEqual(changed(['packages/wallet-core/Cargo.lock']), only('mobile', 'desktop'));
});

test('the credits package is linked into the services and both apps', () => {
  assert.deepEqual(
    changed(['packages/messenger-credits/credits/credit_crypto.mpl']),
    only('backend', 'mobile', 'desktop'),
  );
  assert.deepEqual(changed(['services/credit-issuer/main.mpl']), only('backend'));
  // So is the OHTTP package: the gateway in the directory, the client in the core.
  assert.deepEqual(changed(['packages/messenger-ohttp/privacy/ohttp.mpl']), only('backend', 'mobile', 'desktop'));
});

test('what operators build and run themselves deploys nothing', () => {
  assert.deepEqual(
    changed([
      'programs/morse-judge/src/lib.rs',
      'ops/relay/relay.mjs',
      'ops/witness/build.sh',
      'ops/drills/local.mjs',
      'ops/acceptance/run.mjs',
      'clients/monitor/main.mpl',
    ]),
    only(),
  );
});

test('backend services and their deploy tooling deploy the backend', () => {
  assert.deepEqual(
    changed(['services/privacy-edge/main.mpl', 'ops/cloudflare/worker.mjs']),
    only('backend'),
  );
  assert.deepEqual(changed(['packages/service-jobs/jobs.mpl']), only('backend'));
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
  assert.deepEqual(changed(['apps/landing-old/index.html']), only());
});

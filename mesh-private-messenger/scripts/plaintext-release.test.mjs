import assert from 'node:assert/strict';
import test from 'node:test';
import { captureNativeInputs, finalizeNativeInputs, easBuildIdentity, evidenceConfigured, discoverEasApplicationArchive, retrieveEasEvidence } from './plaintext-release.mjs';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { disclosureSites, writePlaintextBuildEvidence } from '../ops/plaintext/report.mjs';

const env = { GITHUB_SHA: 'a'.repeat(40), MESH_LANG_REVISION: 'b'.repeat(40), GITHUB_REPOSITORY: 'example/morse',
  EXPO_PROJECT_ID: 'c'.repeat(8) + '-1111-2222-3333-' + 'd'.repeat(12), PROFILE: 'production', PLATFORM: 'android' };
const build = { id: '12345678-1234-1234-1234-123456789abc', status: 'FINISHED', platform: 'ANDROID',
  buildProfile: 'production', gitCommitHash: env.GITHUB_SHA, app: { id: env.EXPO_PROJECT_ID } };

test('EAS evidence is bound to one exact finished build, project, platform, profile and source', () => {
  const identity = easBuildIdentity(build, env, build.id);
  assert.equal(identity.build_id, build.id);
  for (const change of [ { id: '87654321-1234-1234-1234-123456789abc' }, { status: 'IN_PROGRESS' },
    { platform: 'IOS' }, { buildProfile: 'staging' }, { gitCommitHash: 'c'.repeat(40) }, { app: { id: 'another-project' } } ]) {
    assert.throws(() => easBuildIdentity({ ...build, ...change }, env, build.id), /EAS/);
  }
  assert.throws(() => easBuildIdentity([build, build], env, build.id));
});

test('unconfigured legacy EAS flow stays explicit; partial evidence configuration is refused', () => {
  const pkg = { scripts: {} };
  const config = { build: { production: {} } };
  assert.equal(evidenceConfigured(pkg, config, 'production'), false);
  config.build.production.env = { MORSE_PLAINTEXT_EVIDENCE: '1' };
  assert.throws(() => evidenceConfigured(pkg, config, 'production'), /partial/);
  pkg.scripts['eas-build-on-success'] = 'node ../../scripts/plaintext-release.mjs worker-success';
  config.build.production.buildArtifactPaths = ['plaintext-release'];
  assert.equal(evidenceConfigured(pkg, config, 'production'), true);
  config.build.production.android = { env: { MORSE_PLAINTEXT_EVIDENCE: '0' } };
  assert.throws(() => evidenceConfigured(pkg, config, 'production', 'android'), /partial/);
});

test('capture retains pre-sign bytes and finalization binds final package and post-sign bytes', async t => {
  const root = await mkdtemp(join(tmpdir(), 'morse-release-capture-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const release = easBuildIdentity(build, env, build.id);
  const paths = Object.fromEntries(['compiler', 'artifact', 'report', 'review', 'evidence', 'package'].map(key => [key, join(root, key)]));
  const report = { schema_version: 1, policy: 'plaintext-v1', compiler_version: '0.1.8', modules: [
    { module: 'Mobile.Proof', file: 'proof.mpl', source_sha256: 'ab'.repeat(32), sites: [
      { kind: 'display', reason: 'local rendering', start: 1, end: 4, line: 1, column: 1 },
    ] },
  ] };
  await writeFile(paths.report, JSON.stringify(report));
  await writeFile(paths.review, JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: disclosureSites(report) }));
  await writeFile(paths.compiler, 'pinned compiler'); await writeFile(paths.artifact, 'compiler output');
  await writePlaintextBuildEvidence({ ...paths, output: paths.evidence });
  const input = join(root, 'capture');
  await captureNativeInputs({ release, review: paths.review, targets: [{ ...paths, target: 'aarch64-linux-android' }] }, input);
  await writeFile(paths.artifact, 'signed native input to packaging');
  await writeFile(paths.package, 'one actual package');
  const result = await finalizeNativeInputs(input, join(root, 'bundle'), [{ name: 'App.aab', path: paths.package }], release);
  assert.notEqual(result.targets[0].artifact_sha256, result.targets[0].packaged_artifact_sha256);
  assert.equal(await readFile(join(root, 'bundle', result.targets[0].artifact), 'utf8'), 'compiler output');
  await assert.rejects(finalizeNativeInputs(input, join(root, 'other'), [], release), /package/);
  await assert.rejects(finalizeNativeInputs(input, join(root, 'wrong-source'), [{ name: 'App.aab', path: paths.package }], { ...release, source_revision: 'c'.repeat(40) }), /identity/);
});

test('actual custom-artifact tar retrieval verifies one EAS package across both Android targets', async t => {
  const root = await mkdtemp(join(tmpdir(), 'morse-eas-retrieval-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const release = easBuildIdentity(build, env, build.id);
  const paths = Object.fromEntries(['compiler', 'artifact', 'report', 'review', 'evidence', 'package'].map(key => [key, join(root, key)]));
  const report = { schema_version: 1, policy: 'plaintext-v1', compiler_version: '0.1.8', modules: [
    { module: 'Mobile.Sample', file: 'sample.mpl', source_sha256: 'ab'.repeat(32), sites: [] },
  ] };
  await writeFile(paths.report, JSON.stringify(report));
  await writeFile(paths.review, JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: [] }));
  await writeFile(paths.compiler, 'owned fake compiler fixture, never executed');
  await writeFile(paths.artifact, 'owned native fixture');
  await writeFile(paths.package, 'exact owned application package');
  await writePlaintextBuildEvidence({ ...paths, output: paths.evidence });
  await captureNativeInputs({ release, review: paths.review, targets: ['aarch64-linux-android', 'x86_64-linux-android'].map(target => ({ ...paths, target })) }, join(root, 'capture'));
  await mkdir(join(root, 'artifact-root'));
  await finalizeNativeInputs(join(root, 'capture'), join(root, 'artifact-root/plaintext-release'), [{ name: 'App.aab', path: paths.package }], release);
  // Unrelated uploaded artifact content must never be retained for publication.
  await writeFile(join(root, 'artifact-root/unrelated-secret.fixture'), 'not a release deliverable');
  const archive = join(root, 'custom-artifacts.tar.gz');
  const tar = spawnSync('tar', ['-czf', archive, '-C', join(root, 'artifact-root'), 'plaintext-release', 'unrelated-secret.fixture'], { env: { ...process.env, COPYFILE_DISABLE: '1' } });
  assert.equal(tar.status, 0);
  const downloaded = { ...build, artifacts: { buildArtifactsUrl: 'https://artifacts.example/custom', applicationArchiveUrl: 'https://artifacts.example/app' } };
  const fetch_ = async url => new Response(await readFile(url.endsWith('/custom') ? archive : paths.package));
  const output = join(root, 'retrieved');
  const result = await retrieveEasEvidence(downloaded, env, build.id, output, fetch_);
  assert.equal(result.status, 'verified_exact_eas_build_evidence');
  assert.equal(result.build_id, build.id);
  assert.equal(await readFile(join(output, 'application-archive'), 'utf8'), 'exact owned application package');
  await assert.rejects(readFile(join(output, 'unrelated-secret.fixture')));
  await writeFile(paths.package, 'wrong package returned by server');
  await assert.rejects(retrieveEasEvidence(downloaded, env, build.id, join(root, 'bad-package'), fetch_), /package/);
  await assert.rejects(readFile(join(root, 'bad-package/BUILD-ASSOCIATION.json')));
  const missing = { ...downloaded, artifacts: { applicationArchiveUrl: downloaded.artifacts.applicationArchiveUrl } };
  await assert.rejects(retrieveEasEvidence(missing, env, build.id, join(root, 'missing'), fetch_), /unavailable/);
});

test('desktop release CLI verifies three archived target bundles against the exact downloaded installers', async t => {
  const root = await mkdtemp(join(tmpdir(), 'morse-desktop-release-set-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const release = { source_revision: env.GITHUB_SHA, mesh_revision: env.MESH_LANG_REVISION,
    build_id: 'github:123:2', version: '0.1.23', channel: 'desktop', repository: env.GITHUB_REPOSITORY };
  const installers = join(root, 'installers'); await mkdir(installers);
  const paths = Object.fromEntries(['compiler', 'artifact', 'report', 'review', 'evidence'].map(key => [key, join(root, key)]));
  const report = { schema_version: 1, policy: 'plaintext-v1', compiler_version: '0.1.8', modules: [
    { module: 'Mobile.DesktopFixture', file: 'fixture.mpl', source_sha256: 'ab'.repeat(32), sites: [] },
  ] };
  await writeFile(paths.report, JSON.stringify(report));
  await writeFile(paths.review, JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: [] }));
  await writeFile(paths.compiler, 'owned compiler fixture'); await writeFile(paths.artifact, 'owned native fixture');
  await writePlaintextBuildEvidence({ ...paths, output: paths.evidence });
  const matrix = [ ['aarch64-apple-darwin', 'macos-arm64', 'Morse_0.1.23_aarch64.dmg'],
    ['x86_64-apple-darwin', 'macos-x64', 'Morse_0.1.23_x64.dmg'],
    ['x86_64-pc-windows-msvc', 'windows-x64', 'Morse_0.1.23_x64-setup.exe'] ];
  for (const [target, platform, name] of matrix) {
    const packagePath = join(installers, name); await writeFile(packagePath, `owned ${platform} installer`);
    const capture = join(root, `capture-${platform}`);
    await captureNativeInputs({ release, review: paths.review, targets: [{ ...paths, target }] }, capture);
    const bundle = join(root, `bundle-${platform}`);
    await finalizeNativeInputs(capture, bundle, [{ name, path: packagePath }], release);
    const result = spawnSync('tar', ['-czf', join(installers, `morse-plaintext-${platform}.tar.gz`), '-C', root, `bundle-${platform}`], { env: { ...process.env, COPYFILE_DISABLE: '1' } });
    assert.equal(result.status, 0);
  }
  const run = (scratch, output) => spawnSync(process.execPath, [fileURLToPath(new URL('./plaintext-release.mjs', import.meta.url)), 'verify-desktop-set',
    '--packages', installers, '--scratch', join(root, scratch), '--output', join(root, output)],
  { env: { ...process.env, ...env, GITHUB_RUN_ID: '123', GITHUB_RUN_ATTEMPT: '2', MORSE_VERSION: '0.1.23', RELEASE_BUILD: 'true' }, encoding: 'utf8' });
  const success = run('verify', 'notes.md');
  assert.equal(success.status, 0, success.stderr);
  const notes = await readFile(join(root, 'notes.md'), 'utf8');
  for (const [target] of matrix) assert.ok(notes.includes(target));
  await writeFile(join(installers, matrix[0][2]), 'substituted installer');
  const failure = run('verify-substitution', 'invalid-notes.md');
  assert.notEqual(failure.status, 0);
  assert.match(failure.stderr, /package association mismatch/);
  await assert.rejects(readFile(join(root, 'invalid-notes.md')));
});

test('worker uses resolved EAS applicationArchivePath/defaults and refuses ambiguous packages', async t => {
  const root = await mkdtemp(join(tmpdir(), 'morse-eas-archive-path-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const config = { build: { production: {}, staging: { extends: 'production' } } };
  const android = join(root, 'android/app/build/outputs/bundle/release'); await mkdir(android, { recursive: true });
  await writeFile(join(android, 'app-release.aab'), 'one app bundle');
  assert.ok((await discoverEasApplicationArchive(root, config, 'android', 'staging')).endsWith('app-release.aab'));
  await writeFile(join(android, 'second.aab'), 'ambiguous app bundle');
  await assert.rejects(discoverEasApplicationArchive(root, config, 'android', 'staging'), /exactly one/);
  config.build.production.android = { applicationArchivePath: 'android/app/build/outputs/bundle/release/app-release.aab' };
  config.build.staging.android = { buildType: 'apk' };
  assert.ok((await discoverEasApplicationArchive(root, config, 'android', 'staging')).endsWith('app-release.aab'));
  const ios = join(root, 'ios/build'); await mkdir(ios, { recursive: true });
  await writeFile(join(ios, 'App.ipa'), 'one iOS archive');
  assert.ok((await discoverEasApplicationArchive(root, config, 'ios', 'production')).endsWith('App.ipa'));
  config.build.staging.ios = { applicationArchivePath: 'ios/custom/*.ipa' };
  await assert.rejects(discoverEasApplicationArchive(root, config, 'ios', 'staging'), /exactly one/);
  await mkdir(join(root, 'ios/custom')); await writeFile(join(root, 'ios/custom/Selected.ipa'), 'configured iOS archive');
  assert.ok((await discoverEasApplicationArchive(root, config, 'ios', 'staging')).endsWith('Selected.ipa'));
  config.build.staging.ios.applicationArchivePath = '../outside/*.ipa';
  await assert.rejects(discoverEasApplicationArchive(root, config, 'ios', 'staging'), /unsafe/);
});

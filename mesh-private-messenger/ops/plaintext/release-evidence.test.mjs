import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { disclosureSites, writePlaintextBuildEvidence } from './report.mjs';
import { createReleaseBundle, verifyReleaseBundle } from './release-evidence.mjs';

const release = { source_revision: 'a'.repeat(40), mesh_revision: 'b'.repeat(40),
  build_id: 'github:123:2', version: '0.1.23', channel: 'desktop', repository: 'example/morse' };

async function fixture(t) {
  const root = await mkdtemp(join(tmpdir(), 'morse-release-evidence-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  const paths = Object.fromEntries(['report', 'review', 'compiler', 'artifact', 'evidence', 'package', 'signed'].map(name => [name, join(root, name)]));
  const document = { schema_version: 1, policy: 'plaintext-v1', compiler_version: '0.1.8', modules: [
    { module: 'Mobile.Example', file: 'mobile/example.mpl', source_sha256: 'cd'.repeat(32), sites: [
      { kind: 'display', reason: 'render text | local observer', start: 2, end: 14, line: 1, column: 3 },
      { kind: 'declassify_discriminant', reason: 'bounded outcome only', start: 20, end: 30, line: 2, column: 1 },
    ] },
  ] };
  await writeFile(paths.report, JSON.stringify(document));
  await writeFile(paths.review, JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: disclosureSites(document) }));
  for (const name of ['compiler', 'artifact', 'package', 'signed']) await writeFile(paths[name], `exact ${name} bytes`);
  await writePlaintextBuildEvidence({ ...paths, output: paths.evidence });
  const target = { target: 'aarch64-apple-darwin', report: paths.report, evidence: paths.evidence,
    compiler: paths.compiler, artifact: paths.artifact, packaged_artifact: paths.signed,
    packages: [{ name: 'Morse_0.1.23_aarch64.dmg', path: paths.package }] };
  return { root, paths, document, spec: { release, review: paths.review, targets: [target] },
    output: join(root, 'bundle'), options: { release, targets: [target.target], packages: { [target.packages[0].name]: paths.package } } };
}

test('bundle retains exact sites, source identities, compiler/native files and final package association', async t => {
  const f = await fixture(t);
  const manifest = await createReleaseBundle(f.spec, f.output);
  const verified = await verifyReleaseBundle(f.output, f.options);
  assert.deepEqual(verified, manifest);
  assert.equal(manifest.targets[0].disclosure_count, 2);
  assert.notEqual(manifest.targets[0].artifact_sha256, manifest.targets[0].packaged_artifact_sha256);
  const notes = await readFile(join(f.output, 'DISCLOSURES.md'), 'utf8');
  for (const expected of ['bounded outcome only', 'render text \\| local observer', release.source_revision, release.mesh_revision,
    'github:123:2', 'Morse_0.1.23_aarch64.dmg', 'not complete plaintext-source coverage', 'build transparency']) assert.ok(notes.includes(expected), expected);
  assert.equal(manifest.claims.complete_plaintext_migration, false);
});

test('missing report/review/evidence/compiler/native/package is refused before publishing a bundle', async t => {
  for (const name of ['report', 'review', 'evidence', 'compiler', 'artifact', 'package']) {
    const f = await fixture(t);
    await rm(f.paths[name]);
    await assert.rejects(createReleaseBundle(f.spec, f.output));
    await assert.rejects(readFile(join(f.output, 'manifest.json')));
  }
});

test('stale evidence, a changed reviewed reason, and compiler/native substitutions are refused', async t => {
  for (const name of ['report', 'review', 'compiler', 'artifact']) {
    const f = await fixture(t);
    if (name === 'report') { f.document.modules[0].source_sha256 = 'ef'.repeat(32); await writeFile(f.paths.report, JSON.stringify(f.document)); }
    else if (name === 'review') { const value = JSON.parse(await readFile(f.paths.review)); value.sites[0].reason = 'unreviewed'; await writeFile(f.paths.review, JSON.stringify(value)); }
    else await writeFile(f.paths[name], 'substituted bytes');
    await assert.rejects(createReleaseBundle(f.spec, f.output), /evidence|review/);
  }
});

test('external verification requires the exact release, target set and actual package bytes', async t => {
  const f = await fixture(t);
  await createReleaseBundle(f.spec, f.output);
  await assert.rejects(verifyReleaseBundle(f.output, { ...f.options, release: { ...release, source_revision: 'c'.repeat(40) } }), /identity/);
  await assert.rejects(verifyReleaseBundle(f.output, { ...f.options, targets: ['x86_64-apple-darwin'] }), /target/);
  await assert.rejects(verifyReleaseBundle(f.output, { ...f.options, packages: {} }), /package/);
  await writeFile(f.paths.package, 'another installer');
  await assert.rejects(verifyReleaseBundle(f.output, f.options), /package/);
});

test('incomplete, duplicate and unsafe target/package associations fail', async t => {
  for (const change of [
    f => { f.spec.targets = []; },
    f => { f.spec.targets.push(f.spec.targets[0]); },
    f => { f.spec.targets[0].packages = []; },
    f => { f.spec.targets[0].packages[0].name = '../installer'; },
    f => { f.spec.release = { ...release, build_id: '' }; },
    f => { f.spec.release = { ...release, source_revision: 'release' }; },
  ]) {
    const f = await fixture(t); change(f);
    await assert.rejects(createReleaseBundle(f.spec, f.output));
  }
});

test('tampered and extra bundle files fail closed without executing packaged binaries', async t => {
  const f = await fixture(t);
  const manifest = await createReleaseBundle(f.spec, f.output);
  await writeFile(join(f.output, 'unexpected-file'), 'unrecorded');
  await assert.rejects(verifyReleaseBundle(f.output, f.options), /files/);
  await rm(join(f.output, 'unexpected-file'));
  await writeFile(join(f.output, manifest.targets[0].artifact), 'changed native');
  await assert.rejects(verifyReleaseBundle(f.output, f.options), /hash|bytes/);
});

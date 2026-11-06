import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, readFile, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { disclosureSites, verifyDisclosureReview, writePlaintextBuildEvidence } from './report.mjs';

const report = () => ({
  schema_version: 1, policy: 'plaintext-v1', compiler_version: '0.1.8',
  modules: [{ module: 'Mobile.Main', file: 'mobile/main.mpl', source_sha256: 'ab'.repeat(32), sites: [
    { kind: 'display', reason: 'chat shown to the user', start: 4, end: 20, line: 1, column: 5 },
    { kind: 'declassify', reason: 'user enabled previews', start: 40, end: 80, line: 3, column: 1 },
  ] }],
});

test('strict report inventory rejects malformed spans, hashes, reasons and unrecognized exits', () => {
  assert.equal(disclosureSites(report()).length, 2);
  for (const mutate of [
    value => { value.schema_version = 2; },
    value => { value.modules[0].source_sha256 = 'not-a-hash'; },
    value => { value.modules[0].sites[0].end = 4; },
    value => { value.modules[0].sites[0].line = 0; },
    value => { value.modules[0].sites[0].reason = '   '; },
    value => { value.modules[0].sites[0].kind = 'unreviewed-native-exit'; },
    value => { value.modules.push(value.modules[0]); },
  ]) {
    const changed = report(); mutate(changed);
    assert.throws(() => disclosureSites(changed), /invalid plaintext report/);
  }
});

test('every addition, removal and changed reason requires a matching reviewed inventory', () => {
  const before = report();
  const review = { schema_version: 1, policy: 'plaintext-v1', sites: disclosureSites(before) };
  assert.doesNotThrow(() => verifyDisclosureReview(before, review));
  for (const changed of [
    { ...before, modules: [] },
    (() => { const value = report(); value.modules[0].sites[0].reason = 'different reason'; return value; })(),
    (() => { const value = report(); value.modules[0].sites.push({ ...value.modules[0].sites[1], start: 100, end: 120 }); return value; })(),
  ]) assert.throws(() => verifyDisclosureReview(changed, review), /disclosure review changed/);
});

test('result discriminant disclosure is a distinct reviewed site, never interchangeable with whole-value disclosure', () => {
  const document = report();
  document.modules[0].sites[1].kind = 'declassify_discriminant';
  document.modules[0].sites[1].reason = 'attachment sealing exposes success or failure only';
  const sites = disclosureSites(document);
  assert.equal(sites[1].kind, 'declassify_discriminant');
  const review = { schema_version: 1, policy: 'plaintext-v1', sites };
  assert.doesNotThrow(() => verifyDisclosureReview(document, review));
  for (const kind of ['declassify', 'display']) {
    const changed = structuredClone(document);
    changed.modules[0].sites[1].kind = kind;
    assert.throws(() => verifyDisclosureReview(changed, review), /disclosure review changed/);
  }
  for (const reason of ['', '   ', 'invalid\nreason']) {
    const changed = structuredClone(document);
    changed.modules[0].sites[1].reason = reason;
    assert.throws(() => disclosureSites(changed), /invalid plaintext report/);
  }
});

test('evidence hashes the actual report, compiler and artifact after inventory verification', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'mesh-plaintext-report-'));
  const paths = Object.fromEntries(['report', 'review', 'compiler', 'artifact', 'output'].map(name => [name, join(directory, `${name}.json`)]));
  const document = report();
  await writeFile(paths.report, JSON.stringify(document));
  await writeFile(paths.review, JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: disclosureSites(document) }));
  await writeFile(paths.compiler, 'actual compiler bytes');
  await writeFile(paths.artifact, 'actual library bytes');
  await writePlaintextBuildEvidence(paths);
  const evidence = JSON.parse(await readFile(paths.output, 'utf8'));
  for (const key of ['report', 'compiler', 'artifact']) {
    assert.equal(evidence[`${key}_sha256`], createHash('sha256').update(await readFile(paths[key])).digest('hex'));
  }
  assert.deepEqual(evidence.mesh_sources, [{ module: 'Mobile.Main', file: 'mobile/main.mpl', sha256: 'ab'.repeat(32) }]);
  await writeFile(paths.review, JSON.stringify({ schema_version: 1, policy: 'plaintext-v1', sites: [] }));
  await assert.rejects(writePlaintextBuildEvidence(paths), /disclosure review changed/);
});

import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { copyFile, lstat, mkdir, readFile, readdir, rename, rm, stat, writeFile } from 'node:fs/promises';
import { basename, dirname, join, resolve } from 'node:path';
import { isDeepStrictEqual } from 'node:util';
import { verifyDisclosureReview, writePlaintextBuildEvidence } from './report.mjs';

const fail = message => { throw new Error(`invalid plaintext release evidence: ${message}`); };
const text = value => typeof value === 'string' && value.trim() && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
const hash = value => /^[a-f0-9]{64}$/.test(value ?? '');
const claims = { complete_plaintext_migration: false, build_transparency: false,
  association: 'same-build records; native code and installed-byte identity are outside the Mesh report' };
const json = async path => JSON.parse(await readFile(path, 'utf8'));

export async function fileIdentity(path) {
  const details = await stat(path);
  if (!details.isFile()) fail(`not a regular file: ${path}`);
  const digest = createHash('sha256');
  for await (const bytes of createReadStream(path)) digest.update(bytes);
  return { sha256: digest.digest('hex'), bytes: details.size };
}

function releaseIdentity(value) {
  const names = ['source_revision', 'mesh_revision', 'build_id', 'version', 'channel', 'repository'];
  if (!value || Object.keys(value).length !== names.length || names.some(name => !text(value[name]))
    || !/^[a-f0-9]{40}$/.test(value.source_revision) || !/^[a-f0-9]{40}$/.test(value.mesh_revision)) fail('release identity');
  return value;
}
function targetName(value) {
  if (!/^[a-z0-9][a-z0-9_-]{0,99}$/.test(value ?? '')) fail('target identity');
  return value;
}
function packageName(value) {
  if (!text(value) || value !== basename(value) || /[\\/]/.test(value) || value === '.' || value === '..') fail('package name');
  return value;
}
const same = (a, b, label) => { if (!isDeepStrictEqual(a, b)) fail(label); };

export async function verifyNativeBuildEvidence(paths, review, scratch) {
  const expected = await writePlaintextBuildEvidence({ ...paths, review, output: scratch });
  const supplied = await json(paths.evidence);
  same(supplied, expected, 'stale or mismatched per-target evidence');
  await rm(scratch);
  return expected;
}

export function releaseDisclosureNotes(manifest, review) {
  const escape = value => String(value).replaceAll('|', '\\|').replaceAll('`', '\\`');
  return [
    '# Reviewed Mesh disclosure inventory', '',
    `Source revision: \`${manifest.release.source_revision}\`. Mesh revision: \`${manifest.release.mesh_revision}\`.`,
    `Build: \`${escape(manifest.release.build_id)}\`; version \`${escape(manifest.release.version)}\`; channel \`${escape(manifest.release.channel)}\`.`, '',
    'This is the reviewed list for the associated build, not complete plaintext-source coverage or release approval. It does not provide build transparency, prove installed-byte identity, or cover Rust/OS/third-party native code.', '',
    'The evidence keeps compiler-produced native bytes separate from the bytes supplied to packaging after platform signing. Package hashes bind this build record to the named downloadable package; they are not an attestation of package contents.', '',
    '| Target | Compiler SHA-256 | Compiler native SHA-256 | Native after signing SHA-256 | Packages |',
    '| --- | --- | --- | --- | --- |',
    ...manifest.targets.map(value => `| ${value.target} | ${value.compiler_sha256} | ${value.artifact_sha256} | ${value.packaged_artifact_sha256} | ${value.packages.map(p => `${escape(p.name)} (${p.sha256})`).join(', ')} |`), '',
    '| Kind | Module/source location | Reviewed reason |', '| --- | --- | --- |',
    ...review.sites.map(site => `| ${site.kind} | ${escape(site.module)} — ${escape(site.file)}:${site.line}:${site.column} [${site.start},${site.end}) | ${escape(site.reason)} |`), '',
  ].join('\n');
}

export async function createReleaseBundle(spec, output) {
  releaseIdentity(spec.release);
  if (!Array.isArray(spec.targets) || !spec.targets.length || new Set(spec.targets.map(t => t.target)).size !== spec.targets.length) fail('target association');
  output = resolve(output);
  if (await lstat(output).catch(() => null)) fail('bundle output already exists');
  const stage = join(dirname(output), `.${basename(output)}-${randomUUID()}.tmp`);
  await mkdir(stage, { recursive: false });
  const files = {};
  const put = async path => {
    const identity = await fileIdentity(path);
    const relative = `objects/${identity.sha256}`;
    if (!files[relative]) {
      await mkdir(join(stage, 'objects'), { recursive: true });
      await copyFile(path, join(stage, relative));
      same(await fileIdentity(join(stage, relative)), identity, 'input bytes changed while copying');
      files[relative] = identity;
    }
    return relative;
  };
  try {
    const review = await json(spec.review);
    const reviewPath = await put(spec.review);
    const targets = [];
    const packageNames = new Map();
    for (const value of spec.targets) {
      targetName(value.target);
      if (!Array.isArray(value.packages) || !value.packages.length) fail('missing package association');
      const evidence = await verifyNativeBuildEvidence(value, spec.review, join(stage, 'expected-evidence.tmp'));
      const packages = [];
      for (const pack of value.packages) {
        packageName(pack.name);
        const identity = await fileIdentity(pack.path);
        if (packageNames.has(pack.name)) same(identity, packageNames.get(pack.name), 'conflicting package association');
        packageNames.set(pack.name, identity);
        packages.push({ name: pack.name, ...identity });
      }
      const packaged = value.packaged_artifact ?? value.artifact;
      targets.push({ target: value.target, compiler: await put(value.compiler), artifact: await put(value.artifact),
        packaged_artifact: await put(packaged), report: await put(value.report), evidence: await put(value.evidence),
        compiler_sha256: evidence.compiler_sha256, artifact_sha256: evidence.artifact_sha256,
        packaged_artifact_sha256: (await fileIdentity(packaged)).sha256,
        disclosure_count: evidence.disclosure_count, packages });
    }
    const manifest = { schema_version: 1, policy: 'plaintext-release-v1', release: spec.release, claims,
      review: reviewPath, targets, files };
    await writeFile(join(stage, 'DISCLOSURES.md'), releaseDisclosureNotes(manifest, review), { flag: 'wx' });
    files['DISCLOSURES.md'] = await fileIdentity(join(stage, 'DISCLOSURES.md'));
    await writeFile(join(stage, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`, { flag: 'wx' });
    await verifyReleaseBundle(stage, { release: spec.release, targets: targets.map(t => t.target),
      packages: Object.fromEntries(spec.targets.flatMap(t => t.packages.map(p => [p.name, p.path]))) });
    await rename(stage, output);
    return manifest;
  } finally { await rm(stage, { recursive: true, force: true }); }
}

async function listFiles(root, prefix = '') {
  const files = [];
  for (const entry of await readdir(join(root, prefix), { withFileTypes: true })) {
    const name = prefix ? `${prefix}/${entry.name}` : entry.name;
    if (entry.isSymbolicLink() || (!entry.isFile() && !entry.isDirectory())) fail('unsafe bundle files');
    if (entry.isDirectory()) files.push(...await listFiles(root, name)); else files.push(name);
  }
  return files.sort();
}

export async function verifyReleaseBundle(directory, expected) {
  const manifest = await json(join(directory, 'manifest.json'));
  if (manifest.schema_version !== 1 || manifest.policy !== 'plaintext-release-v1') fail('bundle schema');
  releaseIdentity(manifest.release);
  same(manifest.release, releaseIdentity(expected.release), 'release identity association changed');
  same(manifest.claims, claims, 'unsupported claim');
  if (!Array.isArray(manifest.targets) || !manifest.targets.length || new Set(manifest.targets.map(t => t.target)).size !== manifest.targets.length) fail('target association');
  same(manifest.targets.map(t => targetName(t.target)).sort(), [...expected.targets].sort(), 'target association');
  same(await listFiles(directory), [...Object.keys(manifest.files), 'manifest.json'].sort(), 'bundle files differ');
  for (const [name, identity] of Object.entries(manifest.files)) {
    if (name !== 'DISCLOSURES.md' && !/^objects\/[a-f0-9]{64}$/.test(name)) fail('unsafe bundle files path');
    if (!hash(identity.sha256) || !Number.isSafeInteger(identity.bytes) || identity.bytes < 0) fail('file identity');
    same(await fileIdentity(join(directory, name)), identity, 'bundle hash/bytes changed');
  }
  const file = name => { if (!Object.hasOwn(manifest.files, name)) fail('missing associated file'); return join(directory, name); };
  const reviewPath = file(manifest.review);
  const review = await json(reviewPath);
  const packages = new Map();
  for (const target of manifest.targets) {
    const report = await json(file(target.report));
    const evidence = await json(file(target.evidence));
    const sites = verifyDisclosureReview(report, review);
    const sources = report.modules.map(m => ({ module: m.module, file: m.file, sha256: m.source_sha256 }))
      .sort((a, b) => a.module < b.module ? -1 : a.module > b.module ? 1 : a.file < b.file ? -1 : a.file > b.file ? 1 : 0);
    same(evidence.mesh_sources, sources, 'source report/evidence association');
    for (const [key, path] of [['report', target.report], ['review', manifest.review], ['compiler', target.compiler], ['artifact', target.artifact]]) {
      if ((await fileIdentity(file(path))).sha256 !== evidence[`${key}_sha256`]) fail(`${key} evidence association`);
    }
    if (evidence.policy !== 'plaintext-v1' || evidence.schema_version !== 1 || evidence.compiler_version !== report.compiler_version
      || evidence.disclosure_count !== sites.length || target.disclosure_count !== sites.length
      || target.compiler_sha256 !== evidence.compiler_sha256 || target.artifact_sha256 !== evidence.artifact_sha256
      || target.packaged_artifact_sha256 !== (await fileIdentity(file(target.packaged_artifact))).sha256) fail('target evidence association');
    if (!Array.isArray(target.packages) || !target.packages.length) fail('missing package association');
    for (const pack of target.packages) {
      packageName(pack.name);
      if (!expected.packages?.[pack.name]) fail('missing package association');
      if (packages.has(pack.name)) same(packages.get(pack.name), pack, 'conflicting package association');
      packages.set(pack.name, pack);
      same(await fileIdentity(expected.packages[pack.name]), { sha256: pack.sha256, bytes: pack.bytes }, 'package association mismatch');
    }
  }
  same(await readFile(join(directory, 'DISCLOSURES.md'), 'utf8'), releaseDisclosureNotes(manifest, review), 'published inventory/association changed');
  return manifest;
}

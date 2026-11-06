import { createHash, randomUUID } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { readFile, realpath, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const policy = 'plaintext-v1';
const fail = message => { throw new Error(`invalid plaintext report: ${message}`); };
const text = value => typeof value === 'string' && value.trim() !== '' && !/[\u0000-\u001f\u007f-\u009f]/u.test(value);
const integer = value => Number.isSafeInteger(value) && value >= 0;
function keys(value, names, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)
    || Object.keys(value).length !== names.length || names.some(name => !Object.hasOwn(value, name))) fail(label);
}
function site(value) {
  keys(value, ['kind', 'reason', 'start', 'end', 'line', 'column'], 'site fields');
  if (!['declassify', 'declassify_discriminant', 'display'].includes(value.kind) || !text(value.reason)
    || !integer(value.start) || !integer(value.end) || value.end <= value.start
    || !integer(value.line) || value.line < 1 || !integer(value.column) || value.column < 1) fail('site value');
  return value;
}
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const orderSites = (left, right) => compare(left.module, right.module) || compare(left.file, right.file)
  || left.start - right.start || left.end - right.end || compare(left.kind, right.kind) || compare(left.reason, right.reason);
function uniqueSites(sites) {
  const seen = new Set();
  for (const value of sites) {
    const key = JSON.stringify([value.module, value.file, value.start, value.end, value.kind]);
    if (seen.has(key)) fail('duplicate site');
    seen.add(key);
  }
  return sites.sort(orderSites);
}

export function disclosureSites(report) {
  keys(report, ['schema_version', 'policy', 'compiler_version', 'modules'], 'root fields');
  if (report.schema_version !== 1 || report.policy !== policy || !text(report.compiler_version) || !Array.isArray(report.modules)) fail('root value');
  const modules = new Set();
  const sites = [];
  for (const module of report.modules) {
    keys(module, ['module', 'file', 'source_sha256', 'sites'], 'module fields');
    if (!text(module.module) || !text(module.file) || !/^[a-f0-9]{64}$/.test(module.source_sha256) || !Array.isArray(module.sites)) fail('module value');
    const key = JSON.stringify([module.module, module.file]);
    if (modules.has(key)) fail('duplicate module');
    modules.add(key);
    for (const value of module.sites) {
      const checked = site(value);
      sites.push({ module: module.module, file: module.file, kind: checked.kind, reason: checked.reason,
        start: checked.start, end: checked.end, line: checked.line, column: checked.column });
    }
  }
  return uniqueSites(sites);
}

export function verifyDisclosureReview(report, review) {
  const actual = disclosureSites(report);
  keys(review, ['schema_version', 'policy', 'sites'], 'review fields');
  if (review.schema_version !== 1 || review.policy !== policy || !Array.isArray(review.sites)) fail('review value');
  const expected = uniqueSites(review.sites.map(value => {
    keys(value, ['module', 'file', 'kind', 'reason', 'start', 'end', 'line', 'column'], 'review site fields');
    if (!text(value.module) || !text(value.file)) fail('review module');
    const checked = site({ kind: value.kind, reason: value.reason, start: value.start, end: value.end, line: value.line, column: value.column });
    return { module: value.module, file: value.file, kind: checked.kind, reason: checked.reason,
      start: checked.start, end: checked.end, line: checked.line, column: checked.column };
  }));
  if (JSON.stringify(actual) !== JSON.stringify(expected)) throw new Error('plaintext disclosure review changed; additions, removals and changed sites require an updated reviewed inventory');
  return actual;
}

async function digestFile(path) {
  const digest = createHash('sha256');
  for await (const bytes of createReadStream(path)) digest.update(bytes);
  return digest.digest('hex');
}

// This binds actual build files and checked Mesh source hashes. It does not
// attest compiler trust, complete field coverage, native code or UI networking.
export async function writePlaintextBuildEvidence(paths) {
  const [reportBytes, reviewBytes] = await Promise.all([readFile(paths.report), readFile(paths.review)]);
  const report = JSON.parse(reportBytes.toString('utf8'));
  const review = JSON.parse(reviewBytes.toString('utf8'));
  const sites = verifyDisclosureReview(report, review);
  const inputs = await Promise.all(['report', 'review', 'compiler', 'artifact'].map(key => realpath(paths[key])));
  const output = await realpath(paths.output).catch(() => resolve(paths.output));
  if (inputs.includes(output)) throw new Error('plaintext evidence output must differ from its inputs');
  const [compiler, artifact] = await Promise.all([digestFile(paths.compiler), digestFile(paths.artifact)]);
  const evidence = {
    schema_version: 1, policy, compiler_version: report.compiler_version,
    report_sha256: createHash('sha256').update(reportBytes).digest('hex'),
    review_sha256: createHash('sha256').update(reviewBytes).digest('hex'),
    compiler_sha256: compiler, artifact_sha256: artifact, disclosure_count: sites.length,
    mesh_sources: report.modules.map(value => ({ module: value.module, file: value.file, sha256: value.source_sha256 }))
      .sort((left, right) => compare(left.module, right.module) || compare(left.file, right.file)),
  };
  const temporary = join(dirname(output), `.plaintext-evidence-${process.pid}-${randomUUID()}.tmp`);
  try {
    await writeFile(temporary, `${JSON.stringify(evidence, null, 2)}\n`, { flag: 'wx' });
    await rename(temporary, output);
  } finally {
    await rm(temporary, { force: true });
  }
  return evidence;
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const arguments_ = process.argv.slice(2);
  const paths = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    const name = arguments_[index].replace(/^--/, '');
    if (!['report', 'review', 'compiler', 'artifact', 'output'].includes(name) || !arguments_[index + 1] || Object.hasOwn(paths, name)) throw new Error('expected --report --review --compiler --artifact --output paths');
    paths[name] = arguments_[index + 1];
  }
  if (Object.keys(paths).length !== 5) throw new Error('expected --report --review --compiler --artifact --output paths');
  await writePlaintextBuildEvidence(paths);
}

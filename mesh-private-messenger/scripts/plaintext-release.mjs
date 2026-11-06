import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createWriteStream } from 'node:fs';
import { copyFile, cp, glob, lstat, mkdir, mkdtemp, readFile, readdir, realpath, rm, writeFile } from 'node:fs/promises';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { Readable, Transform } from 'node:stream';
import { pipeline } from 'node:stream/promises';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { createReleaseBundle, fileIdentity, verifyNativeBuildEvidence, verifyReleaseBundle } from '../ops/plaintext/release-evidence.mjs';

const root = fileURLToPath(new URL('../..', import.meta.url));
const product = join(root, 'mesh-private-messenger');
const mobile = join(product, 'apps/mobile');
const json = async path => JSON.parse(await readFile(path, 'utf8'));
const save = (path, data) => writeFile(path, `${JSON.stringify(data, null, 2)}\n`, { flag: 'wx' });
const require_ = (value, message) => { if (!value) throw new Error(message); };
const revision = value => /^[a-f0-9]{40}$/.test(value ?? '');
const uuid = value => /^[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}$/.test(value ?? '');

export async function captureNativeInputs(spec, output) {
  await mkdir(output);
  try {
    const files = {};
    const copy = async (source, name) => {
      const target = join(output, name);
      await mkdir(dirname(target), { recursive: true });
      await copyFile(source, target);
      files[name] = await fileIdentity(target);
      assert.deepEqual(files[name], await fileIdentity(source), 'capture input changed');
      return name;
    };
    const review = await copy(spec.review, 'review.json');
    const targets = [];
    for (const target of spec.targets) {
      require_(/^[a-z0-9][a-z0-9_-]{0,99}$/.test(target.target), 'unsafe capture target');
      await verifyNativeBuildEvidence(target, spec.review, join(output, 'expected-evidence.tmp'));
      const paths = {};
      for (const name of ['compiler', 'artifact', 'report', 'evidence']) paths[name] = await copy(target[name], `${target.target}/${name}`);
      targets.push({ target: target.target, ...paths, packaged_artifact: resolve(target.artifact) });
    }
    const capture = { schema_version: 1, release: spec.release, review, targets, files };
    await save(join(output, 'inputs.json'), capture);
    return capture;
  } catch (error) { await rm(output, { recursive: true, force: true }); throw error; }
}

export async function finalizeNativeInputs(input, output, packages, release) {
  const capture = await json(join(input, 'inputs.json'));
  assert.deepEqual(capture.release, release, 'release identity changed since native build');
  for (const [name, identity] of Object.entries(capture.files)) assert.deepEqual(await fileIdentity(join(input, name)), identity, 'captured bytes changed');
  const targets = capture.targets.map(target => ({ ...target,
    ...Object.fromEntries(['compiler', 'artifact', 'report', 'evidence'].map(key => [key, join(input, target[key])])), packages }));
  return createReleaseBundle({ release, review: join(input, capture.review), targets }, output);
}

function oneBuild(value) {
  if (Array.isArray(value)) { require_(value.length === 1, 'EAS requires exactly one build'); return value[0]; }
  require_(value && typeof value === 'object', 'missing EAS build'); return value;
}

export function easBuildIdentity(value, env, expectedId) {
  const build = oneBuild(value);
  require_(uuid(expectedId) && build.id === expectedId && build.status === 'FINISHED'
    && build.platform === env.PLATFORM?.toUpperCase() && build.buildProfile === env.PROFILE
    && revision(env.GITHUB_SHA) && build.gitCommitHash === env.GITHUB_SHA
    && uuid(env.EXPO_PROJECT_ID) && build.app?.id === env.EXPO_PROJECT_ID
    && revision(env.MESH_LANG_REVISION), 'EAS build/source/project/profile association mismatch');
  return { source_revision: env.GITHUB_SHA, mesh_revision: env.MESH_LANG_REVISION,
    build_id: build.id, version: `EAS build ${build.id}`, channel: env.PROFILE, repository: env.GITHUB_REPOSITORY };
}

// Match the pinned EAS resolver's env/platform inheritance and five-profile bound.
function mergeProfile(base, update) {
  const result = { ...base, ...update };
  for (const field of ['env', 'ios', 'android']) {
    if (base[field] && update[field]) result[field] = field === 'env'
      ? { ...base[field], ...update[field] } : mergeProfile(base[field], update[field]);
  }
  return result;
}

function profile(config, name, seen = new Set()) {
  require_(!seen.has(name) && seen.size < 5 && config.build?.[name], 'invalid EAS profile inheritance');
  seen.add(name);
  const own = config.build[name];
  const parent = own.extends ? profile(config, own.extends, seen) : {};
  return mergeProfile(parent, own);
}

function platformProfile(config, name, platform) {
  const resolved = profile(config, name);
  return platform ? mergeProfile(resolved, resolved[platform] ?? {}) : resolved;
}

export function evidenceConfigured(pkg, config, name, platform) {
  const value = platformProfile(config, name, platform);
  const hook = pkg.scripts?.['eas-build-on-success']?.includes('plaintext-release.mjs worker-success');
  const paths = value.buildArtifactPaths?.includes('plaintext-release');
  const enabled = value.env?.MORSE_PLAINTEXT_EVIDENCE === '1';
  if (!hook && !paths && !enabled) return false;
  require_(hook && paths && enabled, 'partial EAS plaintext evidence configuration');
  return true;
}

export async function discoverEasApplicationArchive(project, config, platform, name) {
  require_(['ios', 'android'].includes(platform), 'unknown EAS archive platform');
  const resolved = platformProfile(config, name, platform);
  require_(!resolved.simulator || platform !== 'ios', 'EAS simulator directory archives require a separate association policy');
  const pattern = resolved.applicationArchivePath ?? (platform === 'ios'
    ? 'ios/build/*.ipa' : 'android/app/build/outputs/**/*.{apk,aab}');
  require_(typeof pattern === 'string' && pattern && !isAbsolute(pattern) && !pattern.split('/').includes('..') && !pattern.includes('\\'), 'unsafe EAS applicationArchivePath');
  project = await realpath(project);
  const candidates = [];
  for await (const name of glob(pattern, { cwd: project })) {
    const path = resolve(project, name);
    const resolvedPath = await realpath(path);
    require_(!relative(project, resolvedPath).startsWith('..') && !isAbsolute(relative(project, resolvedPath)), 'EAS package escapes project');
    const details = await lstat(path);
    require_(!details.isSymbolicLink(), 'symlink EAS package');
    if (!details.isFile()) continue;
    require_(platform === 'ios' ? path.endsWith('.ipa') : /\.(?:apk|aab)$/.test(path), 'unsupported EAS application archive format');
    candidates.push(path);
    require_(candidates.length <= 1, 'expected exactly one final EAS application archive');
  }
  require_(candidates.length === 1, 'expected exactly one final EAS application archive');
  return candidates[0];
}

async function walk(directory) {
  const entries = [];
  for (const item of await readdir(directory, { withFileTypes: true }).catch(error => { if (error.code === 'ENOENT') return []; throw error; })) {
    require_(!item.isSymbolicLink(), 'symlink in release artifact tree');
    const path = join(directory, item.name);
    if (item.isDirectory()) entries.push(...await walk(path)); else if (item.isFile()) entries.push(path);
    else throw new Error('special file in release artifact tree');
    require_(entries.length <= 4096, 'too many release artifact files');
  }
  return entries;
}

function desktopIdentity(env, version) {
  return { source_revision: env.GITHUB_SHA, mesh_revision: env.MESH_LANG_REVISION,
    build_id: `github:${env.GITHUB_RUN_ID}:${env.GITHUB_RUN_ATTEMPT}`, version,
    channel: env.RELEASE_BUILD === 'true' ? 'desktop' : 'desktop-preview', repository: env.GITHUB_REPOSITORY };
}

function workerIdentity(env) {
  require_(env.EAS_BUILD === 'true' && uuid(env.EAS_BUILD_ID) && revision(env.EAS_BUILD_GIT_COMMIT_HASH)
    && revision(env.MESH_LANG_REVISION) && env.EAS_BUILD_PROFILE && env.MORSE_RELEASE_REPOSITORY,
  'missing exact EAS worker source/build identity');
  return { source_revision: env.EAS_BUILD_GIT_COMMIT_HASH, mesh_revision: env.MESH_LANG_REVISION,
    build_id: env.EAS_BUILD_ID, version: `EAS build ${env.EAS_BUILD_ID}`, channel: env.EAS_BUILD_PROFILE,
    repository: env.MORSE_RELEASE_REPOSITORY };
}

async function download(url, output, fetch_ = fetch) {
  const parsed = new URL(url);
  require_(parsed.protocol === 'https:' && !parsed.username && !parsed.password, 'artifact URL must use HTTPS');
  const response = await fetch_(url, { redirect: 'follow' });
  require_(response.ok && response.body && (!response.url || new URL(response.url).protocol === 'https:'), 'artifact download failed');
  let bytes = 0;
  const limit = new Transform({ transform(chunk, encoding, callback) {
    bytes += chunk.length;
    callback(bytes > 2_147_483_648 ? new Error('artifact download exceeds 2 GiB') : null, chunk);
  } });
  await pipeline(Readable.fromWeb(response.body), limit, createWriteStream(output, { flags: 'wx' }));
}

function extract(archive, output) {
  const result = spawnSync('python3', [join(product, 'ops/plaintext/extract-release-evidence.py'), archive, output], { stdio: 'inherit' });
  require_(!result.error && result.status === 0, 'unsafe or invalid evidence archive');
}

export async function retrieveEasEvidence(build, env, expectedId, output, fetch_ = fetch) {
  build = oneBuild(build);
  const release = easBuildIdentity(build, env, expectedId);
  require_(build.artifacts?.buildArtifactsUrl && build.artifacts?.applicationArchiveUrl, 'EAS evidence/application archive unavailable');
  await mkdir(output);
  const scratch = await mkdtemp(join(dirname(output), '.eas-evidence-download-'));
  const archive = join(scratch, 'worker-artifacts.tar.gz');
  const application = join(scratch, 'application-archive');
  try {
  // These URLs can contain temporary credentials. Retain only IDs and hashes.
  await download(build.artifacts.buildArtifactsUrl, archive, fetch_);
  await download(build.artifacts.applicationArchiveUrl, application, fetch_);
  const unpacked = join(scratch, 'worker');
  extract(archive, unpacked);
  const candidates = [];
  for (const file of await walk(unpacked)) {
    if (basename(file) !== 'manifest.json') continue;
    const data = await json(file);
    if (data.policy === 'plaintext-release-v1') candidates.push({ directory: dirname(file), data });
  }
  require_(candidates.length === 1, 'expected exactly one EAS evidence bundle');
  const { directory, data } = candidates[0];
  const targets = env.PLATFORM === 'ios' ? ['aarch64-apple-ios'] : ['aarch64-linux-android', 'x86_64-linux-android'];
  const names = [...new Set(data.targets.flatMap(target => target.packages.map(pack => pack.name)))];
  require_(names.length === 1, 'EAS requires exactly one application package association');
  await verifyReleaseBundle(directory, { release, targets, packages: { [names[0]]: application } });
  const record = { schema_version: 1, status: 'verified_exact_eas_build_evidence', build_id: build.id,
    platform: build.platform, build_profile: build.buildProfile, source_revision: build.gitCommitHash,
    mesh_revision: release.mesh_revision, project_id: build.app.id, app_version: build.appVersion ?? null,
    app_build_version: build.appBuildVersion ?? null, evidence_manifest: await fileIdentity(join(directory, 'manifest.json')),
    application_archive: await fileIdentity(application), worker_artifacts_archive: await fileIdentity(archive),
    package_name: names[0], claims_complete_plaintext_migration: false };
  // Publish only verified bundle files and the bound application archive, never
  // arbitrary custom-artifact contents or temporary authenticated URLs.
  await cp(directory, join(output, 'bundle'), { recursive: true, errorOnExist: true, force: false });
  await copyFile(application, join(output, 'application-archive'));
  await save(join(output, 'BUILD-ASSOCIATION.json'), record);
  await copyFile(join(directory, 'DISCLOSURES.md'), join(output, 'DISCLOSURES.md'));
  return record;
  } finally { await rm(scratch, { recursive: true, force: true }); }
}

async function main() {
  const [mode, ...arguments_] = process.argv.slice(2);
  const args = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    require_(arguments_[index]?.startsWith('--') && arguments_[index + 1] && !Object.hasOwn(args, arguments_[index].slice(2)), 'expected named path arguments');
    args[arguments_[index].slice(2)] = arguments_[index + 1];
  }
  const env = process.env;
  const module = join(mobile, 'modules/mesh-messenger');
  if (mode === 'configured') {
    const enabled = evidenceConfigured(await json(join(mobile, 'package.json')), await json(join(mobile, 'eas.json')), env.PROFILE, env.PLATFORM);
    if (env.GITHUB_OUTPUT) await writeFile(env.GITHUB_OUTPUT, `enabled=${enabled}\n`, { flag: 'a' });
    console.log(enabled); return;
  }
  if (mode === 'desktop-capture') {
    const desktop = join(product, 'apps/desktop');
    const extension = process.platform === 'win32' ? 'dll' : 'dylib';
    const artifact = join(desktop, `src-tauri/native/libmessenger_mobile.${extension}`);
    await captureNativeInputs({ release: desktopIdentity(env, env.MORSE_VERSION ?? (await json(join(desktop, 'package.json'))).version),
      review: join(product, 'protocol/plaintext-disclosures.json'), targets: [{ target: args.target,
        compiler: resolve(env.MESHC ?? join(root, `mesh-lang/target/debug/meshc${process.platform === 'win32' ? '.exe' : ''}`)),
        artifact, report: `${artifact}.plaintext.json`, evidence: `${artifact}.plaintext-evidence.json` }] }, args.output); return;
  }
  if (mode === 'desktop-finalize') {
    const input = args.input;
    const capture = await json(join(input, 'inputs.json'));
    const files = (await walk(args.packages)).filter(path => /(?:\.dmg|\.exe|\.app\.tar\.gz|\.sig)$/.test(path));
    require_(files.length && files.some(path => /(?:\.dmg|\.exe)$/.test(path)), 'missing final desktop installer');
    await finalizeNativeInputs(input, args.output, files.map(path => ({ name: basename(path), path })), desktopIdentity(env, capture.release.version)); return;
  }
  if (mode === 'worker-capture') {
    const meshRevision = spawnSync('git', ['-C', join(root, 'mesh-lang'), 'rev-parse', 'HEAD'], { encoding: 'utf8' });
    require_(meshRevision.status === 0 && meshRevision.stdout.trim() === env.MESH_LANG_REVISION, 'worker Mesh source revision mismatch');
    const targets = env.EAS_BUILD_PLATFORM === 'ios' ? ['aarch64-apple-ios'] : ['aarch64-linux-android', 'x86_64-linux-android'];
    require_(['ios', 'android'].includes(env.EAS_BUILD_PLATFORM), 'unknown EAS platform');
    const paths = { 'aarch64-apple-ios': 'ios/MeshMessengerCore.xcframework/ios-arm64',
      'aarch64-linux-android': 'android/arm64-v8a', 'x86_64-linux-android': 'android/x86_64' };
    await captureNativeInputs({ release: workerIdentity(env), review: join(product, 'protocol/plaintext-disclosures.json'), targets: targets.map(target => {
      const reportTarget = { 'aarch64-linux-android': 'android-arm64-v8a', 'x86_64-linux-android': 'android-x86_64' }[target] ?? target;
      return { target, compiler: join(root, 'mesh-lang/target/debug/meshc'), artifact: join(module, `native/${paths[target]}/libmessenger_mobile.a`),
        report: join(module, `native/plaintext/${reportTarget}/report.json`), evidence: join(module, `native/plaintext/${reportTarget}/evidence.json`) };
    }) }, join(mobile, 'plaintext-build-inputs')); return;
  }
  if (mode === 'worker-success') {
    const application = await discoverEasApplicationArchive(mobile, await json(join(mobile, 'eas.json')), env.EAS_BUILD_PLATFORM, env.EAS_BUILD_PROFILE);
    await finalizeNativeInputs(join(mobile, 'plaintext-build-inputs'), join(mobile, 'plaintext-release'),
      [{ name: basename(application), path: application }], workerIdentity(env)); return;
  }
  if (mode === 'eas-id') {
    const build = oneBuild(await json(args.build)); easBuildIdentity(build, env, build.id); console.log(build.id); return;
  }
  if (mode === 'retrieve-eas') {
    await retrieveEasEvidence(await json(args.build), env, args.id, args.output); return;
  }
  if (mode === 'pending-eas') {
    const build = oneBuild(await json(args.build)); await mkdir(args.output);
    await save(join(args.output, 'BUILD-ASSOCIATION.json'), { schema_version: 1, status: 'pending_worker_evidence_configuration',
      build_id: build.id ?? null, platform: build.platform ?? null, build_profile: build.buildProfile ?? null,
      reported_source_revision: build.gitCommitHash ?? null, expected_source_revision: env.GITHUB_SHA,
      review_published_for_this_build: false, claims_complete_plaintext_migration: false }); return;
  }
  if (mode === 'verify-desktop-set') {
    const expectedTargets = new Set(['aarch64-apple-darwin', 'x86_64-apple-darwin', 'x86_64-pc-windows-msvc']);
    const files = await walk(args.packages);
    const packages = Object.fromEntries(files.map(path => [basename(path), path]));
    const archives = files.filter(path => /^morse-plaintext-[a-z0-9-]+\.tar\.gz$/.test(basename(path)));
    require_(archives.length === 3, 'expected three desktop evidence archives');
    await mkdir(args.scratch);
    const notes = [];
    for (const [index, archive] of archives.entries()) {
      const directory = join(args.scratch, String(index)); extract(archive, directory);
      const manifests = (await walk(directory)).filter(path => basename(path) === 'manifest.json');
      require_(manifests.length === 1, 'expected one desktop bundle per archive');
      const manifest = await json(manifests[0]);
      require_(manifest.targets.length === 1 && expectedTargets.delete(manifest.targets[0].target), 'duplicate/unexpected desktop evidence target');
      await verifyReleaseBundle(dirname(manifests[0]), { release: desktopIdentity(env, env.MORSE_VERSION), targets: manifest.targets.map(t => t.target), packages });
      notes.push(await readFile(join(dirname(manifests[0]), 'DISCLOSURES.md'), 'utf8'));
    }
    require_(expectedTargets.size === 0, 'missing desktop target');
    await writeFile(args.output, notes.join('\n\n---\n\n'), { flag: 'wx' }); return;
  }
  throw new Error('unknown plaintext release command');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) await main();

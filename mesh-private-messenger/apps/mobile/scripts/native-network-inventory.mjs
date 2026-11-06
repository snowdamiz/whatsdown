import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, existsSync, writeFileSync, lstatSync } from 'node:fs';
import { createRequire } from 'node:module';
import { dirname, join, relative, resolve, extname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';

const mobile = fileURLToPath(new URL('../', import.meta.url));
const require = createRequire(import.meta.url);
const sourceExtensions = new Set(['.swift', '.m', '.mm', '.h', '.c', '.cc', '.cpp', '.kt', '.java', '.rs', '.podspec', '.gradle', '.kts']);
const omittedDirectories = new Set(['node_modules', 'build', '.gradle', '.cxx', 'target', 'Pods', 'prebuilds', 'test', 'tests', '__tests__', 'androidTest', 'testFixtures']);
const networkPrimitive = /URLSession|NSURLSession|URLRequest|OkHttp|HttpURLConnection|HttpsURLConnection|WebSocket|NWConnection|Cronet|WKWebView|\bWebView\b|openConnection\(|openURL|RCTNetworking|NetworkingModule|reqwest::|ureq::|TcpStream|UdpSocket/;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');

const jsiProducerInputs = new Set([
  'apple/scripts/build-xcframework.sh', 'apple/scripts/generate-modulemap.sh',
  'apple/scripts/create-stub-xcframework.sh', 'apple/scripts/xcframework-helpers.sh',
  'apple/scripts/unexported-swift-runtime-symbols.txt',
]);

function isNormalizedVendorCopy(root, packageName, path, entry) {
  let canonical;
  if (packageName === 'expo-modules-jsi') {
    const header = /^apple\/Products\/ExpoModulesJSI\.xcframework\/[^/]+\/ExpoModulesJSI\.framework\/(?:Versions\/A\/)?Headers\/([^/]+\.h)$/.exec(path)?.[1];
    if (header === 'ExpoModulesJSI-Swift.h') return true;
    if (header) canonical = join(root, 'apple/Sources/ExpoModulesJSI-Cxx/include/Public', header);
  } else if (packageName === 'expo-updates' && path === 'ios/EXUpdates/BSPatch/bspatch.c') {
    canonical = join(root, 'vendor/bspatch/bspatch.c');
  }
  if (!canonical) return false;
  if (!entry.isFile() || !existsSync(canonical) || !lstatSync(canonical).isFile() ||
    !readFileSync(join(root, path)).equals(readFileSync(canonical))) {
    throw Error(`native_network_inventory_copy_mismatch:${packageName}/${path}`);
  }
  return true;
}

export function nativeSourceInventory(root, omitRootDirectories = [], { packageName } = {}) {
  const sources = [];
  function visit(directory) {
    for (const entry of readdirSync(directory, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name, 'en'))) {
      const path = join(directory, entry.name);
      const source = relative(root, path).replaceAll('\\', '/');
      if (isNormalizedVendorCopy(root, packageName, source, entry)) continue;
      if (entry.isDirectory()) {
        if (omittedDirectories.has(entry.name) || entry.name.endsWith('-proof') ||
          directory === root && omitRootDirectories.includes(entry.name) ||
          packageName === 'expo-modules-jsi' && source === 'apple/.DerivedData') continue;
        visit(path);
      } else if (entry.isFile() && (sourceExtensions.has(extname(entry.name)) ||
        packageName === 'expo-modules-jsi' && (jsiProducerInputs.has(source) || source.startsWith('apple/APINotes/')))) {
        const bytes = readFileSync(path);
        sources.push([source, hash(bytes), networkPrimitive.test(bytes.toString('utf8'))]);
      }
    }
  }
  visit(root);
  return { sha256: hash(JSON.stringify(sources.map(([path, digest]) => [path, digest]))), sources: sources.length,
    connectionSites: sources.filter(([, , connection]) => connection).map(([path]) => path) };
}

export function requireReviewedInventory(current, reviewed) {
  if (JSON.stringify(current) !== JSON.stringify(reviewed)) throw Error('native_network_inventory_changed: review linked modules, native source changes and dependency/configuration pins');
}

export function applicationNetworkViolations(source) {
  const { parse } = require('@babel/parser');
  const tree = parse(source, { sourceType: 'module', plugins: ['typescript', 'jsx'] });
  const failures = new Set();
  const globals = new Set(['fetch', 'XMLHttpRequest', 'WebSocket', 'EventSource', 'WebTransport', 'RTCPeerConnection', 'webkitRTCPeerConnection', 'sendBeacon']);
  const nativeImports = /^(?:expo\/fetch|expo-modules-core|expo-file-system\/legacy|@tauri-apps\/plugin-http|react-native-webview|@expo\/dom-webview|react-native\/Libraries\/(?:Network|WebSocket))/;
  const fileMethods = new Set(['downloadAsync', 'uploadAsync', 'downloadFileAsync', 'createDownloadResumable', 'createUploadTask']);
  const runtimeTS = new Set(['TSAsExpression', 'TSSatisfiesExpression', 'TSNonNullExpression', 'TSInstantiationExpression', 'TSEnumDeclaration', 'TSEnumMember', 'TSParameterProperty']);
  function visit(node) {
    if (!node || typeof node !== 'object') return;
    if (node.type?.startsWith('TS') && !runtimeTS.has(node.type)) return;
    if (node.type === 'ImportDeclaration' && node.importKind !== 'type') {
      if (nativeImports.test(node.source.value)) failures.add(`import:${node.source.value}`);
      if (node.source.value === 'react-native') for (const item of node.specifiers) {
        if (['NativeModules', 'TurboModuleRegistry', 'Linking'].includes(item.imported?.name)) failures.add(`native:${item.imported.name}`);
      }
    }
    if (node.type === 'CallExpression' && (node.callee.name === 'require' || node.callee.type === 'Import') &&
      typeof node.arguments[0]?.value === 'string' && nativeImports.test(node.arguments[0].value)) failures.add(`import:${node.arguments[0].value}`);
    if (node.type === 'Identifier' && globals.has(node.name)) failures.add(`transport:${node.name}`);
    if (['MemberExpression', 'OptionalMemberExpression'].includes(node.type)) {
      const name = node.computed ? node.property.value : node.property.name;
      if (globals.has(name)) failures.add(`transport:${name}`);
      if (fileMethods.has(name)) failures.add(`filesystem-network:${name}`);
    }
    for (const [key, value] of Object.entries(node)) {
      if (['loc', 'start', 'end', 'comments', 'typeAnnotation', 'typeParameters', 'typeArguments', 'returnType'].includes(key)) continue;
      if (Array.isArray(value)) value.forEach(visit);
      else if (value && typeof value === 'object') visit(value);
    }
  }
  visit(tree);
  return [...failures].sort();
}

export function validateApplicationSources(directory) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    if (entry.isDirectory()) { validateApplicationSources(join(directory, entry.name)); continue; }
    if (!entry.isFile() || !/\.[cm]?[jt]sx?$/.test(entry.name) || entry.name.includes('.test.')) continue;
    const failures = applicationNetworkViolations(readFileSync(join(directory, entry.name), 'utf8'));
    if (failures.length) throw Error(`application_network_capability:${entry.name}:${failures.join(',')}`);
  }
}

export function collectInventory() {
  validateApplicationSources(join(mobile, 'src'));
  const autolink = join(mobile, 'node_modules/expo-modules-autolinking/bin/expo-modules-autolinking');
  const registrations = new Map();
  const roots = new Map([['react-native', dirname(require.resolve('react-native/package.json'))]]);
  for (const [command, platform] of [['resolve', 'apple'], ['resolve', 'android'], ['react-native-config', 'ios'], ['react-native-config', 'android']]) {
    const result = JSON.parse(execFileSync(process.execPath, [autolink, command, '--platform', platform, '--json'], { cwd: mobile, encoding: 'utf8' }));
    for (const item of result.modules ?? []) {
      let root;
      try { root = dirname(require.resolve(`${item.packageName}/package.json`)); }
      catch { root = join(mobile, 'modules', item.packageName); }
      roots.set(item.packageName, root);
      const values = registrations.get(item.packageName) ?? [];
      values.push(`${command}:${platform}`);
      registrations.set(item.packageName, values);
    }
    for (const [name, item] of Object.entries(result.dependencies ?? {})) {
      roots.set(name, item.root);
      const values = registrations.get(name) ?? [];
      values.push(`${command}:${platform}`);
      registrations.set(name, values);
    }
  }
  const lock = JSON.parse(readFileSync(join(mobile, 'package-lock.json'), 'utf8'));
  const packages = [...roots].sort(([a], [b]) => a.localeCompare(b, 'en')).map(([name, root]) => {
    const manifestPath = join(root, 'package.json');
    const local = root === join(mobile, 'modules', name) && existsSync(join(root, 'expo-module.config.json'));
    if (!existsSync(manifestPath) && !local) throw Error('native_module_manifest_missing');
    const manifest = existsSync(manifestPath) ? JSON.parse(readFileSync(manifestPath, 'utf8')) : { version: 'local' };
    const integrity = lock.packages?.[`node_modules/${name}`]?.integrity ?? null;
    return { name, version: manifest.version, integrity, registrations: registrations.get(name) ?? ['react-native-core'],
      moduleConfig: existsSync(join(root, 'expo-module.config.json')) ? hash(readFileSync(join(root, 'expo-module.config.json'))) : null,
      ...nativeSourceInventory(root, local ? ['native'] : [], { packageName: local ? undefined : name }) };
  });
  const product = resolve(mobile, '../..');
  const controls = Object.fromEntries(['apps/mobile/package-lock.json', 'apps/desktop/src-tauri/Cargo.lock', 'apps/desktop/src-tauri/Cargo.toml',
    'apps/desktop/src-tauri/tauri.conf.json', 'apps/desktop/src-tauri/src/ipc-postmessage.js', 'apps/mobile/index.ts',
    'apps/mobile/src/network-lockdown.ts', 'apps/mobile/src/network-lockdown-bootstrap.ts',
    'apps/mobile/modules/mesh-messenger/index.ts', 'apps/mobile/modules/mesh-messenger/index.web.ts'].map(path => [path, hash(readFileSync(join(product, path)))]));
  const csp = JSON.parse(readFileSync(join(product, 'apps/desktop/src-tauri/tauri.conf.json'), 'utf8')).app.security.csp;
  if (!csp.split(';').some(rule => rule.trim() === "connect-src 'none'")) throw Error('desktop_network_csp_required');
  return { schemaVersion: 1, packages, desktopHost: nativeSourceInventory(join(product, 'apps/desktop/src-tauri/src')), controls };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const path = join(mobile, 'native-network-inventory.json');
  const current = collectInventory();
  if (process.argv[2] === '--capture') {
    if (!process.argv[3]) throw Error('Expected an explicit review output path');
    writeFileSync(resolve(process.argv[3]), `${JSON.stringify(current, null, 2)}\n`);
  } else {
    if (!existsSync(path)) throw Error('native_network_inventory_missing');
    requireReviewedInventory(current, JSON.parse(readFileSync(path, 'utf8')));
    console.log(`Native connection inventory unchanged: ${current.packages.length} linked packages, ${current.packages.reduce((n, p) => n + p.sources, 0)} native source files`);
  }
}

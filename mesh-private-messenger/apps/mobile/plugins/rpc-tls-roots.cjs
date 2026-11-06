const fs = require('node:fs');
const path = require('node:path');
const { createHash } = require('node:crypto');
const securityConfig = require('./security-config.cjs');
const { readBoundedFile, readCaPEM } = require('./tls-root-files.cjs');

const ASSET = 'app/src/main/assets/morse-rpc-tls-roots-v1.bin';

function exactFields(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== [...names].sort().join(',')) {
    throw new Error(`RPC TLS manifest requires exactly ${names.join(', ')}`);
  }
}

function canonicalOrigin(value) {
  if (typeof value !== 'string' || value.length < 1 || value.length > 2048 ||
      !/^[\x21-\x7e]+$/.test(value) || /[\\@?#]/.test(value)) {
    throw new Error('RPC TLS origins must be exact canonical HTTPS origins');
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.origin !== value) {
    throw new Error('RPC TLS origins must be exact canonical HTTPS origins');
  }
  return value;
}

function configuredOrigins(environment, securityFrame) {
  // This is the same generated text installed in the native resource. Checking
  // it against the build generator prevents a second endpoint authority.
  if (typeof securityFrame !== 'string' || !securityFrame ||
      securityConfig(environment, { development: true }) !== securityFrame) {
    throw new Error('RPC TLS roots require the generated canonical SecurityConfig');
  }
  let lines = securityFrame.split('\n');
  if (lines[0] === '6') lines = lines.slice(2);
  if (!['2', '3', '4', '5'].includes(lines[0])) throw new Error('RPC TLS roots require configured RPC origins');
  const witnesses = Number(lines[5]);
  const count = Number(lines[7 + witnesses]);
  if (count < 3 || count > 8) throw new Error('RPC TLS roots require 3–8 configured RPC origins');
  const origins = lines.slice(8 + witnesses, 8 + witnesses + count).map(url => canonicalOrigin(new URL(url).origin));
  if (new Set(origins).size !== count) throw new Error('RPC TLS origins must be distinct');
  return origins.sort();
}

function rpcTLSRoots(environment, securityFrame) {
  const file = environment.MORSE_RPC_TLS_ROOTS_FILE;
  if (file === undefined) return null;
  const origins = configuredOrigins(environment, securityFrame);
  const input = readBoundedFile(file, 65536, 'RPC TLS manifest');
  const manifest = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(input));
  exactFields(manifest, ['version', 'origins']);
  if (manifest.version !== 1 || !Array.isArray(manifest.origins) || manifest.origins.length !== origins.length) {
    throw new Error('RPC TLS manifest version 1 must cover every configured RPC origin');
  }
  const entries = new Map();
  let aggregate = 0;
  for (const row of manifest.origins) {
    exactFields(row, ['origin', 'pemFile']);
    const origin = canonicalOrigin(row.origin);
    if (!origins.includes(origin) || entries.has(origin)) throw new Error('RPC TLS origin is unknown or duplicated');
    const pem = row.pemFile === null ? Buffer.alloc(0) : readCaPEM(
      typeof row.pemFile === 'string' && row.pemFile ? path.resolve(path.dirname(file), row.pemFile) : row.pemFile);
    aggregate += pem.length;
    if (aggregate > 65536) throw new Error('RPC TLS roots exceed the 65536-byte aggregate PEM bound');
    entries.set(origin, pem);
  }
  if (aggregate === 0) throw new Error('RPC TLS manifest requires at least one explicit CA bundle');
  const prefix = Buffer.from([1, origins.length]);
  const digest = createHash('sha256').update(securityFrame, 'utf8').digest();
  const rows = origins.map(origin => {
    const name = Buffer.from(origin, 'ascii');
    const pem = entries.get(origin);
    const originLength = Buffer.alloc(2); originLength.writeUInt16BE(name.length);
    const pemLength = Buffer.alloc(4); pemLength.writeUInt32BE(pem.length);
    return Buffer.concat([originLength, name, pemLength, pem]);
  });
  const frame = Buffer.concat([prefix, digest, ...rows]);
  if (frame.length > 82002 || frame.toString('base64').length > 109336) throw new Error('RPC TLS resource exceeds native bounds');
  return frame;
}

rpcTLSRoots.writeAndroid = function writeAndroid(platformRoot, environment, securityFrame) {
  const target = path.join(platformRoot, ASSET);
  const wire = rpcTLSRoots(environment, securityFrame);
  if (wire) {
    fs.mkdirSync(path.dirname(target), { recursive: true });
    fs.writeFileSync(target, wire);
  } else fs.rmSync(target, { force: true });
};
module.exports = rpcTLSRoots;

// Host shell only: validate bounds/origins, run compiled Mesh, write a static artifact.
// Account decoding, custody arithmetic, status and agreement stay in Mesh.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const fail = reason => { throw new Error(reason); };
function integer(value, maximum = 18446744073709551615n) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > maximum) fail('Expected bounded canonical decimal string');
}
function collateralConfiguration(value, pins) {
  if (!value || value.schema_version !== 2) fail('Explicit v2 collateral schema required');
  const keys = ['schema_version', 'judge', 'judge_slot', 'rewards', 'rewards_slot', 'rewards_governance', 'log_name', 'log_version', 'service_public_key', 'morse_mint', 'network_started', 'witnesses', 'proofs'];
  if (Object.keys(value).some(key => !keys.includes(key))) fail('Unknown collateral configuration field');
  const publicKey = key => {
    if (typeof key !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(key) || key === '11111111111111111111111111111111') fail('Invalid collateral public key pin');
  };
  for (const key of ['judge', 'rewards', 'rewards_governance', 'morse_mint']) publicKey(value[key]);
  for (const key of ['program', 'governance', 'usdc']) publicKey(pins[key]);
  if (new Set([pins.program, value.judge, value.rewards]).size !== 3 || value.morse_mint === pins.usdc) fail('Collateral identities must be distinct');
  integer(value.judge_slot); integer(value.rewards_slot); integer(value.network_started);
  if (value.network_started === '0' || ![1, 2].includes(value.log_version) || typeof value.log_name !== 'string' || !/^[a-z0-9-]{1,32}$/.test(value.log_name)) fail('Invalid collateral log identity');
  const hash = input => typeof input === 'string' && /^[0-9a-f]{64}$/.test(input) && input !== '00'.repeat(32);
  if (!hash(value.service_public_key)) fail('Invalid collateral service identity');
  if (!Array.isArray(value.witnesses) || value.witnesses.length > 16 || !Array.isArray(value.proofs) || value.proofs.length > 16) fail('Select at most 16 witnesses and proofs');
  const identities = value.witnesses.map(witness => {
    if (!witness || typeof witness.witness_id !== 'string' || !/^[a-z0-9-]{1,64}$/.test(witness.witness_id) || !hash(witness.public_key) || Object.keys(witness).some(key => !['witness_id', 'public_key'].includes(key))) fail('Invalid selected witness identity');
    return `${witness.witness_id}:${witness.public_key}`;
  });
  if (new Set(identities).size !== identities.length || !value.proofs.every(hash) || new Set(value.proofs).size !== value.proofs.length) fail('Invalid or repeated collateral selection');
}
function legacyConfiguration(value) {
  const legacy = value.legacy_collateral;
  const keys = ['schema_version', 'judge', 'judge_slot', 'governance', 'anchor_authority', 'log_name', 'log_version', 'service_public_key', 'mint'];
  if (!legacy || legacy.schema_version !== 1 || Object.keys(legacy).some(key => !keys.includes(key)) || value.pins !== undefined || value.collateral !== undefined || value.history === undefined || value.epochs.length !== 0) fail('Explicit exclusive legacy context required');
  for (const key of ['judge', 'governance', 'anchor_authority', 'mint']) if (typeof legacy[key] !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(legacy[key]) || legacy[key] === '11111111111111111111111111111111') fail('Invalid legacy identity pin');
  integer(legacy.judge_slot);
  if (!/^[a-z0-9-]{1,32}$/.test(legacy.log_name) || ![1, 2].includes(legacy.log_version) || typeof legacy.service_public_key !== 'string' || !/^[0-9a-f]{64}$/.test(legacy.service_public_key) || legacy.service_public_key === '00'.repeat(32)) fail('Invalid legacy log pin');
}
export function validateConfiguration(value) {
  if (!value || value.schema_version !== 1 || !['local-fixture', 'configured-rpc'].includes(value.scope)) fail('Explicit report scope required');
  if (value.history !== undefined) {
    const h = value.history;
    if (!h || h.schema_version !== 1 || Object.keys(h).some(key => !['schema_version', 'maximum_records', 'page_size'].includes(key)) || !Number.isInteger(h.maximum_records) || h.maximum_records < 1 || h.maximum_records > 128 || !Number.isInteger(h.page_size) || h.page_size < 1 || h.page_size > 16) fail('Explicit bounded history schema required');
  }
  if (!Array.isArray(value.epochs) || (value.epochs.length < 1 && value.history === undefined) || value.epochs.length > 16 || new Set(value.epochs).size !== value.epochs.length) fail('Select 1 to 16 distinct epochs or opt into bounded history');
  value.epochs.forEach(epoch => integer(epoch));
  integer(value.minimum_context_slot); integer(value.max_age_seconds, 86400n);
  if (value.max_age_seconds === '0') fail('Explicit maximum report age required');
  if (value.legacy_collateral !== undefined) legacyConfiguration(value);
  else {
    if (!value.pins) fail('Explicit release pins required');
    for (const key of ['program', 'governance', 'usdc', 'treasury', 'factory']) if (typeof value.pins[key] !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value.pins[key])) fail('Invalid public key pin');
    integer(value.pins.program_slot);
    if (value.collateral !== undefined) collateralConfiguration(value.collateral, value.pins);
  }
  if (!Array.isArray(value.endpoints) || value.endpoints.length !== 3) fail('Three configured RPC origins required');
  const origins = value.endpoints.map(endpoint => {
    if (typeof endpoint !== 'string' || endpoint.length > 2048 || /[\r\n]/.test(endpoint)) fail('Invalid RPC endpoint');
    const url = new URL(endpoint);
    if (url.username || url.password || url.hash) fail('Invalid RPC endpoint');
    if (value.scope === 'local-fixture' ? url.protocol !== 'http:' || url.hostname !== '127.0.0.1' : url.protocol !== 'https:') fail('Fixture reads require loopback HTTP; configured reads require HTTPS');
    return url.origin;
  });
  if (new Set(origins).size !== 3) fail('Three distinct RPC origins required; this does not establish operator independence');
}

export async function createReport({ configuration, binary, generatedAt = Math.floor(Date.now() / 1000) }) {
  validateConfiguration(configuration);
  if (!Number.isSafeInteger(generatedAt) || generatedAt < 0) fail('Invalid retrieval time');
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'morse-public-read-'));
  const input = path.join(directory, 'input.json');
  fs.writeFileSync(input, JSON.stringify({ ...configuration, generated_at_unix: String(generatedAt) }), { mode: 0o600 });
  try {
    const output = await new Promise((resolve, reject) => {
      const child = spawn(binary, ['--input', input], { stdio: ['ignore', 'pipe', 'pipe'] });
      let stdout = '', stderr = '';
      const timer = setTimeout(() => { child.kill('SIGKILL'); reject(new Error('Bounded read timed out')); }, (configuration.epochs.length + (configuration.collateral ? 2 : 0)) * 16_000 + 5000 + (configuration.history ? 180000 : 0));
      child.stdout.on('data', chunk => { stdout += chunk; if (stdout.length > (configuration.history ? 8_388_608 : 2_097_152)) { child.kill('SIGKILL'); reject(new Error('Report exceeds output bound')); } });
      child.stderr.on('data', chunk => { stderr += chunk; if (stderr.length > 32768) { child.kill('SIGKILL'); reject(new Error('Read diagnostics exceed bound')); } });
      child.on('error', reject);
      child.on('close', code => { clearTimeout(timer); code === 0 ? resolve(stdout) : reject(new Error(`Mesh report failed (${code})`)); });
    });
    const report = JSON.parse(output);
    if (report.schema_version !== 1 || report.scope !== configuration.scope || report.burns.length !== configuration.epochs.length || report.phase5_complete !== false) fail('Invalid Mesh report envelope');
    if (configuration.history ? !report.history || report.history.schema_version !== 1 || report.history_completeness !== 'bounded-filtered-index-with-separate-value-pages' : report.history !== undefined || report.history_completeness !== 'selected-epochs-only') fail('Mesh report discovery scope mismatch');
    return report;
  } finally { fs.rmSync(directory, { recursive: true, force: true }); }
}

export function writeReport(output, report) {
  const json = JSON.stringify(report, null, 2).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
  fs.writeFileSync(output, output.endsWith('.js') ? `globalThis.MORSE_NETWORK_REPORT = ${json};\n` : `${json}\n`, { flag: 'wx' });
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const args = process.argv.slice(2);
    if (args.length !== 6 || args[0] !== '--input' || args[2] !== '--binary' || args[4] !== '--output') fail('usage: node export.mjs --input CONFIG --binary COMPILED_MESH_REPORT --output NEW_JSON_OR_JS');
    const input = fs.readFileSync(args[1], 'utf8');
    if (input.length > 32768) fail('Report configuration exceeds bound');
    writeReport(args[5], await createReport({ configuration: JSON.parse(input), binary: args[3] }));
  } catch (error) { process.stderr.write(`${error.message}\n`); process.exitCode = 1; }
}

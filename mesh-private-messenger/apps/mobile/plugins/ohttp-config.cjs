// Build-time companion only. Call with the already-validated native network
// and canonical security frames. Mesh independently checks both bindings.
const { createHash } = require('node:crypto');
const maximumU64 = 18446744073709551615n;

function invalid(detail) {
  throw new Error(`Invalid OHTTP configuration: ${detail}`);
}

function fields(value, expected) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.keys(value).sort().join(',') !== [...expected].sort().join(',')) {
    invalid('exact fields required');
  }
}

function integer(value, positive = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    invalid('integers must be canonical u64 strings');
  }
  const number = BigInt(value);
  if (number > maximumU64 || number.toString() !== value || (positive && number === 0n)) {
    invalid('integer out of range');
  }
  return number;
}

function parent(value, maximum) {
  if (typeof value !== 'string' || Buffer.byteLength(value, 'utf8') < 1 ||
      Buffer.byteLength(value, 'utf8') > maximum) invalid('both bounded native parents required');
  return createHash('sha256').update(value, 'utf8').digest('hex');
}

module.exports = function ohttpConfig(environment, networkFrame, securityFrame) {
  const input = environment.MESSENGER_OHTTP_CONFIG;
  if (input === undefined && networkFrame === undefined && securityFrame === undefined) return undefined;
  const network = parent(networkFrame, 8244);
  const security = parent(securityFrame, 8192);
  let configuration = { schema_version: 1, mode: 'off', revision: '1', keys: [] };
  if (input !== undefined) {
    if (typeof input !== 'string' || Buffer.byteLength(input, 'utf8') > 4096) invalid('JSON exceeds bound');
    configuration = JSON.parse(input);
  }
  fields(configuration, ['schema_version', 'mode', 'revision', 'keys']);
  const { schema_version: version, mode, revision, keys } = configuration;
  if (version !== 1 || (mode !== 'off' && mode !== 'required')) invalid('unsupported version or mode');
  integer(revision, true);
  if (!Array.isArray(keys) || (mode === 'off' ? keys.length !== 0 : keys.length < 1 || keys.length > 2)) {
    invalid('mode and key count disagree');
  }
  const ids = new Set();
  const publicKeys = new Set();
  const lines = keys.map(key => {
    fields(key, ['key_id', 'public_key', 'not_before_ms', 'not_after_ms']);
    if (!Number.isInteger(key.key_id) || key.key_id < 0 || key.key_id > 255) invalid('key ID must be u8');
    if (typeof key.public_key !== 'string' || key.public_key.length !== 64 ||
        !/^[0-9a-f]{64}$/.test(key.public_key) || /^0+$/.test(key.public_key)) invalid('public key encoding');
    if (ids.has(key.key_id) || publicKeys.has(key.public_key)) invalid('duplicate key ID or encoding');
    ids.add(key.key_id);
    publicKeys.add(key.public_key);
    if (integer(key.not_before_ms) >= integer(key.not_after_ms)) invalid('empty or reversed validity window');
    const wire = Buffer.concat([
      Buffer.from([key.key_id, 0, 32]), Buffer.from(key.public_key, 'hex'),
      Buffer.from([0, 4, 0, 1, 0, 3]),
    ]);
    return `${key.not_before_ms} ${key.not_after_ms} ${wire.toString('base64')}`;
  });
  const frame = ['1', network, security, revision, mode, String(keys.length), ...lines].join('\n');
  if (Buffer.byteLength(frame, 'utf8') > 600) invalid('frame exceeds native bound');
  return frame;
};

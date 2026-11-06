const SECURITY_FIELDS = [
  'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX',
  'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX',
  'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX',
  'MESSENGER_DELIVERY_PUBLIC_KEY_HEX',
  'MESSENGER_ABUSE_DIFFICULTY',
];


function legacySecurityConfig(environment) {
  const securityProvisioned = SECURITY_FIELDS.some(
    (name) => environment[name] !== undefined,
  );
  let securityFrame;
  if (securityProvisioned) {
    for (const name of SECURITY_FIELDS.slice(0, 4)) {
      if (!/^[0-9a-f]{64}$/.test(environment[name] ?? '')) {
        throw new Error(`${name} must be a 32-byte lowercase-hex key`);
      }
    }
    if (
      !/^([1-9]|1[0-9]|2[0-4])$/.test(
        environment.MESSENGER_ABUSE_DIFFICULTY ?? '',
      )
    ) {
      throw new Error(
        'MESSENGER_ABUSE_DIFFICULTY must be a canonical integer from 1 through 24',
      );
    }
    if (
      environment.MESSENGER_WITNESS_A_PUBLIC_KEY_HEX ===
      environment.MESSENGER_WITNESS_B_PUBLIC_KEY_HEX
    ) {
      throw new Error('MESSENGER witness public keys must be distinct');
    }
    securityFrame = `1\n${SECURITY_FIELDS.map((name) => environment[name]).join(
      '\n',
    )}`;
  }
  return securityFrame;
}

const V2_FIELDS = [
  'MESSENGER_WITNESS_SET_JSON', 'MESSENGER_WITNESS_THRESHOLD',
  'MESSENGER_ANCHOR_RING_ADDRESS', 'MESSENGER_ANCHOR_RPC_URLS',
  'MESSENGER_CREDIT_ISSUER_ORIGIN',
];

function key(value, label) {
  if (typeof value !== 'string' || !/^[0-9a-f]{64}$/.test(value)) throw new Error(`${label} must be a 32-byte lowercase-hex key`);
  return value;
}

function endpoint(value, originOnly) {
  if (typeof value !== 'string' || value.length > 2048 || !/^[\x21-\x7e]+$/.test(value) || /[\\#@]/.test(value)) {
    throw new Error('Security endpoints must be canonical HTTPS URLs without credentials or fragments');
  }
  const url = new URL(value);
  if (url.protocol !== 'https:' || (originOnly ? value !== url.origin :
    value !== url.origin && !value.startsWith(`${url.origin}/`) && !value.startsWith(`${url.origin}?`))) {
    throw new Error('Security endpoints must use a canonical HTTPS origin');
  }
  return value;
}

function anchorAddress(value) {
  if (value === '-') return value;
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  if (typeof value !== 'string' || value.length < 32 || value.length > 44) throw new Error('Invalid anchor ring address');
  let number = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) throw new Error('Invalid anchor ring address');
    number = number * 58n + BigInt(digit);
  }
  const bytes = number === 0n ? 0 : Math.ceil(number.toString(16).length / 2);
  if (/^1*/.exec(value)[0].length + bytes !== 32) throw new Error('Anchor ring address must encode 32 bytes');
  return value;
}

const V3_FIELDS = [
  'MESSENGER_TRANSPARENCY_LOG_VERSION', 'MESSENGER_LEGACY_WITNESS_SET_JSON',
  'MESSENGER_LEGACY_WITNESS_THRESHOLD',
];

const V4_FIELDS = ['MESSENGER_ANCHOR_PROGRAM_ADDRESS', 'MESSENGER_ANCHOR_LOG_NAME'];
const V5_FIELDS = ['MESSENGER_RELAY_URLS', 'MESSENGER_SLASH_MINT_ADDRESS'];

function witnessPolicy(environment, prefix) {
  const pins = JSON.parse(environment[`${prefix}_WITNESS_SET_JSON`] ?? 'null');
  if (!Array.isArray(pins) || pins.length < 1 || pins.length > 16) throw new Error(`Provide 1–16 witnesses in ${prefix}_WITNESS_SET_JSON`);
  const threshold = Math.floor(pins.length / 2) + 1;
  if (environment[`${prefix}_WITNESS_THRESHOLD`] !== String(threshold)) throw new Error(`${prefix}_WITNESS_THRESHOLD must be the strict majority`);
  const ids = new Set(), keys = new Set();
  for (const pin of pins) {
    if (!pin || typeof pin !== 'object' || Object.keys(pin).sort().join(',') !== 'id,operator,publicKey' ||
      typeof pin.id !== 'string' || !/^[a-z0-9-]{1,64}$/.test(pin.id) || typeof pin.operator !== 'string' ||
      !/^[\x20-\x7e]{1,48}$/.test(pin.operator) || pin.operator.trim() !== pin.operator) {
      throw new Error('Invalid witness ID or operator label');
    }
    key(pin.publicKey, pin.id);
    if (ids.has(pin.id) || keys.has(pin.publicKey)) throw new Error('Witness IDs and public keys must be distinct');
    ids.add(pin.id); keys.add(pin.publicKey);
  }
  pins.sort((a, b) => a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
  return { pins, threshold };
}

function baseSecurityConfig(environment, { development = false } = {}) {
  const relayPins = V5_FIELDS.some(name => environment[name] !== undefined);
  const anchorIdentity = relayPins || V4_FIELDS.some(name => environment[name] !== undefined);
  const migrating = anchorIdentity || V3_FIELDS.some(name => environment[name] !== undefined);
  if (!migrating && !V2_FIELDS.some(name => environment[name] !== undefined)) return legacySecurityConfig(environment);
  if (migrating && environment.MESSENGER_TRANSPARENCY_LOG_VERSION !== '2') {
    throw new Error('RFC migration requires MESSENGER_TRANSPARENCY_LOG_VERSION=2 and its legacy witness policy');
  }
  const { pins, threshold } = witnessPolicy(environment, 'MESSENGER');
  const legacy = migrating ? witnessPolicy(environment, 'MESSENGER_LEGACY') : null;
  const difficulty = environment.MESSENGER_ABUSE_DIFFICULTY;
  if (!/^(?:[1-9]|1[0-9]|2[0-4])$/.test(difficulty ?? '')) throw new Error('MESSENGER_ABUSE_DIFFICULTY must be a canonical integer from 1 through 24');
  const anchor = anchorAddress(environment.MESSENGER_ANCHOR_RING_ADDRESS ?? '-');
  let program, logName;
  if (anchorIdentity) {
    program = anchorAddress(environment.MESSENGER_ANCHOR_PROGRAM_ADDRESS);
    logName = environment.MESSENGER_ANCHOR_LOG_NAME;
    if (anchor === '-') {
      if (program !== '-' || logName !== '-') throw new Error('Disabled anchors require both identity pins to be -');
    } else {
      if (program === '-' || typeof logName !== 'string' || logName === '-' || !/^[a-z0-9-]{1,32}$/.test(logName)) {
        throw new Error('Enabled anchors require a program and canonical 1–32 byte log name');
      }
      if (!development && logName !== 'morse-main') throw new Error('Production releases must pin morse-main');
    }
  }
  const rpcs = JSON.parse(environment.MESSENGER_ANCHOR_RPC_URLS ?? '[]');
  if (!Array.isArray(rpcs) || (rpcs.length !== 0 && (rpcs.length < 3 || rpcs.length > 8)) || new Set(rpcs).size !== rpcs.length || (anchor !== '-' && rpcs.length === 0)) {
    throw new Error('Pin 3–8 distinct RPC URLs when enabling an anchor ring');
  }
  const origins = rpcs.map(url => new URL(endpoint(url, false)).origin);
  if (new Set(origins).size !== origins.length) throw new Error('RPC providers must have distinct origins');
  const issuer = environment.MESSENGER_CREDIT_ISSUER_ORIGIN ?? '-';
  const relays = relayPins ? JSON.parse(environment.MESSENGER_RELAY_URLS ?? '[]') : [];
  const mint = relayPins ? anchorAddress(environment.MESSENGER_SLASH_MINT_ADDRESS ?? '-') : '-';
  if (!Array.isArray(relays) || relays.length > 8 || new Set(relays).size !== relays.length) {
    throw new Error('Pin at most eight distinct relay HTTPS origins');
  }
  for (const origin of relays) endpoint(origin, true);
  if ((relays.length > 0 && mint === '-') || (mint !== '-' && (anchor === '-' || mint === '1'.repeat(32)))) {
    throw new Error('Relay filing requires anchor identity and a nonzero slash mint');
  }
  const frame = [
    relayPins ? '5' : anchorIdentity ? '4' : migrating ? '3' : '2', key(environment.MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX, 'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX'),
    key(environment.MESSENGER_DELIVERY_PUBLIC_KEY_HEX, 'MESSENGER_DELIVERY_PUBLIC_KEY_HEX'),
    difficulty, String(threshold), String(pins.length),
    ...pins.map(pin => `${pin.id} ${pin.publicKey} ${pin.operator}`),
    anchor, String(rpcs.length), ...rpcs.map(url => endpoint(url, false)),
    issuer === '-' ? issuer : endpoint(issuer, true),
    ...(legacy ? ['2', String(legacy.threshold), String(legacy.pins.length),
      ...legacy.pins.map(pin => `${pin.id} ${pin.publicKey} ${pin.operator}`)] : []),
    ...(anchorIdentity ? [program, logName] : []),
    ...(relayPins ? [mint, String(relays.length), ...relays] : []),
  ].join('\n');
  const maximum = migrating ? 8192 : 4096;
  if (Buffer.byteLength(frame, 'utf8') > maximum) throw new Error(`Security configuration exceeds ${maximum} bytes`);
  return frame;
}

// The envelope adds only session admission policy. The embedded profile retains
// its exact log, anchor and relay authority and its own canonical size bound.
module.exports = function securityConfig(environment, options = {}) {
  const minimum = environment.MESSENGER_MINIMUM_SESSION_SUITE;
  if (minimum !== undefined && minimum !== '1' && minimum !== '2') {
    throw new Error('MESSENGER_MINIMUM_SESSION_SUITE must be exactly 1 or 2');
  }
  const base = baseSecurityConfig(environment, options);
  if (minimum === undefined) return base;
  if (base === undefined) throw new Error('A suite floor requires complete security pins');
  const frame = `6\n${minimum}\n${base}`;
  if (Buffer.byteLength(frame, 'utf8') > 8192) throw new Error('Security configuration exceeds 8192 bytes');
  return frame;
};

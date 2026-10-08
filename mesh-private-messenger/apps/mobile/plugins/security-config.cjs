// Builds the native security config frame, v2 (INTERFACES §4 / WITNESS_NETWORK_PLAN §6.1),
// from build environment variables. An empty value counts as unset.
//
//   MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX  log service Ed25519 key, 64 lowercase hex
//   MESSENGER_DELIVERY_PUBLIC_KEY_HEX      delivery X25519 key, 64 lowercase hex
//   MESSENGER_ABUSE_DIFFICULTY             proof-of-work difficulty, 1-24
//   MESSENGER_WITNESSES                    pinned set: `id:hexkey:label;…` (label: 1-48 printable
//                                          ASCII, no `;` or `:`, no edge spaces; `Morse` = Morse-run)
//   MESSENGER_WITNESS_{A,B}_PUBLIC_KEY_HEX used only without MESSENGER_WITNESSES: witness-a and
//                                          witness-b, both labelled Morse (rollout step 1)
//   MESSENGER_ANCHOR                       `<judge program id> <log account>` (base58), or `-`
//   MESSENGER_RPC_URLS                     comma-separated https URLs: 3-8 with an anchor, else none
//   MESSENGER_RELAY_URLS                   comma-separated https origins, 0-8
//   MESSENGER_CREDIT_ISSUER                https origin, or `-`
//   MESSENGER_LOG_ORIGIN                   C2SP log origin (e.g. morseapp.io/log/main), or `-`
//   MESSENGER_MINIMUM_SUITE                1 (default) or 2
//   MESSENGER_OHTTP_KEY                    OHTTP gateway key: `<key id 0-255>:<X25519 public key hex>`
//   MESSENGER_OHTTP_RELAY                  the relay (privacy edge) origin: https, or http on a
//                                          loopback or private address for development builds
//
// The OHTTP pair is optional and set together (protocol/ohttp-v1.md): the frame's last line is
// then the RFC 9458 key configuration in hex and the relay origin.
//
// The threshold k is always ⌊n/2⌋ + 1 and is never configured.
const {
  createHash,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
} = require('node:crypto');

const VARIABLES = [
  'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX',
  'MESSENGER_DELIVERY_PUBLIC_KEY_HEX',
  'MESSENGER_ABUSE_DIFFICULTY',
  'MESSENGER_WITNESSES',
  'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX',
  'MESSENGER_WITNESS_B_PUBLIC_KEY_HEX',
  'MESSENGER_ANCHOR',
  'MESSENGER_RPC_URLS',
  'MESSENGER_RELAY_URLS',
  'MESSENGER_CREDIT_ISSUER',
  'MESSENGER_LOG_ORIGIN',
  'MESSENGER_MINIMUM_SUITE',
  'MESSENGER_OHTTP_KEY',
  'MESSENGER_OHTTP_RELAY',
];
const BASE58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function fail(name, message) {
  throw new Error(`${name} ${message}`);
}

function key(environment, name) {
  if (!/^[0-9a-f]{64}$/.test(environment[name] ?? '')) {
    fail(name, 'must be a 32-byte lowercase-hex key');
  }
  return environment[name];
}

// The core refuses low-order X25519 keys; OpenSSL refuses to derive with them too.
function contributory(hex) {
  try {
    diffieHellman({
      privateKey: generateKeyPairSync('x25519').privateKey,
      publicKey: createPublicKey({
        key: { kty: 'OKP', crv: 'X25519', x: Buffer.from(hex, 'hex').toString('base64url') },
        format: 'jwk',
      }),
    });
    return true;
  } catch {
    return false;
  }
}

function witnesses(environment) {
  if (!environment.MESSENGER_WITNESSES) {
    return ['a', 'b'].map((letter) => ({
      id: `witness-${letter}`,
      key: key(environment, `MESSENGER_WITNESS_${letter.toUpperCase()}_PUBLIC_KEY_HEX`),
      label: 'Morse',
    }));
  }
  return environment.MESSENGER_WITNESSES.split(';').map((entry) => {
    const [id, hex, label, ...rest] = entry.split(':');
    if (
      rest.length > 0 ||
      !/^[a-z0-9-]{1,64}$/.test(id) ||
      !/^[0-9a-f]{64}$/.test(hex ?? '') ||
      !/^[\x20-\x7e]{1,48}$/.test(label ?? '') ||
      label.trim() !== label
    ) {
      fail(
        'MESSENGER_WITNESSES',
        `entry "${entry}" must be id:key:label (id [a-z0-9-]{1,64}, 64 lowercase hex, ` +
          'label 1-48 printable ASCII without edge spaces)',
      );
    }
    return { id, key: hex, label };
  });
}

function address(text) {
  if (!/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(text)) return false;
  let value = 0n;
  for (const character of text) value = value * 58n + BigInt(BASE58.indexOf(character));
  const zeros = text.match(/^1*/)[0].length;
  return zeros + (value === 0n ? 0 : Math.ceil(value.toString(16).length / 2)) === 32;
}

function urls(environment, name, origins) {
  const values = environment[name] ? environment[name].split(',') : [];
  for (const value of values) {
    let url = null;
    try {
      url = new URL(value);
    } catch {}
    if (
      !/^https:\/\/[!-~]+$/.test(value) ||
      /[@?#]/.test(value) ||
      url?.protocol !== 'https:' ||
      (origins && url.origin !== value)
    ) {
      fail(
        name,
        `entry "${value}" must be an https ${origins ? 'origin' : 'URL'} with no userinfo, query or fragment`,
      );
    }
  }
  if (new Set(values).size !== values.length) fail(name, 'must not repeat a URL');
  return values;
}

// A relay a development build reaches: localhost, [::1] or a private IPv4 address.
function developmentOrigin(value) {
  let url = null;
  try {
    url = new URL(value);
  } catch {}
  const octets = url?.hostname.split('.').map(Number) ?? [];
  const privateIPv4 = octets.length === 4 && octets.every((part) => Number.isInteger(part) && part >= 0 && part <= 255) &&
    (octets[0] === 127 || octets[0] === 10 || (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31));
  return url?.protocol === 'http:' && url.origin === value &&
    (url.hostname === 'localhost' || url.hostname === '[::1]' || privateIPv4);
}

// RFC 9458 key configuration: key id, X25519, the key, HKDF-SHA256 with ChaCha20-Poly1305.
function ohttpLine(environment) {
  const key = environment.MESSENGER_OHTTP_KEY;
  const relay = environment.MESSENGER_OHTTP_RELAY;
  if (!key && !relay) return [];
  const [id, hex, ...rest] = (key ?? '').split(':');
  if (rest.length > 0 || !/^(0|[1-9][0-9]{0,2})$/.test(id ?? '') || Number(id) > 255 ||
    !/^[0-9a-f]{64}$/.test(hex ?? '') || !contributory(hex)) {
    fail('MESSENGER_OHTTP_KEY', 'must be <key id 0-255>:<contributory X25519 public key, 64 lowercase hex>');
  }
  if (!relay || !(developmentOrigin(relay) || urls(environment, 'MESSENGER_OHTTP_RELAY', true).length === 1)) {
    fail('MESSENGER_OHTTP_RELAY', 'must be the relay\'s https origin (http only on a local address)');
  }
  const config = Buffer.concat([Buffer.from([Number(id)]), Buffer.from('0020', 'hex'), Buffer.from(hex, 'hex'),
    Buffer.from('000400010003', 'hex')]);
  return [`${config.toString('hex')} ${relay}`];
}

function securityConfig(environment) {
  if (!VARIABLES.some((name) => environment[name])) return undefined;
  const transparency = key(environment, 'MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX');
  const delivery = key(environment, 'MESSENGER_DELIVERY_PUBLIC_KEY_HEX');
  if (!contributory(delivery)) {
    fail('MESSENGER_DELIVERY_PUBLIC_KEY_HEX', 'must not be a low-order X25519 key');
  }
  const difficulty = environment.MESSENGER_ABUSE_DIFFICULTY ?? '';
  if (!/^([1-9]|1[0-9]|2[0-4])$/.test(difficulty)) {
    fail('MESSENGER_ABUSE_DIFFICULTY', 'must be a canonical integer from 1 through 24');
  }

  const pinned = witnesses(environment);
  const source = environment.MESSENGER_WITNESSES
    ? 'MESSENGER_WITNESSES'
    : 'MESSENGER_WITNESS_A/B_PUBLIC_KEY_HEX';
  if (pinned.length > 16) fail(source, 'must pin 1 to 16 witnesses');
  if (
    new Set(pinned.map((witness) => witness.id)).size !== pinned.length ||
    new Set(pinned.map((witness) => witness.key)).size !== pinned.length
  ) {
    fail(source, 'witness IDs and public keys must be unique');
  }
  // ASCII IDs: UTF-16 order is byte order.
  pinned.sort((left, right) => (left.id < right.id ? -1 : 1));

  const anchor = environment.MESSENGER_ANCHOR || '-';
  const accounts = anchor.split(' ');
  if (anchor !== '-' && (accounts.length !== 2 || !accounts.every(address))) {
    fail('MESSENGER_ANCHOR', 'must be "<judge program id> <log account>" (base58 Solana addresses) or "-"');
  }
  const rpc = urls(environment, 'MESSENGER_RPC_URLS', false);
  if (anchor === '-' ? rpc.length > 0 : rpc.length < 3 || rpc.length > 8) {
    fail(
      'MESSENGER_RPC_URLS',
      anchor === '-' ? 'must be empty while MESSENGER_ANCHOR is "-"' : 'must list 3 to 8 URLs with an anchor',
    );
  }
  const relays = urls(environment, 'MESSENGER_RELAY_URLS', true);
  if (relays.length > 8) fail('MESSENGER_RELAY_URLS', 'must list at most 8 origins');
  const issuers =
    environment.MESSENGER_CREDIT_ISSUER === '-' ? [] : urls(environment, 'MESSENGER_CREDIT_ISSUER', true);
  if (issuers.length > 1) fail('MESSENGER_CREDIT_ISSUER', 'must be one origin');
  const logOrigin = environment.MESSENGER_LOG_ORIGIN || '-';
  // Printable ASCII without spaces or "+" (C2SP tlog-checkpoint origin).
  if (!/^[!-*,-~]+$/.test(logOrigin)) {
    fail('MESSENGER_LOG_ORIGIN', 'must be printable ASCII with no spaces or "+", or "-"');
  }
  const suite = environment.MESSENGER_MINIMUM_SUITE || '1';
  if (!/^[12]$/.test(suite)) fail('MESSENGER_MINIMUM_SUITE', 'must be 1 or 2');

  const frame = [
    '2',
    transparency,
    delivery,
    difficulty,
    String(Math.floor(pinned.length / 2) + 1),
    String(pinned.length),
    ...pinned.map((witness) => `${witness.id} ${witness.key} ${witness.label}`),
    anchor,
    String(rpc.length),
    ...rpc,
    String(relays.length),
    ...relays,
    issuers[0] ?? '-',
    logOrigin,
    suite,
    ...ohttpLine(environment),
  ].join('\n');
  const size = Buffer.byteLength(frame);
  if (size > 4096) fail('MESSENGER security config', `is ${size} bytes; the limit is 4,096`);
  return frame;
}

// set_id and trust profile of a v2 frame, for builds to print.
function witnessSet(frame) {
  const lines = frame.split('\n');
  const k = Number(lines[4]);
  const n = Number(lines[5]);
  const morseRun = lines
    .slice(6, 6 + n)
    .filter((line) => line.split(' ').slice(2).join(' ') === 'Morse').length;
  return {
    setId: createHash('sha256')
      .update(`morse-witness-set-v1${lines.slice(4, 6 + n).join('\n')}`)
      .digest('hex'),
    profile: morseRun >= k ? 'Bootstrap' : morseRun > 1 ? 'Transitional' : 'Open',
    k,
    n,
  };
}

module.exports = securityConfig;
securityConfig.witnessSet = witnessSet;
securityConfig.variables = VARIABLES;

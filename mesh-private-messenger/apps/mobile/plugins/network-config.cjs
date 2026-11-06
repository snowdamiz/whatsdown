// Executed at native build time. The resulting resource is unavailable to OTA
// URL overrides; Mesh independently validates the exact same frame on reads.
module.exports = function networkConfig(environment, { development = false } = {}) {
  const names = ['EXPO_PUBLIC_MESSENGER_BASE_URL', 'EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL',
    'EXPO_PUBLIC_MESSENGER_OBJECT_URL', 'EXPO_PUBLIC_MESSENGER_STREAM_URL'];
  if (!development && names.every((name) => environment[name] === undefined)) return undefined;
  function origin(input, label) {
    if (typeof input !== 'string' || input.length > 2048 || !/^[\x21-\x7e]+$/.test(input) || /[\\@?#]/.test(input)) {
      throw new Error(`Set a canonical ${label} origin`);
    }
    const url = new URL(input);
    if (url.origin !== input) throw new Error(`Set a canonical ${label} origin`);
    const loopback = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    if (url.protocol !== 'https:' && !(development && loopback && url.protocol === 'http:')) {
      throw new Error(`${label} requires TLS; development HTTP is loopback only`);
    }
    return input;
  }
  const localDefaults = development && !environment.EXPO_PUBLIC_MESSENGER_BASE_URL;
  const core = origin(environment.EXPO_PUBLIC_MESSENGER_BASE_URL ?? (localDefaults ? 'http://127.0.0.1:18086' : undefined), 'core');
  const edge = origin(environment.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL ?? (localDefaults ? 'http://127.0.0.1:18087' : undefined), 'edge');
  const objects = origin(environment.EXPO_PUBLIC_MESSENGER_OBJECT_URL || (localDefaults ? 'http://127.0.0.1:18089' : core), 'object');
  const stream = environment.EXPO_PUBLIC_MESSENGER_STREAM_URL || (localDefaults
    ? 'ws://127.0.0.1:18090/v1/mailbox/stream' : `${core.replace(/^http/, 'ws')}/v1/mailbox/stream`);
  const converted = stream.replace(/^ws:/, 'http:').replace(/^wss:/, 'https:');
  const streamOrigin = origin(new URL(converted).origin, 'stream');
  if (converted !== `${streamOrigin}/v1/mailbox/stream` || !/^wss?:\/\//.test(stream)) {
    throw new Error('Set a canonical mailbox stream URL');
  }
  const difficulty = environment.EXPO_PUBLIC_MESSENGER_OBJECT_WORK_DIFFICULTY ?? '16';
  if (!/^(?:[1-9]|1[0-9]|2[0-4])$/.test(difficulty)) {
    throw new Error('Object work difficulty must be a canonical integer between 1 and 24');
  }
  return ['2', development ? '1' : '0', core, edge, objects, stream, difficulty].join('\n');
};

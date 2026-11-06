import { getBase58Encoder } from '@solana/kit';
import { boundedBody } from './storage.mjs';

function wide(value, positive = false) {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 18446744073709551615n ||
    (positive && value === '0')) throw new Error('Invalid anchor directory coordinate');
  return BigInt(value);
}
function hex(value) {
  if (typeof value !== 'string' || !/^[a-f0-9]{64}$/.test(value)) throw new Error('Invalid anchor directory hash');
  return Uint8Array.from(value.match(/../g),byte=>parseInt(byte,16));
}
function index(value) {
  if (!Number.isInteger(value) || value < 0 || value >= 4096) throw new Error('Invalid anchor directory ring index');
  return value;
}

export function createAnchorDirectory(env, pins) {
  if (typeof env.MESSENGER_DELIVERY_INTERNAL_TOKEN !== 'string' || !env.MESSENGER_DELIVERY_INTERNAL_TOKEN.length) throw new Error('Missing anchor directory token');
  async function request(path, body) {
    return env.DIRECTORY.getByName('primary').fetch(`http://service/internal/v1/transparency/${path}`, {
      method:body ? 'POST' : 'GET',body,redirect:'error',signal:AbortSignal.timeout(10_000),
      headers:{Authorization:`Bearer ${env.MESSENGER_DELIVERY_INTERNAL_TOKEN}`,'Content-Type':'application/octet-stream'},
    });
  }
  async function document(response, limit) {
    if (response.status !== 200) {await response.body?.cancel(); throw new Error('Anchor directory request failed');}
    const bytes = await boundedBody(response,limit);
    if (!bytes) throw new Error('Anchor directory response too large');
    const value = JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));
    if (!value || Array.isArray(value) || value.version !== pins.version || value.service_key !== pins.serviceKey ||
      wide(value.tree_size,true) > 4294967295n) throw new Error('Anchor directory identity mismatch');
    wide(value.sequence,true); wide(value.timestamp_ms); hex(value.checkpoint_hash); hex(value.root);
    return value;
  }
  return {
    async candidate() {
      const response = await request(`anchor-candidate/${pins.version}`);
      if (response.status === 404) {await response.body?.cancel(); return null;}
      return document(response,8192);
    },
    async cosigns(entry, set) {
      if (entry.version !== pins.version || set.generation !== entry.generation || set.bytes.length !== 2752) throw new Error('Anchor historical set mismatch');
      const bytes = new Uint8Array(2768), data = new DataView(bytes.buffer);
      bytes.set([1,65,87,81]); data.setUint16(4,entry.version); data.setBigUint64(6,wide(entry.sequence,true));
      data.setUint16(14,index(entry.ringIndex)); bytes.set(set.bytes,16);
      const value = await document(await request('anchor-cosigns',bytes),65536);
      if (value.checkpoint_hash !== entry.checkpointHash || value.sequence !== entry.sequence || value.tree_size !== entry.treeSize ||
        value.generation !== entry.generation || value.ring_index !== entry.ringIndex || value.log_id !== pins.logId ||
        !Array.isArray(value.cosigns) || value.cosigns.length > 16) throw new Error('Anchor historical response mismatch');
      return value;
    },
    async record(intent, confirmation) {
      if (intent.kind !== 'post' || intent.version !== pins.version || wide(intent.treeSize,true) > 4294967295n) throw new Error('Invalid anchor directory receipt');
      const signature = getBase58Encoder().encode(confirmation.signature);
      if (signature.length !== 64) throw new Error('Invalid anchor transaction signature');
      const bytes = new Uint8Array(128), data = new DataView(bytes.buffer);
      bytes.set([1,75,84,65]); data.setUint16(4,intent.version); data.setBigUint64(6,wide(intent.sequence,true));
      data.setBigUint64(14,wide(intent.treeSize,true)); bytes.set(hex(intent.checkpointHash),22);
      data.setUint16(54,index(confirmation.ringIndex)); bytes.set(signature,56); data.setBigUint64(120,wide(confirmation.slot));
      const response = await request('anchors',bytes);
      await response.body?.cancel();
      if (![200,201].includes(response.status)) throw new Error('Anchor directory receipt failed');
    },
  };
}

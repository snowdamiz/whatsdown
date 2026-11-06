import { assertIsAddress, createKeyPairSignerFromBytes, getAddressDecoder } from '@solana/kit';

// Solana SDK ClusterType::get_genesis_hash. A mode never accepts an arbitrary
// supplied hash that could turn a mistaken endpoint into the intended cluster.
const GENESIS = {
  devnet:'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG',
  mainnet:'5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d',
};

async function wallet(encoded) {
  if (typeof encoded !== 'string' || !/^[a-f0-9]{128}$/.test(encoded)) throw new Error('Invalid anchor wallet secret');
  const bytes = Uint8Array.from(encoded.match(/../g),value=>parseInt(value,16));
  try { return await createKeyPairSignerFromBytes(bytes, false); }
  catch { throw new Error('Invalid anchor wallet key pair'); }
  finally { bytes.fill(0); }
}

export async function anchorWriterConfig(env) {
  const mode = env.MORSE_ANCHOR_MODE ?? 'off';
  if (mode === 'off') return null;
  if (!Object.hasOwn(GENESIS,mode) || !['on','off'].includes(env.MORSE_COSIGN_CRANK ?? 'off') ||
    typeof env.MORSE_ANCHOR_CONFIG !== 'string' || env.MORSE_ANCHOR_CONFIG.length > 4096) throw new Error('Invalid anchor writer configuration');
  let config;
  try { config = JSON.parse(env.MORSE_ANCHOR_CONFIG); }
  catch { throw new Error('Invalid anchor writer configuration'); }
  if (!config || Array.isArray(config) || Object.keys(config).some(key=>!['program','logName','version','serviceKey','origin','rpcUrl'].includes(key)) ||
    typeof config.logName !== 'string' || !/^[a-z0-9-]{1,32}$/.test(config.logName) || ![1,2].includes(config.version) ||
    typeof config.serviceKey !== 'string' || !/^[a-f0-9]{64}$/.test(config.serviceKey) || /^0+$/.test(config.serviceKey)) throw new Error('Invalid anchor log configuration');
  assertIsAddress(config.program);
  if (config.program === '11111111111111111111111111111111') throw new Error('Invalid anchor judge');
  const origin = config.origin ?? '';
  if (typeof origin !== 'string' || origin.length > 128 || (config.version === 1 ? origin !== '' : !/^[\x21-\x2a\x2c-\x7e]+$/.test(origin))) throw new Error('Invalid anchor log origin');
  let url;
  try { url = new URL(config.rpcUrl); }
  catch { throw new Error('Invalid anchor RPC configuration'); }
  if (url.protocol !== 'https:' || url.username || url.password || url.hash) throw new Error('Invalid anchor RPC configuration');
  const feePayer = await wallet(env.MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX);
  const anchorAuthority = await wallet(env.MORSE_ANCHOR_AUTHORITY_KEYPAIR_HEX);
  const serviceAddress = getAddressDecoder().decode(Uint8Array.from(config.serviceKey.match(/../g),value=>parseInt(value,16)));
  if (feePayer.address === anchorAuthority.address || [feePayer.address,anchorAuthority.address].includes(serviceAddress)) throw new Error('Anchor wallets and service key must be separate');
  const genesisHash = GENESIS[mode];
  const scope = JSON.stringify([genesisHash,config.program,config.logName,config.version,config.serviceKey,origin,feePayer.address,anchorAuthority.address]);
  return {...config,origin,rpcUrl:url.href,mode,genesisHash,scope,feePayer,anchorAuthority,
    authority:anchorAuthority.address,cosign:env.MORSE_COSIGN_CRANK === 'on'};
}

import assert from 'node:assert/strict';
import test from 'node:test';
import { createKeyPairSignerFromPrivateKeyBytes, getAddressEncoder, getAddressDecoder } from '@solana/kit';
import { anchorWriterConfig } from './anchor-config.mjs';

async function secret(seed) {
  const bytes = new Uint8Array(32).fill(seed), signer = await createKeyPairSignerFromPrivateKeyBytes(bytes);
  return Buffer.concat([Buffer.from(bytes),Buffer.from(getAddressEncoder().encode(signer.address))]).toString('hex');
}

test('writer configuration is off by default and imports separate nonextractable wallet resources only when enabled', async () => {
  assert.equal(await anchorWriterConfig({}),null);
  assert.equal(await anchorWriterConfig({MORSE_ANCHOR_MODE:'off',MORSE_ANCHOR_CONFIG:'broken'}),null);
  const document = {program:getAddressDecoder().decode(new Uint8Array(32).fill(3)),logName:'morse-main',version:2,
    serviceKey:'07'.repeat(32),origin:'morseapp.io/log/main/v2',rpcUrl:'https://rpc.example/'};
  const env = {MORSE_ANCHOR_MODE:'devnet',MORSE_COSIGN_CRANK:'on',MORSE_ANCHOR_CONFIG:JSON.stringify(document),
    MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX:await secret(41),MORSE_ANCHOR_AUTHORITY_KEYPAIR_HEX:await secret(42)};
  const config = await anchorWriterConfig(env);
  assert.equal(config.genesisHash,'EtWTRABZaYq6iMfeYKouRu166VU2xqa1wcaWoxPkrZBG');
  assert.equal(config.cosign,true); assert.equal(config.feePayer.keyPair.privateKey.extractable,false);
  assert.equal(config.anchorAuthority.keyPair.privateKey.extractable,false);
  assert.equal((await anchorWriterConfig({...env,MORSE_ANCHOR_CONFIG:JSON.stringify({...document,rpcUrl:'https://new.example/'})})).scope,config.scope);
  assert.notEqual((await anchorWriterConfig({...env,MORSE_ANCHOR_MODE:'mainnet'})).scope,config.scope);
  for (const changed of [{MORSE_ANCHOR_MODE:'testnet'},{MORSE_COSIGN_CRANK:'yes'},
    {MORSE_ANCHOR_CONFIG:JSON.stringify({...document,logName:null})},
    {MORSE_ANCHOR_AUTHORITY_KEYPAIR_HEX:env.MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX},
    {MORSE_ANCHOR_FEE_PAYER_KEYPAIR_HEX:'ab'.repeat(64)},
    {MORSE_ANCHOR_CONFIG:JSON.stringify({...document,rpcUrl:'http://rpc.example/'})},
    {MORSE_ANCHOR_CONFIG:JSON.stringify({...document,serviceKey:Buffer.from(getAddressEncoder().encode(config.feePayer.address)).toString('hex')})}]) {
    await assert.rejects(anchorWriterConfig({...env,...changed}));
  }
});

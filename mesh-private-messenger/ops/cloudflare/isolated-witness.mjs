import { Witness } from './witness-container.mjs';
import { initializeWitness, witnessRequest, directoryRequest } from './witness.mjs';
export { ContainerProxy } from '@cloudflare/containers';
export { CheckpointStore } from './checkpoint.mjs';

export class IsolatedWitness extends Witness {
  async attest() {
    await initializeWitness(this.env);
    await super.attest();
  }

  envVars = {
    MESSENGER_BASE_URL: 'http://directory.internal',
    MESSENGER_WITNESS_ID: this.env.MESSENGER_WITNESS_ID,
    MESSENGER_WITNESS_CHECKPOINT_PATH: 'http://checkpoint.internal/',
    MESSENGER_WITNESS_SIGNING_SEED_HEX: this.env.MESSENGER_WITNESS_SIGNING_SEED_HEX,
    MESSENGER_WITNESS_PUBLIC_KEY_HEX: this.env.MESSENGER_WITNESS_PUBLIC_KEY_HEX,
    MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX: this.env.MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX,
  };
}
IsolatedWitness.outboundByHost = {
  'directory.internal': async (request, env) => {
    const forwarded = directoryRequest(request, env);
    if (!forwarded) return new Response(null, { status: 404 });
    const response = await fetch(forwarded);
    if (response.status >= 300 && response.status < 400) return new Response(null, { status: 502 });
    return response;
  },
  'checkpoint.internal': (request, env) => env.WITNESS_STATE.getByName('primary').fetch(request),
};
export default { fetch: witnessRequest };

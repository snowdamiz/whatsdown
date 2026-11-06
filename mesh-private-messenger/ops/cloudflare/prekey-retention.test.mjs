import assert from 'node:assert/strict';
import test from 'node:test';
import { build } from 'esbuild';
import { fileURLToPath } from 'node:url';

test('Directory passes the explicit retention policy to Mesh and defaults to off', async () => {
  // Exercise the production class's environment construction. Only the host
  // Container/DurableObject bases are replaced; no Worker network is started.
  const output = await build({
    stdin: { resolveDir: fileURLToPath(new URL('.', import.meta.url)), contents: `
      import {Directory} from './worker.mjs';
      export function environment(value) { return new Directory({},value).envVars; }
    ` },
    bundle: true, write: false, platform: 'node', format: 'esm', conditions: ['workerd'],
    plugins: [{ name: 'owned-container-base', setup(builder) {
      builder.onResolve({ filter: /^(@cloudflare\/containers|cloudflare:workers)$/ }, args => ({ path: args.path, namespace: 'owned-host' }));
      builder.onLoad({ filter: /.*/, namespace: 'owned-host' }, () => ({ contents: `
        export class Container { constructor(ctx,env) { this.ctx=ctx; this.env=env; } }
        export class DurableObject extends Container {}
        export class ContainerProxy extends Container {}
        export const switchPort = value => value;
      `, loader: 'js' }));
    } }],
  });
  const { environment } = await import('data:text/javascript;base64,' + Buffer.from(output.outputFiles[0].text).toString('base64'));
  const env = Object.fromEntries(['MESSENGER_DATABASE_URL','MESSENGER_TRANSPARENCY_SIGNING_SEED_HEX',
    'MESSENGER_WITNESS_A_PUBLIC_KEY_HEX','MESSENGER_WITNESS_B_PUBLIC_KEY_HEX','MESSENGER_DELIVERY_SEALING_SEED_HEX',
    'MESSENGER_DELIVERY_INTERNAL_TOKEN','MESSENGER_PUSH_BROKER_INTERNAL_TOKEN'].map(name => [name,'owned-fixture']));
  assert.equal(environment(env).MESSENGER_PREKEY_RETENTION, 'off');
  for (const value of ['off','on','','true','ON',' on ']) {
    assert.equal(environment({ ...env, MESSENGER_PREKEY_RETENTION: value }).MESSENGER_PREKEY_RETENTION, value,
      'preserve explicit values so Mesh validates malformed configuration instead of silently disabling it');
  }
});

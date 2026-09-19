import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

export function compilerConfig(config, revision) {
  if (!/^[a-f0-9]{40}$/.test(revision)) throw new Error('Mesh revision must be a full commit SHA');
  return { ...config, containers: config.containers.map(container => ({
    ...container,
    image_vars: { ...container.image_vars, MESH_LANG_REVISION: revision },
  })) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const revision = process.env.MESH_LANG_REVISION ?? execFileSync('git', [
    'ls-remote', 'https://github.com/snowdamiz/mesh-lang.git', 'refs/heads/main',
  ], { encoding: 'utf8' }).split(/\s+/)[0];
  const config = JSON.parse(readFileSync(new URL('./wrangler.jsonc', import.meta.url), 'utf8'));
  writeFileSync(new URL('./wrangler.build.json', import.meta.url), JSON.stringify(compilerConfig(config, revision), null, 2) + '\n');
  console.log(`Building all services with Mesh ${revision}`);
}

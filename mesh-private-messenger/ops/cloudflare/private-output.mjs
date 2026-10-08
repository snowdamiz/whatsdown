import { existsSync, mkdirSync, readdirSync, realpathSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// The nearest existing ancestor, with symlinks resolved.
function real(path) {
  return existsSync(path) ? realpathSync(path) : join(real(dirname(path)), relative(dirname(path), path));
}

// A new private (0700) directory for generated keys, outside the repository.
// Exits with a message rather than write into the repository or over a key.
export function privateOutput(target, usage) {
  const fail = message => { console.error(message); process.exit(1); };
  if (!target) fail(usage);
  const out = resolve(target);
  const repository = realpathSync(fileURLToPath(new URL('../../../', import.meta.url)));
  const inside = relative(repository, real(out));
  if (!inside.startsWith('..') && !isAbsolute(inside)) fail(`Write keys outside the repository, not ${out}`);
  if (existsSync(out) && readdirSync(out).length) fail(`${out} is not empty; refusing to overwrite keys`);
  process.umask(0o077);
  mkdirSync(out, { recursive: true, mode: 0o700 });
  return out;
}

// Writes the security-pin variables of a client.env for a witness set:
//
//   node client-env.mjs --env <client.env> --keys <secrets.json> [--keys <more.json>] <id>:<label>...
//
// Witness `witness-a` takes MESSENGER_WITNESS_A_PUBLIC_KEY_HEX from the key files (id upper-cased,
// "-" -> "_"); the transparency and delivery public keys are refreshed when present. Only
// *_PUBLIC_KEY_HEX fields are read: seeds are never copied or printed. Other lines are kept, and
// nothing is written unless the resulting file builds a valid security config v2 frame.
// When a key file holds the OHTTP gateway's public key (and MESSENGER_OHTTP_GATEWAY_KEY_ID, a public
// number), MESSENGER_OHTTP_KEY pins it and MESSENGER_OHTTP_RELAY defaults to the privacy edge's origin.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { parseArgs } from 'node:util';
import securityConfig from '../../apps/mobile/plugins/security-config.cjs';

const quote = (value) => (/^[\w./:,@%+=-]*$/.test(value) ? value : `'${value.replaceAll("'", `'\\''`)}'`);
const unquote = (value) =>
  /^'.*'$/.test(value) ? value.slice(1, -1).replaceAll(`'\\''`, "'")
    : /^".*"$/.test(value) ? value.slice(1, -1) : value;

try {
  const { values, positionals } = parseArgs({
    options: { env: { type: 'string' }, keys: { type: 'string', multiple: true } },
    allowPositionals: true,
  });
  if (!values.env || !values.keys || positionals.length === 0) {
    throw new Error('usage: client-env.mjs --env <client.env> --keys <secrets.json> [--keys <file>] <id>:<label>...');
  }
  const publicKeys = {};
  let ohttpKeyId = '1';
  for (const file of values.keys) {
    let fields;
    try {
      fields = JSON.parse(readFileSync(file, 'utf8'));
    } catch {
      // JSON.parse errors quote the text, which may hold seeds.
      throw new Error(`${file} is not a readable JSON object`);
    }
    for (const [name, value] of Object.entries(fields)) {
      if (name.endsWith('_PUBLIC_KEY_HEX')) publicKeys[name] = value;
      if (name === 'MESSENGER_OHTTP_GATEWAY_KEY_ID') ohttpKeyId = String(value);
    }
  }
  const updates = {
    MESSENGER_WITNESSES: positionals.map((spec) => {
      const [id, label = ''] = spec.split(/:(.*)/s);
      const name = `MESSENGER_${id.toUpperCase().replaceAll('-', '_')}_PUBLIC_KEY_HEX`;
      if (typeof publicKeys[name] !== 'string') throw new Error(`No ${name} for witness "${id}" in the key files`);
      return `${id}:${publicKeys[name]}:${label}`;
    }).join(';'),
  };
  for (const name of ['MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX', 'MESSENGER_DELIVERY_PUBLIC_KEY_HEX']) {
    if (publicKeys[name]) updates[name] = publicKeys[name];
  }

  const lines = existsSync(values.env) ? readFileSync(values.env, 'utf8').split('\n') : [];
  const assignment = /^(?:export )?([A-Za-z_][A-Za-z0-9_]*)=(.*)$/;
  const current = Object.fromEntries(lines.map((line) => line.match(assignment)).filter(Boolean)
    .map(([, name, value]) => [name, unquote(value)]));
  if (publicKeys.MESSENGER_OHTTP_GATEWAY_PUBLIC_KEY_HEX) {
    updates.MESSENGER_OHTTP_KEY = `${ohttpKeyId}:${publicKeys.MESSENGER_OHTTP_GATEWAY_PUBLIC_KEY_HEX}`;
    if (!current.MESSENGER_OHTTP_RELAY && current.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL) {
      updates.MESSENGER_OHTTP_RELAY = new URL(current.EXPO_PUBLIC_MESSENGER_PRIVACY_EDGE_URL).origin;
    }
  }
  const frame = securityConfig({ ...current, ...updates });
  const { setId, profile, k, n } = securityConfig.witnessSet(frame);

  for (const [name, value] of Object.entries(updates)) {
    const line = `export ${name}=${quote(value)}`;
    const index = lines.findIndex((existing) => existing.match(assignment)?.[1] === name);
    if (index >= 0) {
      lines[index] = line;
    } else {
      lines.splice(lines.findLastIndex((existing) => existing.startsWith('export ')) + 1, 0, line);
    }
  }
  writeFileSync(values.env, lines.join('\n'), { mode: 0o600 });
  console.log(`Updated ${Object.keys(updates).join(', ')} in ${values.env}.`);
  console.log(`Witness set_id ${setId}, ${profile}, ${k} of ${n}.`);
} catch (error) {
  console.error(error.message);
  process.exitCode = 1;
}

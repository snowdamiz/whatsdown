// The security config release builds pin (INTERFACES §4), read the way
// phones read it. No dependencies, so the status page and alerts need none.
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';

const securityConfig = createRequire(import.meta.url)('../../apps/mobile/plugins/security-config.cjs');
const { witnessSet } = securityConfig;

// The frame release builds pin: given whole, from a file, or built from the
// same MESSENGER_* variables the release workflows build it from.
export function securityFrame(env) {
  if (env.MORSE_SECURITY_CONFIG) return env.MORSE_SECURITY_CONFIG;
  if (env.MORSE_SECURITY_CONFIG_FILE) return readFileSync(env.MORSE_SECURITY_CONFIG_FILE, 'utf8').replace(/\n$/, '');
  return env.MESSENGER_TRANSPARENCY_PUBLIC_KEY_HEX ? securityConfig(env) : null;
}

export function parseSecurityConfig(frame) {
  const lines = frame.replace(/\n$/, '').split('\n');
  if (lines[0] === '1') {
    return { frame, version: 1, k: 2, n: 2, witnesses: [{ id: 'witness-a', key: lines[2], label: 'Morse' }, { id: 'witness-b', key: lines[3], label: 'Morse' }],
      anchor: null, rpc: [], relays: [], issuer: null, origin: null, profile: 'Bootstrap', profileLine: 'Bootstrap: all 2 witnesses are run by Morse', setId: null,
      difficulty: Number(lines[5]) };
  }
  if (lines[0] !== '2') throw new Error('unsupported security config version');
  const n = Number(lines[5]);
  const witnesses = lines.slice(6, 6 + n).map(line => {
    const [id, key, ...label] = line.split(' ');
    return { id, key, label: label.join(' ') };
  });
  let at = 6 + n;
  const anchorLine = lines[at++];
  const anchor = anchorLine === '-' ? null : { judge: anchorLine.split(' ')[0], log: anchorLine.split(' ')[1] };
  const take = () => { const count = Number(lines[at++]); const out = lines.slice(at, at + count); at += count; return out; };
  const rpc = take();
  const relays = take();
  const optional = value => value === '-' ? null : value;
  const issuer = optional(lines[at++]);
  const origin = optional(lines[at++]);
  const { setId, profile } = witnessSet(frame);
  const morseRun = witnesses.filter(w => w.label === 'Morse').length;
  const profileLine = profile === 'Bootstrap' ? `Bootstrap: all ${n} witnesses are run by Morse`
    : profile === 'Transitional' ? `Transitional: ${morseRun} of ${n} witnesses are run by Morse`
      : `Open: ${n - morseRun} of ${n} witnesses are independent`;
  return { frame, version: 2, k: Number(lines[4]), n, witnesses, anchor, rpc, relays, issuer, origin, profile, profileLine, setId, morseRun,
    difficulty: Number(lines[3]) };
}


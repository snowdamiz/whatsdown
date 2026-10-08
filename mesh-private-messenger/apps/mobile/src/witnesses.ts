import {
  parseAlarmSection,
  parseAnchorSection,
  parseBondSection,
  type AnchorStatus,
  type BondCounter,
  type TrustAlarmNotice,
} from './public-record.ts';

// The witness network as this build pins it, from Mesh's network status (see
// mobile-core Mobile.NetworkStatus): the profile, k of n, and each pinned
// witness with its operator label. A witness is run by Morse when its label is
// exactly "Morse".

export type NetworkProfile = 'bootstrap' | 'transitional' | 'open';

export type PinnedWitness = { id: string; label: string; morseRun: boolean };

export type NetworkStatus = {
  profile: NetworkProfile;
  threshold: number;
  witnesses: PinnedWitness[];
  setId: Uint8Array;
  // A group this device is in uses a witness set this build does not know.
  updateRequired: boolean;
  // The phone's last check against the public record, the bond counter, and
  // the trust alarm blocking new chats (sections 2-4; absent on older builds).
  anchor?: AnchorStatus;
  bonds?: BondCounter;
  alarm?: TrustAlarmNotice;
};

const profiles: readonly string[] = ['bootstrap', 'transitional', 'open'];
const decoder = new TextDecoder('utf-8', { fatal: true });

export function parseNetworkStatus(input: Uint8Array): NetworkStatus {
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  let offset = 0;
  const take = (length: number): Uint8Array => {
    if (offset + length > input.length) throw new Error('Truncated network status');
    const value = input.slice(offset, offset + length);
    offset += length;
    return value;
  };
  const byte = (): number => take(1)[0]!;
  const u16 = (): number => { take(2); return view.getUint16(offset - 2); };
  const vector = (maximum: number): Uint8Array => {
    take(4);
    const length = view.getUint32(offset - 4);
    if (length > maximum) throw new Error('Invalid network status');
    return take(length);
  };
  const text = (maximum: number): string => decoder.decode(vector(maximum));
  if (byte() !== 1 || decoder.decode(take(3)) !== 'NST') throw new Error('Invalid network status');
  const profile = text(16);
  const threshold = byte();
  const count = byte();
  const morse = byte();
  const setId = take(32);
  const witnesses: PinnedWitness[] = [];
  for (let index = 0; index < count; index += 1) {
    witnesses.push({ id: text(64), label: text(48), morseRun: byte() === 1 });
  }
  let updateRequired = false;
  const extra: Pick<NetworkStatus, 'anchor' | 'bonds' | 'alarm'> = {};
  const sections = byte();
  for (let index = 0; index < sections; index += 1) {
    const tag = u16();
    const body = vector(65_536);
    // Tags this build does not know are skipped.
    if (tag === 1) updateRequired = body[0] === 1;
    else if (tag === 2) extra.anchor = parseAnchorSection(body);
    else if (tag === 3) extra.bonds = parseBondSection(body);
    else if (tag === 4) extra.alarm = parseAlarmSection(body);
  }
  if (
    offset !== input.length || !profiles.includes(profile) || count < 1 || count > 16 ||
    threshold < 1 || threshold > count || morse !== witnesses.filter((witness) => witness.morseRun).length
  ) {
    throw new Error('Invalid network status');
  }
  return { profile: profile as NetworkProfile, threshold, witnesses, setId, updateRequired, ...extra };
}

const plural = (count: number, one: string, many: string): string => `${count} ${count === 1 ? one : many}`;

// Settings -> Network: "Bootstrap: all 3 witnesses are run by Morse", or
// "Open: 4 of 5 witnesses are independent".
export function profileLine({ profile, witnesses }: NetworkStatus): string {
  const total = witnesses.length;
  const morse = witnesses.filter((witness) => witness.morseRun).length;
  const independent = total - morse;
  if (profile === 'bootstrap') {
    return morse === total
      ? `Bootstrap: ${total === 1 ? 'the witness is' : `all ${total} witnesses are`} run by Morse`
      : `Bootstrap: ${morse} of ${plural(total, 'witness', 'witnesses')} are run by Morse`;
  }
  const name = profile === 'open' ? 'Open' : 'Transitional';
  return `${name}: ${independent} of ${plural(total, 'witness', 'witnesses')} ${independent === 1 ? 'is' : 'are'} independent`;
}

// The safety number screen: "Key checked by 2 of 3 witnesses".
export const keyCheckedLine = ({ threshold, witnesses }: NetworkStatus): string =>
  `Key checked by ${threshold} of ${plural(witnesses.length, 'witness', 'witnesses')}`;

export const witnessNote = (witness: PinnedWitness): string =>
  witness.morseRun ? 'Run by Morse' : witness.label;

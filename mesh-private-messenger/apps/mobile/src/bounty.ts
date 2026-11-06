import { isLegacyDesktopBridge } from '../modules/mesh-messenger';
import type { ScopedClient } from '../modules/mesh-messenger/scoped';
import {
  bounty_status_export, bounty_transfer_status_export, bounty_transfer_recover_export,
  bounty_transfer_cancel_export, invokeWallet,
} from '../modules/mesh-messenger';
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });
const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const nonzero = (bytes: Uint8Array, length: number) => bytes.length === length && bytes.some(n => n !== 0);
const same = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((n, i) => n === b[i]);
function packet(...values: Uint8Array[]): Uint8Array {
  const bytes = new Uint8Array(4 + values.reduce((n, v) => n + 4 + v.length, 0));
  const view = new DataView(bytes.buffer); view.setUint32(0, values.length);
  let at = 4;
  for (const value of values) { view.setUint32(at, value.length); at += 4; bytes.set(value, at); at += value.length; }
  return bytes;
}
function fields(input: Uint8Array, count: number, maximum: number): Uint8Array[] {
  if (input.length < 4 || input.length > maximum) throw Error('invalid_bounty_response');
  const view = new DataView(input.buffer, input.byteOffset, input.byteLength);
  if (view.getUint32(0) !== count) throw Error('invalid_bounty_response');
  const values: Uint8Array[] = []; let at = 4;
  for (let i = 0; i < count; i++) {
    if (at + 4 > input.length) throw Error('invalid_bounty_response');
    const length = view.getUint32(at); at += 4;
    if (length > input.length - at) throw Error('invalid_bounty_response');
    values.push(input.slice(at, at + length)); at += length;
  }
  if (at !== input.length) throw Error('invalid_bounty_response');
  return values;
}
function byte(value: Uint8Array, maximum: number): number {
  if (value.length !== 1 || value[0]! > maximum) throw Error('invalid_bounty_response');
  return value[0]!;
}
function wide(value: Uint8Array): bigint {
  if (value.length !== 8) throw Error('invalid_bounty_response');
  return new DataView(value.buffer, value.byteOffset, 8).getBigUint64(0);
}
export // Public address presentation only. The native journal and SDK independently
// validate destinations and own every transaction/custody decision.
function publicAddress(bytes: Uint8Array): string {
  let value = 0n; for (const n of bytes) value = value * 256n + BigInt(n);
  let text = '';
  while (value > 0n) { text = alphabet[Number(value % 58n)]! + text; value /= 58n; }
  for (const n of bytes) { if (n !== 0) break; text = '1' + text; }
  return text;
}
export function destinationAddress(text: string): Uint8Array {
  if (text.length < 32 || text.length > 44) throw Error('invalid_bounty_destination');
  let value = 0n;
  for (const char of text) {
    const digit = alphabet.indexOf(char); if (digit < 0) throw Error('invalid_bounty_destination');
    value = value * 58n + BigInt(digit);
  }
  const bytes = new Uint8Array(32);
  for (let at = 31; at >= 0; at--) { bytes[at] = Number(value % 256n); value /= 256n; }
  if (value !== 0n || !nonzero(bytes, 32) || publicAddress(bytes) !== text) throw Error('invalid_bounty_destination');
  return bytes;
}
export function tokenAmount(amount: bigint, decimals: number): string {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 18 || amount < 0n) throw Error('invalid_bounty_response');
  const text = amount.toString();
  if (decimals === 0) return text;
  const padded = text.padStart(decimals + 1, '0');
  return padded.slice(0, -decimals) + '.' + padded.slice(-decimals);
}
export type BountySelection = { enabled: boolean; status: 0|1|2|3|4|5; proofHash: Uint8Array; finder: Uint8Array; index: bigint };
export function parseBountySelection(input: Uint8Array): BountySelection {
  const f = fields(input, 6, 160);
  if (decoder.decode(f[0]) !== '\u0001BFP') throw Error('invalid_bounty_response');
  const enabled = byte(f[1]!, 1) === 1, status = byte(f[2]!, 5) as BountySelection['status'];
  const index = wide(f[5]!);
  if ((status === 0 ? f[3]!.length !== 0 : !nonzero(f[3]!, 32)) ||
      (status < 2 ? f[4]!.length !== 0 : f[4]!.length !== 32) ||
      (status === 3 ? index >= 2147483648n || !nonzero(f[4]!, 32) : index !== 0n) ||
      ((status === 2 || status === 4) && f[4]!.some(n => n !== 0))) throw Error('invalid_bounty_response');
  return { enabled, status, proofHash: f[3]!, finder: f[4]!, index };
}
export type BountyMovement = {
  identity: Uint8Array; status: 0|1|2|3|4|5; signature: Uint8Array; finder: Uint8Array;
  destination: Uint8Array; mint: Uint8Array; amount: bigint; decimals: number;
  fee: bigint; finalizedSlot: bigint; error: string;
};
export function parseBountyMovement(input: Uint8Array): BountyMovement {
  const f = fields(input, 12, 2048);
  if (decoder.decode(f[0]) !== '\u0001BMW') throw Error('invalid_bounty_response');
  const status = byte(f[2]!, 5) as BountyMovement['status'];
  const amount = wide(f[7]!), decimals = byte(f[8]!, 18), fee = wide(f[9]!), finalizedSlot = wide(f[10]!);
  const error = decoder.decode(f[11]);
  if (f[11]!.length > 256) throw Error('invalid_bounty_response');
  if (f[1]!.length === 0) {
    if (status !== 0 || f[3]!.length || f[4]!.length || f[5]!.length || f[6]!.length || amount || decimals || fee || finalizedSlot || error) throw Error('invalid_bounty_response');
  } else if (!nonzero(f[1]!, 32) || !nonzero(f[4]!, 32) || !nonzero(f[5]!, 32) || !nonzero(f[6]!, 32) || amount === 0n ||
      (status < 2 ? f[3]!.length !== 0 : !nonzero(f[3]!, 64)) ||
      (status < 4 ? fee !== 0n || finalizedSlot !== 0n || error !== '' : finalizedSlot === 0n || (status === 4 ? error !== '' : error === ''))) throw Error('invalid_bounty_response');
  return { identity: f[1]!, status, signature: f[3]!, finder: f[4]!, destination: f[5]!, mint: f[6]!, amount, decimals, fee, finalizedSlot, error };
}
export function createBountyServices(deps: Pick<ScopedClient, 'runPrivate' | 'bounty_status_export' | 'bounty_transfer_cancel_export' | 'bounty_transfer_recover_export' | 'bounty_transfer_status_export' | 'invokeWallet' | 'onDispose'>) {
const { bounty_status_export, bounty_transfer_status_export, bounty_transfer_recover_export, bounty_transfer_cancel_export, invokeWallet } = deps;
const readBountySelection = async (database: string) => parseBountySelection(await bounty_status_export(encoder.encode(database)));
const setBountyEnabled = async (enabled: boolean) => parseBountySelection(await invokeWallet(7, Uint8Array.of(enabled ? 1 : 0)));
const readBountyMovement = async (database: string) => parseBountyMovement(await bounty_transfer_status_export(encoder.encode(database)));
async function recoverBountyMovement(database: string, identity: Uint8Array): Promise<BountyMovement> {
  if (!nonzero(identity, 32)) throw Error('invalid_bounty_request');
  const value = parseBountyMovement(await bounty_transfer_recover_export(packet(encoder.encode(database), identity)));
  if (!same(value.identity, identity)) throw Error('invalid_bounty_response');
  return value;
}
async function cancelBountyMovement(database: string, identity: Uint8Array): Promise<BountyMovement> {
  if (!nonzero(identity, 32)) throw Error('invalid_bounty_request');
  const value = parseBountyMovement(await bounty_transfer_cancel_export(packet(encoder.encode(database), identity)));
  if (!same(value.identity, identity) || value.status !== 0) throw Error('invalid_bounty_response');
  return value;
}
async function moveBounty(database: string, destination: string): Promise<BountyMovement> {
  const address = destinationAddress(destination);
  const value = parseBountyMovement(await invokeWallet(8, packet(encoder.encode(database), address)));
  if (!same(value.destination, address)) throw Error('invalid_bounty_response');
  return value;
}
return Object.freeze({
  readBountySelection: (...args: Parameters<typeof readBountySelection>) => deps.runPrivate(() => readBountySelection(...args)),
  setBountyEnabled: (...args: Parameters<typeof setBountyEnabled>) => deps.runPrivate(() => setBountyEnabled(...args)),
  readBountyMovement: (...args: Parameters<typeof readBountyMovement>) => deps.runPrivate(() => readBountyMovement(...args)),
  recoverBountyMovement: (...args: Parameters<typeof recoverBountyMovement>) => deps.runPrivate(() => recoverBountyMovement(...args)),
  cancelBountyMovement: (...args: Parameters<typeof cancelBountyMovement>) => deps.runPrivate(() => cancelBountyMovement(...args)),
  moveBounty: (...args: Parameters<typeof moveBounty>) => deps.runPrivate(() => moveBounty(...args)),
});
}
let legacyScopeServices: ReturnType<typeof createBountyServices> | undefined;
function desktopCompatibility() {
if (!isLegacyDesktopBridge) throw new Error('scoped_client_required');
return legacyScopeServices ??= createBountyServices({ runPrivate: operation => operation(), onDispose: () => () => {}, bounty_status_export, bounty_transfer_status_export, bounty_transfer_recover_export, bounty_transfer_cancel_export, invokeWallet });
}
export const readBountySelection: ReturnType<typeof createBountyServices>['readBountySelection'] = (...args) => desktopCompatibility().readBountySelection(...args);
export const setBountyEnabled: ReturnType<typeof createBountyServices>['setBountyEnabled'] = (...args) => desktopCompatibility().setBountyEnabled(...args);
export const readBountyMovement: ReturnType<typeof createBountyServices>['readBountyMovement'] = (...args) => desktopCompatibility().readBountyMovement(...args);
export const recoverBountyMovement: ReturnType<typeof createBountyServices>['recoverBountyMovement'] = (...args) => desktopCompatibility().recoverBountyMovement(...args);
export const cancelBountyMovement: ReturnType<typeof createBountyServices>['cancelBountyMovement'] = (...args) => desktopCompatibility().cancelBountyMovement(...args);
export const moveBounty: ReturnType<typeof createBountyServices>['moveBounty'] = (...args) => desktopCompatibility().moveBounty(...args);

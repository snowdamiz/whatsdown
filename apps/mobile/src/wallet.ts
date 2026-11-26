import { walletNative } from '../modules/mesh-messenger/wallet';
import { base58, fromBase58 } from './base58.ts';

export { base58, fromBase58 };

// The in-app Solana wallet (plan §6.13), for phones and the desktop alike. The seed
// lives in the platform keystore and wallet-core signs; this file only builds the
// frames of packages/wallet-core/README.md ("C ABI") that follow the seed, and reads
// the answers. Wallet addresses never go to a Morse server.

// Mainnet USDC. Which mint the wallet treats as USDC follows the chain its
// providers serve (solana.ts clusterOf).
export const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v';
export const USDC_DECIMALS = 6;
export const SOL_DECIMALS = 9;

export type WalletKey = { kind: 'account' | 'bounty'; index: number };
export type Asset = { kind: 'sol' } | { kind: 'spl'; mint: string; decimals: number };
export type Transfer = {
  owner: WalletKey;
  // The account that pays the fee (and any token account creation).
  feePayer: number;
  asset: Asset;
  amount: bigint;
  recipient: string;
  createRecipientAccount: boolean;
  references: string[];
  memo: string;
  computeUnitLimit: number;
  computeUnitPrice: bigint;
  blockhash: string;
};
export type Signed = { signature: string; transaction: string };
export type PayRequest = {
  recipient: string;
  // amount = mantissa / 10^scale, as the URL wrote it.
  amount: { mantissa: bigint; scale: number } | null;
  splToken: string | null;
  references: string[];
  label: string;
  message: string;
  memo: string;
};
export type BountyAddress = { index: number; address: string };

const concat = (...parts: Uint8Array[]): Uint8Array => {
  const output = new Uint8Array(parts.reduce((total, part) => total + part.length, 0));
  let offset = 0;
  for (const part of parts) { output.set(part, offset); offset += part.length; }
  return output;
};
const u32 = (value: number): Uint8Array => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, value); return b; };
const u64 = (value: bigint): Uint8Array => { const b = new Uint8Array(8); new DataView(b.buffer).setBigUint64(0, value); return b; };
const vec32 = (value: Uint8Array): Uint8Array => concat(u32(value.length), value);
const utf8 = (text: string): Uint8Array => new TextEncoder().encode(text);

class Read {
  private offset = 0;
  private readonly input: Uint8Array;
  constructor(input: Uint8Array) { this.input = input; }
  take(length: number): Uint8Array {
    if (this.offset + length > this.input.length) throw new Error('bad_frame');
    this.offset += length;
    return this.input.subarray(this.offset - length, this.offset);
  }
  byte(): number { return this.take(1)[0]!; }
  u32(): number { const b = this.take(4); return new DataView(b.buffer, b.byteOffset, 4).getUint32(0); }
  u64(): bigint { const b = this.take(8); return new DataView(b.buffer, b.byteOffset, 8).getBigUint64(0); }
  text(): string { return new TextDecoder('utf-8', { fatal: true }).decode(this.take(this.u32())); }
  end(): void { if (this.offset !== this.input.length) throw new Error('bad_frame'); }
}

export const encodeKey = (key: WalletKey): Uint8Array => concat(Uint8Array.of(key.kind === 'account' ? 1 : 2), u32(key.index));

// Op 5's body after the seed.
export function encodeTransfer(transfer: Transfer): Uint8Array {
  const asset = transfer.asset.kind === 'sol'
    ? Uint8Array.of(1)
    : concat(Uint8Array.of(2), fromBase58(transfer.asset.mint), Uint8Array.of(transfer.asset.decimals));
  if (transfer.references.length > 255) throw new Error('bad_reference');
  return concat(
    encodeKey(transfer.owner),
    encodeKey({ kind: 'account', index: transfer.feePayer }),
    asset,
    u64(transfer.amount),
    fromBase58(transfer.recipient),
    Uint8Array.of(transfer.createRecipientAccount ? 1 : 0),
    Uint8Array.of(transfer.references.length),
    ...transfer.references.map(fromBase58),
    vec32(utf8(transfer.memo)),
    u32(transfer.computeUnitLimit),
    u64(transfer.computeUnitPrice),
    fromBase58(transfer.blockhash),
  );
}

export function decodePayRequest(input: Uint8Array): PayRequest {
  const read = new Read(input);
  const recipient = base58(read.take(32));
  const amount = read.byte() === 1 ? { mantissa: read.u64(), scale: read.byte() } : null;
  const splToken = read.byte() === 1 ? base58(read.take(32)) : null;
  const references = Array.from({ length: read.byte() }, () => base58(read.take(32)));
  const [label, message, memo] = [read.text(), read.text(), read.text()];
  read.end();
  return { recipient, amount, splToken, references, label, message, memo };
}

// A Solana Pay amount in the asset's base units; more decimals than it has is refused.
export function baseUnits(amount: { mantissa: bigint; scale: number }, decimals: number): bigint {
  if (amount.scale > decimals) throw new Error('too_many_decimals');
  return amount.mantissa * 10n ** BigInt(decimals - amount.scale);
}

export const walletExists = (): Promise<boolean> => walletNative.walletExists();
// Returns the recovery phrase: the one time it is shown without asking.
export const createWallet = (words: 12 | 24): Promise<string> => walletNative.walletCreate(words);
export const restoreWallet = (phrase: string): Promise<void> => walletNative.walletRestore(phrase);
export const showPhrase = (): Promise<string> => walletNative.walletPhrase();
export const wipeWallet = (): Promise<void> => walletNative.walletWipe();

export async function walletAddress(key: WalletKey = { kind: 'account', index: 0 }): Promise<string> {
  const answer = await walletNative.walletCall(4, encodeKey(key));
  if (answer.length !== 32) throw new Error('bad_frame');
  return base58(answer);
}

// A fresh one-time address for one fork proof (plan §6.3): the host persists the
// next index before it answers, so an address is never handed out twice.
export async function nextBountyAddress(): Promise<BountyAddress> {
  const read = new Read(await walletNative.walletNextBountyAddress());
  const index = read.u32();
  const address = base58(read.take(32));
  read.end();
  return { index, address };
}

export async function bountyAddresses(): Promise<BountyAddress[]> {
  const issued = await walletNative.walletBountyIndex(0);
  const addresses: BountyAddress[] = [];
  for (let index = 0; index < issued; index += 1) {
    addresses.push({ index, address: await walletAddress({ kind: 'bounty', index }) });
  }
  return addresses;
}

export const raiseBountyIndex = (atLeast: number): Promise<number> => walletNative.walletBountyIndex(atLeast);

export async function signTransfer(transfer: Transfer): Promise<Signed> {
  const read = new Read(await walletNative.walletCall(5, encodeTransfer(transfer)));
  const signed = { signature: read.text(), transaction: read.text() };
  read.end();
  return signed;
}

export async function parsePayUrl(url: string): Promise<PayRequest> {
  return decodePayRequest(await walletNative.walletCall(6, vec32(utf8(url))));
}

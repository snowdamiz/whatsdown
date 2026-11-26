import { invoke, type InvokeArgs, type InvokeOptions } from '@tauri-apps/api/core';
import type { WalletNative } from './wallet';

// Desktop: the same host API as Tauri commands (src-tauri/src/wallet.rs), with the
// seed in the OS credential store.
const call = <T>(command: string, args?: InvokeArgs, options?: InvokeOptions) =>
  invoke<T>(command, args, options).catch((error) => { throw new Error(String(error)); });
const bytes = async (pending: Promise<ArrayBuffer>): Promise<Uint8Array> => new Uint8Array(await pending);

export const walletNative: WalletNative = {
  walletExists: () => call('wallet_exists'),
  walletCreate: (words) => call('wallet_create', { words }),
  walletRestore: (phrase) => call('wallet_restore', { phrase }),
  walletPhrase: () => call('wallet_phrase'),
  walletWipe: () => call('wallet_wipe'),
  walletCall: (op, body) => bytes(call('wallet_call', body, { headers: { 'X-Wallet-Op': String(op) } })),
  walletNextBountyAddress: () => bytes(call('wallet_next_bounty_address')),
  walletBountyIndex: (atLeast) => call('wallet_bounty_index', { atLeast }),
};

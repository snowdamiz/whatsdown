import { requireNativeModule } from 'expo-modules-core';

// The in-app wallet's native side: packages/wallet-core behind the platform keystore
// (Keychain this-device-only, Android Keystore). The seed never crosses into
// JavaScript; only the recovery phrase, for display, and public keys, parsed pay
// requests and signed transactions do. Error messages carry wallet-core's codes
// (bad_mnemonic, ...) or the host's: wallet_exists, wallet_missing,
// bounty_not_issued, fee_payer_not_account, authentication_failed.
export type WalletNative = {
  walletExists(): Promise<boolean>;
  // 12 or 24 words; stores the seed and returns the phrase to show once.
  walletCreate(words: number): Promise<string>;
  walletRestore(phrase: string): Promise<void>;
  // Behind the device owner's authentication where the platform has it.
  walletPhrase(): Promise<string>;
  walletWipe(): Promise<void>;
  // wallet-core op 4 (address), 5 (transfer) or 6 (parse a Solana Pay URL), with
  // the frame body after the seed; the host puts the seed in.
  walletCall(op: number, body: Uint8Array): Promise<Uint8Array>;
  // u32 index || public key: the next bounty address, its index persisted first.
  walletNextBountyAddress(): Promise<Uint8Array>;
  // Raises the next bounty index to at least `atLeast` and returns it.
  walletBountyIndex(atLeast: number): Promise<number>;
};

export const walletNative = requireNativeModule<WalletNative>('MorseWallet');

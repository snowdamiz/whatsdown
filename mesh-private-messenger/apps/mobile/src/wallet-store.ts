import { fromBase58, nextBountyAddress, walletExists } from './wallet.ts';
import { finderAddress, parseWalletSettings, type WalletSettings } from './wallet-settings.ts';
import { journals } from './sealed-journals';

// The wallet's settings, sealed by the core in the app's database like every journal.
export const loadWalletSettings = async (): Promise<WalletSettings> => parseWalletSettings(await journals.load('wallet'));
export const saveWalletSettings = (settings: WalletSettings): Promise<void> => journals.save('wallet', { settings });

// The anchor check's finder hook (network.ts setFinderAddressSource): a fresh bounty
// address when "Collect fork bounties" is on and the wallet exists, else none.
export async function walletFinderAddress(): Promise<Uint8Array | null> {
  const ready = await walletExists().catch(() => false);
  return finderAddress(await loadWalletSettings(), ready, async () => fromBase58((await nextBountyAddress()).address));
}

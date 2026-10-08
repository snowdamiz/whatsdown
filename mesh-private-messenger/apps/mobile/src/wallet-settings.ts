import { friendlyError } from './format.ts';

// The wallet's choices, sealed in the app's database (journal "wallet") and reset
// when the wallet is deleted. Plan §10 and D13: "Collect fork bounties" is off until
// the person turns it on, needs the in-app wallet, and is offered once, when the
// wallet is set up.
export type WalletSettings = {
  collectBounties: boolean;
  bountiesOffered: boolean;
  // "A move is as public as any transfer", said before the first bounty move.
  moveNoticeSeen: boolean;
  // "The purchase is as public as any on-chain payment" (§6.11), before the first payment.
  payNoticeSeen: boolean;
  // A restored wallet still has to find the bounty addresses it handed out before.
  bountyScanPending: boolean;
};

export const defaultWalletSettings: WalletSettings = {
  collectBounties: false,
  bountiesOffered: false,
  moveNoticeSeen: false,
  payNoticeSeen: false,
  bountyScanPending: false,
};

export function parseWalletSettings(journal: string | null): WalletSettings {
  let kept: unknown;
  try { kept = journal === null ? null : (JSON.parse(journal) as { settings?: unknown }).settings; } catch { kept = null; }
  if (!kept || typeof kept !== 'object') return defaultWalletSettings;
  const flags = kept as Record<string, unknown>;
  return Object.fromEntries(Object.keys(defaultWalletSettings).map((name) => [name, flags[name] === true])) as WalletSettings;
}

export const offerBounties = (settings: WalletSettings, walletReady: boolean): boolean =>
  walletReady && !settings.bountiesOffered;

export const answerBountyOffer = (settings: WalletSettings, accept: boolean): WalletSettings =>
  ({ ...settings, bountiesOffered: true, collectBounties: accept });

export function setCollectBounties(settings: WalletSettings, walletReady: boolean, on: boolean): WalletSettings {
  if (on && !walletReady) throw new Error('wallet_required');
  return { ...settings, collectBounties: on };
}

// The anchor check's finder hook: a fresh one-time address (its 32 bytes) for this
// proof, or none (the finder field stays zero, and the proof is filed all the same):
// a wallet that can't answer never holds the proof up.
export async function finderAddress(
  settings: WalletSettings,
  walletReady: boolean,
  next: () => Promise<Uint8Array>,
): Promise<Uint8Array | null> {
  if (!settings.collectBounties || !walletReady) return null;
  try { return await next(); } catch { return null; }
}

// The confirm step after a new phrase is shown: two distinct word positions, in order.
export function pickConfirmation(count: number, random: () => number = Math.random): [number, number] {
  const first = Math.floor(random() * count);
  const second = (first + 1 + Math.floor(random() * (count - 1))) % count;
  return first < second ? [first, second] : [second, first];
}

export const confirmsPhrase = (words: string[], asked: [number, number], typed: [string, string]): boolean =>
  asked.every((position, index) => typed[index]!.trim().toLowerCase() === words[position]);

const messages: Record<string, string> = {
  wallet_exists: 'This device already has a wallet.',
  wallet_missing: 'This device has no wallet.',
  wallet_locked: 'Unlock your phone to use the wallet.',
  bad_mnemonic: 'That isn’t a valid recovery phrase. Check each word.',
  bad_word_count: 'A recovery phrase has 12 or 24 words.',
  authentication_failed: 'Couldn’t confirm it’s you, so the phrase stays hidden.',
  bad_base58: 'That isn’t a Solana address.',
  bad_url: 'That isn’t a Solana Pay link.',
  unsupported_token: 'Morse pays in SOL or USDC only.',
  amount_required: 'That link doesn’t say how much to pay.',
  nothing_to_move: 'There’s nothing to move.',
  rpc_unavailable: 'Couldn’t reach Solana. Try again.',
  transaction_expired: 'The network didn’t take the transfer in time, so nothing was sent. Try again.',
  transaction_failed: 'The transfer failed on chain. Nothing was moved.',
};

export function walletMessage(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  if (/insufficient (lamports|funds)|debit an account but found no record/i.test(raw)) return 'Not enough SOL to pay the network fee.';
  const code = Object.keys(messages).find((name) => new RegExp(`\\b${name}\\b`).test(raw));
  return code ? messages[code]! : friendlyError(raw.replace(/^.*Caused by:\s*/, ''));
}

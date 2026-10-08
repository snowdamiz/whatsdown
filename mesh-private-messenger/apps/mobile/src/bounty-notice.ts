import { base58 } from './base58.ts';
import type { FiledProof, TrustDetails } from './public-record.ts';

// The Phase 4 notice (plan §10): the phone caught a forked key log, filed the proof
// naming one of this wallet's bounty addresses, and follows the bounty until it lands.

// The newest proof that named a finder address and reached at least one relay.
export function bountyProof(alarms: TrustDetails[]): FiledProof | null {
  const named = [...alarms]
    .sort((left, right) => right.raisedAt - left.raisedAt)
    .flatMap((alarm) => [...alarm.proofs].reverse())
    .filter((proof) => proof.finder && proof.relays.some((relay) => relay.status === 'sent'));
  return named[0] ?? null;
}

export function formatUnits(amount: bigint, decimals: number): string {
  const scale = 10n ** BigInt(decimals);
  const whole = (amount / scale).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = (amount % scale).toString().padStart(decimals, '0').replace(/0+$/, '');
  return fraction ? `${whole}.${fraction}` : whole;
}

export type BountyNotice = { text: string; details: string | null; transaction: string | null };

const CAUGHT = 'Your phone caught a forked key log.';

// payout: what the chain shows was paid to the finder address, once it is read.
export function bountyNotice(proof: FiledProof, payout: { amount: bigint; signature: string } | null): BountyNotice {
  if (proof.landed && proof.paidElsewhere && proof.paidTo) {
    return {
      text: `${CAUGHT} The proof was filed.`,
      details: `The bounty paid ${base58(proof.paidTo)}, not your wallet. That happens when a monitor or a contact's phone proved the same fork first, or when a relay named its own address.`,
      transaction: null,
    };
  }
  if (proof.landed && payout) {
    return {
      text: `${CAUGHT} The proof was filed, and the bounty landed in your wallet: ${formatUnits(payout.amount, 6)} USDC.`,
      details: null,
      transaction: `https://explorer.solana.com/tx/${payout.signature}`,
    };
  }
  return { text: `${CAUGHT} The proof was filed; the bounty is on its way to your wallet.`, details: null, transaction: null };
}

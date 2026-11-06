import { decodeUtf8, parseByteList } from './codec.ts';
import { t } from './i18n.ts';

const statuses = ['none', 'disabled', 'invalid_evidence', 'pending', 'accepted', 'rpc_unavailable', 'rpc_disagree', 'settled', 'paid_elsewhere'] as const;
type FilingStatus = typeof statuses[number];
export type FilingObservation = {
  status: FilingStatus;
  proofHash: string;
  expectedFinder: string;
  paidFinder: string;
  paidUnits: string;
  mint: string;
  accepted: number;
  targets: number;
  checkedAt: string;
  nextAttempt: string;
  contextSlot: string;
  working: boolean;
};
const zeroAddress = '1'.repeat(32);
const address = (value: string) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value);
const u64 = (value: string) => /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;

// Presentation only: the Mesh worker authenticates receipts against the pinned
// program, log, mint, proof and finalized RPC quorum before exporting this view.
export function parseFilingObservation(input: Uint8Array): FilingObservation {
  const fields = parseByteList(input, 12, 64).map(decodeUtf8);
  const [status, proofHash, expectedFinder, paidFinder, paidUnits, mint, accepted, targets, checkedAt, nextAttempt, contextSlot, working] = fields;
  const invalid = () => { throw new Error('Invalid native filing observation'); };
  if (fields.length !== 12 || !statuses.includes(status as FilingStatus) || !/^[01]$/.test(working!) ||
      [paidUnits!, checkedAt!, nextAttempt!, contextSlot!].some(value => !u64(value)) ||
      !/^[0-8]$/.test(accepted!) || !/^[0-8]$/.test(targets!) || Number(accepted) > Number(targets)) invalid();
  const blank = ['none', 'disabled', 'invalid_evidence'].includes(status!);
  const paid = status === 'settled' || status === 'paid_elsewhere';
  if (blank) {
    if (proofHash || expectedFinder || paidFinder || mint || [paidUnits, accepted, targets, checkedAt, nextAttempt, contextSlot, working].some(value => value !== '0')) invalid();
  } else {
    if (!/^[a-f0-9]{64}$/.test(proofHash!) || !address(expectedFinder!) || !address(mint!) || mint === zeroAddress) invalid();
    if (paid) {
      if (working !== '0') invalid();
      if (!address(paidFinder!) || paidFinder === zeroAddress) invalid();
      const elsewhere = expectedFinder !== zeroAddress && expectedFinder !== paidFinder;
      if ((status === 'paid_elsewhere') !== elsewhere) invalid();
    } else if (paidFinder || paidUnits !== '0') invalid();
    if (status === 'accepted' && accepted === '0') invalid();
  }
  return { status: status as FilingStatus, proofHash: proofHash!, expectedFinder: expectedFinder!, paidFinder: paidFinder!,
    paidUnits: paidUnits!, mint: mint!, accepted: Number(accepted), targets: Number(targets), checkedAt: checkedAt!,
    nextAttempt: nextAttempt!, contextSlot: contextSlot!, working: working === '1' };
}

export function describeFilingObservation(value: FilingObservation | null) {
  if (!value) return { detail: t('Filing status has not been checked yet.'), acknowledgments: '', payment: '' };
  const status = value.status;
  const details: Record<FilingStatus, string> = {
    none: t('No retained evidence is available to file.'),
    disabled: t('Automatic filing is not configured in this app release. You can copy the evidence for a relay operator.'),
    invalid_evidence: t('This evidence could not be filed under this app release’s security configuration. The original evidence remains available to copy.'),
    pending: value?.targets === 0 ? t('This release has no relay configured. Your device is watching for a public receipt; you can copy the evidence for a relay operator.') : t('Your device is filing the evidence and watching for a public receipt. It will retry while the app is open or on an available background wake.'),
    accepted: t('A relay accepted the evidence. Payment has not been confirmed. Your device will keep checking the public receipt.'),
    rpc_unavailable: t('The public receipt could not be checked. Payment has not been confirmed. Your device will retry.'),
    rpc_disagree: t('Public receipt providers disagree. Payment has not been confirmed. Your device will retry.'),
    settled: value?.expectedFinder === zeroAddress ? t('A public receipt confirms the payout. This proof did not name a bounty address, so the submitter received the finder share.') : t('A public receipt confirms the payout to this proof’s finder address.'),
    paid_elsewhere: t('A public receipt confirms payment to a different finder address. Another phone or monitor may have filed the same proof first. This receipt alone does not identify who changed the finder address.'),
  };
  return {
    detail: details[status],
    acknowledgments: value.targets > 0 && value.checkedAt !== '0' && !['settled', 'paid_elsewhere'].includes(status)
      ? t.plural('{accepted} of {count} relay acknowledged the latest completed attempt.', '{accepted} of {count} relays acknowledged the latest completed attempt.', value.targets, { accepted: value.accepted }) : '',
    // Mint decimals are not part of this native view. Do not assume a currency
    // or convert a full-width token amount through a JavaScript Number.
    payment: value && ['settled', 'paid_elsewhere'].includes(status) ? t('{units} token base units', { units: value.paidUnits }) : '',
  };
}

import { decodeUtf8, parseByteList } from './codec.ts';
import { t } from './i18n.ts';

const statuses = ['none', 'disabled', 'invalid_evidence', 'pending', 'accepted', 'rpc_unavailable', 'rpc_disagree', 'settled', 'paid_elsewhere'] as const;
type LegacyFilingStatus = typeof statuses[number];
type FilingStatus = LegacyFilingStatus | 'prepared';
type FilingFields = {
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
type LegacyFilingObservation = FilingFields & {
  status: LegacyFilingStatus;
  viewVersion?: never;
  morsePaidUnits?: never;
  morseMint?: never;
  receiptFormat?: never;
};
type VersionedFilingFields = FilingFields & { viewVersion: '2'; morseMint: string };
type VersionedFilingObservation = VersionedFilingFields & (
  | { status: 'pending' | 'accepted' | 'rpc_unavailable' | 'rpc_disagree'; receiptFormat: '0'; paidFinder: ''; paidUnits: '0'; morsePaidUnits: '0' }
  | { status: 'prepared'; receiptFormat: '2'; paidUnits: '0'; morsePaidUnits: '0' }
  | { status: 'settled' | 'paid_elsewhere'; receiptFormat: '1'; morsePaidUnits: '0' }
  | { status: 'settled' | 'paid_elsewhere'; receiptFormat: '2'; morsePaidUnits: string }
);
export type FilingObservation = LegacyFilingObservation | VersionedFilingObservation;
const zeroAddress = '1'.repeat(32);
const address = (value: string) => /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value);
const u64 = (value: string) => /^(0|[1-9][0-9]{0,19})$/.test(value) && BigInt(value) <= 18446744073709551615n;
const isLegacyStatus = (value: string): value is LegacyFilingStatus => statuses.some(status => status === value);
function invalid(): never { throw new Error('Invalid native filing observation'); }
function address32(value: string): boolean {
  if (!address(value)) return false;
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let decoded = 0n;
  for (const char of value) decoded = decoded * 58n + BigInt(alphabet.indexOf(char));
  let length = value.length - value.replace(/^1+/, '').length;
  while (decoded > 0n) { length += 1; decoded >>= 8n; }
  return length === 32;
}

// Presentation only: the Mesh worker authenticates receipts against the pinned
// program, log, mint, proof and finalized RPC quorum before exporting this view.
export function parseFilingObservation(input: Uint8Array): FilingObservation {
  const fields = parseByteList(input, 16, 64).map(decodeUtf8);
  if (fields.length !== 12 && fields.length !== 16) invalid();
  const versioned = fields.length === 16;
  const [status = '', proofHash = '', expectedFinder = '', paidFinder = '', paidUnits = '', mint = '', accepted = '', targets = '', checkedAt = '', nextAttempt = '', contextSlot = '', working = '', viewVersion = '', morsePaidUnits = '', morseMint = '', receiptFormat = ''] = fields;
  if (!isLegacyStatus(status) && !(versioned && status === 'prepared')) invalid();
  if (!/^[01]$/.test(working) || [paidUnits, checkedAt, nextAttempt, contextSlot].some(value => !u64(value)) ||
      !/^[0-8]$/.test(accepted) || !/^[0-8]$/.test(targets) || Number(accepted) > Number(targets)) invalid();
  const blank = ['none', 'disabled', 'invalid_evidence'].includes(status);
  const paid = status === 'settled' || status === 'paid_elsewhere';
  if (blank) {
    if (versioned || proofHash || expectedFinder || paidFinder || mint || [paidUnits, accepted, targets, checkedAt, nextAttempt, contextSlot, working].some(value => value !== '0')) invalid();
  } else {
    const validAddress = versioned ? address32 : address;
    if (!/^[a-f0-9]{64}$/.test(proofHash) || !validAddress(expectedFinder) || !validAddress(mint) || mint === zeroAddress) invalid();
    if (paid || status === 'prepared') {
      if (paid && working !== '0') invalid();
      if (!validAddress(paidFinder) || paidFinder === zeroAddress) invalid();
      const elsewhere = expectedFinder !== zeroAddress && expectedFinder !== paidFinder;
      if (paid && (status === 'paid_elsewhere') !== elsewhere) invalid();
    } else if (paidFinder || paidUnits !== '0') invalid();
    if (status === 'accepted' && accepted === '0') invalid();
  }
  const observation = { proofHash, expectedFinder, paidFinder, paidUnits, mint, accepted: Number(accepted), targets: Number(targets),
    checkedAt, nextAttempt, contextSlot, working: working === '1' };
  if (!versioned) {
    if (status === 'prepared') invalid();
    return { status, ...observation };
  }
  if (viewVersion !== '2' || !u64(morsePaidUnits) || !address32(morseMint) || morseMint === zeroAddress || morseMint === mint) invalid();
  const versionedObservation = { ...observation, viewVersion, morseMint } satisfies VersionedFilingFields;
  switch (status) {
    case 'prepared':
      if (receiptFormat !== '2' || paidUnits !== '0' || morsePaidUnits !== '0') invalid();
      return { ...versionedObservation, status, receiptFormat, paidUnits, morsePaidUnits };
    case 'settled':
    case 'paid_elsewhere':
      if (receiptFormat === '1' && morsePaidUnits === '0') return { ...versionedObservation, status, receiptFormat, morsePaidUnits };
      if (receiptFormat === '2') return { ...versionedObservation, status, receiptFormat, morsePaidUnits };
      return invalid();
    case 'pending':
    case 'accepted':
    case 'rpc_unavailable':
    case 'rpc_disagree':
      if (receiptFormat !== '0' || morsePaidUnits !== '0' || paidFinder !== '' || paidUnits !== '0') invalid();
      return { ...versionedObservation, status, receiptFormat, paidFinder, paidUnits, morsePaidUnits };
    default:
      return invalid();
  }
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
    prepared: 'A public receipt records a prepared payout. Payment has not been confirmed.',
    settled: value?.expectedFinder === zeroAddress ? t('A public receipt confirms the payout. This proof did not name a bounty address, so the submitter received the finder share.') : t('A public receipt confirms the payout to this proof’s finder address.'),
    paid_elsewhere: t('A public receipt confirms payment to a different finder address. Another phone or monitor may have filed the same proof first. This receipt alone does not identify who changed the finder address.'),
  };
  return {
    detail: value.viewVersion === '2' && value.paidFinder
      ? `${details[status]} Actual finder: ${value.paidFinder}. Requested finder: ${value.expectedFinder}.`
      : details[status],
    acknowledgments: value.targets > 0 && value.checkedAt !== '0' && !['settled', 'paid_elsewhere'].includes(status)
      ? t.plural('{accepted} of {count} relay acknowledged the latest completed attempt.', '{accepted} of {count} relays acknowledged the latest completed attempt.', value.targets, { accepted: value.accepted }) : '',
    // Mint decimals are not part of this native view. Preserve integer base units.
    payment: ['settled', 'paid_elsewhere'].includes(status)
      ? value.viewVersion === '2'
        ? `${value.paidUnits} USDC base units; ${value.morsePaidUnits} MORSE base units`
        : t('{units} token base units', { units: value.paidUnits })
      : '',
  };
}

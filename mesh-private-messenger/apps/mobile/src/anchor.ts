import { decodeUtf8, parseByteList } from './codec.ts';
import { msg, t } from './i18n.ts';

const descriptions = {
  off: { title: msg('Public checkpoint checks are off'), detail: msg('This app release has no public checkpoint configured.'), blocking: false },
  pending: { title: msg('Public checkpoint not checked yet'), detail: msg('Your device will check when it is online.'), blocking: false },
  observed: { title: msg('Public checkpoint observed'), detail: msg('Two providers agreed on the public record. Consistency with your device’s key log has not yet been verified.'), blocking: false },
  stale: { title: msg('Public checkpoint is overdue'), detail: msg('The latest public checkpoint is over two hours old. Existing chats can continue.'), blocking: false },
  rpc_unavailable: { title: msg('Public checkpoint unavailable'), detail: msg('Your device could not reach enough providers. It will try again later.'), blocking: false },
  rpc_disagree: { title: msg('Public checkpoint providers disagree'), detail: msg('Your device could not confirm one public record. It will try again later.'), blocking: false },
  clock_unavailable: { title: msg('Checkpoint time could not be confirmed'), detail: msg('The public posting time and this device’s clock could not be reconciled. Your device will try again later.'), blocking: false },
  empty: { title: msg('Waiting for a public checkpoint'), detail: msg('No checkpoint has been published to this log yet.'), blocking: false },
  service_slashed: { title: msg('Morse’s key log was caught signing two versions'), detail: msg('Two providers confirmed that the public judge rejected this service key. New chats and key changes are paused. Existing chats can continue.'), blocking: true },
  consistent: { title: msg('Public checkpoint verified'), detail: msg('Your device verified that its key log and the public checkpoint belong to the same growing tree.'), blocking: false },
  mismatch: { title: msg('Public checkpoint could not be verified'), detail: msg('The directory refused or returned invalid evidence for the public checkpoint. New chats and key changes are paused. Existing chats can continue. Your device will retry.'), blocking: true },
  proof_unavailable: { title: msg('Checkpoint proof unavailable'), detail: msg('Your device could not retrieve the checkpoint proof. It will try again later. Existing chats can continue.'), blocking: false },
} as const;

export type AnchorStatus = keyof typeof descriptions;
export type AnchorObservation = {
  status: AnchorStatus;
  checkedAt: string;
  contextSlot: string;
  postedSlot: string;
  blockTime: string;
};

// The native timestamp is seconds; the UI clock is milliseconds. Keep the
// public u64 exact until its bounded, nonnegative age can safely be a Number.
export function checkpointAgeSeconds(blockTime: string, nowMs: number): number | null {
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || !/^[1-9][0-9]{0,19}$/.test(blockTime)) return null;
  const posted = BigInt(blockTime);
  const now = BigInt(Math.floor(nowMs / 1000));
  if (posted > 18446744073709551615n || posted > now) return null;
  return Number(now - posted);
}

export function parseAnchorObservation(input: Uint8Array): AnchorObservation {
  const fields = parseByteList(input, 5, 32).map(decodeUtf8);
  const [status, checkedAt, contextSlot, postedSlot, blockTime] = fields;
  if (fields.length !== 5 || !Object.hasOwn(descriptions, status!) ||
      fields.slice(1).some(value => !/^(0|[1-9][0-9]{0,19})$/.test(value) || BigInt(value) > 18446744073709551615n)) {
    throw new Error('Invalid native anchor observation');
  }
  return { status: status as AnchorStatus, checkedAt: checkedAt!, contextSlot: contextSlot!, postedSlot: postedSlot!, blockTime: blockTime! };
}

// Translated where it is shown, in the language in effect then.
export function describeAnchorObservation(status: AnchorStatus) {
  const { title, detail, blocking } = descriptions[status];
  return { title: t(title), detail: t(detail), blocking };
}

import { msg, t, type MessageKey } from './i18n.ts';

const day = 86_400_000;

const startOfDay = (timestamp: number): number => {
  const date = new Date(timestamp);
  date.setHours(0, 0, 0, 0);
  return date.getTime();
};

export const sameDay = (a: number, b: number): boolean => startOfDay(a) === startOfDay(b);

const daysAgo = (timestamp: number, now: number): number =>
  Math.round((startOfDay(now) - startOfDay(timestamp)) / day);

// Times and dates follow the app's language, in the phone's own region when
// it speaks that language: a 24-hour clock in Britain, a 12-hour one in the US.
export const formatClock = (timestamp: number): string =>
  new Date(timestamp).toLocaleTimeString(t.locale, { hour: 'numeric', minute: '2-digit' });

export function formatDayLabel(timestamp: number, now = Date.now()): string {
  const age = daysAgo(timestamp, now);
  if (age <= 0) return t('Today');
  if (age === 1) return t('Yesterday');
  const date = new Date(timestamp);
  if (age < 7) return date.toLocaleDateString(t.locale, { weekday: 'long' });
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return date.toLocaleDateString(t.locale, {
    month: 'long',
    day: 'numeric',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
}

export function formatInboxTime(timestamp: number, now = Date.now()): string {
  const age = daysAgo(timestamp, now);
  if (age <= 0) return formatClock(timestamp);
  if (age === 1) return t('Yesterday');
  const date = new Date(timestamp);
  if (age < 7) return date.toLocaleDateString(t.locale, { weekday: 'short' });
  const sameYear = date.getFullYear() === new Date(now).getFullYear();
  return date.toLocaleDateString(t.locale, {
    month: 'short',
    day: 'numeric',
    ...(sameYear ? {} : { year: 'numeric' }),
  });
}

// The letters an avatar is drawn with: the first of two words, or the start
// of one, leaving out anything that is not a letter or digit.
export function initials(name: string): string {
  const words = name
    .split(/[._\-\s]+/)
    .map((word) => word.replace(/[^\p{L}\p{N}]/gu, ''))
    .filter(Boolean);
  const letters = words.length >= 2 ? `${words[0]![0]}${words[1]![0]}` : (words[0] ?? '').slice(0, 2);
  return letters.toUpperCase();
}

export const groupDigits = (value: string, size: number): string[] =>
  value.match(new RegExp(`.{1,${size}}`, 'g')) ?? [];

const knownErrors: readonly [RegExp, MessageKey][] = [
  [/group_expiry_upgrade_required/, msg('Every group member’s device needs an updated Morse app before you can send disappearing messages. Turn the timer off to send a permanent message.')],
  [/attachment_legacy_upload/, msg('This saved upload uses an older format. Recover its reservation before retrying or selecting the file again.')],
  [/attachment_recipient_upgrade_required/, msg('Every recipient’s device needs an updated Morse app before you can send this file. Text messages still work.')],
  [/invalid_attachment_recipients|attachment_recipient_(?:changed|unavailable)|attachment_configuration_changed/, msg('The recipients or their security information changed. Try sending the file again.')],
  [/credit_preview_expired/, msg('This file’s price preview expired. Remove it and select it again to review a fresh price.')],
  [/postage_required/, msg('Message queued. Review postage before delivery.')],
  [/paid_attachment_staging_incomplete/, msg('This upload was not fully encrypted before the app closed. Recover its reservation; choose the file again only as a new upload.')],
  [/paid_attachment_cancelled/, msg('Reservation cancelled; credits restored.')],
  [/paid_attachment_(?:http_|verification_pending|response_too_large)/, msg('Upload outcome unknown. Keep this saved upload and retry; do not start a replacement.')],
  [/credit_(?:wallet|reservation)_capacity/, msg('This device’s credit storage is full. Finish pending purchases before buying more.')],
  [/transparency_stale/, msg('Security information is out of date. Reconnect and refresh before sending.')],
  [/transparency_fork_detected/, msg('Conflicting signed key logs were found. New chats and key changes are paused. Open Details to view the evidence.')],
  [/anchor_service_slashed/, msg('The public judge rejected Morse’s key log. New chats and key changes are paused. Existing chats can continue.')],
  [/anchor_check_pending/, msg('A public checkpoint check has not finished saving. Try again shortly. Existing chats can continue.')],
  [/anchor_mismatch/, msg('The public checkpoint could not be verified. New chats and key changes are paused while your device retries. Existing chats can continue.')],
  [/fanout_contact_identity_changed/, msg('The contact identity changed. Verify the contact before sending.')],
  [/peer_keys_changed/, msg('Their security keys changed. Verify before sending.')],
  [/message_request_pending/, msg('Accept this message request before replying.')],
  [/conversation_blocked/, msg('Unblock this conversation before sending.')],
  [/recipient_unavailable/, msg('Someone can’t receive more messages right now. Yours will send on its own when they can.')],
  [/username_taken/, msg('That username is taken. Try another.')],
  [/(?:account_state_changed|directory_identity_changed)/, msg('The account on this device changed. Review it before trying again.')],
  [/account_deletion_unsupported/, msg('This server can’t delete accounts yet. Nothing was erased.')],
  [/unproven_removal/, msg('The server says this device is no longer in its account but can’t prove it. Nothing was erased.')],
  [
    /account_deletion_refused/,
    msg('The server refused to delete the account. Check this device’s date and time, then try again.'),
  ],
  [/removed_from_account/, msg('This device is no longer part of its account. Erase it in You to start again.')],
  [
    /registration_refused/,
    msg('The server won’t register this device. If it was removed from your account, erase it in You to start again.'),
  ],
  [/\b404\b/, msg('No exact username match was found.')],
  [/AbortError/, msg('The server did not respond. Try again when connected.')],
  [
    /Could not connect|Network request failed|fetch failed|ECONNREFUSED|(?:account|device)_transport_unavailable/i,
    msg('Can’t reach the server. Check your connection and try again.'),
  ],
  [/\b5\d\d\b|(?:account|device)_http_5\d\d/, msg('The server hit a problem. Try again in a moment.')],
];

export function friendlyError(error: unknown): string {
  const raw = error instanceof Error ? error.message : error == null ? '' : String(error);
  if (/safety_number_mismatch/.test(raw)) return t('These safety numbers do not match. Check that this is the right conversation and compare again.');
  if (/invalid_safety_code/.test(raw)) return t('This is not a safety number code. Open Conversation details on the other device.');
  if (/safety_verification_changed/.test(raw)) return t('The conversation changed while verifying. Compare the current safety numbers again.');
  for (const [pattern, message] of knownErrors) {
    if (pattern.test(raw)) return t(message);
  }
  const cleaned = raw
    .replace(/^Call to function '[^']*' has been rejected\.\s*→ Caused by:\s*/, '')
    .replace(/\s*\(at [^)]*\)\s*$/, '')
    .replace(/^(?:[A-Za-z.]*(?:Exception|Error)):\s*/, '')
    .replace(/^Mesh library call failed \(status=\d+\):\s*/, '')
    .trim();
  if (/^[a-z0-9_]+$/.test(cleaned)) {
    const words = cleaned.replace(/_/g, ' ');
    return `${words.charAt(0).toUpperCase()}${words.slice(1)}.`;
  }
  return cleaned || t('Something went wrong.');
}

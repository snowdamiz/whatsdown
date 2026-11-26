import type { Conversation } from './codec.ts';

// What the safety number card says about a conversation: the tone of its
// glyph, the state in a few words, the sentence under the card, and whether
// "Mark as verified" applies.
export type SafetyState = {
  tone: 'success' | 'warning' | 'muted';
  status: string;
  note: string;
  verifiable: boolean;
};

// A key change outranks everything else the record says: the backend clears
// `verified` when keys change, but the warning must show regardless. Marking
// verified needs a number to verify, which a conversation only has once a
// message has been exchanged.
export function describeSafety(
  { username, safetyNumber, verified, keyChanged }: Pick<Conversation, 'username' | 'safetyNumber' | 'verified' | 'keyChanged'>,
): SafetyState {
  const ready = safetyNumber.length > 0;
  if (keyChanged) {
    return {
      tone: 'warning',
      status: 'Changed',
      note: ready
        ? `@${username}’s devices changed, so this number did too. Compare it again before you trust this conversation.`
        : `@${username}’s devices changed. A new number appears here once you’ve exchanged a message.`,
      verifiable: ready,
    };
  }
  if (!ready) {
    return {
      tone: 'muted',
      status: 'Not ready',
      note: `It appears here once you’ve exchanged a message with @${username}.`,
      verifiable: false,
    };
  }
  if (verified) {
    return {
      tone: 'success',
      status: 'Verified on this device',
      note: 'You’ll be warned if it ever changes.',
      verifiable: false,
    };
  }
  return {
    tone: 'muted',
    status: 'Not verified',
    note: `Compare with @${username} in person or through a channel you already trust. It reads the same on both of your screens.`,
    verifiable: true,
  };
}

export const reactionEmojis = [
  { emoji: '👍', label: 'Thumbs up' },
  { emoji: '❤️', label: 'Heart' },
  { emoji: '😂', label: 'Laugh' },
  { emoji: '😮', label: 'Surprised' },
  { emoji: '😢', label: 'Sad' },
  { emoji: '🙏', label: 'Thanks' },
  { emoji: '🎉', label: 'Celebrate' },
  { emoji: '👎', label: 'Thumbs down' },
] as const;

export type Reaction = { emoji: string; senders: string[] };

export const reactionLabel = (emoji: string): string =>
  reactionEmojis.find((item) => item.emoji === emoji)?.label ?? emoji;

// Reactions ordered as they are shown: the most-given emoji first, ties in the
// order people first gave them, so the pill does not reshuffle as people react.
export function rankReactions(reactions: Reaction[]): Reaction[] {
  return [...reactions].sort((left, right) => right.senders.length - left.senders.length);
}

// What fits in the pill under a message: up to three emojis and how many
// people reacted in all.
export function summarizeReactions(reactions: Reaction[], limit = 3): { emojis: string[]; total: number } {
  return {
    emojis: rankReactions(reactions).slice(0, limit).map((reaction) => reaction.emoji),
    total: reactions.reduce((count, reaction) => count + reaction.senders.length, 0),
  };
}

export function describeReactions(reactions: Reaction[]): string {
  const total = reactions.reduce((count, reaction) => count + reaction.senders.length, 0);
  if (!total) return 'No reactions';
  const names = rankReactions(reactions).map(({ emoji, senders }) =>
    total === 1 ? reactionLabel(emoji) : `${reactionLabel(emoji)} ${senders.length}`);
  return `${total} ${total === 1 ? 'reaction' : 'reactions'}: ${names.join(', ')}`;
}

const prefix = 'MORSE-REACTION/1\n';
type Update = [target: string, emoji: string, revision: number];

function validUpdate(value: unknown): value is Update {
  return Array.isArray(value) && value.length === 3 &&
    typeof value[0] === 'string' && /^(?:[a-f0-9]{32}|[a-f0-9]{64})$/.test(value[0]) &&
    (value[1] === '' || reactionEmojis.some(({ emoji }) => emoji === value[1])) &&
    Number.isSafeInteger(value[2]) && value[2] > 0;
}

export function encodeReaction(target: string, emoji: string, revision = Date.now()): string {
  const update = [target, emoji, revision];
  if (!validUpdate(update)) throw new Error('Invalid reaction');
  return prefix + JSON.stringify(update);
}

// Reaction events use the same encrypted, bounded history as messages. Actor IDs
// come from the authenticated history record, never from the reaction body.
export function applyReactions<T extends { body: string }>(
  history: T[],
  keyOf: (message: T) => string,
  senderOf: (message: T) => string,
): (T & { reactions?: Reaction[] })[] {
  const messages: T[] = [];
  const updates = new Map<string, Map<string, Update>>();
  for (const message of history) {
    if (!message.body.startsWith(prefix)) {
      messages.push(message);
      continue;
    }
    // Reserved control messages, including malformed ones, never become bubbles.
    if (message.body.length > 256) continue;
    let update: unknown;
    try { update = JSON.parse(message.body.slice(prefix.length)); }
    catch { continue; }
    if (!validUpdate(update)) continue;
    const actors = updates.get(update[0]) ?? new Map<string, Update>();
    const sender = senderOf(message);
    const previous = actors.get(sender);
    // Explicit values make retries idempotent. Equal revisions resolve the same
    // way on every device; a removal wins a simultaneous add.
    if (!previous || update[2] > previous[2] || (update[2] === previous[2] && update[1] < previous[1])) {
      actors.set(sender, update);
    }
    updates.set(update[0], actors);
  }
  return messages.map((message) => {
    const reactions: Reaction[] = [];
    for (const [sender, [, emoji]] of updates.get(keyOf(message)) ?? []) {
      if (!emoji) continue;
      const existing = reactions.find((reaction) => reaction.emoji === emoji);
      if (existing) existing.senders.push(sender);
      else reactions.push({ emoji, senders: [sender] });
    }
    return reactions.length ? { ...message, reactions } : message;
  });
}

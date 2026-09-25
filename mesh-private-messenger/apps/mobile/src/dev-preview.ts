import type { Presentation } from './presentation';
import { hex, type Conversation, type GroupDetails, type GroupHistoryMessage, type GroupSummary, type HistoryMessage } from './codec.ts';
import { receivedMessageKeys, type ReadState } from './read-state.ts';

export type DevPreview = {
  presentations: Record<string, Presentation>;
  conversations: Conversation[];
  histories: Record<string, HistoryMessage[]>;
  groups: GroupSummary[];
  groupDetails: Record<string, GroupDetails>;
  groupHistories: Record<string, GroupHistoryMessage[]>;
  readState: ReadState;
};

const usernames = ['alex_w', 'maya_1987', 'jordan_runs', 'sam_k', 'riley_42', 'taylor_m', 'jamie_c', 'casey_chen', 'morgan_r', 'avery_j', 'quinn_reads', 'drew_s', 'charlie_b', 'robin_w', 'blake_92', 'cameron_d'];
const displayNames = ['Alex Walker', 'Maya Chen', 'Jordan', 'Sam Kim', 'Riley', 'Taylor', 'Jamie', 'Casey Chen', 'Morgan', 'Avery', 'Quinn', 'Drew', 'Charlie', 'Robin', '', 'Cameron'];
const exchanges = [
  [
    'Coffee this weekend?', 'There’s a new place by the park.',
    'Saturday works for me.', 'How about 10:30?',
    'Perfect. I’ll grab us a table.', 'They have outdoor seating too ☀️',
    'Sounds good!', 'See you there.',
  ],
  [
    'Made it back from the trail!', 'The view at the top was worth the early start.',
    'I’m glad the weather held up.', 'We should try the longer route next time.',
    'Definitely. Let’s bring lunch and make a day of it.\nI’ll check which trails are open.',
    'Would Sunday work?', 'Yes, putting it on my calendar.', 'I’ll bring snacks 🥾',
  ],
  [
    'I tried that recipe you sent.', 'It turned out really well!',
    'Nice! Did you add the lemon at the end?', 'That made a big difference for me.',
    'Yes, and a little extra garlic.', 'Saving this one for dinner with friends.',
    'Let me know when you make it again.', 'I’ll bring dessert 🍰',
  ],
];

// Deliberately synthetic IDs. These records belong only to the UI, never the protocol.
const id = (value: number, length = 32) => new Uint8Array(length).fill(value);

// The shape the protocol gives a safety number: a 64-character hex digest.
const safetyNumber = 'a3f91c2e77b00d4f9e215a6cb3d844100f7ac2e18b936d052c4ea917f30b5e68';

export function createDevPreview(now = Date.now()): DevPreview {
  const preview: DevPreview = { presentations: {}, conversations: [], histories: {}, groups: [], groupDetails: {}, groupHistories: {}, readState: {} };
  const messages = (offset: number, unread: number): HistoryMessage[] => Array.from({ length: 24 }, (_, index) => ({
    direction: index >= 24 - unread || index % 4 < 2 ? 'received' : 'sent',
    // Older sent messages were read, recent ones delivered, and the newest only sent.
    ...(index < 24 - unread && index % 4 >= 2 && index < 16 ? { receipt: index < 8 ? 2 as const : 1 as const } : {}),
    messageId: id(index + 1, 16),
    timestamp: now - Math.floor((23 - index) / 8) * 86_400_000 - ((23 - index) % 8) * 120_000 - offset * 600_000,
    body: exchanges[(offset + Math.floor(index / 8)) % exchanges.length]![index % 8]!,
    disappearingSeconds: 0,
  }));
  // The newest exchange shows what people do with messages: react to them and
  // answer one in particular. `others` names who reacts to a message.
  const decorate = <T extends HistoryMessage | GroupHistoryMessage>(history: T[], others: (message: T) => string[]): T[] => {
    const [liked, loved, , , , quoted, answer] = history.slice(-8);
    return history.map((message) =>
      message === liked ? { ...message, reactions: [{ emoji: '👍', senders: others(message) }] }
      : message === loved ? { ...message, reactions: [{ emoji: '❤️', senders: others(message) }] }
      : message === answer ? { ...message, reply: { target: hex(quoted!.messageId!), message: quoted! } }
      : message);
  };
  usernames.forEach((username, index) => {
    const conversationId = id(index + 10, 16);
    const unread = [2, 0, 1, 0, 12, 0][index % 6]!;
    preview.conversations.push({
      conversationId, username, peerAccountId: id(index + 10), peerDeviceId: id(index + 10, 16),
      safetyNumber, requestPending: false, blocked: index === 13,
      verified: index % 3 === 0, keyChanged: index === 8, disappearingSeconds: 0,
    });
    const history = decorate(messages(index, unread), (message) => [message.direction === 'sent' ? 'received' : 'sent']);
    preview.histories[hex(conversationId)] = history;
    preview.readState[`chat/${hex(conversationId)}`] = receivedMessageKeys(history.slice(0, history.length - unread));
    if (displayNames[index]) preview.presentations[`user/${hex(id(index + 10))}`] = { name: displayNames[index]! };
  });
  preview.presentations[`nickname/${hex(id(13))}`] = { name: 'Sam (work)' };
  for (let index = 0; index < 6; index += 1) {
    const groupId = id(index + 80);
    const unread = [3, 0, 1, 0, 8, 0][index]!;
    const memberCount = index + 3;
    // The first two people after you are the contacts of the same name, so a
    // group mixes people you chat with and people you have only met here.
    const members = Array.from({ length: memberCount }, (_, leaf) => ({
      leaf, local: leaf === 0, accountId: leaf === 1 || leaf === 2 ? id(leaf + 9) : id(leaf + 1), deviceId: id(leaf + 1, 16),
      directorySequence: 1, witnessCount: 2,
      ...(leaf > 0 ? { username: usernames[leaf - 1] } : {}),
    }));
    preview.presentations[`group/${hex(groupId)}`] = { name: ['Weekend walks', 'The dinner club', 'Studio friends', 'Family', 'Book club', 'Summer plans'][index]! };
    members.forEach((member, leaf) => { if (leaf > 0) preview.presentations[`user/${hex(member.accountId)}`] = { name: displayNames[leaf - 1]! }; });
    preview.groups.push({ groupId, epoch: 1, memberCount });
    preview.groupDetails[hex(groupId)] = {
      groupId, epoch: 1, treeHash: id(index + 100), checkpointHash: id(index + 120), members,
    };
    const history = decorate(messages(index, unread).map((message, messageIndex) => {
      const sender = members[message.direction === 'sent' ? 0 : 1 + messageIndex % (memberCount - 1)]!;
      return {
        direction: message.direction, epoch: 1, messageId: message.messageId, timestamp: message.timestamp, body: message.body,
        senderAccountId: sender.accountId, senderDeviceId: sender.deviceId,
      };
    }), (message) => members.slice(1).filter((member) => member.accountId !== message.senderAccountId)
      .slice(0, 2).map((member) => hex(member.accountId)));
    preview.groupHistories[hex(groupId)] = history;
    preview.readState[`group/${hex(groupId)}`] = receivedMessageKeys(history.slice(0, history.length - unread));
  }
  return preview;
}

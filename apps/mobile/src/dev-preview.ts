import type { Presentation } from './presentation';
import { hex, type Conversation, type GroupDetails, type GroupHistoryMessage, type GroupSummary, type HistoryMessage } from './codec.ts';
import { receivedMessageKeys, type ReadState } from './read-state.ts';
import { authorities, encodeJoinRequest, mergeParts, type Community } from './communities.ts';
import { applyCommunityControls, encodeCommunityRequest } from './community-requests.ts';

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
// What the groups linked to the sample community talk about.
const builderExchanges = [
  [
    'Draft proposal is in the doc.', 'Budget line looks high for the audit.',
    'Two quotes came in, the second is 30% cheaper.', 'Let’s go with that one then.',
    'Updating the proposal now.', 'Milestones split into three payouts.',
    'Makes sense to me.', 'Submitting before the deadline 🙏',
  ],
  [
    'Anyone need a frontend dev for the hackathon?', 'We do! Building a gas-free checkout.',
    'Sounds fun. What stack?', 'Next.js and viem, contracts in Foundry.',
    'I’m in. Sharing my handle with the team.', 'Kickoff call tonight at 8?',
    'Works for me.', 'Bringing the pitch deck draft 🎉',
  ],
  [
    'Testnet deploy went through.', 'Gas came in under the estimate.',
    'Nice. Did the indexer pick it up?', 'After a restart, yes.',
    'Let’s write that down for mainnet.\nAdding it to the checklist.', 'Audit call is Thursday.',
    'I’ll prepare the diff.', 'Thanks, this is looking solid.',
  ],
];
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

// `self` is the account the preview stands for, so the sample community it
// owns is run by whoever turned the preview on.
export function createDevPreview(now = Date.now(), self: Uint8Array = id(1)): DevPreview {
  const preview: DevPreview = { presentations: {}, conversations: [], histories: {}, groups: [], groupDetails: {}, groupHistories: {}, readState: {} };
  const messages = (offset: number, unread: number, lines = exchanges): HistoryMessage[] => Array.from({ length: 24 }, (_, index) => ({
    direction: index >= 24 - unread || index % 4 < 2 ? 'received' : 'sent',
    // Older sent messages were read, recent ones delivered, and the newest only sent.
    ...(index < 24 - unread && index % 4 >= 2 && index < 16 ? { receipt: index < 8 ? 2 as const : 1 as const } : {}),
    messageId: id(index + 1, 16),
    timestamp: now - Math.floor((23 - index) / 8) * 86_400_000 - ((23 - index) % 8) * 120_000 - offset * 600_000,
    body: lines[(offset + Math.floor(index / 8)) % lines.length]![index % 8]!,
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
      verified: index % 3 === 0, keyChanged: index === 8, disappearingSeconds: 0, sessionResetAt: 0,
    });
    const history = decorate(messages(index, unread), (message) => [message.direction === 'sent' ? 'received' : 'sent']);
    preview.histories[hex(conversationId)] = history;
    preview.readState[`chat/${hex(conversationId)}`] = receivedMessageKeys(history.slice(0, history.length - unread));
    if (displayNames[index]) preview.presentations[`user/${hex(id(index + 10))}`] = { name: displayNames[index]! };
  });
  preview.presentations[`nickname/${hex(id(13))}`] = { name: 'Sam (work)' };
  const groupNames = ['Weekend walks', 'The dinner club', 'Studio friends', 'Family', 'Book club', 'Summer plans', 'Grants desk', 'Hackathon crew'];
  for (let index = 0; index < groupNames.length; index += 1) {
    const groupId = id(index + 80);
    const unread = [3, 0, 1, 0, 8, 0, 2, 0][index]!;
    const memberCount = [3, 4, 5, 6, 7, 8, 6, 7][index]!;
    // The first two people after you are the contacts of the same name, so a
    // group mixes people you chat with and people you have only met here.
    const members = Array.from({ length: memberCount }, (_, leaf) => ({
      leaf, local: leaf === 0, accountId: leaf === 0 ? self : leaf === 1 || leaf === 2 ? id(leaf + 9) : id(leaf + 1), deviceId: id(leaf + 1, 16),
      directorySequence: 1, witnessCount: 2,
      ...(leaf > 0 ? { username: usernames[leaf - 1] } : {}),
    }));
    preview.presentations[`group/${hex(groupId)}`] = { name: groupNames[index]! };
    members.forEach((member, leaf) => { if (leaf > 0) preview.presentations[`user/${hex(member.accountId)}`] = { name: displayNames[leaf - 1]! }; });
    preview.groups.push({ groupId, epoch: 1, memberCount });
    preview.groupDetails[hex(groupId)] = {
      groupId, epoch: 1, treeHash: id(index + 100), checkpointHash: id(index + 120), members,
    };
    const history = decorate(messages(index, unread, index >= 6 ? builderExchanges : exchanges).map((message, messageIndex) => {
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
  addCommunities(preview, now, self);
  return preview;
}

type Person = { account: Uint8Array; username: string; name: string };
const person = (account: number, username: string, name: string): Person => ({ account: id(account), username, name });
// People met only in the sample communities.
const strangers = [
  person(40, 'ape_andy', 'Andy'), person(41, 'wagmi_will', 'Will'), person(42, 'gm_grace', 'Grace'), person(43, '0xpablo', 'Pablo'),
  person(44, 'defi_dee', 'Dee'), person(45, 'solsurfer', 'Kai'), person(46, 'layer2lena', 'Lena'),
];
const contact = (index: number): Person => person(index + 10, usernames[index]!, displayNames[index] || usernames[index]!);

// Two communities: Base Camp DAO, which you own and which spans two parts, and
// Solana Builders, where you read what its owner and admin post. Around them,
// someone asks through your link to join, and you wait on your own request.
function addCommunities(preview: DevPreview, now: number, self: Uint8Array): void {
  const me: Person = { account: self, username: '', name: '' };
  const hour = 3_600_000;
  const day = 24 * hour;
  // A part: its roster, where you are local, and each post as its own message there.
  const part = (partId: number, record: { name: string; community: Community }, roster: Person[],
    posts: { author: Person; body: string; age: number; reply?: number; reactors?: Person[]; emoji?: string }[],
    controls: { author: Person; body: string; age: number }[]) => {
    const groupId = id(partId);
    const members = roster.map((member, leaf) => ({
      leaf, local: member === me, accountId: member.account, deviceId: id(member.account[0]! + 100, 16),
      directorySequence: 1, witnessCount: 2, ...(member.username ? { username: member.username } : {}),
    }));
    const entry = (author: Person, body: string, age: number, serial: number): GroupHistoryMessage => ({
      direction: author === me ? 'sent' : 'received', epoch: 1,
      messageId: Uint8Array.from({ length: 32 }, (_, index) => index === 0 ? partId : index === 1 ? serial : 7),
      timestamp: now - age, body, senderAccountId: author.account, senderDeviceId: id(author.account[0]! + 100, 16),
    });
    const history = posts.map((post, serial) => ({
      ...entry(post.author, post.body, post.age, serial),
      ...(post.reactors ? { reactions: [{ emoji: post.emoji ?? '👍', senders: post.reactors.map((reactor) => hex(reactor.account)) }] } : {}),
    })) as GroupHistoryMessage[];
    posts.forEach((post, serial) => {
      if (post.reply === undefined) return;
      const quoted = history[post.reply]!;
      history[serial] = { ...history[serial]!, reply: { target: hex(quoted.messageId!), message: quoted } };
    });
    history.push(...controls.map((control, serial) => entry(control.author, control.body, control.age, 100 + serial)));
    history.sort((left, right) => left.timestamp - right.timestamp);
    preview.groups.push({ groupId, epoch: 1, memberCount: members.length });
    preview.groupDetails[hex(groupId)] = { groupId, epoch: 1, treeHash: id(partId + 60), checkpointHash: id(partId + 70), members };
    preview.groupHistories[hex(groupId)] = history;
    preview.presentations[`group/${hex(groupId)}`] = { ...record, revision: 1 };
    for (const member of roster) if (member !== me && member.account[0]! >= 40) preview.presentations[`user/${hex(member.account)}`] = { name: member.name };
  };
  const unreadAfter = (parts: number[], community: Community, unread: number) => {
    const merged = mergeParts(parts.map((partId) => ({ id: hex(id(partId)), messages: preview.groupHistories[hex(id(partId))]! })),
      authorities(community));
    preview.readState[`group/${hex(id(parts[0]!))}`] = receivedMessageKeys(merged.slice(0, merged.length - unread));
  };

  // Base Camp DAO: you own it with Maya as admin; it has grown into two parts.
  const maya = contact(1);
  const baseCamp: Community = {
    about: 'Builders and researchers on Base. Weekly calls, grants and hackathons.\nWe never DM first about airdrops.',
    groups: [{ id: hex(id(86)), name: 'Grants desk' }, { id: hex(id(87)), name: 'Hackathon crew' }],
    parts: [hex(id(90)), hex(id(91))], owner: hex(self), admins: [hex(maya.account)],
  };
  const baseRecord = { name: 'Base Camp DAO', community: baseCamp };
  const basePosts = (audience: Person[]) => [
    { author: maya, body: 'Welcome to Base Camp DAO 👋 Say hi in Hackathon crew and pick up a role.', age: 9 * day, reactors: audience.slice(0, 3), emoji: '🎉' },
    { author: me, body: 'Grant round 4 is open. Proposals close Friday at 18:00 UTC.', age: 7 * day, reactors: audience.slice(1, 4) },
    { author: maya, body: 'Community call Thursday 17:00 UTC: treasury update and the new builder grants.', age: 6 * day },
    { author: me, body: 'Recording of today’s call is up. Thanks to everyone who joined!', age: 5 * day, reactors: audience.slice(0, 2), emoji: '❤️' },
    { author: me, body: 'Reminder: we never DM you first about airdrops. Report anyone who does.', age: 4 * day, reactors: audience.slice(2, 5), emoji: '🙏' },
    { author: me, body: 'Deadline extended to Sunday for teams at ETHGlobal.', age: 3 * day, reply: 1 },
    { author: maya, body: 'Hackathon teams are forming in Hackathon crew. Solo builders welcome.', age: 2 * day },
    { author: me, body: 'Round 4 results: 12 grants funded, 38k USDC in total. Congrats to every team 🎉', age: 26 * hour, reactors: audience.slice(0, 5), emoji: '🎉' },
    { author: maya, body: 'Base Camp IRL: side event in Lisbon on Oct 12. RSVP opens next week.', age: 3 * hour },
  ];
  const [andy, will, grace, pablo, dee, kai, lena] = strangers as [Person, Person, Person, Person, Person, Person, Person];
  const firstRoster = [me, maya, contact(2), contact(4), contact(5), contact(6), andy, will, grace, pablo];
  const secondRoster = [me, maya, contact(7), contact(8), contact(9), dee, kai, lena];
  part(90, baseRecord, firstRoster, basePosts(firstRoster.slice(2)),
    [{ author: contact(4), body: encodeJoinRequest(hex(id(87))), age: 5 * hour }]);
  part(91, baseRecord, secondRoster, basePosts(secondRoster.slice(2)),
    [{ author: contact(7), body: encodeJoinRequest(hex(id(86))), age: 90 * 60_000 }]);
  unreadAfter([90, 91], baseCamp, 1);

  // Solana Builders: Alex owns it and Quinn helps; you are in one of its two parts.
  const alex = contact(0);
  const quinn = contact(10);
  const solana: Community = {
    about: 'Shipping on Solana: office hours, validator notes and hackathon teams.',
    groups: [{ id: hex(id(97)), name: 'Validators' }, { id: hex(id(98)), name: 'Memecoin lounge' }],
    parts: [hex(id(94)), hex(id(95))], owner: hex(alex.account), admins: [hex(quinn.account)],
  };
  const solanaRoster = [alex, quinn, me, contact(11), contact(12), contact(13), kai];
  part(94, { name: 'Solana Builders', community: solana }, solanaRoster, [
    { author: alex, body: 'gm builders ☀️ Office hours every Tuesday at 16:00 UTC.', age: 8 * day, reactors: [me, contact(11)] },
    { author: quinn, body: 'Firedancer testnet notes are up in Validators.', age: 6 * day, reactors: [contact(12)], emoji: '🙏' },
    { author: alex, body: 'Breakpoint side events list is live. Add yours before Friday.', age: 4 * day },
    { author: quinn, body: 'Heads up: a fake airdrop site is going around. We never ask you to connect a wallet.', age: 3 * day, reactors: [me, contact(11), kai], emoji: '🙏' },
    { author: quinn, body: 'If you see it posted anywhere, tell Alex or me.', age: 3 * day - hour, reply: 3 },
    { author: alex, body: 'Hackathon winners announced 🎉 Thanks to everyone who shipped.', age: 5 * hour, reactors: [contact(13), kai], emoji: '🎉' },
    { author: alex, body: 'RPC credits for builders: apply through the form in the About section by Sunday.', age: 40 * 60_000 },
  ], [
    { author: me, body: encodeJoinRequest(hex(id(97))), age: 2 * day },
  ]);
  unreadAfter([94], solana, 2);

  // Direct chats about joining: a stranger asks through your link, and you asked Nova Labs.
  const chat = (account: number, username: string, name: string, requestPending: boolean,
    lines: { direction: 'sent' | 'received'; body: string; age: number }[], unread: number) => {
    const conversationId = id(account, 16);
    preview.conversations.push({
      conversationId, username, peerAccountId: id(account), peerDeviceId: id(account, 16),
      safetyNumber: 'c4e0a19b52d7f36e81a4b20d9f5e37c16a8b04f2d9e1c7305b6a4f8e2d1c9b07', requestPending, blocked: false,
      verified: false, keyChanged: false, disappearingSeconds: 0, sessionResetAt: 0,
    });
    const history = applyCommunityControls(lines.map((line, index) => ({
      direction: line.direction, messageId: id(account + index, 16), timestamp: now - line.age, body: line.body, disappearingSeconds: 0,
      ...(line.direction === 'sent' ? { receipt: 1 as const } : {}),
    })));
    preview.histories[hex(conversationId)] = history;
    preview.readState[`chat/${hex(conversationId)}`] = receivedMessageKeys(history.slice(0, history.length - unread));
    preview.presentations[`user/${hex(id(account))}`] = { name };
  };
  chat(30, 'degen_dan', 'Dan', true, [
    { direction: 'received', body: encodeCommunityRequest(hex(id(90)), 'Base Camp DAO'), age: 2 * hour },
    { direction: 'received', body: 'Saw your link on X. Would love to help with the hackathon!', age: 2 * hour - 60_000 },
  ], 2);
  chat(31, 'nova_labs', 'Nova Labs', false, [
    { direction: 'sent', body: encodeCommunityRequest(hex(id(99)), 'Arbitrum Guild'), age: 20 * hour },
  ], 0);
}

import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  announcements,
  LEAVE_REQUEST,
  authorities,
  communityNotices,
  communityThread,
  departures,
  encodeLeft,
  deviceRequests,
  encodeCommunity,
  encodeDeviceRequest,
  encodeJoinRequest,
  encodeRoles,
  indexCommunities,
  joinRequests,
  leftBy,
  mergeParts,
  parseCommunity,
  parseRoles,
  pickPart,
  withRoles,
} from './communities.ts';
import { encodePresentation, parsePresentation } from './presentation.ts';
import { planNotifications } from './notification-policy.ts';

const id = (byte: string) => byte.repeat(64);
const account = (byte: number) => new Uint8Array(32).fill(byte);
const accountHex = (byte: number) => byte.toString(16).padStart(2, '0').repeat(32);
const message = (sender: number, body: string, timestamp = 1_000, extra: Record<string, unknown> = {}) =>
  ({ senderAccountId: account(sender), senderDeviceId: new Uint8Array(16).fill(sender), body, timestamp, ...extra });
const details = { about: 'Builders\nWeekly calls', groups: [{ id: id('a'), name: 'Trading' }, { id: id('b'), name: 'Dev' }], parts: [id('c'), id('d')] };
const community = { ...details, owner: accountHex(1), admins: [accountHex(5)] };

test('community details round trip canonically and reject what the core or the list cannot hold', () => {
  assert.deepEqual(parseCommunity(encodeCommunity(details)), details);
  assert.deepEqual(parseCommunity(encodeCommunity({ about: '  ', groups: [], parts: [id('c')] })), { about: '', groups: [], parts: [id('c')] });
  const invalid = [
    { about: 'x'.repeat(513), groups: [], parts: [id('c')] },
    { about: 'bell\u0007', groups: [], parts: [id('c')] },
    { about: '', groups: [{ id: 'not-an-id', name: 'x' }], parts: [id('c')] },
    { about: '', groups: [{ id: id('a'), name: ' ' }], parts: [id('c')] },
    { about: '', groups: [details.groups[0]!, details.groups[0]!], parts: [id('c')] },
    { about: '', groups: Array.from({ length: 33 }, (_, index) => ({ id: index.toString(16).padStart(64, '0'), name: 'g' })), parts: [id('c')] },
    { about: '', groups: [], parts: [] },
    { about: '', groups: [], parts: [id('c'), id('c')] },
    { about: '', groups: [], parts: Array.from({ length: 65 }, (_, index) => index.toString(16).padStart(64, '0')) },
  ];
  for (const value of invalid) assert.throws(() => encodeCommunity(value));
  // A record the owner's client did not write is not a community, rather than an error.
  assert.equal(parseCommunity('{"about":"x"}'), undefined);
  assert.equal(parseCommunity(`["x",[],["${id('c')}"]] `), undefined);
  assert.equal(parseCommunity('not json'), undefined);
});

test('roles name the owner, then admins in the ascending order the core requires', () => {
  const encoded = encodeRoles(accountHex(1), [accountHex(9), accountHex(3)]);
  assert.equal(encoded.length, 96);
  assert.deepEqual(parseRoles(encoded), { owner: accountHex(1), admins: [accountHex(3), accountHex(9)] });
  assert.throws(() => encodeRoles(accountHex(1), [accountHex(1)]));
  assert.throws(() => encodeRoles(accountHex(1), [accountHex(2), accountHex(2)]));
  assert.throws(() => encodeRoles(accountHex(1), Array.from({ length: 17 }, (_, index) => accountHex(index + 2))));
  assert.equal(parseRoles(new Uint8Array(31)), undefined);
  assert.equal(parseRoles(new Uint8Array([...account(1), ...account(3), ...account(2)])), undefined);
  assert.deepEqual([...authorities(community)], [accountHex(1), accountHex(5)]);
  // Handing over keeps the former owner as an admin.
  assert.deepEqual(withRoles(community, { owner: accountHex(5) }), { ...community, owner: accountHex(5), admins: [accountHex(1)] });
  assert.deepEqual(withRoles(community, { admins: [accountHex(7), accountHex(5)] }).admins, [accountHex(5), accountHex(7)]);
});

test('a group record carries its community and roles after the revision and stays readable without them', () => {
  const value = { name: 'Solana builders', revision: 5, community };
  assert.deepEqual(parsePresentation(encodePresentation(value)), { ...value, avatar: undefined });
  assert.deepEqual(parsePresentation(encodePresentation({ name: 'Walks', revision: 5 })), { name: 'Walks', avatar: undefined, revision: 5 });
  assert.throws(() => encodePresentation({ name: 'Solana builders', community }));
  const head = encodePresentation({ name: 'Solana builders', revision: 5 });
  const vector = (bytes: Uint8Array) => {
    const out = new Uint8Array(4 + bytes.length);
    new DataView(out.buffer).setUint32(0, bytes.length);
    out.set(bytes, 4);
    return out;
  };
  const junk = vector(new TextEncoder().encode('{"about":"x"}'));
  assert.deepEqual(parsePresentation(new Uint8Array([...head, ...junk, ...vector(account(1))])),
    { name: 'Solana builders', avatar: undefined, revision: 5 });
});

test('announcements are the owner’s and admins’ alone, and controls never show as posts', () => {
  const history = [
    message(1, 'Welcome'),
    message(2, 'Spam from a member'),
    message(2, encodeJoinRequest(id('a'))),
    message(5, 'Admin note'),
    message(5, encodeDeviceRequest(id('d'), new Uint8Array(369))),
  ];
  assert.deepEqual(announcements(history, authorities(community)).map((item) => item.body), ['Welcome', 'Admin note']);
});

test('join requests name a linked group, keep the latest per person and group, and lapse after a week', () => {
  const week = 7 * 24 * 60 * 60 * 1000;
  const now = 10 * week;
  const history = [
    message(2, encodeJoinRequest(id('a')), now - week - 1),
    message(3, encodeJoinRequest(id('a')), now - 5),
    message(3, encodeJoinRequest(id('a')), now - 2),
    message(3, encodeJoinRequest(id('e')), now - 2),
    message(3, `MORSE-JOIN/1\n${id('A')}`, now - 2),
    message(4, `${encodeJoinRequest(id('b'))}\nextra`, now - 2),
    message(4, encodeJoinRequest(id('b')), now - 1, { messageId: new Uint8Array(32).fill(7) }),
  ];
  assert.deepEqual(joinRequests(history, community, now), [
    { accountId: accountHex(3), groupId: id('a'), timestamp: now - 2 },
    { accountId: accountHex(4), groupId: id('b'), timestamp: now - 1 },
  ]);
  assert.throws(() => encodeJoinRequest('A'.repeat(64)));
  // Owners and admins are told once per request; everyone else never.
  const notices = communityNotices(history, community, accountHex(1), now);
  assert.deepEqual(notices.map((item) => item.body), ['Asked to join Trading', 'Asked to join Trading', 'Asked to join Dev']);
  assert.equal(notices.at(-1)!.messageId?.[0], 7);
  assert.deepEqual(communityNotices(history, community, accountHex(3), now), []);
});

test('an admin device asks for the parts it is missing, one package at a time, and only admins are heard', () => {
  const pkg = new Uint8Array(369).fill(9);
  const history = [
    message(5, encodeDeviceRequest(id('d'), new Uint8Array(369)), 10),
    message(5, encodeDeviceRequest(id('d'), pkg), 20),
    message(2, encodeDeviceRequest(id('d'), pkg), 30),
    message(1, encodeDeviceRequest(id('e'), pkg), 40),
    message(1, 'MORSE-DEVICE/1\nbad', 50),
  ];
  const requests = deviceRequests(history, community);
  assert.equal(requests.length, 1);
  assert.equal(requests[0]!.accountId, accountHex(5));
  assert.equal(requests[0]!.part, id('d'));
  assert.deepEqual(requests[0]!.keyPackage, pkg);
  assert.throws(() => encodeDeviceRequest(id('d'), new Uint8Array(12)));
});

test('parts merge one post sent to each into one announcement with its reactions and copies', () => {
  const file = { objectId: new Uint8Array(32).fill(4), filename: 'chart.png', size: 10 };
  const partC = [
    message(1, 'Mainnet upgrade', 1_000, { messageId: new Uint8Array(32).fill(1), reactions: [{ emoji: '👍', senders: [accountHex(2)] }] }),
    message(1, 'Chart', 2_000, { messageId: new Uint8Array(32).fill(2), attachments: [file] }),
    message(1, 'gm', 3_000, { messageId: new Uint8Array(32).fill(3) }),
    message(2, 'member chatter', 3_500),
  ];
  const partD = [
    message(1, 'Mainnet upgrade', 1_400, { messageId: new Uint8Array(32).fill(11), reactions: [{ emoji: '👍', senders: [accountHex(8)] }, { emoji: '🎉', senders: [accountHex(9)] }] }),
    message(1, 'Chart', 2_300, { messageId: new Uint8Array(32).fill(12), attachments: [file] }),
    // The same words a day later are a new post.
    message(1, 'gm', 3_000 + 24 * 60 * 60 * 1000, { messageId: new Uint8Array(32).fill(13) }),
  ];
  const merged = mergeParts([{ id: id('c'), messages: partC }, { id: id('d'), messages: partD }], authorities(community));
  assert.deepEqual(merged.map((item) => [item.body, item.copies.length]), [['Mainnet upgrade', 2], ['Chart', 2], ['gm', 1], ['gm', 1]]);
  assert.deepEqual(merged[0]!.reactions, [{ emoji: '👍', senders: [accountHex(2), accountHex(8)] }, { emoji: '🎉', senders: [accountHex(9)] }]);
  assert.deepEqual(merged[0]!.copies.map((copy) => copy.part), [id('c'), id('d')]);
  assert.equal(merged[0]!.messageId?.[0], 1);
});

test('a new member joins the first part with room to spare for linked devices and new admins', () => {
  assert.equal(pickPart([{ id: 'a', leaves: 48, pending: 1 }, { id: 'b', leaves: 40, pending: 3 }]), 'b');
  assert.equal(pickPart([{ id: 'a', leaves: 47, pending: 1 }]), undefined);
  assert.equal(pickPart([{ id: 'a', leaves: 20, pending: 0 }, { id: 'b', leaves: 1, pending: 0 }]), 'a');
});

test('the groups this device is in gather into communities in their own part order, newest record first', () => {
  const older = { community: { ...community, parts: [id('c')] }, revision: 1 };
  const newer = { community, revision: 2 };
  const records: Record<string, { community?: typeof community; revision?: number }> = {
    [id('d')]: newer, [id('c')]: older, [id('f')]: {},
  };
  const index = indexCommunities([id('f'), id('d'), id('c')], (group) => records[group]);
  assert.deepEqual([...index.keys()], [id('c')]);
  assert.deepEqual(index.get(id('c'))!.parts, [id('c'), id('d')]);
  assert.equal(index.get(id('c'))!.community, community);
  // A part whose record has not listed it yet still belongs to its community.
  const alone = indexCommunities([id('d')], (group) => group === id('d') ? { community: { ...community, parts: [id('c')] } } : undefined);
  assert.deepEqual(alone.get(id('c'))!.parts, [id('d')]);
});

test('a leave request stands until an owner or admin marks it done, so a later return is not undone', () => {
  const present = new Set([accountHex(2), accountHex(3), accountHex(4)]);
  const history = [
    message(2, LEAVE_REQUEST, 10, { messageId: new Uint8Array(32).fill(1) }),
    message(3, LEAVE_REQUEST, 20, { messageId: new Uint8Array(32).fill(2) }),
    message(3, encodeLeft(accountHex(2)), 30),
    message(5, encodeLeft(accountHex(2)), 40),
    message(4, LEAVE_REQUEST, 50, { messageId: new Uint8Array(32).fill(3) }),
    message(9, LEAVE_REQUEST, 60, { messageId: new Uint8Array(32).fill(4) }),
  ];
  assert.deepEqual(departures(history, present, authorities(community)).map((item) => item.accountId), [accountHex(3), accountHex(4)]);
  assert.deepEqual(departures([...history, message(1, encodeLeft(accountHex(3)), 70)], present, authorities(community))
    .map((item) => item.accountId), [accountHex(4)]);
  assert.equal(leftBy(history, accountHex(4)), true);
  assert.equal(leftBy(history, accountHex(5)), false);
  assert.deepEqual(announcements(history, authorities(community)), []);
});

test('a community notifies once per announcement across its parts, and its admins of each request', () => {
  const now = Date.now();
  const post = (part: number, sender: number, body: string, id: number) =>
    ({ ...message(sender, body, now - id), messageId: new Uint8Array(32).fill(id), direction: 'received' as const, epoch: 1 });
  const parts = [
    { id: id('c'), messages: [post(0xc, 1, 'Mainnet upgrade', 1), post(0xc, 2, 'member chatter', 2)] },
    { id: id('d'), messages: [post(0xd, 1, 'Mainnet upgrade', 3), post(0xd, 3, encodeJoinRequest(id('a')), 4)] },
  ];
  const thread = (viewer: number) => ({ scope: `group/${id('c')}`, title: 'Solana builders',
    messages: communityThread(parts, community, accountHex(viewer), now), senders: { [accountHex(1)]: '@bob', [accountHex(3)]: '@carol' } });
  assert.deepEqual(planNotifications([thread(5)], {}, { accountId: accountHex(5), username: 'dave' }, null).notifications.map((item) => item.body),
    ['@carol: Asked to join Trading', '@bob: Mainnet upgrade']);
  assert.deepEqual(planNotifications([thread(2)], {}, { accountId: accountHex(2), username: 'erin' }, null).notifications.map((item) => item.body),
    ['@bob: Mainnet upgrade']);
});

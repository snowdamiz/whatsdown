import { hex, utf8 } from './codec.ts';
import type { Reaction } from './reactions.ts';

// A community is a set of groups, its parts, whose records carry the same
// details and roles. The core lets only the owner change the roles, and the
// owner and admins everything else, and only they add or remove members. A
// part holds at most 64 devices, so a community grows by adding parts; its
// owner and admins sit in every part and post to all of them.
export type LinkedGroup = { id: string; name: string };
export type CommunityDetails = { about: string; groups: LinkedGroup[]; parts: string[] };
export type Roles = { owner: string; admins: string[] };
export type Community = CommunityDetails & Roles;

export const MAX_LINKED_GROUPS = 32;
export const MAX_PARTS = 64;
export const MAX_ADMINS = 16;
// The core holds at most this much beside a group's name and photo.
const MAX_COMMUNITY_BYTES = 16_384;
// A part takes new members while this leaves room for their linked devices and new admins.
const PART_FILL = 48;
const WEEK = 7 * 24 * 60 * 60 * 1000;
const HOUR = 60 * 60 * 1000;
const joinPrefix = 'MORSE-JOIN/1\n';
const devicePrefix = 'MORSE-DEVICE/1\n';
const leftPrefix = 'MORSE-LEFT/1\n';
// A member leaving asks the owner and admins to remove their devices.
export const LEAVE_REQUEST = 'MORSE-LEAVE/1';
const groupId = /^[a-f0-9]{64}$/;

export const communityId = (community: CommunityDetails): string => community.parts[0]!;

export function encodeCommunity(value: CommunityDetails): string {
  const about = value.about.trim();
  // Newlines are escaped in JSON; other control characters would reach the core raw.
  if (utf8(about).length > 512 || /[\u0000-\u0009\u000b-\u001f\u007f]/.test(about)) throw new Error('Shorten the description.');
  if (value.groups.length > MAX_LINKED_GROUPS) throw new Error(`A community holds up to ${MAX_LINKED_GROUPS} groups.`);
  if (new Set(value.groups.map((group) => group.id)).size !== value.groups.length) throw new Error('That group is already in the community.');
  if (!value.parts.length || value.parts.length > MAX_PARTS || new Set(value.parts).size !== value.parts.length ||
    !value.parts.every((part) => groupId.test(part))) {
    throw new Error(`A community spans up to ${MAX_PARTS} groups of members.`);
  }
  const groups = value.groups.map(({ id, name }) => {
    const trimmed = name.trim();
    if (!groupId.test(id) || !trimmed || utf8(trimmed).length > 96 || /[\u0000-\u001f\u007f]/.test(trimmed)) throw new Error('Invalid linked group.');
    return [id, trimmed];
  });
  const text = JSON.stringify([about, groups, value.parts]);
  if (utf8(text).length > MAX_COMMUNITY_BYTES) throw new Error('Shorten the description or the group names.');
  return text;
}

// Only the canonical encoding counts; anything else leaves the group a plain group.
export function parseCommunity(text: string): CommunityDetails | undefined {
  try {
    const value: unknown = JSON.parse(text);
    if (!Array.isArray(value) || value.length !== 3 || typeof value[0] !== 'string' || !Array.isArray(value[1]) ||
      !Array.isArray(value[2]) || !value[2].every((part: unknown) => typeof part === 'string')) {
      return undefined;
    }
    const details = {
      about: value[0],
      groups: value[1].map((group: unknown) => {
        if (!Array.isArray(group) || group.length !== 2 || typeof group[0] !== 'string' || typeof group[1] !== 'string') throw new Error();
        return { id: group[0], name: group[1] };
      }),
      parts: value[2] as string[],
    };
    return encodeCommunity(details) === text ? details : undefined;
  } catch {
    return undefined;
  }
}

// The owner's account, then each admin's in ascending order, as the core checks them.
export function encodeRoles(owner: string, admins: string[]): Uint8Array {
  const sorted = [...admins].sort();
  if (![owner, ...sorted].every((account) => groupId.test(account)) || sorted.includes(owner) ||
    new Set(sorted).size !== sorted.length || sorted.length > MAX_ADMINS) {
    throw new Error(`A community has one owner and up to ${MAX_ADMINS} admins.`);
  }
  return fromHex([owner, ...sorted].join(''));
}

export function parseRoles(input: Uint8Array): Roles | undefined {
  if (!input.length || input.length % 32 || input.length > 32 * (MAX_ADMINS + 1)) return undefined;
  const accounts = Array.from({ length: input.length / 32 }, (_, index) => hex(input.subarray(index * 32, index * 32 + 32)));
  const [owner, ...admins] = accounts;
  const valid = admins.every((admin, index) => admin !== owner && (index === 0 || admins[index - 1]! < admin));
  return valid ? { owner: owner!, admins } : undefined;
}

export const authorities = (community: Roles): Set<string> => new Set([community.owner, ...community.admins]);

// New roles for a community. Whoever hands ownership over stays on as an admin.
export function withRoles(community: Community, change: Partial<Roles>): Community {
  const owner = change.owner ?? community.owner;
  const kept = change.admins ?? community.admins;
  const admins = [...new Set(owner === community.owner ? kept : [...kept, community.owner])].filter((admin) => admin !== owner).sort();
  return { ...community, owner, admins };
}

// A member asks for a linked group inside the community's own encrypted groups,
// so the request reaches its owner and admins, who invite them the usual way.
export function encodeJoinRequest(id: string): string {
  if (!groupId.test(id)) throw new Error('Invalid group.');
  return joinPrefix + id;
}

// An owner's or admin's device that is missing from a part hands its one-use
// join package to the admins, one part at a time, inside a part it is already in.
export function encodeDeviceRequest(part: string, keyPackage: Uint8Array): string {
  if (!groupId.test(part) || keyPackage.length !== 369) throw new Error('Invalid device request.');
  return `${devicePrefix}${part}\n${hex(keyPackage)}`;
}

type Posted = { senderAccountId: Uint8Array; body: string; timestamp: number };
const isControl = (body: string) => body.startsWith(joinPrefix) || body.startsWith(devicePrefix) ||
  body === LEAVE_REQUEST || body.startsWith(leftPrefix);

// Members read, react and ask to join; only the owner and admins post. A client
// that posts anyway reaches no one's thread.
export function announcements<T extends Posted>(history: T[], authority: Set<string>): T[] {
  return history.filter((message) => authority.has(hex(message.senderAccountId)) && !isControl(message.body));
}

export type JoinRequest = { accountId: string; groupId: string; timestamp: number };

function joinTarget(message: Posted, community: CommunityDetails, now: number): string | undefined {
  if (!message.body.startsWith(joinPrefix)) return undefined;
  const id = message.body.slice(joinPrefix.length);
  return community.groups.some((group) => group.id === id) && now - message.timestamp <= WEEK ? id : undefined;
}

// The latest request per person and linked group from the past week, which is
// also how long the invitation it leads to stays open. Oldest first.
export function joinRequests(history: Posted[], community: CommunityDetails, now = Date.now()): JoinRequest[] {
  const latest = new Map<string, JoinRequest>();
  for (const message of history) {
    const id = joinTarget(message, community, now);
    if (!id) continue;
    const accountId = hex(message.senderAccountId);
    latest.set(`${accountId}/${id}`, { accountId, groupId: id, timestamp: message.timestamp });
  }
  return [...latest.values()];
}

// What an owner or admin is told about: each request, as the message that made it.
export function communityNotices<T extends Posted>(history: T[], community: Community, viewer: string, now = Date.now()): T[] {
  if (!authorities(community).has(viewer)) return [];
  return history.flatMap((message) => {
    const id = joinTarget(message, community, now);
    const group = community.groups.find((item) => item.id === id);
    return group ? [{ ...message, body: `Asked to join ${group.name}` }] : [];
  });
}

export type DeviceRequest = { accountId: string; deviceId: string; part: string; keyPackage: Uint8Array; timestamp: number };

// The latest request per device from the owner and admins: each device asks for
// one part at a time, so an older package is never used twice.
export function deviceRequests(history: (Posted & { senderDeviceId: Uint8Array })[], community: Community): DeviceRequest[] {
  const authority = authorities(community);
  const latest = new Map<string, DeviceRequest>();
  for (const message of history) {
    const match = /^MORSE-DEVICE\/1\n([a-f0-9]{64})\n([a-f0-9]{738})$/.exec(message.body);
    const accountId = hex(message.senderAccountId);
    if (!match || !authority.has(accountId) || !community.parts.includes(match[1]!)) continue;
    const deviceId = hex(message.senderDeviceId);
    latest.set(deviceId, { accountId, deviceId, part: match[1]!, keyPackage: fromHex(match[2]!), timestamp: message.timestamp });
  }
  return [...latest.values()];
}

// Whoever removed someone who left says so, so their request is not answered
// again should they be invited back.
export const encodeLeft = (accountId: string): string => {
  if (!groupId.test(accountId)) throw new Error('Invalid account.');
  return leftPrefix + accountId;
};

export type Departure = { accountId: string; timestamp: number };

// Who in a part asked to leave and is still there. A request is done once an
// owner or admin marks that person as gone after it. Oldest first.
export function departures(history: Posted[], present: Set<string>, authority: Set<string>): Departure[] {
  const pending = new Map<string, Departure>();
  for (const message of history) {
    const accountId = hex(message.senderAccountId);
    if (message.body === LEAVE_REQUEST) pending.set(accountId, { accountId, timestamp: message.timestamp });
    else if (message.body.startsWith(leftPrefix) && authority.has(accountId)) pending.delete(message.body.slice(leftPrefix.length));
  }
  return [...pending.values()].filter((departure) => present.has(departure.accountId));
}

// A device that sees its own account leave forgets the community too.
export const leftBy = (history: Posted[], accountId: string): boolean =>
  history.some((message) => message.body === LEAVE_REQUEST && hex(message.senderAccountId) === accountId);

export type Copy = { part: string; messageId?: Uint8Array };
type Mergeable = Posted & {
  messageId?: Uint8Array;
  attachments?: { objectId: Uint8Array }[];
  reactions?: Reaction[];
  reply?: { message?: { body: string } };
};

// The owner and admins send each post to every part. One post is the same
// sender, words, files and quote within an hour, once per part; its reactions
// add up across parts. Parts come in the community's own order, so a post keeps
// the first part's message ID as its key.
export function mergeParts<T extends Mergeable>(parts: { id: string; messages: T[] }[], authority: Set<string>): (T & { copies: Copy[] })[] {
  const merged: { key: string; post: T & { copies: Copy[] } }[] = [];
  for (const part of parts) {
    for (const message of announcements(part.messages, authority)) {
      const key = [hex(message.senderAccountId), message.body, message.reply?.message?.body ?? '',
        ...(message.attachments ?? []).map((file) => hex(file.objectId))].join('\n');
      const copy = { part: part.id, messageId: message.messageId };
      const match = merged.find((entry) => entry.key === key && Math.abs(entry.post.timestamp - message.timestamp) <= HOUR &&
        !entry.post.copies.some((item) => item.part === part.id));
      if (!match) {
        merged.push({ key, post: { ...message, copies: [copy] } });
        continue;
      }
      match.post.copies.push(copy);
      match.post.reactions = mergeReactions(match.post.reactions ?? [], message.reactions ?? []);
    }
  }
  return merged.map((entry) => entry.post).sort((left, right) => left.timestamp - right.timestamp);
}

// What a community thread tells a reader: the posts across its parts, and for
// its owner and admins each request to join its groups, oldest first.
export function communityThread<T extends Mergeable>(parts: { id: string; messages: T[] }[], community: Community,
  viewer: string, now = Date.now()): (T & { copies?: Copy[] })[] {
  return [...mergeParts(parts, authorities(community)), ...communityNotices(parts.flatMap((part) => part.messages), community, viewer, now)]
    .sort((left, right) => left.timestamp - right.timestamp);
}

function mergeReactions(left: Reaction[], right: Reaction[]): Reaction[] {
  const merged = left.map((reaction) => ({ ...reaction, senders: [...reaction.senders] }));
  for (const reaction of right) {
    const existing = merged.find((item) => item.emoji === reaction.emoji);
    if (!existing) merged.push({ ...reaction, senders: [...reaction.senders] });
    else existing.senders.push(...reaction.senders.filter((sender) => !existing.senders.includes(sender)));
  }
  return merged;
}

export type CommunityEntry = { community: Community; parts: string[] };

// The communities this device is in, by the ID of their first part: the newest
// record among the parts it holds, and those parts in the community's order.
export function indexCommunities(
  groups: string[],
  recordOf: (id: string) => { community?: Community; revision?: number } | undefined,
): Map<string, CommunityEntry> {
  const newest = new Map<string, { community: Community; revision: number }>();
  for (const group of groups) {
    const record = recordOf(group);
    if (!record?.community) continue;
    const id = communityId(record.community);
    const known = newest.get(id);
    if (!known || (record.revision ?? 0) > known.revision) newest.set(id, { community: record.community, revision: record.revision ?? 0 });
  }
  return new Map([...newest].map(([id, { community }]) => {
    const mine = groups.filter((group) => {
      const record = recordOf(group)?.community;
      return record && communityId(record) === id;
    });
    const ordered = community.parts.filter((part) => mine.includes(part));
    return [id, { community, parts: [...ordered, ...mine.filter((part) => !ordered.includes(part))] }];
  }));
}

// Two parts' records agree when everything but their revisions does.
export function sameRecord(left: { name: string; avatar?: string; community?: Community },
  right: { name: string; avatar?: string; community?: Community }): boolean {
  const roles = (value?: Community) => value ? [value.owner, ...value.admins].join() : '';
  return left.name === right.name && (left.avatar ?? '') === (right.avatar ?? '') &&
    (left.community ? encodeCommunity(left.community) : '') === (right.community ? encodeCommunity(right.community) : '') &&
    roles(left.community) === roles(right.community);
}

// The part a new member joins: the first with room to spare. Each pending
// invitation counts twice, for the devices it may bring.
export function pickPart(parts: { id: string; leaves: number; pending: number }[]): string | undefined {
  return parts.find((part) => part.leaves + 2 * part.pending <= PART_FILL)?.id;
}

export function fromHex(value: string): Uint8Array {
  return Uint8Array.from(value.match(/../g) ?? [], (byte) => Number.parseInt(byte, 16));
}

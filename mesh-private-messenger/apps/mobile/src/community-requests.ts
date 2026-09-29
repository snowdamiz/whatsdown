// Asking to join a community from outside it. Its link names the community and
// the owner or admin who shared it. The request and the answer are ordinary
// direct messages between those two, reading as what they say, so the admin
// sees who is asking and the community's members learn nothing until they are
// let in. An approval names the part the invitation that follows it is for.
export type CommunityLink = { community: string; admin: string; name: string };
export type CommunityControl =
  | { kind: 'request'; community: string; name: string }
  | { kind: 'answer'; community: string; part: string | null };

const requestPrefix = 'MORSE-COMMUNITY-REQUEST/1\n';
const answerPrefix = 'MORSE-COMMUNITY-ANSWER/1\n';
const WEEK = 7 * 24 * 60 * 60 * 1000;
const groupId = /^[a-f0-9]{64}$/;
const username = /^[a-z0-9._-]{1,64}$/;
const validName = (name: unknown): name is string => typeof name === 'string' && name.trim() === name && name.length > 0 &&
  new TextEncoder().encode(name).length <= 96 && !/[\u0000-\u001f\u007f]/.test(name);

export function encodeCommunityLink(link: CommunityLink): string {
  if (!groupId.test(link.community) || !username.test(link.admin) || !validName(link.name)) throw new Error('Invalid community link.');
  return JSON.stringify([link.community, link.admin, link.name]);
}

// Only the canonical encoding counts.
export function parseCommunityLink(text: string): CommunityLink | undefined {
  try {
    const value: unknown = JSON.parse(text);
    if (!Array.isArray(value) || value.length !== 3) return undefined;
    const link = { community: value[0], admin: value[1], name: value[2] };
    return encodeCommunityLink(link) === text ? link : undefined;
  } catch {
    return undefined;
  }
}

export function encodeCommunityRequest(community: string, name: string): string {
  if (!groupId.test(community) || !validName(name)) throw new Error('Invalid community request.');
  return requestPrefix + JSON.stringify([community, name]);
}

export function encodeCommunityAnswer(community: string, part: string | null): string {
  if (!groupId.test(community) || (part !== null && !groupId.test(part))) throw new Error('Invalid community answer.');
  return answerPrefix + JSON.stringify([community, part ?? '']);
}

function parseControl(body: string): CommunityControl | undefined {
  const prefix = body.startsWith(requestPrefix) ? requestPrefix : body.startsWith(answerPrefix) ? answerPrefix : undefined;
  if (!prefix) return undefined;
  try {
    const value: unknown = JSON.parse(body.slice(prefix.length));
    if (!Array.isArray(value) || value.length !== 2 || typeof value[0] !== 'string' || !groupId.test(value[0])) return undefined;
    if (prefix === requestPrefix) {
      return validName(value[1]) && body === encodeCommunityRequest(value[0], value[1])
        ? { kind: 'request', community: value[0], name: value[1] } : undefined;
    }
    const part = value[1] === '' ? null : value[1];
    return (part === null || (typeof part === 'string' && groupId.test(part))) && body === encodeCommunityAnswer(value[0], part as string | null)
      ? { kind: 'answer', community: value[0], part: part as string | null } : undefined;
  } catch {
    return undefined;
  }
}

// How requests and answers read in the chat between the two. One that does not
// parse is left as its text, as a malformed reply is.
export function applyCommunityControls<T extends { body: string }>(history: T[]): (T & { community?: CommunityControl })[] {
  const names = new Map<string, string>();
  return history.map((message) => {
    const control = parseControl(message.body);
    if (!control) return message;
    if (control.kind === 'request') {
      names.set(control.community, control.name);
      return { ...message, body: `Asked to join ${control.name}`, community: control };
    }
    const name = names.get(control.community) ?? 'the community';
    return { ...message, body: `${control.part ? 'Approved' : 'Declined'} the request to join ${name}`, community: control };
  });
}

type Controlled = { direction: 'sent' | 'received'; timestamp: number; messageId: Uint8Array; community?: CommunityControl };
const keyOf = (message: Controlled) => Array.from(message.messageId, (byte) => byte.toString(16).padStart(2, '0')).join('');

// The declined requests as kept: chat scope to request message IDs. Anything else is dropped.
export function parseDeclined(text: string | null): Record<string, string[]> {
  try {
    const value: unknown = JSON.parse(text ?? '{}');
    if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
    return Object.fromEntries(Object.entries(value).filter(([scope, keys]) => /^chat\/[a-f0-9]{32}$/.test(scope) &&
      Array.isArray(keys) && keys.length <= 256 && keys.every((key) => typeof key === 'string' && /^[a-f0-9]{32}$/.test(key))));
  } catch {
    return {};
  }
}

export type UnansweredRequest = { community: string; name: string; timestamp: number; key: string };

// What an admin has yet to answer in one chat: each community's latest request
// from the past week, unless an answer followed or it was declined here.
export function unansweredRequests(history: Controlled[], declined: readonly string[], now = Date.now()): UnansweredRequest[] {
  const latest = new Map<string, UnansweredRequest>();
  for (const message of history) {
    const control = message.community;
    if (control?.kind === 'request' && message.direction === 'received') {
      latest.set(control.community, { community: control.community, name: control.name, timestamp: message.timestamp, key: keyOf(message) });
    } else if (control?.kind === 'answer' && message.direction === 'sent') latest.delete(control.community);
  }
  return [...latest.values()].filter((request) => now - request.timestamp <= WEEK && !declined.includes(request.key));
}

export type OwnRequest = { community: string; name: string; timestamp: number } & (
  | { state: 'waiting' | 'declined' }
  | { state: 'approved'; part: string });

// What this account asked to join from the past week, and what it heard back.
export function ownRequests(history: Controlled[], now = Date.now()): OwnRequest[] {
  const latest = new Map<string, OwnRequest>();
  for (const message of history) {
    const control = message.community;
    if (control?.kind === 'request' && message.direction === 'sent') {
      latest.set(control.community, { community: control.community, name: control.name, state: 'waiting', timestamp: message.timestamp });
    } else if (control?.kind === 'answer' && message.direction === 'received') {
      const asked = latest.get(control.community);
      if (asked) {
        const base = { community: asked.community, name: asked.name, timestamp: asked.timestamp };
        latest.set(control.community, control.part ? { ...base, state: 'approved', part: control.part } : { ...base, state: 'declined' });
      }
    }
  }
  return [...latest.values()].filter((request) => now - request.timestamp <= WEEK);
}

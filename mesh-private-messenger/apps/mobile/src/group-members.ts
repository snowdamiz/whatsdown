import { hex } from './codec.ts';
import { t } from './i18n.ts';

type Device = { leaf: number; accountId: Uint8Array; deviceId: Uint8Array; local: boolean };

export type Person = {
  accountId: Uint8Array;
  // One of this person's devices is the one in hand.
  local: boolean;
  deviceIds: Uint8Array[];
  devices: number;
};

// A group's members are its devices, one leaf each; the people in it are
// those devices folded by account, in the order they joined. The creator
// holds the first leaf, so they lead.
export function summarizeMembers(members: readonly Device[]): { people: Person[]; devices: number } {
  const people = new Map<string, Person>();
  for (const member of [...members].sort((a, b) => a.leaf - b.leaf)) {
    const key = hex(member.accountId);
    const person = people.get(key) ?? { accountId: member.accountId, local: false, deviceIds: [], devices: 0 };
    person.deviceIds.push(member.deviceId);
    person.devices += 1;
    person.local ||= member.local;
    people.set(key, person);
  }
  return { people: [...people.values()], devices: members.length };
}

// "3 members", and the device count too once it says something the member
// count does not.
export function describeMembers({ people, devices }: { people: readonly Person[]; devices: number }): string {
  const members = t.plural('{count} member', '{count} members', people.length);
  return devices > people.length ? `${members} · ${t.plural('{count} device', '{count} devices', devices)}` : members;
}

// The line under a member's name: what they are to the group, then what they
// are to you, which is your private thread with them if you have one. You
// get only the first; you know the rest.
export function describeMember({
  local,
  creator,
  conversation,
}: {
  local: boolean;
  creator: boolean;
  conversation?: { verified: boolean; blocked: boolean };
}): string | undefined {
  const notes: string[] = [];
  if (creator) notes.push(t('Created the group'));
  if (!local) {
    notes.push(
      !conversation
        ? t('Not in your chats yet')
        : conversation.blocked
          ? t('Blocked')
          : conversation.verified
            ? t('Verified contact')
            : t('In your chats'),
    );
  }
  return notes.length ? notes.join(' · ') : undefined;
}

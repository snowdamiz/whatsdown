# Communities

A community is a set of ordinary encrypted groups, its parts, that share one
record. Its thread holds announcements, which only its owner and admins post;
members read and react. It lists other groups, its linked groups, which members
ask to join. A part holds at most 64 devices, so a community grows by adding
parts. Nothing new reaches the server: the record, the requests and the
announcements travel inside the existing group messages and durable outbox.

## The community record

A group's presentation record (name, photo, revision) gains two optional
vectors after the revision. The first holds the community's details as
canonical UTF-8 JSON:

```text
[about, [[linked group ID, name], ...], [part ID, ...]]
```

IDs are 64 lowercase hex digits and the first part ID names the community. The
second vector holds the roles: the owner's 32-byte account ID, then each
admin's in strictly ascending order.

| Value | Limit |
|---|---:|
| About text | 512 bytes |
| Linked groups | 32, names 1–96 bytes |
| Parts | 64 |
| Admins | 16 |
| Details vector | 16,384 bytes |
| Group record | 29,340 bytes |

The app trims values and serializes with `JSON.stringify`, so the details never
hold a raw control character, and it treats any non-canonical details as a
plain group. The core requires the details to be nonempty UTF-8 without control
characters, and the roles to be present with the details, a multiple of 32
bytes, at most 17 accounts, and ascending with no admin equal to the owner. The
group record ceiling rose from 12,500 to 29,340 bytes, including group records
inside presented messages; sender profile records keep the 12,500-byte bound.

## Who may change what

The core enforces these rules when a device saves a record, when it stores a
record received with a message, when it adds or removes a member, and when it
applies another member's commit.

- A plain group's record is its creator's (leaf 0), as before.
- A device first accepts a community record from the member whose welcome added
  it, recorded when it joins, and only if that record names them owner or admin.
  A device with no such record (it created the group, or joined before this
  change) accepts it from the group's creator instead, under the same condition.
- After that, the owner may change anything. Admins may change everything but
  the roles. A community never turns back into a plain group, and the highest
  revision wins.
- In a community only the owner and admins add or remove members, and send
  invitations. The owner alone removes an admin, no one removes the owner, and
  anyone with a role may remove their own other devices. Key updates are
  anyone's. A plain group's creator can never be removed; in a community that
  protection belongs to the owner instead.
- A commit that breaks these rules is rejected permanently, like any other
  invalid commit.

Handing ownership over is a record change by the owner that names someone else
owner; the former owner stays on as an admin.

## Parts

A new member joins the first part with room: at most 48 devices, counting each
pending invitation twice for the devices it may bring. When no part has room,
the inviting owner's or admin's device creates a group, writes the record with
the new part to it and to every part it holds, and invites the member there.

Owner and admin devices belong in every part so their posts reach everyone. A
device missing a part posts `MORSE-DEVICE/1\n`, the part's ID, `\n` and its
one-use join package in hex into its first part, one missing part at a time.
The owner's or admin's device with the lowest leaf in that part adds it through
the existing package join. Only the latest request per device counts, so a
package is never offered for two parts. This covers the creator's other
devices, newly appointed admins, and new parts.

A record change made in one part reaches the others through the devices that
hold both: an owner's or admin's device copies the newest record to its other
parts, and an admin's device does so only when the roles are unchanged.

The owner and admins send each post to every part they are in. Clients merge
the copies (same sender, words, quoted words and files within an hour) into one
announcement whose reactions add up; a reaction or a reply goes to each part's
own copy. Members see only the owner and admins listed; the owner and admins
see everyone across the parts.

A group send first checks every recipient account's devices against a
transparency checkpoint no older than five minutes, one stamped directory
lookup per account. A post to a large community therefore takes time in
proportion to its members, and each part's message is encrypted to each of its
devices.

## Announcements

Clients show only the owner's and admins' messages in a community's thread,
unread counts and notifications, with members' reactions folded in. Replies
are the owner's and admins' alone. Each recipient's client enforces this: a
modified client can still send to a part, and members' devices receive and
store what it sends, but no current client shows it.

## Joining through a link

An owner or admin shares a link, also shown as a QR code: `mesh://community/`
followed by the base64url encoding of canonical JSON `[community ID, their
username, community name]`. Whoever opens it can ask to join. Their device sends
`MORSE-COMMUNITY-REQUEST/1\n` and JSON `[community ID, name]` to that username as
an ordinary direct message, which arrives as a message request.

The admin's device lists requests from the past week for communities it runs,
leaving out anyone already in a part it holds, and notifies as for any message.
Letting someone in accepts their message request, since the core sends nothing
to an unanswered request, invitations included. It then invites them to a part
with room, and sends `MORSE-COMMUNITY-ANSWER/1\n` and JSON `[community ID, part
ID]`. The requester's device then accepts that admin's invitation to that part
without asking again, because asking was the consent. A decline cannot be sent
to an unanswered request, so it stays on the admin's device, in a sealed journal
the core keeps for that alone, and the request lapses for the requester after a
week. In the chat between the two, both messages read as what they say:
"Asked to join …" and "Approved the request to join …".

A link names the community and whoever shared it; it is not a key. Anyone can
ask, only that admin decides, and the core lets no one add members to a
community they do not run. A request reveals the requester to that admin alone;
the community's members learn of them only once they join.

## Join requests

A member asks to join a linked group with an ordinary message in their part
whose body is `MORSE-JOIN/1\n` followed by that group's ID. The requester is
the authenticated sender; the body names only the group. Requests never appear
as posts. The owner and admins are notified once per request.

An owner's or admin's device lists requests from the past seven days, across
the parts it holds, for linked groups it belongs to, the latest per person and
group, leaving out people already in that group or holding an open invitation
to it. Invite sends the existing [group invitation](group-invitations-v1.md) to
the requester's directory-bound username. Seven days matches that invitation's
lifetime.

A request is encrypted to the whole part, so every device in that part receives
it and could learn who asked to join which group.

## Leaving

A member or admin leaves by posting `MORSE-LEAVE/1` in each part their device is
in; the device then forgets the community in one transaction per part: its
index entry, state and keys, history, baseline and records. The account's other
devices forget it too when they receive the request. The owner hands the
community over before leaving.

In each part, the device allowed to remove the leaver with the lowest leaf (the
owner's for an admin, which also ends their role) removes every device of that
account and posts `MORSE-LEFT/1\n` with the account's ID. A request stands until
such a marker follows it, so a member invited back later is not removed again.
Groups joined through the community stay.

## Limits

- Parts and linked groups each keep the 64-device group limit.
- Linked group names are copied when a group is linked and do not follow later
  renames.
- Older clients cannot decode a record with the new vectors. They store and show
  the community's messages undecoded and may fail to load its history, so every
  member needs this version.

Development builds show sample communities under **You → Development → Sample
content**: one you own spanning two parts, one you belong to, a request through
your link and one of your own that is waiting.

Checks: `npm test` and `npm run typecheck` in `apps/mobile`; after the desktop
web export, `npm run test:communities` in `apps/mobile`. In
`packages/mobile-core`, `tests/presentation.test.mpl` covers the record bounds
and who may change it, and `tests/community_roles.test.mpl` covers roles,
enforced commits, handover and forgetting over real groups, and
`tests/journal.test.mpl` the journal of declined requests.

# Contact address v1

A mailbox's address is published in the directory, so anyone can deposit into
it, and every deposit is anonymous to the delivery service. Without more,
anyone can fill a person's mailbox and stop their own contacts reaching them.
The service cannot tell senders apart. It can tell addresses apart.

## The second address

A device creates one secret 32-byte **contact address** and publishes only its
SHA-256 hash, in its signed `OTB` publication (`canonical-codecs-v1.md`). A
sender who knows the address uses it as the `mailbox_token` of an ordinary
outer envelope. Nothing else on the wire changes: not the envelope, not the
sealed delivery, not the proof of work.

The service looks a deposit's address hash up among contact addresses first and
public addresses second, stores the envelope under the mailbox's own hash, and
marks it as a contact's. Fetch, acknowledgement and deduplication are
untouched. A delivered envelope is rebuilt with the public address, which
nothing end to end authenticates, so a device's own-mailbox check needs no
knowledge of the scheme.

## What it buys

A mailbox holds 4 MiB and 4,096 envelopes (`delivery-wire-v1.md`). Envelopes
sent to the public address may hold at most three quarters of each, 3 MiB and
3,072, and are limited to 24 a minute; envelopes sent to the contact address
may use the whole mailbox at 32 a minute. The last quarter is therefore always
there for contacts, whatever strangers do. Every limit answers `429`, so a
sender cannot tell which one it met.

The share kept for the public address is large on purpose. A group fans out to
members who are often not each other's direct contacts, and their envelopes
arrive at the public address.

## How a contact gets it

A device hands its contact address over inside the encrypted channel, as
inner-envelope extension `1` (32 bytes, never mandatory), on every direct
message it sends: to the other side's devices and to its own. A device that
receives one from an authenticated, unblocked peer keeps it against that
peer device's public address, and from then on addresses envelopes for that
device to it, in direct messages and in group fan-out alike. The first message
from a stranger necessarily arrives at the public address.

A device only hands an address over once the directory has answered a
publication that named it. Before that the directory could not route it.

The address is a hint about where to send, not a credential. A wrong one only
costs its giver their own delivery: the directory answers an address nothing is
registered under with `410`, exactly as it answers a revoked mailbox, the
sender gives up on that one envelope, forgets the address, and goes back to the
public one.

## Rotation

Blocking a conversation gives the device a new contact address. The next
publication names it, the directory retires the old one, and everyone else is
handed the new one with the next message. A retired address keeps routing for
good, as a stranger's would: rotation never makes an envelope undeliverable, a
hostile former contact is demoted rather than refused, and republishing an old
address (a device that lost its state does so in good faith) is accepted
without bringing it back. An address that already routes anywhere can never be
claimed by another mailbox, and contact addresses are looked up before public
ones, so neither publishing nor registering under someone's address can
intercept it.

## What the service learns

One bit per envelope: whether it arrived at the mailbox's contact address. It
learns that the sender is someone the recipient, or a contact of theirs, gave
the address to; it does not learn who. The address is the same for all of a
device's contacts, so it does not distinguish them. The privacy edge sees
neither the address nor the bit, which travel inside the sealed delivery.

## Not covered

There is no setting to rotate without blocking, and no way to refuse the public
address altogether. Group members who are not direct contacts reach each other
at the public address. A contact who turns hostile can fill the mailbox until
they are blocked.

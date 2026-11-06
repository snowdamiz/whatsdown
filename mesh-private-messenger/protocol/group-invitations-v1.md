# Group invitations by username

An existing member sends an invitation from group details by exact username.
The recipient sees the inviter and group in Groups and explicitly accepts or
declines. Acceptance adds only the device on which the user accepts. Other
active devices can accept their own copy independently. QR joining remains an
optional local exchange.

Invitations and acceptances use the existing authenticated, encrypted direct
message sessions and durable outbox. They are control messages, never parsed
from ordinary chat text or sent as public directory records. No service endpoint
or group secret is added to the directory. Both clients need this version;
older clients reject the new message types.

## Wire and identity binding

Inner-envelope type 3 carries a canonical vector list containing the random
16-byte invitation ID, 32-byte group ID, eight-byte expiry in milliseconds, and
188-byte group baseline checkpoint. Type 4 carries the invitation ID, group ID,
and the accepting device's signed group key package (369-byte v1 or 401-byte v2).
The v2 signature binds the 32-byte witness-set ID after the witness count.
Clients create v2 packages and check their set and threshold against the native
configuration. A legacy unbound package is accepted only under native config v1.
Envelope sender account/device identity is authenticated by the direct session.

The inviter records every target device under the invitation ID. A response is
actionable only for a still-pending invitation and the exact authenticated
recipient account/device. Completion resolves the account's current device set
again and uses the existing signature, revocation, and transparency checks.
Group membership and the outgoing welcome commit atomically with marking the
invitation complete. Repeated completion does not add the device again.

The accepting device generates a separate key package for each invitation.
Private keys stay in native encrypted storage. Acceptance state commits with
the encrypted response's session and outbox. A remote welcome must match the
accepted group, baseline checkpoint, inviter account/device and its signing key
verified at acceptance as committer, and
the accepting device's package. An ordinary message containing an invitation
or key-package string has no invitation semantics.

A native witness-set change invalidates pending packages for that set. After
fresh evidence verifies under the new pins, creating a package replaces its
public bytes and sealed private keys atomically, using a compare-and-swap on
the prior package. A late welcome for the old package cannot join the device.
Retrying an accepted invitation after fresh verification renews its scoped
package and sends a new authenticated acceptance. It preserves the original
inviter signing key, group, baseline and expiration. The inviter can replace a
pending acceptance only with the current native set; delayed old responses
cannot roll it back. Completion authenticates the existing group's policy
transition before admission. Already completed invitations are not reopened:
if their old welcome is stranded across a native upgrade, a member must remove
the unjoined device and send a new invitation.

## Persistence and limits

Incoming controls commit with their receiving ratchet state. Blocked senders
cannot deliver invitations or complete membership changes. Accepting a group
invitation does not implicitly accept a pending direct-message request.
Decline is local and sends no reply.

Invitations must be accepted and completed by the inviter within seven days.
After acceptance, the recipient retains its pending keys for an additional
30 days, matching the welcome's existing delivery lifetime. The encrypted
invitation index holds at most 128 records; expired records and their pending private keys are removed.
The existing outbox, mailbox, and group-size limits still apply.

The device that sent the invitation must connect again after acceptance to
validate the current device set and send the welcome. Until then, the recipient
sees a waiting state. Server delivery retries and app restarts preserve the
pending flow; no simultaneous connection or camera scan is required.

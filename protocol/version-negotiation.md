# Protocol Version Negotiation

Every codec, cryptographic suite, transparency checkpoint, and persisted
snapshot carries an explicit version. Version is the first canonical field;
there is no unversioned production path.

## Version 1 identifiers

- Protocol version: `1`
- Classical suite: `0x0001` (`mesh-msg/profile-a/v1`)
- Experimental hybrid suite: `0x0002` (`mesh-msg/profile-b/v1`)
- Development group suite: `0x0003` (`mesh-mls/v1`), internally verified per candidate and
  not an RFC 9420 wire profile
- Envelope, encrypted payload, credential, prekey bundle, transcript, and
  extension encodings each carry version `1`. The ratchet snapshot is at
  version `3`; versions `1` and `2` are still read and rewritten as `3`
  (`compatibility-matrix.md`), and the direct-security ratchet proof and
  `ratchet_v4.test.mpl` cover those migrations.
- Ratchet messages are versions `1`–`3` (cleartext headers) and `4` (encrypted
  headers and the post-quantum ratchet, [`ratchet-message-v2.md`](ratchet-message-v2.md)).

Hybrid credentials and bundles advertise `[0x0002, 0x0001]`; classical values
advertise only `[0x0001]`. Negotiation selects `0x0002` when both peers support
it. Selecting `0x0001` is an explicit compatibility result, never a retry after
a hybrid failure.

## Suite floor

Security config version 2 carries a minimum session suite (`1` or `2`;
version 1 configs mean `1`). At `2` a new session never starts at suite
`0x0001`: the initiator refuses before claiming a prekey
(`peer_suite_below_floor`, which the app shows as "This contact's app needs an
update to start a secure session"), and a responder refuses a suite `0x0001`
first message (`initial_suite_below_floor`, acknowledged unopened). Existing
classical sessions are not handshakes and keep working; renewal moves their
devices to suite `0x0002` ninety days into their credentials' year, which is why
the floor is raised 90 days after the renewal release (plan D17). Session
resets and suite upgrades start new sessions and obey the floor too. The CLI
reads the same field from `MESSENGER_SECURITY_CONFIG`.

## In-session features

A session's ratchet format is negotiated inside the session, not in bundles or
credentials, so no directory, renewal or new handshake is involved:

- Each client puts optional inner-envelope extension `3` (session features, one
  byte: `1` ratchet message 4, `2` post-quantum ratchet, `4` session reset, `8`
  deniable group messages) in every direct message. Old clients ignore it.
- A device signs a group epoch deniably (group message 6) only when every other
  member device advertised `8` over a session it can send on as it is; a
  receiver holding a device's key for an epoch refuses that device's
  long-term-signed messages there ([`mls-groups-v1.md`](mls-groups-v1.md#deniable-sender-authentication)).
- A receiver records a peer's features only from an authenticated message, and
  never forgets one; an attacker can neither forge nor strip them.
- A session switches to ratchet message `4` at the sender's next sending root
  step after the peer advertised `1`, and starts the post-quantum ratchet at a
  sending root step of a suite `0x0002` session whose peer advertised `2`.
- Receivers read version `4` whether or not they recorded anything (they try the
  upgrade header key), so the switch needs no agreement round.
- There is no way back: an upgraded session refuses to send bare versions and
  refuses a cleartext header that would begin a new chain.

## Downgrade rules

- The selected suite is covered by credential or prekey signatures, handshake
  transcript hashing, and message associated data.
- Each device records the strongest authenticated suite observed for each
  remote device.
- A subsequently offered weaker suite is rejected as a downgrade and requires
  explicit session recovery; the server cannot authorize fallback.
- A higher but unsupported version or suite returns an explicit unsupported
  error. It is never retried with a lower value automatically.
- Malformed version lists, duplicate suite identifiers, and an empty mutual
  suite set fail before key agreement.
- A changed ML-KEM ciphertext fails initial-message authentication; it is not
  retried as a classical handshake.
- Below the security config's suite floor, no new session starts in either
  direction (above).
- After a session encrypts its headers, a cleartext-header message beginning a
  new chain is refused as a downgrade.

## Codec compatibility

Canonical codecs use fixed field order and integer width, bounded lengths and
nesting, explicit optional extensions, and no trailing data. Unknown mandatory
fields are rejected. Unknown optional extensions may be preserved or ignored
only when that behavior is defined by the current version.

A decoder may accept an older version only when the compatibility matrix names
that exact pair and migration tests cover it. Persisted snapshots are migrated
explicitly and atomically; an unknown snapshot version is never interpreted as
the current one.

Every new version must add interoperability, downgrade, unknown-extension, and
snapshot-migration tests before release.

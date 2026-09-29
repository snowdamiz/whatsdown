# Multi-device wire v1

All integers are unsigned big-endian. Variable fields use a four-byte length prefix. Decoders reject unknown versions, wrong magic, trailing bytes, duplicate capabilities, and values over the stated bounds.

## Link request (`LNK`)

```text
u8 version = 1
"LNK"
nonce[32]
device_id[16]
device_signing_public_key[32]
device_dh_public_key[32]
u64 capabilities
u64 created_at_ms
u64 expires_at_ms
```

The request expires after a short linking window. Its SHA-256 hash identifies the exact QR attempt.

## Link authorization (`LNA`)

```text
u8 version = 1
"LNA"
request_hash[32]
username<64>
account_identity<16582>
device_credential<4096>
account_authorization_signature[64]
```

The device credential binds the new device keys to the account. The final account signature is domain-separated and covers the request hash, username, account identity, and credential, preventing authorization replay across link attempts.

## Device set (`DVS`)

```text
u8 version = 1
"DVS"
username<64>
account_identity<16582>
u64 sequence
u8 active_device_count (1..8)
repeated directory_entry<36006>
u8 revoked_device_count (0..32)
repeated revoked_device_id[16]
```

The maximum encoded device set is 305,260 bytes.

Every active entry must use the same username and byte-identical account identity. Mailbox capabilities and revoked IDs must be unique. Clients validate every account-signed device credential before caching or using the set. Milestone 13 adds transparent inclusion and consistency proofs over this canonical record.

## Revocation (`DVR`)

```text
u8 version = 1
"DVR"
account_id[32]
device_id[16]
u64 expected_device_set_sequence
account_authorization_signature[64]
```

The signature is domain-separated over the unsigned record. The directory accepts only the next sequence, permanently records the revoked device ID, disables its mailbox, and never permits that device ID to be registered again. It keeps the revocation and wakes the device's mailbox stream. When the device next registers, it gets `410` with the revocation as the body, and erases its copy if the revocation names it and verifies against the account identity it holds. Devices revoked before revocations were kept get a plain `409`.

## Account deletion (`ADL`)

```text
u8 version = 1
"ADL"
account_id[32]
u64 issued_at_ms
account_authorization_signature[64]
```

The signature covers `mesh-msg/v1/account-deletion` followed by the record with an all-zero signature. Only the device that created the account holds the account authorization key, so only it can delete the account; a linked device leaves it instead (below). The directory takes the statement if it is at most five minutes old and at most one minute ahead, the same window as signed mailbox requests. It then removes every device, mailbox, waiting envelope, prekey, push binding and contact address of the account, frees the username, and clears the account's transparency entries while keeping their leaf hashes. It wakes the account's mailbox streams, so devices still listening fetch, fail, and re-register at once.

The directory keeps the account ID with the statement and answers any later registration of that account with `410` and the statement as the body. The username can go to a new account but never back to the deleted one. A device left behind erases its copy only if the statement verifies against the account identity it holds, with no freshness check: an account is deleted for good, and a server that only claims so erases nothing.

## Departure (`DPT`)

```text
u8 version = 1
"DPT"
account_id[32]
device_id[16]
u64 issued_at_ms
device_signature[64]
```

The signature is made with the departing device's own signing key, over `mesh-msg/v1/device-departure` followed by the record with an all-zero signature, so a device can only ever take itself out. The directory checks it against the signing key in that device's stored credential, under the same freshness window, then revokes the device exactly as `DVR` does: the next device-set sequence, a logged device set, a closed mailbox, and no prekeys. An account or device that is already gone answers as if it had just left. The last active device cannot leave; it deletes the account instead. The departure is kept like a revocation, so a device whose erase did not run gets `410` with its own departure and erases itself once the departure verifies against its own signing key.

## Renewal

A device credential and the signed prekey in its bundle are issued for one
year, and both sit in the logged device set: a client matches every bundle it
is handed against the logged one byte for byte. So a device is renewed only by
a logged transition, which takes the next device-set sequence like any other.
A device renews once fewer than 275 days are left on its credential or its
signed prekey, whichever runs out first: ninety days into a one-year
credential, which leaves nine months for a device that is seldom opened. Every
pass that loads the account's device set, with its transparency evidence,
checks.

Only the device that created the account holds the account key, so only it can
sign a credential.

- **The device holding the account key** renews itself in one transition: a
  new credential for the same device ID, signing key and identity key, at the
  next sequence, for a new ML-KEM-768 prekey, and a new signed prekey with a
  higher identifier. The credential is always hybrid, so a classical device
  moves to suite `0x0002` here.
- **A linked device** asks. It makes its next signed prekey and ML-KEM prekey
  itself and publishes a request for them in its own bundle, under the
  credential it has. The device holding the account key, on its next pass,
  answers every request in the set with a credential for exactly the keys
  asked for, at the next sequence, and registers the answer in that device's
  place. A request no one answers changes nothing, and the device expires with
  the credential it has; a device whose account key is lost can no longer be
  renewed, just as no device can be linked.

### Renewal request (`RNW`)

```text
u8 version = 1
"RNW"
account_id[32]
device_id[16]
u64 signed_prekey_id
signed_prekey[32]
u64 expires_at_ms
signed_prekey_signature[64]
post_quantum_prekey[1184]
device_signature[64]
```

The request is 1,412 bytes. `signed_prekey_signature` is the ordinary
signed-prekey statement (`classical-handshake-v1.md`) for version 1 and suite
`0x0002`, whatever the device's credential says now, because the answer is
hybrid; the statement binds no other credential field, so the signature stays
valid under the credential that answers. `device_signature` is made with the
device's own signing key over `mesh-msg/v1/device-renewal-request` followed by
the record with an all-zero signature, so no one but the device can ask for
keys in its name. The next signed-prekey identifier must be higher than the
one in the bundle.

A request travels in the device's bundle as extensions 1 and 2, the first
1,024 bytes and the other 388, because one extension holds at most 1,024 bytes.
Both are optional extensions, which peers ignore, and no other extension uses
those identifiers. The answer is the bundle made of the new credential, the
requested signed prekey and ML-KEM prekey, suites `[0x0002, 0x0001]`, the
requested expiry, no one-time prekey and no extensions.

### What the directory accepts

A registration for a device the directory already holds, from its own mailbox,
is one of:

- **the same entry**, or **one the device has since replaced**: an older
  credential sequence, or under the same credential the bundle from before a
  request or an older request. Both answer `200` and change nothing, so a
  device that has not yet seen its renewal in the set still connects;
- **a renewal**: a different credential for the same device and keys, at
  exactly the next sequence, never below the suite it replaces, carrying no
  request, with either a higher signed-prekey identifier or (the original
  classical-to-hybrid step) the same signed prekey reauthorized for suite
  `0x0002`;
- **a request**: the same credential and bundle apart from a request, or a
  newer one, that the device signed and that names a higher signed-prekey
  identifier.

Anything else is `409`. An accepted transition answers `201` and is logged.
Renewals leave one-time prekeys and the last-resort prekey alone.

A bundle whose credential or signed prekey has run out, but which verified until
then, is **lapsed**. A device already in the account may still register a
lapsed entry (answered as registered) and publish a request under it, so a
device that stayed away past its expiry can ask for renewal when it returns;
it can do nothing else. A new device cannot join with a lapsed credential
(`400`).

### What clients do with it

A device that registered a renewal treats it as pending until the verified set
shows it; until then it offers the same renewal again (the device holding the
account key re-signs its credential for the sequence the set is at by then) and
already opens mail sealed to it. When the set shows a newer entry for the
device, built only on keys it holds, the device takes it on; an older entry is
a rollback and refused (`unrecognized_device_entry`).

The replaced bundle is not forgotten at once. A sender whose evidence was fresh
may still seal to it for up to five minutes after the switch, and a first
message sealed to it can then wait in a mailbox for up to 31 days. The device keeps the bundle, its signed
prekey and its ML-KEM prekey, and a pending renewal it no longer needs, until
35 days after the set first showed their successor, then destroys them; it
keeps at most sixteen such bundles. Some kept bundles share a signed prekey (a
request changes nothing else), so the responder picks the bundle a first
message was sealed to by its transcript hash, which binds the bundle's hash, and
checks its own bundle as of when it was last valid.

A device whose credential or signed prekey has run out stays in the set, still
signed by the account key: clients keep it apart as expired, encrypt to it no
more, and show it as a device that gets no messages until it is opened again,
which can still be removed. It no longer makes the whole set fail to verify.
Only the device IDs, signing and identity keys of the devices, and the revoked
IDs, count as a change to review; a renewal changes none of them.

Each renewal is one entry in the transparency log: about four a year for the
device holding the account key, and eight for each linked device (its request
and the answer). See `key-transparency-v1.md` for the log's development ceiling.

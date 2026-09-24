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

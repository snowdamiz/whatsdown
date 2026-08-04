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

The signature is domain-separated over the unsigned record. The directory accepts only the next sequence, permanently records the revoked device ID, disables its mailbox, and never permits that device ID to be registered again.

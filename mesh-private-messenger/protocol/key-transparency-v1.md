# Key Transparency v1

Status: development profile. Production activation still requires independent
witness operation and external review.

## Commitments

Each canonical account/device-set transition is hashed as:

```text
SHA-256("mesh-msg/v1/transparency-leaf" || canonical transition bytes)
```

The balanced Merkle tree hashes internal nodes with
`mesh-msg/v1/transparency-node`. Checkpoints bind the tree size and root,
monotonic checkpoint sequence, previous signed-checkpoint hash, timestamp, and
the service signing public key under `mesh-key-transparency-v1`.

## Client rules

Clients reject a directory response unless all of these hold:

- the returned device-set commitment has a valid inclusion proof;
- the service checkpoint signature matches the pinned service key;
- the new tree is consistent with the cached checkpoint;
- the configured threshold of distinct, pinned witnesses signed the exact
  checkpoint hash;
- account and device-set sequence rules still pass independently.

Two valid service-signed checkpoints at the same sequence and tree size with
different roots are a publishable conflict. Witness IDs are not authorities by
themselves; each ID is pinned to an expected public key.

## Proof representation

The initial bounded representation carries at most 4,096 leaf commitments.
This keeps verification straightforward without weakening inclusion or
append-only checks. Replace it with compact RFC 6962-style paths before log
bandwidth becomes material; the leaf, node, checkpoint, and witness domain
separators remain stable.

Witnesses and optional blockchain anchors receive checkpoint commitments only,
never usernames, device records, mailbox capabilities, account identifiers, or
message data.

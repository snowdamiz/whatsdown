# Key Transparency v1

Status: implemented development profile. The two witness keys currently share
an operator/account; they do not provide independent trust against that
operator. Internal verification is required for release. Outside review is
additional scrutiny, not an activation prerequisite.

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

## Proof representation and its ceiling

A proof carries every leaf commitment of the tree it describes, at most 4,096.
The tree itself already has RFC 6962's shape and domain-separated leaf and node
hashes, so roots, checkpoints, and witness signatures would be unchanged by
compact audit paths.

The full leaf list is load-bearing, though, not just simple: it lets a client
check *any* earlier checkpoint against its cached view offline. Every group
member binds such an anchor checkpoint, and `transparency_checkpoint_in_view`
verifies it by re-slicing the one cached leaf list. An RFC 6962 consistency
proof covers a single pair of tree sizes, so moving to compact paths requires
fetching and caching one proof per anchor through the group flows. That
redesign has not been done, and the 4,096-entry ceiling therefore remains.

Registration is anonymous, so the ceiling has to fail safe. It used not to: an
append past 4,096 succeeded, after which building evidence failed and every
lookup for every account returned an error. The directory now refuses to
append past the ceiling, and refuses *new accounts* from 3,584 entries,
reserving 512 for existing accounts to link, rotate, and revoke devices. A
registration flood can therefore close registration (`507`, nothing committed)
but cannot take lookups down or stop anyone revoking a compromised device.
`transparency_capacity.test.mpl` forces the log to both limits and shows
lookups still answer. Reaching the ceiling still ends growth for the
deployment; it is a development bound, not a production capacity.

Witnesses and optional blockchain anchors receive checkpoint commitments only,
never usernames, device records, mailbox capabilities, account identifiers, or
message data.

The client rejects directory evidence more than five minutes old or more than
one minute ahead of its clock. Receipt time does not renew a replayed checkpoint.
The directory refreshes an unchanged tree on demand after four minutes, advancing
the signed checkpoint sequence and retaining the same tree root. New witnesses
must sign that new checkpoint before clients can authorize it. Migration 010
allows several checkpoint sequences for the same tree size. A failed or pending
witness check remains an error; it does not permit unchecked encryption.

Freshness currently applies to evidence ingestion and cached device-set
requirements used by fanout and identity operations. Extending it to every group
send and updating group recipient discovery remain implementation work tracked
in the security plan; these paragraphs do not claim those paths complete.

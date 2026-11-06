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
- The original envelope, encrypted payload, credential, prekey bundle, transcript
  and extension encodings carry version `1`. Legacy ratchet snapshots write
  version `2` and still read version `1` (`compatibility-matrix.md`).

The adopted development C4/D3 [HE profile](header-encryption-v1.md) adds HST/INI `2`,
RAT `4` and HE snapshot RST `3`. It leaves the RCP transport at `1` / outer suite
`4` and retains format-specific legacy readers. HE support is authenticated
credential mask `8`, not a new encryption-suite identifier. The combined mobile
reader mask is `31`; the text-only CLI mask is `9`. These describe the development profile;
production activation remains separate. An unsupported or failed HE path does not authorize
retrying a legacy version. RNWv2 upgrades preserve prior bits and require the
device's exact signed claim before a capability-changing account answer.

Hybrid credentials and bundles advertise `[0x0002, 0x0001]`; classical values
advertise only `[0x0001]`. Negotiation selects `0x0002` when both peers support
it. Selecting `0x0001` is an explicit compatibility result, never a retry after
a hybrid failure.

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

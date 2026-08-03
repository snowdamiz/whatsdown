# Compatibility Matrix

| Feature | Wire/version identifier | Persistence | Compatibility rule | Production status |
|---|---|---|---|---|
| Classical one-to-one | protocol `1`, suite `0x0001` | ratchet snapshot `1` | Authenticate the selected suite; reject unknown mandatory extensions and downgrade below the strongest observed suite | Development only; independent security review required |
| Hybrid one-to-one | protocol `1`, suite `0x0002` | ratchet snapshot `1` | Explicit negotiation only; classical fallback is permitted only when the authenticated peer does not advertise hybrid support | Disabled pending independent cryptographic review |
| Group messaging | group version `1`, suite `0x0003` | group snapshot `1`, storage purposes `16` and `17` | Reject unsupported extensions, stale epochs, non-canonical trees, and incompatible snapshots | Disabled pending independent protocol review; not RFC 9420 wire-compatible |
| Attachments | attachment wire `1` | none; hosts persist only sealed manifests and chunks | Reject changed manifests, wrong chunk indices, non-canonical sizes, oversized input, and trailing bytes | Development only; streaming mobile and object-store integration required |
| Encrypted backups | backup wire/profile `1`, Argon2id v1.3 | opaque sealed manifest and chunks only | Parameters are fixed per version; reject changed profiles, manifests, chunk order, snapshot hash, oversized input, and trailing bytes | Development only; opt-in mobile restore and opaque backup storage required |
| Directory and delivery | delivery wire `1` | migrations `001`–`004` | Clients and services reject unsupported versions and trailing data | Development only |
| Mobile native ABI | `MESH_LIBRARY_ABI_VERSION = 1` | encrypted record format `1` | Host and generated bindings must use the same ABI; secrets never cross into TypeScript | Physical iOS and Android proof required |

Persisted records and wire messages always carry their existing version. An incompatible field, algorithm, domain label, or canonical encoding requires a new version; it must not silently reinterpret version `1`. Database migrations are forward-only. Rollback is allowed only while the target revision understands every deployed migration, protocol version, suite, snapshot, and native ABI.

CI pins the exact Mesh revision used by Whatsdown. Updating that revision requires protocol, persistence, native-binding, downgrade, and mobile proof reruns before merge.

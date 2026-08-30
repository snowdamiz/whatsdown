# Whatsdown

Whatsdown is a Mesh-first, end-to-end encrypted private messenger. The product dogfoods Mesh's public APIs, but the Mesh compiler and runtime are maintained in their own repository.

The implementation roadmap and security caveats live in [mesh-private-messenger-complete-plan.md](mesh-private-messenger-complete-plan.md). This project is under active development and makes no production-security claim.

## Repository layout

- `mesh-private-messenger/` — protocol, services, clients, mobile app, and infrastructure

Developers may keep a separate `mesh-lang/` checkout in this directory for local reference and integration testing. It is intentionally ignored and is never part of this repository.

## Run locally

With Docker, Rust, Xcode or the Android NDK, Node.js, and a local `mesh-lang/`
checkout installed, one command builds and starts PostgreSQL, every backend
service, both transparency witnesses, and the Expo development server:

```sh
./run.sh
```

Use `./run.sh build` to build without starting processes. Ctrl-C stops the
processes and PostgreSQL container while preserving the development volume.
Override `MESH_LANG_DIR` when the Mesh checkout lives elsewhere and
`WHATSDOWN_MOBILE_PLATFORM=ios|android` when platform detection is insufficient.

The protocol contracts include the [threat model](mesh-private-messenger/protocol/threat-model.md),
[privacy contract](mesh-private-messenger/protocol/privacy-contract.md),
[cryptographic profile](mesh-private-messenger/protocol/crypto-profile-v1.md),
[ratchet wire format](mesh-private-messenger/protocol/ratchet-message-v1.md),
[delivery wire format](mesh-private-messenger/protocol/delivery-wire-v1.md),
[sealed-delivery format](mesh-private-messenger/protocol/sealed-delivery-v1.md),
[secret-purpose inventory](mesh-private-messenger/protocol/secret-purpose-inventory.md),
and [storage-wrapping format](mesh-private-messenger/protocol/storage-wrapping-v1.md).

## Development rules

- Reusable capabilities are implemented and reviewed in the separate Mesh repository before the messenger consumes them.
- Protocol state machines are Mesh source; application-level Rust protocol code is prohibited.
- Secret values never use ordinary `Bytes`, logs, or serialization.
- Durable delivery is committed to PostgreSQL before actor wakeups.
- Every behavioral change follows a red-green-refactor cycle.

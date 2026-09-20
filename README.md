# Morse

Morse is a Mesh-first, end-to-end encrypted private messenger. The product dogfoods Mesh's public APIs, but the Mesh compiler and runtime are maintained in their own repository.

The implementation roadmap and security caveats live in [mesh-private-messenger-complete-plan.md](mesh-private-messenger-complete-plan.md). This project is under active development and makes no production-security claim.

The [security hardening and verification plan](mesh-private-messenger-security-plan.md) defines the next implementation slices, adversarial tests, and internal release criteria without requiring outside-audit approval.

## Repository layout

- `mesh-private-messenger/` — protocol, services, clients, mobile app, and infrastructure

Developers may keep a separate `mesh-lang/` checkout in this directory for local reference and integration testing. It is intentionally ignored and is never part of this repository.

## Run locally

The [desktop app](mesh-private-messenger/apps/desktop/README.md) supports Windows
and macOS, shares the mobile UI and encrypted Mesh core, and includes GitHub
Actions installer builds and tagged releases.

On macOS, with Docker Desktop, Rust, Xcode, LLVM 21, Node.js 24+, a development
signing certificate, and a local `mesh-lang/` checkout installed, one command
builds and starts PostgreSQL, every backend service, both transparency witnesses,
the desktop app, and the iOS simulator app:

```sh
./run.sh
```

The launcher opens Docker Desktop if needed, installs missing/outdated npm
dependencies, and reuses healthy services and an open desktop app. Running it
again while the launcher is active exits without starting duplicates. Logs are
in `.morse/logs/`, including `desktop.log` and `mobile.log` for each app's build
and startup. The mobile command builds and installs the app, opens the simulator,
and starts Metro.

Use `./run.sh desktop` or `./run.sh mobile` to start just that app with the
backend, or `./run.sh build` to build the backend and desktop without starting
them. Ctrl-C stops processes
started by this launcher; PostgreSQL and existing services stay running. To stop
the database too, without deleting its data:

```sh
docker compose -p whatsdown-dev -f mesh-private-messenger/services/directory-delivery/docker-compose.yml stop
```

Override `MESH_LANG_DIR` when the Mesh checkout lives elsewhere; the launcher
links it at `mesh-lang` for package dependencies and rejects a conflicting checkout.
For mobile, install Xcode or the Android NDK and set
`MORSE_MOBILE_PLATFORM=ios|android` when platform detection is insufficient.

The protocol contracts include the [threat model](mesh-private-messenger/protocol/threat-model.md),
[privacy contract](mesh-private-messenger/protocol/privacy-contract.md),
[cryptographic profile](mesh-private-messenger/protocol/crypto-profile-v1.md),
[ratchet wire format](mesh-private-messenger/protocol/ratchet-message-v1.md),
[delivery wire format](mesh-private-messenger/protocol/delivery-wire-v1.md),
[sealed-delivery format](mesh-private-messenger/protocol/sealed-delivery-v1.md),
[recipient-sealed transport](mesh-private-messenger/protocol/recipient-transport-v1.md),
[secret-purpose inventory](mesh-private-messenger/protocol/secret-purpose-inventory.md),
and [storage-wrapping format](mesh-private-messenger/protocol/storage-wrapping-v1.md).

## Development rules

Cloud deployment and CI setup are documented in the
[Cloudflare backend guide](mesh-private-messenger/ops/cloudflare/README.md).

- Reusable capabilities are implemented and reviewed in the separate Mesh repository before the messenger consumes them.
- Protocol state machines are Mesh source; application-level Rust protocol code is prohibited.
- Secret values never use ordinary `Bytes`, logs, or serialization.
- Durable delivery is committed to PostgreSQL before actor wakeups.
- Every behavioral change follows a red-green-refactor cycle.

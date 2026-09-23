# Morse

Morse is a Mesh-first, end-to-end encrypted private messenger. The product dogfoods Mesh's public APIs, but the Mesh compiler and runtime are maintained in their own repository.

This project is under active development and makes no production-security claim. [SECURITY.md](SECURITY.md) states what a release must verify.

## Install

macOS (Apple silicon or Intel):

```sh
curl -fsSL https://raw.githubusercontent.com/snowdamiz/whatsdown/main/install.sh | sh
```

Windows (PowerShell):

```powershell
irm https://raw.githubusercontent.com/snowdamiz/whatsdown/main/install.ps1 | iex
```

Each command downloads the newest [desktop release](https://github.com/snowdamiz/whatsdown/releases),
checks it against that release's `SHA256SUMS`, installs Morse, and opens it. Run
it again to update. Afterwards, start Morse with `open -a Morse` or from the
Start menu.

[install.sh](install.sh) installs only an app that passes Gatekeeper, meaning it
is Developer ID-signed and notarized. Windows releases are not code signed yet:
[install.ps1](install.ps1) says so and installs them, but refuses an installer
whose signature is present and invalid. The checksum comes from the same release
as the download, so it detects a damaged download, not a compromised release.

Set `MORSE_VERSION=0.1.0` to install a specific release, `MORSE_NO_LAUNCH=1` to
skip opening the app, or `MORSE_INSTALL_DIR` to choose where `Morse.app` goes
(default `/Applications`, or `~/Applications` when that is not writable). With
`curl`, set them on the `sh` side of the pipe: `curl ... | MORSE_NO_LAUNCH=1 sh`.

## Repository layout

- `mesh-private-messenger/` — protocol, services, clients, mobile app, and infrastructure

`mesh-lang` in this directory links to the Mesh compiler the launcher builds: by default the latest published Mesh release, which `./run.sh` fetches into `.morse/mesh-lang` on every run. It is ignored and never part of this repository.

## Run locally

The [desktop app](mesh-private-messenger/apps/desktop/README.md) supports Windows
and macOS, shares the mobile UI and encrypted Mesh core, and includes GitHub
Actions installer builds and tagged releases.

On macOS, with Docker Desktop, Rust, Xcode, LLVM 21, Node.js 24+, and a development
signing certificate installed, one command
builds and starts PostgreSQL, every backend service, both transparency witnesses,
the desktop app, and the iOS simulator app:

```sh
./run.sh
```

The launcher opens Docker Desktop if needed, creates the database container on
first use, installs missing/outdated npm dependencies, and reuses healthy
services and an open desktop app. Running it
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

PostgreSQL applies `services/directory-delivery/migrations/` when it first
creates the database and never again, so the launcher reports a migration added
since then rather than letting the services fail on a stale schema. `./run.sh
reset` deletes that database, losing its development data, so the next run
rebuilds it from every migration.

The launcher builds the latest published Mesh release, fetched on every run, and
links it at `mesh-lang` for package dependencies and the scripts. Set `MESH_LANG_DIR`
to build with a Mesh checkout you are working on instead; a real directory at
`mesh-lang` is reported rather than replaced.
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

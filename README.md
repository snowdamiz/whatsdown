# Whatsdown

Whatsdown is a Mesh-first, end-to-end encrypted private messenger. The repository contains the Mesh language/runtime checkout used by the product and the messenger implementation that dogfoods its public APIs.

The implementation roadmap and security caveats live in [mesh-private-messenger-complete-plan.md](mesh-private-messenger-complete-plan.md). This project is under active development and makes no production-security claim.

## Repository layout

- `mesh-lang/` — Mesh compiler, runtime, standard APIs, tools, and release proofs
- `mesh-private-messenger/` — protocol, services, clients, mobile app, and infrastructure

The protocol contracts include the [threat model](mesh-private-messenger/protocol/threat-model.md),
[privacy contract](mesh-private-messenger/protocol/privacy-contract.md),
[cryptographic profile](mesh-private-messenger/protocol/crypto-profile-v1.md),
[secret-purpose inventory](mesh-private-messenger/protocol/secret-purpose-inventory.md),
and [storage-wrapping format](mesh-private-messenger/protocol/storage-wrapping-v1.md).

## Development rules

- Reusable capabilities are implemented in Mesh before the messenger consumes them.
- Protocol state machines are Mesh source; application-level Rust protocol code is prohibited.
- Secret values never use ordinary `Bytes`, logs, or serialization.
- Durable delivery is committed to PostgreSQL before actor wakeups.
- Every behavioral change follows a red-green-refactor cycle.

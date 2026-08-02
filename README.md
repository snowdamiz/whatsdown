# Whatsdown

Whatsdown is a Mesh-first, end-to-end encrypted private messenger. The product dogfoods Mesh's public APIs, but the Mesh compiler and runtime are maintained in their own repository.

The implementation roadmap and security caveats live in [mesh-private-messenger-complete-plan.md](mesh-private-messenger-complete-plan.md). This project is under active development and makes no production-security claim.

## Repository layout

- `mesh-private-messenger/` — protocol, services, clients, mobile app, and infrastructure

Developers may keep a separate `mesh-lang/` checkout in this directory for local reference and integration testing. It is intentionally ignored and is never part of this repository.

## Development rules

- Reusable capabilities are implemented and reviewed in the separate Mesh repository before the messenger consumes them.
- Protocol state machines are Mesh source; application-level Rust protocol code is prohibited.
- Secret values never use ordinary `Bytes`, logs, or serialization.
- Durable delivery is committed to PostgreSQL before actor wakeups.
- Every behavioral change follows a red-green-refactor cycle.

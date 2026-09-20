# Contributing to Morse

Morse exists to prove that a private messenger can be implemented through
public Mesh language and runtime capabilities. Start behavioral changes with a
focused failing test, make the smallest change that passes it, and run the
relevant Mesh and messenger verification before submitting the change.

Use [the Mesh feature inventory](MESH_LANGUAGE_FEATURES.md) when writing or
refactoring `.mpl` code. Prefer supported language and library features over
manual nesting or traversal, while preserving ownership and cleanup behavior.

Do not describe the development profiles as production-grade cryptography.
Security-critical behavior must match the published threat model, privacy
contract, cryptographic profile, and version-negotiation rules.

## Dogfooding rules

1. **No private application-level Rust protocol.** Device identity, sessions,
   ratchets, envelope codecs, key transparency, and later group state belong in
   Mesh source. Rust may expose reusable cryptographic primitives, but it must
   not decide messenger protocol transitions.
2. **Generic capabilities go into Mesh first.** Add reusable Mesh support for
   needs such as binary PostgreSQL values, bounded mailboxes, and mobile library
   output before adding messenger code that depends on it.
3. **No messenger-specific compiler magic.** Add general APIs such as
   `Crypto.aead_seal`, never an intrinsic that implements a messenger operation.
4. **No secret keys in ordinary `Bytes`.** Private keys, chain keys, message
   keys, and ratchet material must use secret or resource types.
5. **No binary values disguised as UTF-8.** Keys, nonces, signatures,
   ciphertext, and protocol frames use `Bytes` and typed wrappers.
6. **No silent failure on durable paths.** Every durable operation returns a
   typed result and defines retry or recovery behavior. PostgreSQL commit, not
   an actor message, is the delivery boundary.
7. **Every language change needs repository-wide completion.** Complete the
   parser or type system when relevant, runtime, code generation, tests, docs,
   tooling, and release proof as one change.
8. **The messenger pins Mesh.** Builds and CI must record an exact Mesh commit
   or release.
9. **No production-only hidden path.** Production uses the same public APIs
   exercised by tests and examples.
10. **Every security assumption is documented.** Key derivation, nonce use,
    limits, version behavior, and fallback policy must be explicit and tested.
11. **Native languages stop at the ABI boundary.** C, Objective-C, Swift, and
    Kotlin may own generated bindings, platform callbacks, resources, and
    runtime lifecycle. Messenger behavior, state and storage semantics, and
    security proofs belong in Mesh. If Mesh cannot express a proof, extend Mesh
    instead of adding a native behavioral fallback.

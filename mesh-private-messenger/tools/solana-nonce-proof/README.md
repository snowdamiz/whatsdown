# Test-only Solana nonce oracle

This isolated crate runs the actual Agave4.3.2 Bank and System Program. It is not
an issuer, treasury signer, service dependency, network client or deployment tool.
All fixed Ed25519 seeds in the fixture are public and must never hold funds.
No production private key can be supplied through its interface.

`node --test nonce.test.mjs` builds the public Mesh package at optimization levels
0 and 2, compares SDK3.3.0 nonce-account/state and complete message serialization,
normalizes only legal account ordering with Kit8.4.0, verifies all Ed25519
signatures, and submits the resulting packets to Agave. Successful transfers
above 2^53 and deliberately failed transfers both consume their nonce. Exact
replays and newly signed packets using a consumed nonce are rejected without a
second debit. Failed transfers charge fees while transferring no customer units.

The genesis contains disposable fixture balances. The only test-only clock helper
registers a new recent blockhash. Nonce initialization and every nonce advance
are executed by the actual System Program; the oracle never patches nonce bytes.

Run from the product:

```sh
bash scripts/prove-solana-nonce.sh
```

Use `MESH_LANG_ROOT`, `MESHC`, `CARGO`, `CARGO_TARGET_DIR`, `MORSE_PROOF_DIR` and
`SOLANA_NONCE_ORACLE` for explicit local tool/artifact selection where supported.
The proof has its own pinned Cargo.lock and never changes the public language's
runtime dependencies. Agave/SDK dependencies are Apache-2.0; fixture code uses the
product's license. It runs only against temporary local banks and their loopback fixture RPCs.

The initial LiteSVM0.17 experiment is retained in
`.morse/witness-proof/solana-nonce-litesvm-limitation.log`. LiteSVM charges a failed
transaction fee but does not commit the advanced nonce, so it cannot qualify that
critical rollback case. The passing proof uses Agave instead.

## Dependency audit boundary

The separate oracle lock was audited without ignores. It is not audit-clean:
Agave4.3.2's precompiles retain curve25519-dalek3.2.0 (RUSTSEC-2024-0344) and
ed25519-dalek1.0.1 (RUSTSEC-2022-0093). Its graph also contains upstream legacy
warnings for bincode, derivative, libsecp256k1, paste, memmap2 and rand. Exact
results are preserved as `solana-nonce-oracle-audit.json` in the proof directory.

These are not production Mesh or issuer dependencies. The known signing-oracle
and secret-scalar timing paths are not used: fixture signatures use Node/OpenSSL
and the modern SDK signer, and Agave receives only fixed public test material.
Preserving upstream consensus behavior is the purpose of this independent
oracle; silently changing its crypto major versions would defeat that boundary.
No ignore list or production release gate was weakened. Treat this executable as
local disposable test tooling, never a service artifact or production signer.


The treasury probes additionally run the production Mesh custody policy against
real local System or SPL/ATA execution, an owned disposable PostgreSQL and
`StorageKey.file` across separate processes. The HTTP oracle drops an
acknowledgment only after actual execution. Reconciliation must keep the same
stored signature, reject provider disagreement and missing-history/changed-nonce
replacement, and refund exactly once. The USDC probe closes the original payer's
empty ATA through SPL, then exercises its actual ATA recreation and token CPI.
The weekly probe uses a frozen accounting fixture (the SQL accounting gate proves
membership independently), then executes the emitted revenue intent in the real
rewards SBF program and authenticates its permanent receipt. These fixture
boundaries do not establish independent RPC operators or a live chain.

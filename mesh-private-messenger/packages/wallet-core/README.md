# Morse wallet core

Custom native wallet seed custody and constrained SOL/USDC quote signing.
See [the C interface](include/morse_wallet_core.h) and
[the security boundary](docs/security.md).

Run `bash scripts/prove-wallet-core.sh` from the product root after building
public Mesh and installing the `ops/rewards` Node dependencies. This uses only
owned local PostgreSQL, loopback HTTP, public test keys and LiteSVM balances.

Native callbacks must provide sealed durable storage, cross-process locking
and foreground user confirmation. The crate contains no production network or
blind-RSA/credits business API. The fixture bridge is test-only and must never
be used with funds.

The native Mesh integration obtains blockhashes from pinned providers, verifies
and journals the exact signed packet before submission, and recovers only the
same signature after ambiguity or restart. See the
[network contract](../mobile-core/WALLET_NETWORK.md). The SDK itself has no
production network API. The mandatory proof includes the fake-RPC, real-SBF
restart/ambiguity test and the production issuer HTTP proof.

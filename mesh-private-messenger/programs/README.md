# On-chain programs

`morse-judge` (immutable after review) and `morse-rewards` (upgradeable behind
governance), both Pinocchio. Specification: [`protocol/morse-judge-v1.md`](../protocol/morse-judge-v1.md).

| Path | What |
|---|---|
| `morse-judge/` | anchors, cosigns, witness registry, bonds, staging, fork proofs, slashing |
| `morse-rewards/` | pool, weekly settlement by attendance, claims, token-bond eligibility, burns |
| `tests/` | LiteSVM tests against the built `.so` files; `src/bin/smoke.rs` (local validator); `src/bin/morse-admin.rs` (runbook tool) |
| `scripts/smoke.sh` | builds, starts a throwaway `solana-test-validator`, runs the smoke test and `morse-admin` |

Needs Solana CLI 4.1 (`cargo-build-sbf`, platform-tools v1.54) and rustup's
cargo first in `PATH` (Homebrew's cargo cannot run `cargo +toolchain`).

```sh
cd mesh-private-messenger/programs
export PATH="$HOME/.cargo/bin:$PATH" CARGO_BUILD_JOBS=4

# build the programs (target/deploy/morse_judge.so, morse_rewards.so)
cargo-build-sbf --manifest-path morse-judge/Cargo.toml
cargo-build-sbf --manifest-path morse-rewards/Cargo.toml

# tests (LiteSVM; rebuild the .so files first after a program change)
cargo test -p morse-program-tests

# local-validator smoke test
./scripts/smoke.sh

# lint and format
cargo clippy -p morse-judge -p morse-rewards
cargo fmt --all --check
```

The Mesh `FRK` vectors in `../tests/fixtures/frk/*.json` are replayed by
`tests/tests/frk_vectors.rs` whenever the directory exists.

CI (`chain` job in `.github/workflows/ci.yml`) runs all of the above with
Solana CLI 4.1.1, then the relay tests and `ops/drills/local-validator.test.mjs`.
No workflow deploys the programs: that is the manual runbook in
[`protocol/morse-judge-v1.md`](../protocol/morse-judge-v1.md) §12.

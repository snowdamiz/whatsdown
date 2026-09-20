#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly messenger_root="$repo_root/mesh-private-messenger"
readonly compiler_root="$repo_root/mesh-lang"
readonly meshc_bin="${MESHC:-$compiler_root/target/debug/meshc}"
readonly maximum_hybrid_seconds="${M14_MAX_HYBRID_SECONDS:-15}"
readonly rust_toolchain="${MESH_RUST_TOOLCHAIN:-stable}"

fail() {
  printf 'M14 proof failed: %s\n' "$*" >&2
  return 1
}

[[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
[[ "$maximum_hybrid_seconds" =~ ^[1-9][0-9]*$ ]] || \
  fail "M14_MAX_HYBRID_SECONDS must be a positive integer"
[[ "$(git -C "$repo_root" ls-files mesh-lang | wc -l | tr -d ' ')" == 0 ]] || \
  fail "the separate mesh-lang repository is tracked by the messenger repository"

(cd "$compiler_root" && CARGO_INCREMENTAL=0 \
  cargo test --locked -p mesh-rt storage_wrapping)
(cd "$compiler_root" && CARGO_INCREMENTAL=0 \
  cargo test --locked -p mesh-rt --lib \
    crypto::tests::nist_acvp_mlkem768_keygen_tc26_matches_public_key -- --exact)
(cd "$compiler_root" && \
  CARGO_INCREMENTAL=0 cargo test --locked -p meshc --test e2e_crypto_v2 -- --exact \
    crypto_v2_public_api_compiles_and_executes_natively)

started_at=$SECONDS
"$meshc_bin" test "$messenger_root/packages/messenger-protocol/tests/hybrid.test.mpl"
hybrid_seconds=$((SECONDS - started_at))
((hybrid_seconds <= maximum_hybrid_seconds)) || \
  fail "hybrid proof took ${hybrid_seconds}s; limit is ${maximum_hybrid_seconds}s"

"$meshc_bin" test "$messenger_root/packages/messenger-protocol/tests"

if [[ "$(uname -s)" == Darwin ]]; then
  command -v rustup >/dev/null || fail "rustup is required for iOS builds"
  rustc_bin="$(rustup which rustc --toolchain "$rust_toolchain")"
  for target in aarch64-apple-ios aarch64-apple-ios-sim; do
    rustup target list --installed --toolchain "$rust_toolchain" | \
      grep -Fxq "$target" || fail "$target is not installed for $rust_toolchain"
    (cd "$compiler_root" && IPHONEOS_DEPLOYMENT_TARGET=16.4 RUSTC="$rustc_bin" \
      rustup run "$rust_toolchain" cargo build --locked -p mesh-rt --lib \
      --target "$target" --target-dir "$compiler_root/target")
  done
fi

"$messenger_root/scripts/prove-m10.sh"
"$messenger_root/scripts/prove-m9.sh"

printf 'M14 proof passed: hybrid vectors, storage, fallback, downgrade, credential/session migration, exact claim replay, %ss host timing, and mobile builds; internal behavioral checks only.\n' \
  "$hybrid_seconds"

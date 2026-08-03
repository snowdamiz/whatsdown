#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly messenger_root="$repo_root/mesh-private-messenger"
readonly protocol_root="$messenger_root/packages/messenger-protocol"
readonly compiler_root="$repo_root/mesh-lang"
readonly meshc_bin="${MESHC:-$compiler_root/target/debug/meshc}"
readonly rust_toolchain="${MESH_RUST_TOOLCHAIN:-stable}"

fail() {
  printf 'M15 proof failed: %s\n' "$*" >&2
  return 1
}

main() {
  [[ -x "$meshc_bin" ]] || fail "Mesh compiler not found at $meshc_bin"
  [[ "$(git -C "$repo_root" ls-files mesh-lang | wc -l | tr -d ' ')" == 0 ]] || \
    fail "the separate mesh-lang repository is tracked by the messenger repository"

  (cd "$compiler_root" && \
    cargo test -p mesh-rt hpke_base_mode_matches_rfc9180_a2_1_sequence_zero)
  (cd "$compiler_root" && \
    cargo test -p mesh-rt every_registered_purpose_round_trips_to_its_exact_resource_kind)
  (cd "$compiler_root" && cargo test -p mesh-typeck --test crypto_v2 hpke_)
  (cd "$compiler_root" && \
    cargo test -p meshc --test e2e_crypto_v2 -- --exact \
      crypto_v2_public_api_compiles_and_executes_natively)

  "$meshc_bin" fmt "$protocol_root/groups" --check
  "$meshc_bin" fmt "$protocol_root/tests" --check
  "$meshc_bin" test "$protocol_root/tests"

  if [[ "$(uname -s)" == Darwin ]]; then
    command -v rustup >/dev/null || fail "rustup is required for iOS builds"
    rustc_bin="$(rustup which rustc --toolchain "$rust_toolchain")"
    readonly rustc_bin
    for target in aarch64-apple-ios aarch64-apple-ios-sim; do
      rustup target list --installed --toolchain "$rust_toolchain" | \
        grep -Fxq "$target" || fail "$target is not installed for $rust_toolchain"
      (cd "$compiler_root" && IPHONEOS_DEPLOYMENT_TARGET=16.4 RUSTC="$rustc_bin" \
        rustup run "$rust_toolchain" cargo build --locked -p mesh-rt --lib \
          --target "$target" --target-dir "$compiler_root/target")
    done
  fi

  grep -q 'must not be enabled in a production release' \
    "$messenger_root/protocol/mls-groups-v1.md" || \
    fail "the external-review production gate is missing"
  grep -q 'not an RFC 9420 wire-compatible implementation' \
    "$messenger_root/protocol/mls-groups-v1.md" || \
    fail "the interoperability boundary is missing"
  grep -q 'does not provide MLS TreeKEM forward secrecy' \
    "$messenger_root/protocol/mls-groups-v1.md" || \
    fail "the TreeKEM forward-secrecy limitation is missing"

  printf '%s\n' \
    'M15 proof passed: official HPKE vector, groups, codecs, persistence, and iOS runtime builds; production remains externally gated.'
}

main "$@"

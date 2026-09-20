#!/usr/bin/env bash
set -euo pipefail
export CARGO_INCREMENTAL=0

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly script_dir
repo_root="$(cd "$script_dir/../.." && pwd)"
readonly repo_root
readonly messenger_root="$repo_root/mesh-private-messenger"
readonly protocol_root="$messenger_root/packages/messenger-protocol"
readonly mobile_root="$messenger_root/packages/mobile-core"
readonly compiler_root="$repo_root/mesh-lang"
readonly meshc_bin="${MESHC:-$compiler_root/target/debug/meshc}"
readonly rust_toolchain="${MESH_RUST_TOOLCHAIN:-stable}"
readonly temp_parent="${TMPDIR:-/tmp}"
temp_dir="$(mktemp -d "$temp_parent/morse-m15.XXXXXX")"
readonly temp_dir

cleanup() {
  local status=$?
  local resolved_parent
  local resolved_temp
  trap - EXIT INT TERM
  if [[ -d "$temp_dir" && ! -L "$temp_dir" ]]; then
    if resolved_parent="$(cd "$temp_parent" && pwd -P)" &&
      resolved_temp="$(cd "$temp_dir" && pwd -P)"; then
      case "$resolved_temp" in
        "$resolved_parent"/morse-m15.*)
          if [[ "$(/usr/bin/find "$resolved_temp" -type l -print -quit)" == '' ]]; then
            /usr/bin/find "$resolved_temp" -depth -delete
          fi
          ;;
      esac
    fi
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

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
    cargo test -p mesh-rt x25519_public_key_matches_mlswg_treekem_vector)
  (cd "$compiler_root" && \
    cargo test -p mesh-rt every_registered_purpose_round_trips_to_its_exact_resource_kind)
  (cd "$compiler_root" && cargo test -p mesh-typeck --test crypto_v2 hpke_)
  (cd "$compiler_root" && \
    cargo test -p meshc --test e2e_crypto_v2 -- --exact \
      crypto_v2_public_api_compiles_and_executes_natively)

  "$meshc_bin" fmt "$protocol_root/groups" --check
  "$meshc_bin" fmt "$protocol_root/tests" --check
  "$meshc_bin" test "$protocol_root/tests"
  "$meshc_bin" fmt "$mobile_root" --check
  for group_test in "$mobile_root"/tests/group_consistency*.test.mpl \
    "$mobile_root/tests/groups.test.mpl"; do
    "$meshc_bin" test "$group_test"
  done
  "$meshc_bin" build "$mobile_root" --artifact staticlib \
    --output "$temp_dir/libmessenger_mobile.a"
  for extension in h swift kt jni.c ts; do
    cmp "$temp_dir/libmessenger_mobile.$extension" \
      "$messenger_root/apps/mobile/modules/mesh-messenger/generated/libmessenger_mobile.$extension" >/dev/null || \
      fail "generated $extension mobile binding is stale"
  done

  if [[ "$(uname -s)" == Darwin ]]; then
    command -v rustup >/dev/null || fail "rustup is required for iOS builds"
    rustc_bin="$(rustup which rustc --toolchain "$rust_toolchain")"
    readonly rustc_bin
    for target in aarch64-apple-ios aarch64-apple-ios-sim; do
      rustup target list --installed --toolchain "$rust_toolchain" | \
        grep -Fxq "$target" || fail "$target is not installed for $rust_toolchain"
      mkdir -p "$temp_dir/$target"
      IPHONEOS_DEPLOYMENT_TARGET=16.4 RUSTC="$rustc_bin" \
        "$meshc_bin" build "$mobile_root" --artifact staticlib --target "$target" \
          --output "$temp_dir/$target/libmessenger_mobile.a"
    done
  fi

  printf '%s\n' \
    'M15 proof passed: official HPKE and TreeKEM X25519 vectors, groups, codecs, transparency-bound joins, persisted history/outbox retry semantics, generated bindings, and iOS mobile-core builds; internal behavioral checks only.'
}

main "$@"

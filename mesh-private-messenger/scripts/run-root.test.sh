#!/usr/bin/env bash
set -euo pipefail

test_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly test_script_dir
test_repo_root="$(cd "$test_script_dir/../.." && pwd -P)"
readonly test_repo_root

# shellcheck disable=SC1091
source "$test_repo_root/run.sh"

compose() {
  return 0
}
(
  child_pids=()
  cleanup
)

built=()
build_service() {
  built+=("$1")
}
build_services
[[ "${built[*]}" == "directory-delivery privacy-edge push-broker object-store transparency-witness" ]]

started=()
start_process() {
  started+=("$1")
}
wait_for_health() {
  return 0
}
configure_environment
start_services
[[ "${started[*]}" == "push-broker directory-delivery privacy-edge object-store witness-a witness-b mobile" ]]

(
  fake_rust_bin="$(mktemp -d)"
  trap 'rm -rf "$fake_rust_bin"' EXIT
  ln -s /usr/bin/false "$fake_rust_bin/cargo"
  ln -s /usr/bin/false "$fake_rust_bin/rustc"
  PATH="$fake_rust_bin:$PATH"
  build_mesh() {
    [[ "$(command -v cargo)" == "$(rustup which cargo)" ]]
    [[ "$(command -v rustc)" == "$(rustup which rustc)" ]]
  }
  build_services() { return 0; }
  build_mobile() { return 0; }
  build_all
)

MESSENGER_PUSH_BROKER_SEED_HEX=invalid
if configure_environment >/dev/null 2>&1; then
  printf 'malformed development key was accepted\n' >&2
  exit 1
fi

(
  checkout_fixture="$(mktemp -d)"
  trap 'rm -rf "$checkout_fixture"' EXIT
  cp "$test_repo_root/run.sh" "$checkout_fixture/run.sh"
  mkdir "$checkout_fixture/external"
  touch "$checkout_fixture/external/Cargo.toml"
  MESH_LANG_DIR="$checkout_fixture/external" bash -c '
    source "$1/run.sh"
    cargo() { [[ "$PWD" == "$mesh_root" ]] || fail "Mesh compiler configuration was not loaded from its checkout"; }
    build_mesh
    [[ -L "$script_dir/mesh-lang" ]] || fail "external Mesh dependencies were not linked"
    [[ "$(cd "$script_dir/mesh-lang" && pwd -P)" == "$mesh_root" ]]
    build_mesh
    rm "$script_dir/mesh-lang"
    mkdir "$script_dir/mesh-lang"
    if build_mesh >/dev/null 2>&1; then
      fail "a conflicting Mesh checkout was accepted"
    fi
    [[ -d "$script_dir/mesh-lang" && ! -L "$script_dir/mesh-lang" ]]
  ' bash "$checkout_fixture"
)

printf 'root runner topology test passed\n'

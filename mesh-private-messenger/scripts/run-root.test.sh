#!/usr/bin/env bash
set -euo pipefail

test_script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
readonly test_script_dir
test_repo_root="$(cd "$test_script_dir/../.." && pwd -P)"
readonly test_repo_root

# shellcheck disable=SC1091
source "$test_repo_root/run.sh"

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

MESSENGER_PUSH_BROKER_SEED_HEX=invalid
if configure_environment >/dev/null 2>&1; then
  printf 'malformed development key was accepted\n' >&2
  exit 1
fi

printf 'root runner topology test passed\n'

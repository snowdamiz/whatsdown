#!/usr/bin/env bash
set -euo pipefail

product="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
builder="${CARGO_BUILD_SBF:-cargo-build-sbf}"
version="$("$builder" --version)"
if [[ "$version" != *'cargo-build-sbf 4.4.0'* ]]; then
  echo 'Install cargo-build-sbf 4.4.0 with cargo install --locked before this proof.' >&2
  exit 1
fi

cargo fmt --manifest-path "$product/programs/Cargo.toml" --all -- --check
cargo clippy --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge -p morse-judge-program \
  --features morse-judge/svm --all-targets -- -D warnings
# The SBF compiler can print stack-frame errors yet exit zero. Use a fresh
# target directory: cached invalid objects can otherwise hide the diagnostic on
# the next run. Both programs share this temporary dependency build.
sbf_work="$(mktemp -d)"
trap 'rm -rf "$sbf_work"' EXIT
for manifest in "$product/programs/morse-judge-program/Cargo.toml" \
  "$product/programs/morse-judge/tests/probe/Cargo.toml"; do
  CARGO_TARGET_DIR="$sbf_work/target" "$builder" --manifest-path "$manifest" \
    --arch v0 --tools-version v1.57 --sbf-out-dir "$product/programs/target/deploy" -- --locked \
    2>&1 | tee "$sbf_work/build.log"
  if grep -Eq '(^|[[:space:]])(Error:|error:|error\[)' "$sbf_work/build.log"; then
    echo 'SBF compiler diagnostics rejected the build; no judge proof was run.' >&2
    exit 1
  fi
done
export MORSE_JUDGE_PROBE_PATH="$product/programs/target/deploy/morse_judge_introspection_probe.so"
cargo test --manifest-path "$product/programs/Cargo.toml" --locked -p morse-judge --features svm

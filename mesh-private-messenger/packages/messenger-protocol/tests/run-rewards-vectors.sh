#!/bin/sh
set -eu

rewards_test_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
rewards_app_root=$(CDPATH= cd -- "$rewards_test_dir/../../.." && pwd)
rewards_compiler=${MESHC:-"$rewards_app_root/../../mesh-lang/target/debug/meshc"}

cd "$rewards_app_root"
export MORSE_REWARD_MATH_FIXTURES_PATH="$rewards_app_root/programs/morse-rewards-math/tests/fixtures"
exec "$rewards_compiler" test "$rewards_test_dir/rewards_vectors.test.mpl"

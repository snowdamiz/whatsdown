#!/bin/sh
set -eu
: "${MESH_COMPILER_BIN:?provide the qualified Mesh compiler}"
: "${MESH_RT_LIB_PATH:?provide the qualified host runtime archive}"
: "${MORSE_NETWORK_COUNTER_OUTPUT:?provide a new evidence directory}"
base=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
work=$(mktemp -d /tmp/morse-counter-proof.XXXXXX)
trap 'rm -rf "$work"' EXIT HUP INT TERM
"$MESH_COMPILER_BIN" build "$base/driver" --opt-level 0 --output "$work/counter-proof"
MORSE_NETWORK_COUNTER_BIN="$work/counter-proof" node "$base/prove.mjs"

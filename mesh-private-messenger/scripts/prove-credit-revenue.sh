#!/usr/bin/env bash
set -euo pipefail
PRODUCT="$(cd "$(dirname "$0")/.." && pwd -P)"
exec python3 "$PRODUCT/scripts/prove-credit-revenue.py"

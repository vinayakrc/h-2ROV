#!/usr/bin/env bash
# Run cached IPv6 authorization-update correctness checks for C, D, and E.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
for mode in C D E; do
    echo "===== IPv6 cache regression: $mode ====="
    timeout 30s ./experiments/ipv6_cached_regression "$mode" \
        2>&1 | tee "experiments/results/ipv6_cached_${mode}.log"
    grep -q "IPv6 cached $mode regression: 232/232 checks passed" \
        "experiments/results/ipv6_cached_${mode}.log"
done
echo "All C/D/E IPv6 cached regression tests passed."

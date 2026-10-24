#!/usr/bin/env bash
# Validate single-threaded full authorization-snapshot cache reset, C/D/E.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
for mode in C D E; do
    echo "===== Authorization snapshot regression: $mode ====="
    timeout 30s ./experiments/rtr_snapshot_regression "$mode" \
        2>&1 | tee "experiments/results/rtr_snapshot_${mode}.log"
    grep -Eq "RTR-style snapshot ${mode} regression: ([0-9]+)/\1 checks passed" \
        "experiments/results/rtr_snapshot_${mode}.log"
done
echo 'All snapshot replacement regressions passed.'

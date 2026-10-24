#!/usr/bin/env bash
# Build the test with existing cache source and run all three modes.
# This checks coarse-grained-mutex correctness; not simultaneous read throughput.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
gcc -std=gnu11 -O0 -g -Wall -Wextra -I. \
    experiments/concurrent_cache_regression.c -L. -lhrov \
    -lrtr -lxxhash -lm -lpthread \
    -o experiments/concurrent_cache_regression
for mode in C D E; do
    echo "===== Concurrent cache regression: $mode ====="
    timeout 60s ./experiments/concurrent_cache_regression "$mode" \
        2>&1 | tee "experiments/results/concurrent_cache_${mode}.log"
done
echo 'All C/D/E concurrent cache regressions passed.'

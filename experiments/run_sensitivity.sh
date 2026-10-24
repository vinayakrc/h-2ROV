#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

OUT="experiments/results/benchmark_v3.csv"

mkdir -p experiments/results

echo "trial,mode,requests,update_every,capacity,seed,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest" > "$OUT"

for capacity in 16 64 128
do
    for interval in 1000 5000 50000
    do
        for trial in 1 2 3
        do
            seed=$((12345 + trial))

            # Rotate configuration execution order.
            case $((trial % 3)) in
                0) modes=(A B C) ;;
                1) modes=(B C A) ;;
                2) modes=(C A B) ;;
            esac

            echo "Capacity=$capacity Interval=$interval Trial=$trial"

            expected_digest=""

            for mode in "${modes[@]}"
            do
                result=$(
                    timeout 60s \
                    ./experiments/cache_benchmark \
                    "$mode" 5000000 "$interval" "$capacity" "$seed" |
                    tail -n 1
                )

                digest="${result##*,}"

                # Verify equivalent classification sequences.
                if [[ -n "$expected_digest" &&
                      "$digest" != "$expected_digest" ]]
                then
                    echo "ERROR: Validation digest mismatch!" >&2
                    exit 1
                fi

                expected_digest="$digest"

                echo "$trial,$result" >> "$OUT"

                echo "$result"
            done
        done
    done
done

echo "Benchmark completed."
echo "Results saved to $OUT"


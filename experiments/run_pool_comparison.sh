#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

OUT="experiments/results/pool_comparison.csv"

mkdir -p experiments/results

echo "trial,implementation,mode,requests,update_every,capacity,seed,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest" > "$OUT"

for capacity in 16 64 128
do
    for mode in B C
    do
        for trial in 1 2 3 4 5
        do
            seed=$((12345 + trial))

            if (( trial % 2 == 0 )); then
                implementations=(pool original)
            else
                implementations=(original pool)
            fi

            reference=""

            echo "Capacity=$capacity Mode=$mode Trial=$trial"

            for implementation in "${implementations[@]}"
            do
                if [[ "$implementation" == "original" ]]; then
                    executable="./experiments/cache_benchmark"
                else
                    executable="./experiments/cache_benchmark_pool"
                fi

                result=$(
                    timeout 60s "$executable" \
                    "$mode" 5000000 5000 "$capacity" "$seed" |
                    tail -n 1
                )

                # Compare all non-timing fields.
                normalized=$(
                    echo "$result" |
                    awk -F, 'BEGIN {OFS=","}
                    {
                        $6="TIME"
                        $7="THROUGHPUT"
                        print
                    }'
                )

                if [[ -n "$reference" &&
                      "$normalized" != "$reference" ]]
                then
                    echo "ERROR: Cache behavior mismatch" >&2
                    exit 1
                fi

                reference="$normalized"

                echo "$trial,$implementation,$result" >> "$OUT"
            done
        done
    done
done

echo "Completed successfully."
echo "Results: $OUT"

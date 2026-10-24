#!/usr/bin/env bash

set -euo pipefail

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

OUT="experiments/results/index_crossover.csv"

mkdir -p experiments/results

echo "trial,mode,requests,update_every,capacity,seed,route_count,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us,index_peak_nodes,index_visited_nodes,index_peak_bytes_est" > "$OUT"

for interval in 1000 2500 5000 10000 20000 50000
do
    for trial in 1 2 3 4 5
    do
        seed=$((12345 + trial))

        if (( trial % 2 == 0 )); then
            modes=(D C)
        else
            modes=(C D)
        fi

        reference_digest=""
        reference_counters=""

        echo "Interval=$interval Trial=$trial"

        for mode in "${modes[@]}"
        do
            result=$(
                timeout 60s \
                ./experiments/cache_profile_indexed \
                "$mode" \
                5000000 \
                "$interval" \
                8192 \
                "$seed" \
                8192 |
                tail -n 1
            )

            IFS=',' read -r -a fields <<< "$result"

            if (( ${#fields[@]} != 23 )); then
                echo "ERROR: Unexpected output format" >&2
                exit 1
            fi

            digest="${fields[13]}"

            counters="${fields[8]},${fields[9]},${fields[10]},${fields[11]},${fields[12]}"

            if [[ -n "$reference_digest" &&
                  "$digest" != "$reference_digest" ]]; then
                echo "ERROR: Digest mismatch" >&2
                exit 1
            fi

            if [[ -n "$reference_counters" &&
                  "$counters" != "$reference_counters" ]]; then
                echo "ERROR: Cache counter mismatch" >&2
                exit 1
            fi

            reference_digest="$digest"
            reference_counters="$counters"

            echo "$trial,$result" >> "$OUT"

            echo "$result"
        done
    done
done

echo
echo "Crossover experiment completed."
echo "Results saved to $OUT"

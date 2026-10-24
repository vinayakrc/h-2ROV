#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

OUT="experiments/results/validation_path.csv"

mkdir -p experiments/results

echo "trial,scenario,mode,requests,update_every,capacity,seed,route_count,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us,index_peak_nodes,index_visited_nodes,index_peak_bytes_est" > "$OUT"

for capacity in 64 8192
do
    if (( capacity == 64 )); then
        scenario="high_miss"
    else
        scenario="high_hit"
    fi

    for trial in 1 2 3 4 5
    do
        seed=$((12345 + trial))

        case $((trial % 3)) in
            0) modes=(A C D) ;;
            1) modes=(C D A) ;;
            2) modes=(D A C) ;;
        esac

        reference_digest=""

        echo "Scenario=$scenario Trial=$trial"

        for mode in "${modes[@]}"
        do
            result=$(
                timeout 60s \
                ./experiments/cache_profile_indexed \
                "$mode" 5000000 10000000 \
                "$capacity" "$seed" 8192 |
                tail -n 1
            )

            IFS=',' read -r -a fields <<< "$result"

            if (( ${#fields[@]} != 23 )); then
                echo "ERROR: Invalid output format" >&2
                exit 1
            fi

            digest="${fields[13]}"

            if [[ -n "$reference_digest" &&
                  "$digest" != "$reference_digest" ]]; then
                echo "ERROR: Classification digest mismatch" >&2
                exit 1
            fi

            if [[ "${fields[17]}" != "0" ]]; then
                echo "ERROR: Unexpected authorization update" >&2
                exit 1
            fi

            reference_digest="$digest"

            echo "$trial,$scenario,$result" >> "$OUT"
        done
    done
done

echo "Validation-path experiment completed."
echo "Results saved to $OUT"

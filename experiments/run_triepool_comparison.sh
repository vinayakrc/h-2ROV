#!/usr/bin/env bash
# Run from repository root: ./experiments/run_triepool_comparison.sh
# For EACH scenario and trial, run the same workload through D and E.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
OUT="experiments/results/triepool_comparison.csv"

# Same 23 columns as indexed profiler, plus six allocation/pool metrics.
echo 'trial,scenario,mode,requests,update_every,capacity,seed,route_count,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us,index_peak_nodes,index_visited_nodes,index_peak_bytes_est,node_fresh_allocs,node_reuses,node_recycles,node_pool_cached,node_pool_peak_cached,node_reserved_bytes_est' > "$OUT"

for scenario in high_miss high_hit frequent_updates rare_updates; do
    case "$scenario" in
        high_miss)       capacity=64;   interval=10000000 ;;
        high_hit)        capacity=8192; interval=10000000 ;;
        frequent_updates)capacity=8192; interval=1000 ;;
        rare_updates)   capacity=8192; interval=50000 ;;
    esac
    for trial in 1 2 3 4 5; do
        seed=$((12345 + trial))
        if (( trial % 2 == 0 )); then modes=(E D); else modes=(D E); fi
        reference_digest=''
        reference_counts=''
        for mode in "${modes[@]}"; do
            printf 'scenario=%s trial=%s mode=%s\n' "$scenario" "$trial" "$mode"
            row=$(timeout 60s ./experiments/cache_profile_triepool \
                "$mode" 5000000 "$interval" "$capacity" "$seed" 8192 | tail -n 1)
            IFS=, read -r -a f <<< "$row"
            if (( ${#f[@]} != 29 )); then
                printf 'ERROR: got %d CSV columns instead of 29\n' "${#f[@]}" >&2
                exit 1
            fi
            digest="${f[13]}"
            counts="${f[8]},${f[9]},${f[10]},${f[11]},${f[12]}"
            if [[ -n "$reference_digest" && ( "$digest" != "$reference_digest" || "$counts" != "$reference_counts" ) ]]; then
                printf 'ERROR: D/E digest or cache counter mismatch: scenario=%s trial=%s\n' "$scenario" "$trial" >&2
                exit 1
            fi
            if [[ "$scenario" == high_* && "${f[17]}" != '0' ]]; then
                echo 'ERROR: updates occurred in no-update scenario' >&2
                exit 1
            fi
            reference_digest="$digest"
            reference_counts="$counts"
            echo "$trial,$scenario,$row" >> "$OUT"
        done
    done
done
python3 - "$OUT" <<'PY'
import csv, sys
from collections import defaultdict
from statistics import mean, stdev
path = sys.argv[1]
groups = defaultdict(list)
with open(path, newline='') as stream:
    rows = list(csv.DictReader(stream))
for row in rows:
    groups[(row['scenario'], row['mode'])].append(row)
assert len(rows) == 40 and len(groups) == 8
print('\nD/E validation digests and cache counters: PASS')
print(f"{'Scenario':>18} {'Mode':>5} {'Mean M/s':>11} {'SD M/s':>9} {'Invalid us':>11} {'Fresh allocs':>13} {'Reuses':>13} {'Peak KiB':>11}")
for (scenario, mode), sample in sorted(groups.items()):
    tp = [float(x['validations_per_second']) / 1e6 for x in sample]
    print(f'{scenario:>18} {mode:>5} {mean(tp):>11.3f} {stdev(tp):>9.3f} '
          f"{mean(float(x['avg_invalidation_us']) for x in sample):>11.3f} "
          f"{mean(int(x['node_fresh_allocs']) for x in sample):>13.0f} "
          f"{mean(int(x['node_reuses']) for x in sample):>13.0f} "
          f"{mean(int(x['node_reserved_bytes_est']) for x in sample)/1024:>11.1f}")
print('\nE vs D mean throughput difference:')
for scenario in sorted(set(k[0] for k in groups)):
    d = mean(float(x['validations_per_second']) for x in groups[(scenario,'D')])
    e = mean(float(x['validations_per_second']) for x in groups[(scenario,'E')])
    print(f'{scenario:>18}: {(e/d-1)*100:+.2f}%')
print('\nCSV:', path)
PY

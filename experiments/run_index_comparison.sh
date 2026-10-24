#!/usr/bin/env bash
# Phase 2G: A/B/C/D scaling comparison, 3 seeds and rotated execution orders.
# Run from the repository root: ./experiments/run_index_comparison.sh
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
OUT="experiments/results/index_comparison.csv"

printf '%s\n' 'trial,mode,requests,update_every,capacity,seed,route_count,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us,index_peak_nodes,index_visited_nodes,index_peak_bytes_est' > "$OUT"

for routes in 128 1024 8192; do
    for interval in 5000 50000; do
        for trial in 1 2 3; do
            seed=$((12345 + trial))
            case "$trial" in
                1) modes=(B D A C) ;;
                2) modes=(C A D B) ;;
                3) modes=(D C B A) ;;
            esac
            digest_ref=''
            linear_stats=''
            indexed_stats=''
            for mode in "${modes[@]}"; do
                printf 'routes=%d interval=%d trial=%d mode=%s\n' "$routes" "$interval" "$trial" "$mode"
                row=$(timeout 60s ./experiments/cache_profile_indexed \
                    "$mode" 5000000 "$interval" "$routes" "$seed" "$routes" | tail -n 1)
                IFS=, read -r -a fields <<< "$row"
                if (( ${#fields[@]} != 23 )); then
                    echo 'ERROR: unexpected CSV output column count' >&2
                    exit 1
                fi
                digest="${fields[13]}"
                if [[ -n "$digest_ref" && "$digest_ref" != "$digest" ]]; then
                    printf 'ERROR: digest mismatch routes=%d interval=%d trial=%d mode=%s\n' \
                        "$routes" "$interval" "$trial" "$mode" >&2
                    exit 1
                fi
                digest_ref="$digest"
                stats="${fields[8]},${fields[9]},${fields[10]},${fields[11]},${fields[12]}"
                if [[ "$mode" == 'C' ]]; then linear_stats="$stats"; fi
                if [[ "$mode" == 'D' ]]; then indexed_stats="$stats"; fi
                printf '%s,%s\n' "$trial" "$row" >> "$OUT"
            done
            if [[ "$linear_stats" != "$indexed_stats" ]]; then
                printf 'ERROR: linear and indexed cache counters differ routes=%d interval=%d trial=%d\n' \
                    "$routes" "$interval" "$trial" >&2
                exit 1
            fi
        done
    done
done

python3 - "$OUT" <<'PY'
import csv, sys
from collections import defaultdict
from statistics import mean, stdev
path = sys.argv[1]
rows = list(csv.DictReader(open(path, newline='')))
assert len(rows) == 72, f'Expected 72 runs, got {len(rows)}'
by_case = defaultdict(list)
for r in rows:
    by_case[(int(r['route_count']), int(r['update_every']), r['mode'])].append(r)
assert len(by_case) == 24 and all(len(x)==3 for x in by_case.values())
print('\nA/B/C/D digests and C/D cache counters: PASS')
print(f"{'Routes':>7} {'Interval':>9} {'Mode':>5} {'Mean M/s':>11} {'SD M/s':>9} {'Invalid us':>11} {'Index KiB':>10} {'Visited/upd':>12}")
for (routes,interval,mode), items in sorted(by_case.items()):
    tp=[float(x['validations_per_second'])/1e6 for x in items]
    inval=mean(float(x['avg_invalidation_us']) for x in items)
    kb=mean(int(x['index_peak_bytes_est']) for x in items)/1024
    visited=mean(int(x['index_visited_nodes']) / max(1,int(x['update_events'])) for x in items)
    print(f'{routes:7d} {interval:9d} {mode:>5} {mean(tp):11.3f} {stdev(tp):9.3f} {inval:11.3f} {kb:10.1f} {visited:12.1f}')
print('CSV:',path)
PY

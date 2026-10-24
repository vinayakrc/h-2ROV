#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
out="experiments/results/scaling_profile.csv"
head_fields='mode,requests,update_every,capacity,seed,route_count,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us'
printf 'trial,%s\n' "$head_fields" > "$out"

for routes in 128 1024 8192; do
  for trial in 1 2 3; do
    seed=$((12345 + trial))
    case "$trial" in
      1) modes=(B C A) ;;
      2) modes=(C A B) ;;
      3) modes=(A B C) ;;
    esac
    for mode in "${modes[@]}"; do
      echo "route_count=$routes trial=$trial mode=$mode"
      row=$(timeout 60s ./experiments/cache_profile_scale \
           "$mode" 5000000 50000 "$routes" "$seed" "$routes" | tail -n 1)
      printf '%s,%s\n' "$trial" "$row" >> "$out"
    done
  done
done

python3 - "$out" <<'PY'
import csv, sys
from collections import defaultdict
from statistics import mean, stdev
rows = list(csv.DictReader(open(sys.argv[1], newline='')))
checks = defaultdict(set)
grouped = defaultdict(list)
for r in rows:
    checks[(r['route_count'], r['trial'], r['seed'])].add(r['digest'])
    grouped[(int(r['route_count']), r['mode'])].append(r)
if len(rows) != 27 or any(len(x) != 1 for x in checks.values()):
    raise SystemExit('ERROR: missing runs or digest mismatch')
print('\nA/B/C classification digests: PASS')
print(f"{'Routes':>8} {'Mode':>5} {'Mean M/s':>12} {'Invalid us/event':>19} {'Mean Hit %':>12} {'Updates':>8}")
for (routes,mode), data in sorted(grouped.items()):
    tp=mean(float(x['validations_per_second']) / 1e6 for x in data)
    inv=mean(float(x['avg_invalidation_us']) for x in data)
    hits=mean(100 * int(x['hits']) / int(x['requests']) for x in data)
    print(f'{routes:8d} {mode:>5} {tp:12.3f} {inv:19.3f} {hits:12.2f} {data[0]["update_events"]:>8}')
print('Results:',sys.argv[1])
PY

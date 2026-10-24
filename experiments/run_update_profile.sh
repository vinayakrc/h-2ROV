#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mkdir -p experiments/results
out="experiments/results/update_profile.csv"

# Column names match the two instrumented executables. All values in the
# instrumented CSV are measured per process, not shared across modes.
echo 'implementation,trial,mode,requests,update_every,capacity,seed,seconds,validations_per_second,hits,misses,evictions,selectively_invalidated,globally_invalidated,digest,roa_update_seconds,invalidation_seconds,validation_and_loop_seconds,update_events,avg_roa_update_us,avg_invalidation_us' > "$out"

for interval in 1000 5000 50000; do
  for trial in 1 2 3; do
    seed=$((12345 + trial))
    if (( trial % 2 == 1 )); then
      implementations=(original pool)
    else
      implementations=(pool original)
    fi
    case $((trial % 3)) in
      0) modes=(A B C) ;;
      1) modes=(B C A) ;;
      2) modes=(C A B) ;;
    esac

    for implementation in "${implementations[@]}"; do
      for mode in "${modes[@]}"; do
        echo "Interval=$interval trial=$trial $implementation mode=$mode"
        row=$(timeout 60s "./experiments/cache_profile_$implementation" \
            "$mode" 5000000 "$interval" 128 "$seed" | tail -n 1)
        echo "$implementation,$trial,$row" >> "$out"
      done
    done
  done
done

python3 - "$out" <<'PY'
import csv
import sys
from collections import defaultdict
from statistics import mean

records = list(csv.DictReader(open(sys.argv[1], newline='')))
by_workload = defaultdict(set)
by_equivalence = defaultdict(list)
grouped = defaultdict(list)
for r in records:
    key = (r['trial'], r['update_every'], r['seed'])
    by_workload[key].add(r['digest'])
    eqkey = (key, r['mode'])
    by_equivalence[eqkey].append(r)
    grouped[(r['implementation'], r['mode'], r['update_every'])].append(r)

if any(len(v) != 1 for v in by_workload.values()):
    raise SystemExit('ERROR: A/B/C classification digests differ')

fields = ['hits', 'misses', 'evictions',
          'selectively_invalidated', 'globally_invalidated',
          'digest', 'update_events']
for key, rows in by_equivalence.items():
    if len(rows) != 2 or any(r[f] != rows[0][f] for r in rows for f in fields):
        raise SystemExit(f'ERROR: pool/original behavior differs at {key}')

print('\nDigest and pool/original counter checks: PASS')
print('Mean values over 3 trials; update/invalidation measured in microseconds per event')
print(f"{'Variant':>9} {'Mode':>5} {'Interval':>9} {'M validations/s':>17} {'ROA us':>11} {'Cache invalid us':>17} {'Updates':>8}")
for key in sorted(grouped):
    rows = grouped[key]
    throughput = mean(float(r['validations_per_second']) / 1e6 for r in rows)
    roa = mean(float(r['avg_roa_update_us']) for r in rows)
    inv = mean(float(r['avg_invalidation_us']) for r in rows)
    print(f'{key[0]:>9} {key[1]:>5} {key[2]:>9} {throughput:17.3f} {roa:11.3f} {inv:17.3f} {rows[0]["update_events"]:>8}')
print(f'\nFull results: {sys.argv[1]}')
PY

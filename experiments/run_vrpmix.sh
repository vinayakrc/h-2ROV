#!/usr/bin/env bash
# Run from repository root or anywhere. Uses original upstream h2ROV library.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
mkdir -p experiments/results
OUT="experiments/results/vrpmix_comparison.csv"
HEADER="$(./experiments/cache_profile_vrpmix A 1 10000000 32 12345 32 | head -n 1)"
echo "trial,scenario,$HEADER" > "$OUT"

for scenario in small_roa_dense large_roa_dense high_eviction no_churn
 do
  case "$scenario" in
    small_roa_dense) routes=128; cap=128; updates=1000 ;;
    large_roa_dense) routes=8192; cap=8192; updates=1000 ;;
    high_eviction) routes=8192; cap=64; updates=10000000 ;;
    no_churn) routes=8192; cap=8192; updates=10000000 ;;
  esac
  for trial in 1 2 3; do
    seed=$((20000 + trial))
    case $((trial % 3)) in
      0) modes=(A C D E) ;;
      1) modes=(E D C A) ;;
      2) modes=(C A E D) ;;
    esac
    reference_digest=""; reference_counters=""
    for mode in "${modes[@]}"; do
      echo "scenario=$scenario trial=$trial mode=$mode" >&2
      output="$(timeout 120s ./experiments/cache_profile_vrpmix \
         "$mode" 5000000 "$updates" "$cap" "$seed" "$routes")"
      row="$(printf '%s\n' "$output" | tail -n 1)"
      IFS=',' read -r -a fields <<< "$row"
      if (( ${#fields[@]} != 30 )); then
        echo "ERROR: expected 30 CSV fields, got ${#fields[@]}: $row" >&2; exit 1
      fi
      digest="${fields[13]}"
      if [[ -n "$reference_digest" && "$digest" != "$reference_digest" ]]; then
        echo "ERROR: classification digest mismatch scenario=$scenario trial=$trial" >&2; exit 1
      fi
      reference_digest="$digest"
      if [[ "$mode" != A ]]; then
        counters="${fields[8]},${fields[9]},${fields[10]},${fields[11]},${fields[12]}"
        if [[ -n "$reference_counters" && "$counters" != "$reference_counters" ]]; then
          echo "ERROR: C/D/E cache counters differ" >&2; exit 1
        fi
        reference_counters="$counters"
      fi
      echo "$trial,$scenario,$row" >> "$OUT"
    done
  done
 done

python3 - "$OUT" <<'PY'
import csv,sys
from collections import defaultdict
from statistics import mean,stdev
p=sys.argv[1]; groups=defaultdict(list)
with open(p,newline='') as f:
    for r in csv.DictReader(f): groups[(r['scenario'],r['mode'])].append(r)
print('All A/C/D/E digests and C/D/E cache counters match.')
print(f"{'Scenario':<17} {'Mode':<5} {'Mean M/s':>11} {'SD M/s':>9} {'Hit %':>9} {'ROAs':>7}")
for (scenario,mode),rows in sorted(groups.items()):
    tp=[float(r['validations_per_second'])/1e6 for r in rows]
    hr=[100*int(r['hits'])/int(r['requests']) for r in rows]
    print(f"{scenario:<17} {mode:<5} {mean(tp):>11.3f} {stdev(tp):>9.3f} {mean(hr):>9.2f} {rows[0]['static_vrps']:>7}")
print('CSV:',p)
PY

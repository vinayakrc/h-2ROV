#!/usr/bin/env bash
# Five seeded runs each, comparing original A, original F and new F2.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
OLD=./experiments/cache_profile_adaptive
NEW=./experiments/cache_profile_adaptive_backoff
[[ -x "$OLD" && -x "$NEW" ]] || { echo 'Compile original F and F2 first' >&2; exit 1; }
for cap_profile in '64 uniform' '64 phase' '64 reverse' '8192 uniform'; do
  read -r cap profile <<< "$cap_profile"
  echo "===== capacity=$cap profile=$profile ====="
  for strategy in A F F2; do
    bin="$OLD"; mode="$strategy"
    if [[ "$strategy" == F2 ]]; then bin="$NEW"; mode=F; fi
    for trial in 1 2 3 4 5; do
      "$bin" "$mode" 1000000 1000 "$cap" "$((12345+trial))" 8192 "$profile" \
        2>/dev/null | tail -n 1
    done | awk -F, -v label="$strategy" '
        NF>=14 {sum += $8 / 1000000; n++}
        END {if (n!=5) exit 1; printf "%-3s %.3f M/s (%d trials)\n", label, sum/n, n}'
  done
done

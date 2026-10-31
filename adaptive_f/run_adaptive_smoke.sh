#!/usr/bin/env bash
# Run from the h-2ROV repository root after compiling cache_profile_adaptive.
set -euo pipefail
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exe=./experiments/cache_profile_adaptive
if [[ ! -x "$exe" ]]; then
  echo "Missing $exe. Compile first." >&2
  exit 1
fi
req=300000
upd=1000
routes=8192
seed=12345
printf '%-10s %-8s %-10s %-14s %-12s\n' 'Profile' 'Capacity' 'Mode' 'ThroughputM/s' 'Digest'
for case in 'uniform 8192' 'uniform 64' 'phase 64' 'reverse 64'; do
  read -r profile cap <<< "$case"
  expected=''
  for mode in A D E F; do
    log=$(mktemp)
    csv=$("$exe" "$mode" "$req" "$upd" "$cap" "$seed" "$routes" "$profile" 2>"$log" | tail -n 1)
    rm -f "$log"
    digest=$(printf '%s\n' "$csv" | awk -F, '{print $14}')
    if [[ -n "$expected" && "$expected" != "$digest" ]]; then
      printf 'ERROR: digest differs for %s, cap=%s, mode %s\n' "$profile" "$cap" "$mode" >&2
      exit 1
    fi
    expected="$digest"
    printf '%-10s %-8s %-10s %-14s %-12s\n' "$profile" "$cap" "$mode" \
      "$(printf '%s\n' "$csv" | awk -F, '{printf "%.3f", $8/1e6}')" "$digest"
  done
done
printf 'PASS: A/D/E/F produced identical digests in all tested scenarios.\n'

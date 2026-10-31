#!/usr/bin/env bash
# Run from anywhere; assumes current working directory is repository root if auto-detection fails.
set -euo pipefail
cd "$(dirname "$0")/.."
export LD_LIBRARY_PATH="$PWD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
BIN=./experiments/cache_profile_adaptive_backoff
[[ -x "$BIN" ]] || { echo "Compile $BIN first" >&2; exit 1; }
passes=0
for interval in 37 9999 10000 10001; do
  for capacity in 64 8192; do
    for profile in uniform phase reverse; do
      a="$($BIN A 120000 "$interval" "$capacity" 12345 8192 "$profile" | tail -n 1 | cut -d, -f14)"
      f="$($BIN F 120000 "$interval" "$capacity" 12345 8192 "$profile" 2>/dev/null | tail -n 1 | cut -d, -f14)"
      if [[ -z "$a" || "$a" != "$f" ]]; then
        echo "FAIL interval=$interval capacity=$capacity profile=$profile; A=$a F2=$f" >&2
        exit 1
      fi
      echo "PASS interval=$interval capacity=$capacity profile=$profile"
      ((passes+=1))
    done
  done
done
echo "PASS: F2 matched A in $passes scenarios; benchmark independently checked expected classifications."

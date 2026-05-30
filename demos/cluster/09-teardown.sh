#!/usr/bin/env bash
# Step 9 — stop all three nodes (SIGTERM → each runs the kernel's orderly shutdown_all).
set -uo pipefail
cd "$(dirname "$0")"
source ./env.sh

for name in A B C; do
  pidf="$RUN/$name.pid"
  if [ -f "$pidf" ]; then
    pid="$(cat "$pidf")"
    if kill "$pid" 2>/dev/null; then echo "▸ stopped node $name (pid $pid)"; fi
    rm -f "$pidf"
  fi
done
echo "✓ cluster down. Logs remain in $RUN (node pubkeys in *.pub). Re-run ./01-boot.sh to start again."

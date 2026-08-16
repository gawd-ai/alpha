#!/usr/bin/env bash
# Step 9 — stop all three nodes (SIGTERM for orderly shutdown, then bounded-wait/SIGKILL fallback).
set -uo pipefail
cd "$(dirname "$0")"
source ./env.sh

if [[ ! -d "$RUN" ]]; then
  echo "✓ cluster already down; no run directory exists"
  exit 0
fi
acquire_cluster_lifecycle_lock || exit 1

status=0
for name in A B C; do
  pidf="$RUN/$name.pid"
  if [[ -e "$pidf" ]]; then
    if ! record="$(node_pid_record_from_file "$pidf")"; then
      echo "✗ invalid PID file $pidf; retaining it for inspection" >&2
      status=1
      continue
    fi
    pid="${record%%$'\n'*}"
    identity="${record#*$'\n'}"

    was_live=0
    if node_pid_record_is_live "$pid" "$identity"; then
      was_live=1
      echo "▸ stopping node $name (pid $pid)"
    else
      state=$?
      case "$state" in
        1) echo "  ! node $name is already down (stale pid $pid)" ;;
        2) echo "  ! node $name is down; pid $pid now belongs to another process" ;;
        *)
          echo "✗ cannot verify node $name's recorded process (pid $pid); retaining $pidf" >&2
          status=1
          continue
          ;;
      esac
    fi

    if stop_node_pid "$pid" "$identity" "node $name"; then
      if remove_node_pid_if_matches "$pidf" "$pid" "$identity"; then
        if ((was_live == 1)); then
          echo "  ✓ node $name stopped; removed $pidf"
        else
          echo "  ✓ removed stale tracking file $pidf"
        fi
      else
        echo "✗ node $name stopped, but $pidf changed; leaving it untouched" >&2
        status=1
      fi
    else
      status=1
    fi
  fi
done

if ((status == 0)); then
  echo "✓ cluster down. Logs remain in $RUN (node pubkeys in *.pub). Re-run ./01-boot.sh to start again."
else
  echo "✗ cluster teardown incomplete; retained PID files still need attention" >&2
fi
exit "$status"

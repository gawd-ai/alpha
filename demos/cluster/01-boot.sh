#!/usr/bin/env bash
# Step 1 — boot three Sanctum nodes on one mesh, two poles. Node **A** is the **Ω server**
# (`omega serve` — a federation/gateway Sanctum, the mesh anchor); nodes **B** and **C** are **α
# operators** (`alpha node`). Each gets a cluster transport (`--cluster-listen`) and an HTTP/WS
# control plane (`--listen`). MCP is a separate stdio hub demonstrated in Step 05. B and C are handed
# A as their seed, so they know how to reach the one
# node that already exists. Each prints its identity; we capture each node's pubkey for the join step.
#
# Both poles boot the same control plane + transport, so the flags are identical — only the
# binary+subcommand differs (and `omega serve` additionally declares its Realm). `--allow-ai` is set
# because these nodes are headless (no local REPL human to flip the gate); a remote curl/MCP caller is
# the operator here. On a node you sit at, keep the gate off and use the REPL (see
# docs/quickstart/operator.md). `--headless` = API only, no REPL.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

require_command curl
[ -x "$BIN" ]   || { echo "✗ $BIN not found — run ./00-build.sh first"; exit 1; }
[ -x "$OMEGA" ] || { echo "✗ $OMEGA not found — run ./00-build.sh first"; exit 1; }
mkdir -p "$RUN"
[[ -d "$RUN" && ! -L "$RUN" ]] || {
  echo "✗ run path $RUN must be a real directory, not a symlink" >&2
  exit 1
}
acquire_cluster_lifecycle_lock

# Refuse to overwrite a live or unverifiable node PID file. Only a validated record whose exact
# incarnation is confirmed gone is removed before this run owns anything.
preflight_pid_file() {
  local name="$1" pid_file="$RUN/$name.pid" record pid identity state
  [[ -e "$pid_file" ]] || return 0

  if ! record="$(node_pid_record_from_file "$pid_file")"; then
    echo "✗ invalid PID file $pid_file; refusing to overwrite it" >&2
    return 1
  fi
  pid="${record%%$'\n'*}"
  identity="${record#*$'\n'}"
  if node_pid_record_is_live "$pid" "$identity"; then
    echo "✗ node $name already appears live (pid $pid from $pid_file); run ./09-teardown.sh first" >&2
    return 1
  else
    state=$?
  fi
  if ((state == 3)); then
    echo "✗ cannot verify whether $pid_file still owns live pid $pid; refusing to overwrite it" >&2
    return 1
  fi

  if ((state == 2)); then
    echo "  ! removing stale PID file for node $name (pid $pid was reused by another process)"
  else
    echo "  ! removing stale PID file for node $name (recorded process is down)"
  fi
  if ! remove_node_pid_if_matches "$pid_file" "$pid" "$identity"; then
    echo "✗ stale PID file $pid_file changed during preflight; refusing to overwrite it" >&2
    return 1
  fi
}

preflight_ok=1
for name in A B C; do
  preflight_pid_file "$name" || preflight_ok=0
done
((preflight_ok == 1)) || exit 1

# Only processes appended to these arrays belong to this boot attempt. Any later failure or signal
# rolls those processes back in reverse order; pre-existing processes are never touched.
declare -a OWNED_NAMES=()
declare -a OWNED_PIDS=()
declare -a OWNED_PID_FILES=()
declare -a OWNED_IDENTITIES=()
rollback_armed=1

# `jobs -pr` names only running direct children still owned by this shell. It is the exact fallback
# during the few commands between spawn and `/proc` identity capture; a completed child is reaped by
# `wait` and its numerical PID is never signalled after leaving this job table.
owned_child_is_running() {
  local wanted_pid="$1" child_pid
  while IFS= read -r child_pid; do
    [[ "$child_pid" == "$wanted_pid" ]] && return 0
  done < <(jobs -pr)
  return 1
}

stop_owned_child() {
  local pid="$1" label="$2" attempt
  owned_child_is_running "$pid" || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for ((attempt = 0; attempt < 50; attempt++)); do
    owned_child_is_running "$pid" || return 0
    sleep 0.1
  done
  echo "  ! $label (pid $pid) did not stop after 5s; sending SIGKILL" >&2
  owned_child_is_running "$pid" || return 0
  kill -KILL "$pid" 2>/dev/null || true
  for ((attempt = 0; attempt < 20; attempt++)); do
    owned_child_is_running "$pid" || return 0
    sleep 0.1
  done
  ! owned_child_is_running "$pid"
}

rollback_boot() {
  local status="$?" cleanup_failed=0 index name pid pid_file identity
  trap - EXIT
  trap '' HUP INT TERM
  if [[ -n "$NODE_PID_TEMP_FILE" ]]; then
    rm -f -- "$NODE_PID_TEMP_FILE"
    NODE_PID_TEMP_FILE=""
  fi

  if ((rollback_armed == 1 && ${#OWNED_PIDS[@]} > 0)); then
    echo >&2
    echo "! boot did not complete; stopping nodes started by this attempt" >&2
    for ((index = ${#OWNED_PIDS[@]} - 1; index >= 0; index--)); do
      name="${OWNED_NAMES[index]}"
      pid="${OWNED_PIDS[index]}"
      pid_file="${OWNED_PID_FILES[index]}"
      identity="${OWNED_IDENTITIES[index]}"
      echo "▸ rolling back node $name (pid $pid)" >&2
      if { [[ -n "$identity" ]] && stop_node_pid "$pid" "$identity" "node $name"; } || \
          { [[ -z "$identity" ]] && stop_owned_child "$pid" "node $name"; }; then
        # A completed background child is safe to reap now; never wait while it still appears live.
        wait "$pid" 2>/dev/null || true
        if [[ ! -e "$pid_file" ]]; then
          echo "  ✓ node $name stopped" >&2
        elif [[ -n "$identity" ]] && remove_node_pid_if_matches "$pid_file" "$pid" "$identity"; then
          echo "  ✓ node $name stopped" >&2
        else
          echo "  ! node $name stopped, but $pid_file changed; leaving it untouched" >&2
        fi
      else
        cleanup_failed=1
      fi
    done
  fi

  if ((status == 0 && cleanup_failed != 0)); then
    status=1
  fi
  exit "$status"
}

trap rollback_boot EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# Atomically replace non-lifecycle metadata without ever opening an existing destination (which may
# have been changed into a symlink). PID ownership uses the stronger no-clobber protocol in env.sh;
# these pubkey/control-id snapshots are replaceable outputs of an already validated new boot.
write_node_metadata() { # destination value
  local destination="$1" value="$2" temporary
  temporary="$(mktemp "${destination}.tmp.XXXXXXXX")" || return 1
  if ! (umask 077; printf '%s\n' "$value" >"$temporary"); then
    rm -f -- "$temporary"
    return 1
  fi
  if ! mv -fT -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    return 1
  fi
}

boot() { # bin subcmd name host cport aport key seed [extra_args...]
  local bin="$1" subcmd="$2" name="$3" host="$4" cport="$5" aport="$6" key="$7" seed="$8"
  local pid identity owned_index deferred_signal=0 pid_file="$RUN/$name.pid" pubkey control_id
  local log_file="$RUN/$name.log"
  shift 8
  echo "▸ booting node $name (\`$(basename "$bin") $subcmd\`)  cluster=$host:$cport  api=$host:$aport"

  # Defer termination across spawn + ownership capture. Bash runs signal traps between commands; a
  # deferred code lets us record `$!` before honouring the signal, closing the orphan window.
  trap 'deferred_signal=129' HUP
  trap 'deferred_signal=130' INT
  trap 'deferred_signal=143' TERM
  open_cluster_log "$log_file" || {
    echo "✗ could not prepare safe log file $log_file" >&2
    exit 1
  }
  "$bin" "$subcmd" --node-id "$name" \
    --cluster-listen "$host:$cport" \
    --cluster-key "$seed" \
    --listen "$host:$aport" --api-key "$key" \
    --allow-ai --headless "$@" \
    >&"$CLUSTER_LOG_FD" 2>&1 {CLUSTER_LIFECYCLE_LOCK_FD}>&- &
  pid=$!
  close_cluster_log
  OWNED_NAMES+=("$name")
  OWNED_PIDS+=("$pid")
  OWNED_PID_FILES+=("$pid_file")
  OWNED_IDENTITIES+=("")
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  ((deferred_signal == 0)) || exit "$deferred_signal"

  identity="$(node_process_identity "$pid")" || {
    echo "✗ could not capture node $name process identity (pid $pid)" >&2
    exit 1
  }
  owned_index=$((${#OWNED_IDENTITIES[@]} - 1))
  OWNED_IDENTITIES[owned_index]="$identity"
  write_node_pid_file "$pid_file" "$pid" "$identity" || {
    echo "✗ could not atomically write $pid_file" >&2
    exit 1
  }
  wait_health "$host" "$aport" 50 "$pid" "$identity" || {
    echo "✗ node $name did not come up; see $log_file"
    exit 1
  }
  # Capture the node's pubkey and process-local ControlCore id from this exact boot. Both composition
  # roots print these before the HTTP health endpoint becomes ready. Fail rather than publishing an
  # empty/stale identity that would make a later join or MCP target look usable when it is not.
  pubkey="$(awk '/node pubkey = / { sub(/^.*node pubkey = /, ""); print; exit }' "$RUN/$name.log")"
  control_id="$(awk '/Role::CONTROL \(id=[0-9]+\)/ {
    line=$0; sub(/^.*Role::CONTROL \(id=/, "", line); sub(/\).*$/, "", line); print line; exit
  }' "$RUN/$name.log")"
  [[ "$pubkey" =~ ^[0-9A-Fa-f]{64}$ ]] || {
    echo "✗ node $name became healthy but its pubkey was not found in $RUN/$name.log" >&2
    exit 1
  }
  [[ "$control_id" =~ ^[0-9]+$ ]] || {
    echo "✗ node $name became healthy but its ControlCore id was not found in $RUN/$name.log" >&2
    exit 1
  }
  write_node_metadata "$RUN/$name.pub" "$pubkey" || {
    echo "✗ could not atomically write $RUN/$name.pub" >&2
    exit 1
  }
  write_node_metadata "$RUN/$name.control" "$control_id" || {
    echo "✗ could not atomically write $RUN/$name.control" >&2
    exit 1
  }
  echo "  ✓ $name up — pubkey ${pubkey:0:16}…  control-id=$control_id  HTTP/WS=$host:$aport"
}

# A first (the Ω server / seed); then B and C (α operators), each seeded with A so they can
# authenticate the first hop. A declares its Realm; B and C have no federation role.
boot "$OMEGA" serve A "$A_HOST" "$A_CPORT" "$A_APORT" "$A_KEY" "$A_SEED" --realm "$A_REALM"
APUB="$(node_pub A)"
boot "$BIN" node B "$B_HOST" "$B_CPORT" "$B_APORT" "$B_KEY" "$B_SEED" --seed "A@$A_HOST:$A_CPORT#$APUB"
boot "$BIN" node C "$C_HOST" "$C_CPORT" "$C_APORT" "$C_KEY" "$C_SEED" --seed "A@$A_HOST:$A_CPORT#$APUB"

# All three nodes are healthy and their PID files belong to this completed run. Disarm failure and
# signal rollback so they intentionally outlive this launcher.
rollback_armed=0
trap - EXIT HUP INT TERM

echo
echo "✓ three nodes up (A = omega serve, B/C = alpha node). Next: ./02-join.sh  (introduce B and C to A; gossip forms the full mesh)"

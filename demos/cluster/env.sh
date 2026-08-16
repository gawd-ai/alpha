#!/usr/bin/env bash
# Shared config for the 3-node cluster runbook (sourced by every NN-*.sh).
#
# Defaults run all three nodes on loopback (01-boot.sh backgrounds them as local processes). For
# genuinely separate machines, 01-boot.sh does NOT remote-exec — run the per-node boot on each box
# (setting that box's own *_HOST), then run 02–05 from anywhere that can reach all three. See the
# "Run it across three real machines" section of README.md.
#
# Each node has two ports: a cluster transport port (peer mesh) and an HTTP control-plane
# port (the operator + MCP drive it).

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
export ROOT="$(cd "$HERE/../.." && pwd)"
export RUN="$HERE/run"     # pids / logs / captured pubkeys live here
# Two poles, two binaries. `alpha` is the α front door — `alpha node` is an operator daemon,
# `alpha mcp` the MCP hub; BIN/MCP both point at it (`"$BIN" node …` / `"$MCP" mcp …`). `omega` is
# the Ω server — `omega serve` boots a federation/gateway Sanctum. This runbook makes node A an
# `omega serve` server (the mesh anchor + an idle federator) and B/C `alpha node` operators, so the
# cluster shows both poles on one mesh. They share the same control plane, gossip, and transport.
export BIN="${BIN:-$ROOT/target/release/alpha}"
export MCP="${MCP:-$ROOT/target/release/alpha}"
export OMEGA="${OMEGA:-$ROOT/target/release/omega}"

# Node A is the Ω server; it declares its own Realm (the federator's self_realm). With no peer Realm
# configured, A's federator is present but idle — the cross-Realm job is shown by the `federation` demo.
export A_REALM="${A_REALM:-crew}"

# Per-node host / cluster port / api port.
export A_HOST="${A_HOST:-127.0.0.1}"; export A_CPORT="${A_CPORT:-9101}"; export A_APORT="${A_APORT:-7101}"
export B_HOST="${B_HOST:-127.0.0.1}"; export B_CPORT="${B_CPORT:-9102}"; export B_APORT="${B_APORT:-7102}"
export C_HOST="${C_HOST:-127.0.0.1}"; export C_CPORT="${C_CPORT:-9103}"; export C_APORT="${C_APORT:-7103}"

# HTTP Bearer keys (one per node). With --allow-ai (how 01-boot.sh runs the nodes) this key is the
# SOLE gate on POST /api/cluster/connect — and a join propagates by gossip to every node's allowlist,
# so possession of any one node's key is effectively cluster-wide admission authority. Use strong,
# distinct keys (not these) and a trusted bind interface for anything but a local toy run.
export A_KEY="${A_KEY:-demo-key-A}"
export B_KEY="${B_KEY:-demo-key-B}"
export C_KEY="${C_KEY:-demo-key-C}"

# Fixed node-identity seeds (32-byte ed25519 seeds, hex) so pubkeys are stable across runs.
# DEMO ONLY — generate real keys (`alpha node` prints one when --cluster-key is omitted) for real use.
export A_SEED="${A_SEED:-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1}"
export B_SEED="${B_SEED:-b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2}"
export C_SEED="${C_SEED:-c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3}"

# Resolve a node letter to its host/ports/key/seed. Usage: eval "$(node_vars A)"
node_vars() {
  local n="$1"
  echo "HOST=\$${n}_HOST CPORT=\$${n}_CPORT APORT=\$${n}_APORT KEY=\$${n}_KEY SEED=\$${n}_SEED"
}

# Poll a node's public /api/health until it answers (or time out).
wait_health() {
  local host="$1" port="$2" tries="${3:-50}" watched_pid="${4:-}"
  local watched_identity="${5:-}"
  local attempt
  for ((attempt = 0; attempt < tries; attempt++)); do
    if [[ -n "$watched_pid" ]]; then
      node_pid_record_is_live "$watched_pid" "$watched_identity" || return 1
    fi
    # Bound both connection establishment and the whole request. A listener that accepts but never
    # answers must not strand boot (or prevent its EXIT trap from rolling back nodes already started).
    if curl -fsS --connect-timeout 1 --max-time 2 \
        "http://$host:$port/api/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.2
  done
  return 1
}

# Serialize every PID-record lifecycle operation for this run directory. Exact incarnation checks
# prevent signalling a reused PID; this retained advisory lock closes the separate check/unlink race
# between two concurrent boot/teardown commands. Linux `flock` is required by the same runbook that
# relies on `/proc` boot/process identities. Boot explicitly closes this descriptor in node children.
CLUSTER_LIFECYCLE_LOCK_FD=""
acquire_cluster_lifecycle_lock() {
  local lock_path="$RUN/.lifecycle.lock" path_identity fd_identity
  command -v flock >/dev/null 2>&1 || {
    echo "✗ flock is required for safe cluster lifecycle ownership" >&2
    return 1
  }

  if [[ ! -e "$lock_path" ]]; then
    # Noclobber makes a concurrent creator (including a symlink) a harmless failed attempt; the
    # exact regular-file and descriptor/path identity checks below decide what may be opened.
    (umask 077; set -o noclobber; : >"$lock_path") 2>/dev/null || true
  fi
  [[ -f "$lock_path" && ! -L "$lock_path" ]] || {
    echo "✗ lifecycle lock $lock_path is not a regular non-symlink file" >&2
    return 1
  }

  exec {CLUSTER_LIFECYCLE_LOCK_FD}<>"$lock_path" || return 1
  path_identity="$(stat -c '%d:%i' -- "$lock_path")" || return 1
  fd_identity="$(stat -Lc '%d:%i' -- "/proc/$$/fd/$CLUSTER_LIFECYCLE_LOCK_FD")" || return 1
  if [[ "$path_identity" != "$fd_identity" ]]; then
    echo "✗ lifecycle lock $lock_path changed identity while opening" >&2
    exec {CLUSTER_LIFECYCLE_LOCK_FD}>&-
    CLUSTER_LIFECYCLE_LOCK_FD=""
    return 1
  fi
  if ! flock -n "$CLUSTER_LIFECYCLE_LOCK_FD"; then
    echo "✗ another cluster boot/teardown command owns $lock_path" >&2
    exec {CLUSTER_LIFECYCLE_LOCK_FD}>&-
    CLUSTER_LIFECYCLE_LOCK_FD=""
    return 1
  fi
}

# Print two lines describing the current process incarnation: its state, then a stable identity.
# Linux's boot ID plus `/proc/<pid>/stat` start time survives exec and separates both PID reuse and
# a stale run directory carried across reboot. Platforms without that kernel-issued pair fail closed
# instead of approximating ownership from an argv that an unrelated process can reproduce.
node_process_snapshot() {
  local pid="$1" stat stat_tail state start_time boot_id
  local -a stat_fields

  [[ -r "/proc/$pid/stat" && -r /proc/sys/kernel/random/boot_id ]] || return 1
  IFS= read -r stat <"/proc/$pid/stat" || return 1
  IFS= read -r boot_id </proc/sys/kernel/random/boot_id || return 1
  stat_tail="${stat##*) }"
  [[ "$stat_tail" != "$stat" ]] || return 1
  read -r -a stat_fields <<<"$stat_tail"
  ((${#stat_fields[@]} >= 20)) || return 1
  state="${stat_fields[0]}"
  start_time="${stat_fields[19]}"
  [[ "$state" =~ ^[A-Za-z]$ && "$start_time" =~ ^[0-9]+$ ]] || return 1
  [[ "$boot_id" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$ ]] || return 1
  printf '%s\nproc:%s:%s\n' "$state" "$boot_id" "$start_time"
}

node_process_identity() {
  local snapshot
  snapshot="$(node_process_snapshot "$1")" || return 1
  printf '%s\n' "${snapshot#*$'\n'}"
}

# Print a validated PID record as two lines: PID then incarnation identity. A one-line numeric file
# from an older run is accepted as `legacy`, but a live legacy PID is unverifiable and is never
# signalled or overwritten automatically.
node_pid_record_from_file() {
  local pid_file="$1" pid identity
  local -a lines
  [[ -f "$pid_file" ]] || return 1
  mapfile -t lines <"$pid_file" || return 1
  ((${#lines[@]} == 1 || ${#lines[@]} == 2)) || return 2

  pid="${lines[0]}"
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] && ((pid > 1 && pid != $$ && pid != BASHPID)) || return 2
  if ((${#lines[@]} == 1)); then
    identity="legacy"
  else
    identity="${lines[1]}"
    case "$identity" in
      proc:*) [[ "${identity#proc:}" =~ ^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}:[0-9]+$ ]] || return 2 ;;
      *) return 2 ;;
    esac
  fi
  printf '%s\n%s\n' "$pid" "$identity"
}

# Classify a recorded incarnation. Status 0 = exact live process; 1 = gone/zombie; 2 = PID reused
# by another process; 3 = a present PID whose identity cannot be verified. Only status 0 may be
# signalled. Status 1/2 confirms the recorded incarnation is dead; status 3 must fail closed.
node_pid_record_is_live() {
  local pid="$1" expected_identity="$2" snapshot state current_identity
  if ! snapshot="$(node_process_snapshot "$pid")"; then
    if [[ -e "/proc/$pid" ]] || kill -0 "$pid" 2>/dev/null; then
      return 3
    fi
    return 1
  fi

  state="${snapshot%%$'\n'*}"
  current_identity="${snapshot#*$'\n'}"
  [[ "$expected_identity" != "legacy" ]] || return 3
  [[ "$current_identity" == "$expected_identity" ]] || return 2
  [[ "$state" != "Z" && "$state" != "X" ]] || return 1
  return 0
}

# Wait at most `tries` tenths of a second for the recorded incarnation to disappear. A reused PID
# counts as gone; an unverifiable live PID does not.
wait_node_pid_dead() {
  local pid="$1" identity="$2" tries="$3" attempt state
  for ((attempt = 0; attempt < tries; attempt++)); do
    if node_pid_record_is_live "$pid" "$identity"; then
      sleep 0.1
      continue
    else
      state=$?
    fi
    if ((state == 1 || state == 2)); then
      return 0
    fi
    sleep 0.1
  done
  if node_pid_record_is_live "$pid" "$identity"; then
    return 1
  else
    state=$?
  fi
  ((state == 1 || state == 2))
}

# Stop one recorded cluster node: TERM, a bounded grace period, then KILL and one final bounded
# identity confirmation. Success means that exact incarnation is gone; callers may then delete its
# PID file. Failure intentionally leaves that file in place so the process is never lost.
stop_node_pid() {
  local pid="$1" identity="$2" label="${3:-process}" state

  if node_pid_record_is_live "$pid" "$identity"; then
    :
  else
    state=$?
    if ((state == 1 || state == 2)); then
      return 0
    fi
    echo "✗ refusing to signal unverifiable $label (pid $pid); retaining its PID file" >&2
    return 1
  fi

  if ! kill -TERM "$pid" 2>/dev/null; then
    if wait_node_pid_dead "$pid" "$identity" 1; then
      return 0
    fi
    echo "✗ could not send SIGTERM to $label (pid $pid)" >&2
    return 1
  fi
  if wait_node_pid_dead "$pid" "$identity" 50; then
    return 0
  fi

  # Revalidate the incarnation immediately before escalation. If inspection fails or the PID was
  # reused, never direct SIGKILL at whatever now occupies that number.
  if node_pid_record_is_live "$pid" "$identity"; then
    :
  else
    state=$?
    if ((state == 1 || state == 2)); then
      return 0
    fi
    echo "✗ cannot revalidate $label (pid $pid) before SIGKILL; retaining its PID file" >&2
    return 1
  fi
  echo "  ! $label (pid $pid) did not stop after 5s; sending SIGKILL" >&2
  if ! kill -KILL "$pid" 2>/dev/null; then
    if wait_node_pid_dead "$pid" "$identity" 1; then
      return 0
    fi
    echo "✗ could not send SIGKILL to $label (pid $pid)" >&2
    return 1
  fi
  if wait_node_pid_dead "$pid" "$identity" 20; then
    return 0
  fi

  echo "✗ $label still appears live after SIGKILL (pid $pid); retaining its PID file" >&2
  return 1
}

# Atomically publish PID + process-incarnation identity. A same-directory hard link is an atomic,
# no-clobber publish: readers see either no record or the complete record, never a partial write,
# and a concurrent lifecycle command cannot have its PID file overwritten.
NODE_PID_TEMP_FILE=""
write_node_pid_file() {
  local pid_file="$1" pid="$2" identity="$3" temp_file
  NODE_PID_TEMP_FILE="$(mktemp "${pid_file}.tmp.XXXXXXXX")" || {
    NODE_PID_TEMP_FILE=""
    return 1
  }
  temp_file="$NODE_PID_TEMP_FILE"
  if ! (umask 077; printf '%s\n%s\n' "$pid" "$identity" >"$temp_file"); then
    rm -f -- "$temp_file"
    NODE_PID_TEMP_FILE=""
    return 1
  fi
  if ! ln -- "$temp_file" "$pid_file"; then
    rm -f -- "$temp_file"
    NODE_PID_TEMP_FILE=""
    return 1
  fi
  if ! rm -f -- "$temp_file"; then
    return 1
  fi
  NODE_PID_TEMP_FILE=""
}

# Delete a PID file only while it still names the process incarnation the caller owns. This prevents
# a cleanup trap from unlinking a file replaced by another concurrent operator.
remove_node_pid_if_matches() {
  local pid_file="$1" expected_pid="$2" expected_identity="$3"
  local record recorded_pid recorded_identity
  record="$(node_pid_record_from_file "$pid_file")" || return 1
  recorded_pid="${record%%$'\n'*}"
  recorded_identity="${record#*$'\n'}"
  [[ "$recorded_pid" == "$expected_pid" && "$recorded_identity" == "$expected_identity" ]] || return 1
  rm -f -- "$pid_file"
}

# Read a node's captured pubkey (written by 01-boot.sh).
node_pub() { cat "$RUN/$1.pub" 2>/dev/null; }

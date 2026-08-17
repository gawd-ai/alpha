#!/usr/bin/env bash
# Step 5 — prepare and exercise a remote MCP hub. `alpha mcp` is itself a GAWD Sanctum, not a REST proxy. This
# step admits one stable demo hub identity, boots that hub in REMOTE mode, waits for its authenticated
# mesh link, and calls `alpha_cluster` against node B's actual ControlCore. The returned graph must be
# B's converged view; a local tools/list response is not accepted as proof of remote control.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh
require_command curl
require_command jq

[ -x "$MCP" ] || { echo "✗ $MCP not found — run ./00-build.sh first"; exit 1; }
mkdir -p "$RUN" || { echo "✗ could not create local diagnostics directory $RUN" >&2; exit 1; }
[[ -d "$RUN" && ! -L "$RUN" ]] || {
  echo "✗ diagnostics path $RUN must be a real directory, not a symlink" >&2
  exit 1
}
[[ "$MCP_HUB_ID" =~ ^[A-Za-z0-9._-]{1,256}$ ]] || {
  echo "✗ MCP_HUB_ID must contain only [A-Za-z0-9._-] and fit the transport cap" >&2
  exit 1
}
[[ "$MCP_HUB_ID" != A && "$MCP_HUB_ID" != B && "$MCP_HUB_ID" != C ]] || {
  echo "✗ MCP_HUB_ID must be distinct from the three running node ids A, B, and C" >&2
  exit 1
}
[[ "$MCP_HUB_CPORT" =~ ^[0-9]+$ ]] && ((MCP_HUB_CPORT >= 1 && MCP_HUB_CPORT <= 65535)) || {
  echo "✗ MCP_HUB_CPORT must be in 1..65535" >&2
  exit 1
}
[[ "$MCP_HUB_SEED" =~ ^[0-9A-Fa-f]{64}$ ]] || {
  echo "✗ MCP_HUB_SEED must be a 32-byte ed25519 seed encoded as 64 hex characters" >&2
  exit 1
}
[[ "$MCP_HUB_PUB" =~ ^[0-9A-Fa-f]{64}$ ]] || {
  echo "✗ MCP_HUB_PUB must be a 32-byte ed25519 public key encoded as 64 hex characters" >&2
  exit 1
}

A_PUBKEY="$(node_pub A)"
B_CONTROL_ID="$(node_control_id B)"
HUB_ADDR="$MCP_HUB_HOST:$MCP_HUB_CPORT"
SEED_SPEC="A@$A_HOST:$A_CPORT#$A_PUBKEY"
TARGET_SPEC="B@$B_CONTROL_ID"

echo "▸ pre-admitting stable MCP hub $MCP_HUB_ID ($HUB_ADDR) at A before mutual authentication…"
ADMIT_PAYLOAD="$(jq -cn --arg node_id "$MCP_HUB_ID" --arg addr "$HUB_ADDR" \
  --arg pubkey "$MCP_HUB_PUB" '{node_id:$node_id, addr:$addr, pubkey:$pubkey}')"
ADMIT_RESPONSE="$(cluster_curl -X POST "http://$A_HOST:$A_APORT/api/cluster/connect" \
  -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
  -d "$ADMIT_PAYLOAD")"
if ! jq -e --arg node_id "$MCP_HUB_ID" '.ok == true and .joined == $node_id' \
    >/dev/null <<<"$ADMIT_RESPONSE"; then
  echo "✗ A did not admit the MCP hub (A's target-owned allow-ai gate must be on): $ADMIT_RESPONSE" >&2
  exit 1
fi
echo "  ✓ A admitted $MCP_HUB_ID; gossip distributes its exact pubkey before the hub connects."

echo
echo "Usable MCP-host entry for remote node B (MCP is stdio; $HUB_ADDR is the hub's mesh listener):"
jq -n \
  --arg command "$MCP" \
  --arg target "$TARGET_SPEC" \
  --arg node_id "$MCP_HUB_ID" \
  --arg listen "$HUB_ADDR" \
  --arg seed "$SEED_SPEC" \
  --arg cluster_key "$MCP_HUB_SEED" \
  '{mcpServers:{"alpha-B":{command:$command,args:["mcp","--target",$target,"--node-id",$node_id,"--listen",$listen,"--seed",$seed,"--cluster-key",$cluster_key]}}}'
echo
echo "The remote hub deliberately has no --allow-ai flag: node B owns that gate. Step 01 booted B"
echo "headless with --allow-ai because this demo mutates it; alpha_cluster itself is a read-only tool."
echo "For a read-only self-contained hub instead use [\"mcp\",\"--minimal\"]; for a self-contained"
echo "hub that may author/run use [\"mcp\",\"--allow-ai\"]."

MCP_LOG="$RUN/$MCP_HUB_ID.log"
MCP_PID_VALUE=""
MCP_IDENTITY=""
MCP_STDIN_FD=""
MCP_STDOUT_FD=""

close_mcp_fd() {
  local variable_name="$1" descriptor="${!1:-}"
  [[ -n "$descriptor" ]] || return 0
  [[ "$descriptor" =~ ^[0-9]+$ ]] || return 1
  # Bash's {var} close form operates on the numeric descriptor stored in the named variable and
  # clears it. The variable name is a fixed internal token, never user input.
  case "$variable_name" in
    MCP_STDIN_FD) exec {MCP_STDIN_FD}>&- ;;
    MCP_STDOUT_FD) exec {MCP_STDOUT_FD}>&- ;;
    *) return 1 ;;
  esac
}

# Before `/proc` identity capture completes, the coprocess is still a direct child owned by this
# shell. The job table is the only safe fallback in that narrow window: once the PID leaves it we
# never signal that number. After capture, cleanup always uses boot-id + start-time identity instead.
mcp_owned_child_is_running() {
  local child_pid
  while IFS= read -r child_pid; do
    [[ "$child_pid" == "$MCP_PID_VALUE" ]] && return 0
  done < <(jobs -pr)
  return 1
}

stop_uncaptured_mcp_child() {
  local attempt
  mcp_owned_child_is_running || return 0
  if ! kill -TERM "$MCP_PID_VALUE" 2>/dev/null; then
    mcp_owned_child_is_running || return 0
    return 1
  fi
  for ((attempt = 0; attempt < 50; attempt++)); do
    mcp_owned_child_is_running || return 0
    sleep 0.1
  done
  mcp_owned_child_is_running || return 0
  if ! kill -KILL "$MCP_PID_VALUE" 2>/dev/null; then
    mcp_owned_child_is_running || return 0
    return 1
  fi
  for ((attempt = 0; attempt < 20; attempt++)); do
    mcp_owned_child_is_running || return 0
    sleep 0.1
  done
  ! mcp_owned_child_is_running
}

cleanup_mcp_hub() {
  local state cleanup_status=0 safe_to_reap=0
  close_mcp_fd MCP_STDIN_FD || cleanup_status=1
  close_mcp_fd MCP_STDOUT_FD || cleanup_status=1
  if [[ -n "$MCP_PID_VALUE" ]]; then
    if [[ -n "$MCP_IDENTITY" ]]; then
      if node_pid_record_is_live "$MCP_PID_VALUE" "$MCP_IDENTITY"; then
        if stop_node_pid "$MCP_PID_VALUE" "$MCP_IDENTITY" "temporary MCP hub"; then
          safe_to_reap=1
        else
          cleanup_status=1
        fi
      else
        state=$?
        if ((state == 1 || state == 2)); then
          safe_to_reap=1
        else
          echo "✗ temporary MCP hub identity became unverifiable; refusing to signal or wait on pid $MCP_PID_VALUE" >&2
          cleanup_status=1
        fi
      fi
    else
      if stop_uncaptured_mcp_child; then safe_to_reap=1; else cleanup_status=1; fi
    fi
    # It is our direct child. Reap it after exact-incarnation checks prove it is no longer live;
    # a signal-driven cleanup may naturally report a non-zero child status, which is not a leak.
    if ((safe_to_reap == 1)); then
      if wait "$MCP_PID_VALUE" 2>/dev/null; then :; else state=$?; fi
      MCP_PID_VALUE=""
      MCP_IDENTITY=""
    fi
  fi
  return "$cleanup_status"
}

on_exit() {
  local status="$?"
  trap - EXIT HUP INT TERM
  if ! cleanup_mcp_hub && ((status == 0)); then
    status=1
  fi
  exit "$status"
}
trap on_exit EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

echo
echo "▸ booting the remote MCP hub and waiting for B to observe its authenticated link…"
open_cluster_log "$MCP_LOG" || {
  echo "✗ could not prepare safe MCP log file $MCP_LOG" >&2
  exit 1
}
deferred_signal=0
trap 'deferred_signal=129' HUP
trap 'deferred_signal=130' INT
trap 'deferred_signal=143' TERM
coproc MCP_REMOTE {
  exec "$MCP" mcp \
    --target "$TARGET_SPEC" \
    --node-id "$MCP_HUB_ID" \
    --listen "$HUB_ADDR" \
    --seed "$SEED_SPEC" \
    --cluster-key "$MCP_HUB_SEED" \
    2>&"$CLUSTER_LOG_FD"
}
MCP_PID_VALUE="$MCP_REMOTE_PID"
MCP_STDIN_FD="${MCP_REMOTE[1]}"
MCP_STDOUT_FD="${MCP_REMOTE[0]}"
close_cluster_log
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
((deferred_signal == 0)) || exit "$deferred_signal"
MCP_IDENTITY="$(node_process_identity "$MCP_PID_VALUE")" || {
  echo "✗ could not capture the temporary MCP hub's process identity; see $MCP_LOG" >&2
  exit 1
}

hub_connected=0
for ((attempt = 1; attempt <= 40; attempt++)); do
  if ! node_pid_record_is_live "$MCP_PID_VALUE" "$MCP_IDENTITY"; then
    echo "✗ remote MCP hub exited before joining the mesh; see $MCP_LOG" >&2
    exit 1
  fi
  if B_GRAPH="$(cluster_curl --max-time 1 "http://$B_HOST:$B_APORT/api/cluster" \
      -H "Authorization: Bearer $B_KEY")" &&
      jq -e --arg hub "$MCP_HUB_ID" '
        .self == "B" and
        ([.members[]? | select(.node_id == $hub and .connected == true)] | length == 1)
      ' >/dev/null <<<"$B_GRAPH"; then
    hub_connected=1
    break
  fi
  sleep 0.25
done
if ((hub_connected == 0)); then
  echo "✗ $MCP_HUB_ID did not form an authenticated link to B within the bounded poll window" >&2
  echo "  Hub diagnostics: $MCP_LOG" >&2
  exit 1
fi

printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"cluster-runbook","version":"0"}}}' \
  >&"$MCP_STDIN_FD"
if ! IFS= read -r -t 10 INITIALIZE_RESPONSE <&"$MCP_STDOUT_FD"; then
  echo "✗ MCP initialize did not answer within 10s; see $MCP_LOG" >&2
  exit 1
fi
if ! jq -e '.id == 1 and .result.serverInfo.name == "alpha-mcp"' \
    >/dev/null <<<"$INITIALIZE_RESPONSE"; then
  echo "✗ unexpected MCP initialize response: $INITIALIZE_RESPONSE" >&2
  exit 1
fi
printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/initialized"}' >&"$MCP_STDIN_FD"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"alpha_cluster","arguments":{}}}' \
  >&"$MCP_STDIN_FD"
if ! IFS= read -r -t 10 MCP_GRAPH_RESPONSE <&"$MCP_STDOUT_FD"; then
  echo "✗ remote alpha_cluster call did not answer within 10s; see $MCP_LOG" >&2
  exit 1
fi
if ! REMOTE_GRAPH="$(jq -er '
    select(.id == 2 and (.result.isError // false) == false) |
    .result.content[0].text | fromjson
  ' <<<"$MCP_GRAPH_RESPONSE")"; then
  echo "✗ remote alpha_cluster returned an MCP/tool error: $MCP_GRAPH_RESPONSE" >&2
  exit 1
fi
if ! jq -e --arg hub "$MCP_HUB_ID" '
    .self == "B" and
    ([.members[]? | select(.node_id == "A" and .connected == true)] | length == 1) and
    ([.members[]? | select(.node_id == "C" and .connected == true)] | length == 1) and
    ([.members[]? | select(.node_id == $hub and .connected == true)] | length == 1)
  ' >/dev/null <<<"$REMOTE_GRAPH"; then
  echo "✗ MCP reached a control plane, but it did not return B's converged graph: $REMOTE_GRAPH" >&2
  exit 1
fi

# EOF is the MCP host's normal shutdown signal. Require the child to exit cleanly within five
# seconds; the EXIT trap retains exact-incarnation TERM/KILL cleanup as a final bounded fallback.
close_mcp_fd MCP_STDIN_FD
if ! wait_node_pid_dead "$MCP_PID_VALUE" "$MCP_IDENTITY" 50; then
  echo "✗ temporary MCP hub did not shut down within 5s after stdin EOF" >&2
  exit 1
fi
if wait "$MCP_PID_VALUE"; then
  MCP_EXIT=0
else
  MCP_EXIT=$?
fi
MCP_PID_VALUE=""
MCP_IDENTITY=""
close_mcp_fd MCP_STDOUT_FD
if ((MCP_EXIT != 0)); then
  echo "✗ temporary MCP hub exited with status $MCP_EXIT; see $MCP_LOG" >&2
  exit 1
fi

echo "  Remote alpha_cluster result from B:"
jq . <<<"$REMOTE_GRAPH"
echo "✓ remote MCP proof passed: $MCP_HUB_ID authenticated onto the mesh, addressed B@$B_CONTROL_ID,"
echo "  and alpha_cluster returned B's live A+C+hub peer view over GAWD protocol (no HTTP proxy)."
echo "  The admission remains usable by the printed MCP config because it reuses the same id/key/address."
echo "  For one simultaneous hub per target, allocate a distinct id, cluster port, seed, and admitted pubkey."
echo "  When done: ./09-teardown.sh"

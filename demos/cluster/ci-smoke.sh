#!/usr/bin/env bash
# CI-only composition of Steps 01-05. This script never invokes Cargo: it consumes the debug
# binaries produced by the workflow's existing workspace build, runs every public behavioral
# assertion on one inherited CPU, and always tears down the three long-lived node processes.
set -euo pipefail

cd "$(dirname "$0")"
REPO_ROOT="$(cd ../.. && pwd)"

# Requiring a fresh caller-owned run directory prevents this automated harness from adopting or
# stopping an operator's ordinary ./run cluster. GitHub Actions supplies a unique runner-temp path.
[[ -n "${ALPHA_CLUSTER_RUN:-}" ]] || {
  echo "✗ ALPHA_CLUSTER_RUN must name a fresh, dedicated diagnostics directory" >&2
  exit 2
}
[[ "$ALPHA_CLUSTER_RUN" == /* && "$ALPHA_CLUSTER_RUN" != / ]] || {
  echo "✗ ALPHA_CLUSTER_RUN must be an absolute, non-root path" >&2
  exit 2
}

export BIN="${BIN:-$REPO_ROOT/target/debug/alpha}"
export MCP="${MCP:-$BIN}"
export OMEGA="${OMEGA:-$REPO_ROOT/target/debug/omega}"
source ./env.sh

[[ -x "$BIN" ]] || {
  echo "✗ prebuilt Alpha binary not found at $BIN; this smoke does not build it" >&2
  exit 1
}
[[ -x "$MCP" ]] || {
  echo "✗ prebuilt MCP/Alpha binary not found at $MCP; this smoke does not build it" >&2
  exit 1
}
[[ -x "$OMEGA" ]] || {
  echo "✗ prebuilt Omega binary not found at $OMEGA; this smoke does not build it" >&2
  exit 1
}

if ! (umask 077; mkdir -- "$RUN"); then
  echo "✗ could not atomically create fresh diagnostics directory $RUN" >&2
  exit 1
fi

cleanup_cluster_smoke() {
  local original_status="$?" teardown_status=0
  trap - EXIT
  # Once cleanup begins, finish the bounded exact-incarnation teardown. The workflow's outer
  # kill-after remains the hard backstop if the operating system itself stops making progress.
  trap '' HUP INT TERM
  if ./09-teardown.sh; then
    teardown_status=0
  else
    teardown_status=$?
  fi
  if ((original_status == 0 && teardown_status != 0)); then
    original_status="$teardown_status"
  fi
  exit "$original_status"
}
trap cleanup_cluster_smoke EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

./01-boot.sh
./02-join.sh
./03-graph.sh poll
./04-cross-run.sh
./05-connect-ai.sh

echo "✓ cluster CI smoke passed: boot, gossip, exact cross-run, and remote MCP graph"

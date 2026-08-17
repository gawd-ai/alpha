#!/usr/bin/env bash
# Step 3 — observe the cluster graph from each node (`GET /api/cluster`). Each node reports who it
# knows and which peers are connected; once gossip settles, every node sees the other two. With no
# argument this performs one exact check; `poll` retries for a bounded window. Either form fails
# unless every node's view names the expected self and shows both expected peers connected.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh
require_command curl
require_command jq

show() { # name host port key
  echo "── $1 ($2:$3) ────────────────────────────"
  cluster_curl --max-time 3 "http://$2:$3/api/cluster" \
    -H "Authorization: Bearer $4" | jq .
}

graph_once() {
  show A "$A_HOST" "$A_APORT" "$A_KEY"
  show B "$B_HOST" "$B_APORT" "$B_KEY"
  show C "$C_HOST" "$C_APORT" "$C_KEY"
}

view_converged() { # self host api-port key expected-peer-1 expected-peer-2
  local self="$1" host="$2" port="$3" key="$4" peer_one="$5" peer_two="$6" response
  response="$(cluster_curl --max-time 1 "http://$host:$port/api/cluster" \
    -H "Authorization: Bearer $key")" || return 1
  jq -e --arg self "$self" --arg peer_one "$peer_one" --arg peer_two "$peer_two" '
    .self == $self and
    (.connected | type == "number") and .connected >= 2 and
    ([.members[]? | select(.node_id == $peer_one and .connected == true)] | length == 1) and
    ([.members[]? | select(.node_id == $peer_two and .connected == true)] | length == 1)
  ' >/dev/null <<<"$response"
}

full_mesh_converged() {
  view_converged A "$A_HOST" "$A_APORT" "$A_KEY" B C &&
    view_converged B "$B_HOST" "$B_APORT" "$B_KEY" A C &&
    view_converged C "$C_HOST" "$C_APORT" "$C_KEY" A B
}

case "${1:-}" in
  "") attempts=1 ;;
  poll)
    attempts=30
    echo "▸ polling for the exact three-node convergence condition (A↔B, A↔C, B↔C)…"
    ;;
  *) echo "usage: $0 [poll]" >&2; exit 2 ;;
esac

converged=0
for ((attempt = 1; attempt <= attempts; attempt++)); do
  if full_mesh_converged; then
    converged=1
    break
  fi
  ((attempt == attempts)) || sleep 0.3
done

if ((converged == 0)); then
  echo "✗ mesh did not converge: every node must report the other two named peers as connected" >&2
  echo "  Current views:" >&2
  graph_once
  exit 1
fi

graph_once
echo "✓ exact three-node mesh assertion passed: A sees B+C, B sees A+C, and C sees A+B connected."
echo "  Next: ./04-cross-run.sh  (author on B, run it from A — the Ω server — over the mesh)"

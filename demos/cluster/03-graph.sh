#!/usr/bin/env bash
# Step 3 — observe the cluster graph from each node (`GET /api/cluster`). Each node reports who it
# knows and which peers are connected; once gossip settles, every node sees the other two. Pass any
# argument to poll until the full 3-node mesh forms.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

show() { # name host port key
  echo "── $1 ($2:$3) ─────────────────────────────"
  curl -fsS "http://$2:$3/api/cluster" -H "Authorization: Bearer $4"
  echo
}

graph_once() {
  show A "$A_HOST" "$A_APORT" "$A_KEY"
  show B "$B_HOST" "$B_APORT" "$B_KEY"
  show C "$C_HOST" "$C_APORT" "$C_KEY"
}

connected_total() {
  local sum=0 n
  for n in "$A_HOST:$A_APORT:$A_KEY" "$B_HOST:$B_APORT:$B_KEY" "$C_HOST:$C_APORT:$C_KEY"; do
    IFS=: read -r h p k <<<"$n"
    local c
    c=$(curl -fsS "http://$h:$p/api/cluster" -H "Authorization: Bearer $k" \
        | grep -o '"connected":true' | wc -l)
    sum=$((sum + c))
  done
  echo "$sum"
}

if [ "${1:-}" != "" ]; then
  echo "▸ polling until the full mesh forms (each of 3 nodes connected to the other 2 = 6 edges-views)…"
  for _ in $(seq 1 40); do
    if [ "$(connected_total)" -ge 6 ]; then break; fi
    sleep 0.3
  done
fi

graph_once
echo "✓ A '●' marks a connected peer. Full mesh = each node shows 2 connected peers."
echo "  Next: ./04-cross-run.sh  (author on B, run it from A — the Ω server — over the mesh)"

#!/usr/bin/env bash
# Step 2 — form the cluster from the control plane. We introduce B and C to A exactly once each
# (`POST /api/cluster/connect`, the operator/AI-gated join). A admits + dials them; then **gossip**
# tells B about C and C about B, they dial each other, and the mesh completes itself — no node was
# pre-configured with every peer. This is the many-to-many dynamic join.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

introduce() { # at_host at_port at_key  peer_node peer_host peer_cport peer_pub
  local ah="$1" ap="$2" ak="$3" pn="$4" ph="$5" pc="$6" pk="$7"
  echo "▸ introducing $pn ($ph:$pc) to the node at $ah:$ap"
  curl -fsS -X POST "http://$ah:$ap/api/cluster/connect" \
    -H "Authorization: Bearer $ak" -H "Content-Type: application/json" \
    -d "{\"node_id\":\"$pn\",\"addr\":\"$ph:$pc\",\"pubkey\":\"$pk\"}"
  echo
}

# Tell A about B and C. (B and C already know A — it was their seed.)
introduce "$A_HOST" "$A_APORT" "$A_KEY"  B "$B_HOST" "$B_CPORT" "$(node_pub B)"
introduce "$A_HOST" "$A_APORT" "$A_KEY"  C "$C_HOST" "$C_CPORT" "$(node_pub C)"

echo
echo "✓ introductions sent. Give gossip a moment, then: ./03-graph.sh  (watch the mesh converge)"

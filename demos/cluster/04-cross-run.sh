#!/usr/bin/env bash
# Step 4 — the payoff: get the two poles cross-executing. Author a creature on node **B** (an `alpha
# node` operator — authoring is the α seat; the Ω server has no authoring organ), then run it from
# node **A** (the `omega serve` gateway) *over the mesh*. A's send is addressed `Address::Node(B, id)`;
# the transport ships it to B, B's creature handles it, and the reply routes back to A. The Ω server
# uses an α operator's work — the two poles, one mesh.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

echo "▸ author a reverse critter on node B (an alpha operator; no compiler — milliseconds)…"
RESP=$(curl -fsS -X POST "http://$B_HOST:$B_APORT/api/author/critter" \
  -H "Authorization: Bearer $B_KEY" -H "Content-Type: application/json" \
  -d '{"request":"reverse a string"}')
echo "  $RESP"
ID=$(printf '%s' "$RESP" | grep -oE '"creature_id":[0-9]+' | grep -oE '[0-9]+' | head -1)
[ -n "$ID" ] || { echo "✗ author did not return a creature_id (is allow-ai on? see the node log)"; exit 1; }
echo "✓ B authored + hot-loaded a reverse critter as creature id=$ID"

echo
echo "▸ from node A (the Ω server), run B's creature over the cluster:  send B:$ID \"hello\""
REPLY=$(curl -fsS -X POST "http://$A_HOST:$A_APORT/api/send" \
  -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
  -d "{\"node\":\"B\",\"id\":$ID,\"text\":\"hello\"}")
echo "  $REPLY"
echo "✓ A asked B's creature (over the authenticated mesh) to reverse \"hello\" — expect reply \"olleh\"."
echo "  That is cross-execution between the poles: the Ω server ran a creature authored on an α operator."
echo "  (C, the other α node, can do the same — \`send B:$ID …\` from C's control plane.)"
echo "  Next: ./05-connect-ai.sh  (attach an AI to each node over MCP)"

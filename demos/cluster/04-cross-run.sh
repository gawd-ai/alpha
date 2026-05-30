#!/usr/bin/env bash
# Step 4 — the payoff: get the nodes cross-executing. Author a creature on node A, then run it from
# node B *over the mesh*. B's send is addressed `Address::Node(A, id)`; the transport ships it to A,
# A's creature handles it, and the reply routes back to B. One node uses another's work.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

echo "▸ author a reverse critter on node A (no compiler — milliseconds)…"
RESP=$(curl -fsS -X POST "http://$A_HOST:$A_APORT/api/author/critter" \
  -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
  -d '{"request":"reverse a string"}')
echo "  $RESP"
ID=$(printf '%s' "$RESP" | grep -oE '"creature_id":[0-9]+' | grep -oE '[0-9]+' | head -1)
[ -n "$ID" ] || { echo "✗ author did not return a creature_id (is allow-ai on? see the node log)"; exit 1; }
echo "✓ A authored + hot-loaded a reverse critter as creature id=$ID"

echo
echo "▸ from node B, run A's creature over the cluster:  send A:$ID \"hello\""
REPLY=$(curl -fsS -X POST "http://$B_HOST:$B_APORT/api/send" \
  -H "Authorization: Bearer $B_KEY" -H "Content-Type: application/json" \
  -d "{\"node\":\"A\",\"id\":$ID,\"text\":\"hello\"}")
echo "  $REPLY"
echo "✓ B asked A's creature (over the authenticated mesh) to reverse \"hello\" — expect reply \"olleh\"."
echo "  That is cross-execution through the operator's control plane: B used a creature living on A."
echo "  Next: ./05-connect-ai.sh  (attach an AI to each node over MCP)"

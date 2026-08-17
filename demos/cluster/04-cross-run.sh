#!/usr/bin/env bash
# Step 4 — the payoff: get the two poles cross-executing. Author a creature on node **B** (an `alpha
# node` operator — authoring is the α seat; the Ω server has no authoring organ), then run it from
# node **A** (the `omega serve` gateway) *over the mesh*. A's send is addressed `Address::Node(B, id)`;
# the transport ships it to B, B's creature handles it, and the reply routes back to A. The Ω server
# uses an α operator's work — the two poles, one mesh.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh
require_command curl
require_command jq

echo "▸ author a reverse critter on node B (an alpha operator; no compiler — milliseconds)…"
AUTHOR_PAYLOAD="$(jq -cn '{request:"reverse a string"}')"
RESP="$(cluster_curl -X POST "http://$B_HOST:$B_APORT/api/author/critter" \
  -H "Authorization: Bearer $B_KEY" -H "Content-Type: application/json" \
  -d "$AUTHOR_PAYLOAD")"
echo "  $RESP"
if ! jq -e '.ok == true and .stage == "loaded" and
    (.creature_id | type == "number") and .creature_id >= 0' >/dev/null <<<"$RESP"; then
  echo "✗ B did not return a successful loaded critter (is its target-owned allow-ai gate on?): $RESP" >&2
  exit 1
fi
ID="$(jq -er '.creature_id' <<<"$RESP")"
echo "✓ B authored + hot-loaded a reverse critter as creature id=$ID"

echo
echo "▸ from node A (the Ω server), run B's creature over the cluster:  send B:$ID \"hello\""
SEND_PAYLOAD="$(jq -cn --argjson id "$ID" '{node:"B", id:$id, text:"hello"}')"
REPLY="$(cluster_curl -X POST "http://$A_HOST:$A_APORT/api/send" \
  -H "Authorization: Bearer $A_KEY" -H "Content-Type: application/json" \
  -d "$SEND_PAYLOAD")"
echo "  $REPLY"
if ! jq -e '.reply == "olleh" and (.reply_truncated // false) == false and
    (.timeout // false) == false and (.unrouted // false) == false' >/dev/null <<<"$REPLY"; then
  echo "✗ cross-run did not return the exact reply \"olleh\": $REPLY" >&2
  exit 1
fi
echo "✓ exact reply assertion passed: A asked B's creature over the authenticated mesh and received \"olleh\"."
echo "  That is cross-execution between the poles: the Ω server ran a creature authored on an α operator."
echo "  (C, the other α node, can do the same — \`send B:$ID …\` from C's control plane.)"
echo "  Next: ./05-connect-ai.sh  (prove a remote MCP hub reads B's graph over the mesh)"

#!/usr/bin/env bash
# Step 1 — boot three Sanctum nodes (A, B, C), each a real `alpha node` process with a cluster
# transport (`--cluster-listen`) and an HTTP/MCP control plane (`--listen`). B and C are handed A as
# their seed, so they know how to reach the one node that already exists. Each prints its identity;
# we capture each node's pubkey for the join step.
#
# `--allow-ai` is set because these nodes are headless (no local REPL human to flip the gate); a
# remote curl/MCP caller is the operator here. On a node you sit at, keep the gate off and use the
# REPL (see docs/quickstart/operator.md). `--headless` = API only, no REPL.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

[ -x "$BIN" ] || { echo "✗ $BIN not found — run ./00-build.sh first"; exit 1; }
mkdir -p "$RUN"

boot() { # name host cport aport key seed [seed_args...]
  local name="$1" host="$2" cport="$3" aport="$4" key="$5" seed="$6"; shift 6
  echo "▸ booting node $name  cluster=$host:$cport  api=$host:$aport"
  "$BIN" node --node-id "$name" \
    --cluster-listen "$host:$cport" \
    --cluster-key "$seed" \
    --listen "$host:$aport" --api-key "$key" \
    --allow-ai --headless "$@" \
    >"$RUN/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
  wait_health "$host" "$aport" || { echo "✗ node $name did not come up; see $RUN/$name.log"; exit 1; }
  # Capture the node's pubkey (printed once at boot) so later steps can introduce it.
  grep -m1 "node pubkey = " "$RUN/$name.log" | sed 's/.*node pubkey = //' >"$RUN/$name.pub"
  echo "  ✓ $name up — pubkey $(cut -c1-16 "$RUN/$name.pub")…"
}

# A first (the seed); then B and C, each seeded with A so they can authenticate the first hop.
boot A "$A_HOST" "$A_CPORT" "$A_APORT" "$A_KEY" "$A_SEED"
APUB="$(node_pub A)"
boot B "$B_HOST" "$B_CPORT" "$B_APORT" "$B_KEY" "$B_SEED" --seed "A@$A_HOST:$A_CPORT#$APUB"
boot C "$C_HOST" "$C_CPORT" "$C_APORT" "$C_KEY" "$C_SEED" --seed "A@$A_HOST:$A_CPORT#$APUB"

echo
echo "✓ three nodes up. Next: ./02-join.sh  (introduce B and C to A; gossip forms the full mesh)"

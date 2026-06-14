#!/usr/bin/env bash
# Step 1 — boot three Sanctum nodes on one mesh, two poles. Node **A** is the **Ω server**
# (`omega serve` — a federation/gateway Sanctum, the mesh anchor); nodes **B** and **C** are **α
# operators** (`alpha node`). Each gets a cluster transport (`--cluster-listen`) and an HTTP/MCP
# control plane (`--listen`). B and C are handed A as their seed, so they know how to reach the one
# node that already exists. Each prints its identity; we capture each node's pubkey for the join step.
#
# Both poles boot the same control plane + transport, so the flags are identical — only the
# binary+subcommand differs (and `omega serve` additionally declares its Realm). `--allow-ai` is set
# because these nodes are headless (no local REPL human to flip the gate); a remote curl/MCP caller is
# the operator here. On a node you sit at, keep the gate off and use the REPL (see
# docs/quickstart/operator.md). `--headless` = API only, no REPL.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

[ -x "$BIN" ]   || { echo "✗ $BIN not found — run ./00-build.sh first"; exit 1; }
[ -x "$OMEGA" ] || { echo "✗ $OMEGA not found — run ./00-build.sh first"; exit 1; }
mkdir -p "$RUN"

boot() { # bin subcmd name host cport aport key seed [extra_args...]
  local bin="$1" subcmd="$2" name="$3" host="$4" cport="$5" aport="$6" key="$7" seed="$8"; shift 8
  echo "▸ booting node $name (\`$(basename "$bin") $subcmd\`)  cluster=$host:$cport  api=$host:$aport"
  "$bin" "$subcmd" --node-id "$name" \
    --cluster-listen "$host:$cport" \
    --cluster-key "$seed" \
    --listen "$host:$aport" --api-key "$key" \
    --allow-ai --headless "$@" \
    >"$RUN/$name.log" 2>&1 &
  echo $! >"$RUN/$name.pid"
  wait_health "$host" "$aport" || { echo "✗ node $name did not come up; see $RUN/$name.log"; exit 1; }
  # Capture the node's pubkey (printed once at boot) so later steps can introduce it. Both
  # `alpha node` and `omega serve` print a "node pubkey = …" line, so this works for either pole.
  grep -m1 "node pubkey = " "$RUN/$name.log" | sed 's/.*node pubkey = //' >"$RUN/$name.pub"
  echo "  ✓ $name up — pubkey $(cut -c1-16 "$RUN/$name.pub")…"
}

# A first (the Ω server / seed); then B and C (α operators), each seeded with A so they can
# authenticate the first hop. A declares its Realm; B and C have no federation role.
boot "$OMEGA" serve A "$A_HOST" "$A_CPORT" "$A_APORT" "$A_KEY" "$A_SEED" --realm "$A_REALM"
APUB="$(node_pub A)"
boot "$BIN" node B "$B_HOST" "$B_CPORT" "$B_APORT" "$B_KEY" "$B_SEED" --seed "A@$A_HOST:$A_CPORT#$APUB"
boot "$BIN" node C "$C_HOST" "$C_CPORT" "$C_APORT" "$C_KEY" "$C_SEED" --seed "A@$A_HOST:$A_CPORT#$APUB"

echo
echo "✓ three nodes up (A = omega serve, B/C = alpha node). Next: ./02-join.sh  (introduce B and C to A; gossip forms the full mesh)"

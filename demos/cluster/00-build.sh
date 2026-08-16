#!/usr/bin/env bash
# Step 0 — build the two binaries this runbook drives: `alpha` (the α front door — `alpha node` is the
# daemon, `alpha mcp` the MCP hub) and `omega` (the Ω server — `omega serve` boots a gateway Sanctum).
# Node A runs `omega serve`; B and C run `alpha node`. Same mesh, two poles.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

echo "▸ building alpha + omega (release)…"
( cd "$ROOT" && CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 \
    cargo build --locked --release -p alpha -p omega )
echo "✓ built:"
echo "    α front door:  $BIN     (daemon: \`alpha node\`, MCP hub: \`alpha mcp\`)"
echo "    Ω server:      $OMEGA   (gateway: \`omega serve\`)"

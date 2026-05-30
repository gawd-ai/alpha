#!/usr/bin/env bash
# Step 0 — build the one binary the runbook drives: `alpha`, the α front door. `alpha node`
# is the daemon; `alpha mcp` is the MCP bridge — same binary, two subcommands.
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

echo "▸ building alpha (the α front door — node + mcp + http) (release)…"
( cd "$ROOT" && cargo build --release -p alpha )
echo "✓ built:"
echo "    front door: $BIN   (daemon: \`alpha node\`, MCP hub: \`alpha mcp\`)"

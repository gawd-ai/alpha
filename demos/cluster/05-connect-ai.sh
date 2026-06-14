#!/usr/bin/env bash
# Step 5 — connect an AI over MCP. `alpha mcp` is itself a GAWD sanctum — NOT a REST proxy.
# Two shapes:
#   • self-contained: `alpha mcp` boots its own node; the assistant authors/loads/runs on that hub.
#   • remote-over-mesh: `alpha mcp --target <node@control-id> --seed <id@host:port#pubkey> --node-id
#     <hub> --listen <addr>` joins this cluster's mesh and routes every tool call to a *peer* node's
#     Role::CONTROL — the GAWD-protocol path (no HTTP side-channel).
# To author + drive, front an **α operator** (B or C); the **Ω server** (A) is drivable for
# control/federation but has no authoring organ, so `alpha_author` there has nothing to call.
# Below: the `.mcp.json` to register, then a live proof that the MCP surface speaks (tools/list).
set -euo pipefail
cd "$(dirname "$0")"
source ./env.sh

[ -x "$MCP" ] || { echo "✗ $MCP not found — run ./00-build.sh first"; exit 1; }

cat <<EOF
Register these with your MCP host (Claude Desktop/Code, etc.). To co-drive a *specific* cluster node
over the mesh, use remote mode. Front the α operator **B** for authoring/driving (its pubkey was
captured in 01-boot as $RUN/B.pub; grab B's control-plane id from its boot log:
\`grep 'Role::CONTROL (id=' $RUN/B.log\`). The mesh entry point (--seed) is still A, the anchor:

{
  "mcpServers": {
    "alpha-B": {
      "command": "$MCP",
      "args": ["mcp", "--target", "B@<B-control-id>",
               "--node-id", "mcp-hub-B", "--listen", "127.0.0.1:9190",
               "--seed", "A@$A_HOST:$A_CPORT#$(node_pub A)"]
    }
  }
}

(Front the Ω server A the same way — \`--target A@<A-control-id>\` — to read its graph and drive
 control/federation; just don't expect authoring there. Or the simplest assistant sandbox, a
 self-contained hub that authors/runs on its own node:
  { "mcpServers": { "alpha": { "command": "$MCP", "args": ["mcp"] } } }  )
EOF

echo
echo "▸ proving the bridge speaks: boot a local self-contained \`alpha mcp\` hub and list its tools…"
printf '%s\n%s\n%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25","capabilities":{},"clientInfo":{"name":"runbook","version":"0"}}}' \
  '{"jsonrpc":"2.0","method":"notifications/initialized"}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  | "$MCP" mcp --minimal 2>/dev/null \
  | grep -m1 '"id":2' | grep -o '"name":"alpha_[a-z_]*"' | sort -u || true

echo
echo "✓ the MCP surface answered a real tools/list — alpha_author, alpha_send, alpha_cluster, …"
echo "  In remote mode (above) those tools drive a peer cluster node's Role::CONTROL over the mesh;"
echo "  alpha_send with a 'node' arg then cross-executes on another node, exactly like ./04-cross-run.sh."
echo "  When done: ./09-teardown.sh"

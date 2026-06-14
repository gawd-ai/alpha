#!/usr/bin/env bash
# Shared config for the 3-node cluster runbook (sourced by every NN-*.sh).
#
# Defaults run all three nodes on loopback (01-boot.sh backgrounds them as local processes). For
# genuinely separate machines, 01-boot.sh does NOT remote-exec — run the per-node boot on each box
# (setting that box's own *_HOST), then run 02–05 from anywhere that can reach all three. See the
# "Run it across three real machines" section of README.md.
#
# Each node has two ports: a cluster transport port (peer mesh) and an HTTP control-plane
# port (the operator + MCP drive it).

HERE="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" && pwd)"
export ROOT="$(cd "$HERE/../.." && pwd)"
export RUN="$HERE/run"     # pids / logs / captured pubkeys live here
# Two poles, two binaries. `alpha` is the α front door — `alpha node` is an operator daemon,
# `alpha mcp` the MCP hub; BIN/MCP both point at it (`"$BIN" node …` / `"$MCP" mcp …`). `omega` is
# the Ω server — `omega serve` boots a federation/gateway Sanctum. This runbook makes node A an
# `omega serve` server (the mesh anchor + an idle federator) and B/C `alpha node` operators, so the
# cluster shows both poles on one mesh. They share the same control plane, gossip, and transport.
export BIN="${BIN:-$ROOT/target/release/alpha}"
export MCP="${MCP:-$ROOT/target/release/alpha}"
export OMEGA="${OMEGA:-$ROOT/target/release/omega}"

# Node A is the Ω server; it declares its own Realm (the federator's self_realm). With no peer Realm
# configured, A's federator is present but idle — the cross-Realm job is shown by the `federation` demo.
export A_REALM="${A_REALM:-crew}"

# Per-node host / cluster port / api port.
export A_HOST="${A_HOST:-127.0.0.1}"; export A_CPORT="${A_CPORT:-9101}"; export A_APORT="${A_APORT:-7101}"
export B_HOST="${B_HOST:-127.0.0.1}"; export B_CPORT="${B_CPORT:-9102}"; export B_APORT="${B_APORT:-7102}"
export C_HOST="${C_HOST:-127.0.0.1}"; export C_CPORT="${C_CPORT:-9103}"; export C_APORT="${C_APORT:-7103}"

# HTTP Bearer keys (one per node). With --allow-ai (how 01-boot.sh runs the nodes) this key is the
# SOLE gate on POST /api/cluster/connect — and a join propagates by gossip to every node's allowlist,
# so possession of any one node's key is effectively cluster-wide admission authority. Use strong,
# distinct keys (not these) and a trusted bind interface for anything but a local toy run.
export A_KEY="${A_KEY:-demo-key-A}"
export B_KEY="${B_KEY:-demo-key-B}"
export C_KEY="${C_KEY:-demo-key-C}"

# Fixed node-identity seeds (32-byte ed25519 seeds, hex) so pubkeys are stable across runs.
# DEMO ONLY — generate real keys (`alpha node` prints one when --cluster-key is omitted) for real use.
export A_SEED="${A_SEED:-a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1}"
export B_SEED="${B_SEED:-b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2}"
export C_SEED="${C_SEED:-c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3}"

# Resolve a node letter to its host/ports/key/seed. Usage: eval "$(node_vars A)"
node_vars() {
  local n="$1"
  echo "HOST=\$${n}_HOST CPORT=\$${n}_CPORT APORT=\$${n}_APORT KEY=\$${n}_KEY SEED=\$${n}_SEED"
}

# Poll a node's public /api/health until it answers (or time out).
wait_health() {
  local host="$1" port="$2" tries="${3:-50}"
  for _ in $(seq 1 "$tries"); do
    if curl -fsS "http://$host:$port/api/health" >/dev/null 2>&1; then return 0; fi
    sleep 0.2
  done
  return 1
}

# Read a node's captured pubkey (written by 01-boot.sh).
node_pub() { cat "$RUN/$1.pub" 2>/dev/null; }

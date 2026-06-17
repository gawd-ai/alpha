# ADR-0039 — Nested `reply_to` rewrite for Realm/Omega grain

- **Status:** Implemented (v0.4.3)
- **Drives:** [TRD-002](../trd/TRD-002-cross-node-relay-integrity.md) R2
- **Date:** 2026-06-16

## Context

When the transport delivers an inbound cross-node frame, it rewrites `reply_to` so a peer-local address
becomes peer-qualified from our point of view:

```rust
// cosmos/creatures/transport-tcp/src/lib.rs:1463-1466
let reply_to = env.header.reply_to.clone().map(|rt| match rt {
    Address::Creature(mid) => Address::Node(peer.clone(), mid),
    other => other,
});
```

Only `Address::Creature(mid)` is rewritten. A `reply_to` of `Address::Realm { realm, target: Creature(mid) }`
or `Address::Omega { realm, target: Creature(mid) }` falls through as `other => other` — the boxed inner
target keeps its *sender-local* grain, so a reply routed back through a gateway loses the peer context.
Today most callers leave `reply_to` unset (the reply defaults to `from`, which the bus reseals correctly),
so this is latent — but v0.5.0 cross-Realm dialogue is exactly where an explicit nested `reply_to` becomes
common, and a silently-misrouted reply would read as an agent bug.

## Decision

Make the `reply_to` rewrite **recurse into the boxed inner target** of `Address::Realm` and
`Address::Omega`, rewriting a nested `Creature(mid)` to `Node(peer, mid)` while preserving the
`realm` wrapper. Implement it as a small recursive helper (`rewrite_inbound_target(addr, peer)`) so the
same rule applies uniformly at any nesting depth (bounded by the existing address-depth cap).

## Consequences

- A cross-Realm reply addressed at federation grain routes back to the correct creature on the correct
  node.
- The rewrite is uniform and depth-bounded; no special-casing per grain at the call site.
- Pure local routing logic; no peer ever observes the rewritten form on the wire (the rewrite is applied
  *after* signature verification of the original bytes, `transport-tcp:1457-1460`).

## Implementation sketch

- **Files:** `cosmos/creatures/transport-tcp/src/lib.rs` — replace the inline `map` at `:1463-1466` with
  a recursive `rewrite_inbound_target`; reuse it for the `to` target too if the same nested-grain gap
  exists there (verify during implementation).
- **Wire-additivity:** **None** — `reply_to` rewrite is a receive-side, post-verification transformation
  of local routing state; the signed bytes are untouched, and `Address::{Realm,Omega}` already exist on
  the wire.
- **Test:** a cross-node integration test (extend the existing cross-Realm suite, ports in the
  `19_96x` range) that sends a request with `reply_to = Realm{ other, Creature(mid) }` and asserts the
  reply is delivered to `mid` on the originating node.

## Related

TRD-002; ADR-0038 (the companion relay-integrity decision); the cross-Realm placement/dialogue paths.

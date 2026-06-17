# ADR-0041 — Origin-verdict enforcement posture

- **Status:** Implemented (v0.4.3) — chose the boot-time warning (`omni::warn_if_no_immune_response`)
  over a silent default bind, wired into both clustered poles + SECURITY.md.
- **Drives:** [TRD-002](../trd/TRD-002-cross-node-relay-integrity.md) R4
- **Date:** 2026-06-16

## Context

The transport computes an `OriginVerdict` (`Verified` / `BadSig` / `Unresolved`) for every authenticated
inbound frame and **publishes** it on `PROPRIOCEPTION` — it does **not** drop a `BadSig` frame:

```rust
// cosmos/creatures/transport-tcp/src/lib.rs:1502-1514
let verdict = if peer_pubkey.is_empty() { Unresolved } else if sig_ok { Verified } else { BadSig };
publish_origin_verdict(...);
bus.emit_attested(dispatch, Origin::node(peer));   // emitted regardless of verdict
```

This is deliberate and consistent with the kernel's model-free posture (R5/R6 invariants): the substrate
ships the *mechanism* (compute + publish the verdict); the *decision* (quarantine the peer, deny the
sender) belongs to an injected `Role::IMMUNE_RESPONSE` creature. The gap is operational: if an operator
runs a node **without** binding an immune-response that acts on `OriginVerdict::BadSig`, forged-signature
frames are admitted to inboxes. Nothing in the surface makes that consequence visible.

## Decision

Keep the router/transport **non-enforcing**, and make the consequence explicit and easy to do right:

1. **Document** in `SECURITY.md` (and TRD-002): absent a bound `Role::IMMUNE_RESPONSE` reacting to
   `OriginVerdict::BadSig`, a peer sending bad-signature frames has them admitted; binding the reference
   `immune-response` is the recommended baseline for any clustered node.
2. **Recommend a default**: the clustered composition roots (`omega/src/serve.rs`, and the clustered
   `alpha node` path) SHOULD bind the reference immune-response by default (or log a one-line warning at
   boot when clustering is on and no immune-response is bound). Pick one in implementation; prefer the
   warning if a silent default would surprise operators who inject their own.
3. **Do not** add a fail-closed mode to the router/transport — that would move a trust decision into the
   substrate, violating "keep the kernel model-free."

## Consequences

- The architecture invariant holds (enforcement stays in an injected creature).
- Operators get a visible, actionable signal instead of a silent hole.
- A clustered node is safe-by-default *or* loudly warned, never quietly exposed.

## Implementation sketch

- **Files:** `SECURITY.md` (the warning + the recommended binding); `omega/src/serve.rs` and the
  clustered branch of `alpha/src/node.rs` (default bind or boot-time warning). The reference creature
  already exists (`cosmos/creatures/immune-response`).
- **Wire-additivity:** **None** (composition + docs only).
- **Test:** a composition test asserting the clustered boot path either binds an immune-response or emits
  the warning when none is bound.

## Related

TRD-002; the `immune-response` creature; the "containment is opt-in / defense is chosen" invariant in
ROADMAP.md.

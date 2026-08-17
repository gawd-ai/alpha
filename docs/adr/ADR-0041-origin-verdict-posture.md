# ADR-0041 — Origin-verdict enforcement posture

- **Status:** Implemented (v0.4.3; corrected in v0.4.4) — chose the boot-time warning
  (`omni::warn_if_no_origin_defense`)
  over a silent default bind, wired into both clustered poles + SECURITY.md.
- **Drives:** [TRD-002](../trd/TRD-002-cross-node-relay-integrity.md) R4
- **Date:** 2026-06-16

## Context

The transport computes an `OriginVerdict` (`Verified` / `BadSig` / `Unresolved`) for every authenticated
inbound frame and **publishes** it on `PROPRIOCEPTION` — it does **not** drop a `BadSig` frame:

See `transport_tcp::dispatch_inbound` and `publish_origin_verdict`: verdict publication and attested
delivery are distinct operations, and delivery is not conditional on `Verified`.

This is deliberate and consistent with the kernel's model-free posture (R5/R6 invariants): the substrate
ships the *mechanism* (compute + publish the verdict); the *decision* (forget the peer, deny the
sender, page an operator, or another reversible response) belongs to an injected topic consumer.
The shipped reference is `policy-origin`, subscribed to `PROPRIOCEPTION`; it counts non-`Verified`
verdicts and sends `TransportCtl::Forget`. `immune-response` instead quarantines watched local
artifacts and does not parse origin verdicts. Without an origin-defense consumer, forged-signature
frames are admitted to inboxes. Nothing in the transport silently closes that policy choice.

## Decision

Keep the router/transport **non-enforcing**, and make the consequence explicit and easy to do right:

1. **Document** in `SECURITY.md` (and TRD-002): absent an origin-defense subscriber reacting to
   `OriginVerdict::BadSig`, a peer sending bad-signature frames has them admitted; subscribing the
   reference `policy-origin` is the recommended baseline for a clustered node.
2. **Recommend a default**: clustered composition roots (`omega/src/serve.rs`, and the clustered
   `alpha node` path) SHOULD subscribe the reference policy by default or log a one-line warning at
   boot when none was wired. The implementation chooses the warning because a silent policy bind
   would surprise operators who inject their own response.
3. **Do not** add a fail-closed mode to the router/transport — that would move a trust decision into the
   substrate, violating "keep the kernel model-free."

## Consequences

- The architecture invariant holds (enforcement stays in an injected creature).
- Operators get a visible, actionable signal instead of a silent hole.
- A clustered node is safe-by-default *or* loudly warned, never quietly exposed.

## Implementation sketch

- **Files:** `SECURITY.md` (the warning + the recommended subscription); `omega/src/serve.rs` and the
  clustered branch of `alpha/src/node.rs` (default wire or boot-time warning). The reference creature
  is `cosmos/creatures/prototypes/policies/policy-origin`.
- **Wire-additivity:** **None** (composition + docs only).
- **Test:** a posture test asserting the composition reports a wired origin-defense consumer or emits
  the warning when none is wired; cross-node integration separately proves `policy-origin` consumes a
  bad verdict and forgets the peer.

## Related

TRD-002; the `policy-origin` creature; the "containment is opt-in / defense is chosen" invariant in
ROADMAP.md.

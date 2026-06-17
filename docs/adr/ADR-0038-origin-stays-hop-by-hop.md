# ADR-0038 — Origin stays hop-by-hop; agent identity is application-signed

- **Status:** Implemented (v0.4.3) — realized end-to-end (beyond the reserve-only minimum): the
  `dialogue::AnswerBody` provenance fields + helpers, the responder signs (`DialogueResponder::signed`),
  and the initiator verifies on relay (`with_verifier` / `with_expected_signer`).
- **Drives:** [TRD-002](../trd/TRD-002-cross-node-relay-integrity.md) R1
- **Date:** 2026-06-16

## Context

The v0.4.2 review flagged "unauthenticated Answer relay": when `dialogue-initiator` receives a cross-node
`Answer` and relays it to the original requester, the *transport origin* of the real responder is not
forwarded — the requester sees the relay as the `from`. The audit proposed adding `origin: Option<Origin>`
to `Dispatch` so relays preserve attribution.

Verification shows that fix is **unsafe and wrong-layer**:

- `Origin`-sealing is a **boot-only kernel grant** (`may_attest`), conferred by how the kernel loads a
  creature, *never* declared by an artifact — explicitly *"so a signed/authored creature can never grant
  itself the power to forge a cross-node origin"* (`cosmos/aether/src/bus.rs:83-91`).
- A creature **can read** inbound origin (`Envelope.header.origin`, `cosmos/aether/src/envelope.rs:74`)
  but **cannot set** it on outbound (`Dispatch` has no origin field, `instance.rs:16-24`; only
  `emit_attested` seals it, `bus.rs:244-253`).

Adding a creature-settable origin field would let any creature forge cross-node attribution — directly
breaking the anti-forgery invariant. Origin is, and must remain, a **transport mechanism** that attributes
the *immediate authenticated peer* — hop-by-hop by construction.

What v0.5.0 actually needs ("the requester knows *which agent* answered") is **end-to-end agent
identity**, which is an application/creature concern, not a substrate field — the "fabric, not model"
rule.

## Decision

1. **Do not** add a creature-settable origin to `Dispatch` or the bus. Transport `Origin::node(peer)`
   stays hop-by-hop and unforgeable.
2. **Specify** (reserve + document, ship the shape) an application-layer **signed dialogue provenance**:
   the responder includes, inside the `Dialogue` answer body, its agent public key + a signature over
   `(corr, prompt-or-turn, reply)`. The requester (or the relay) verifies it. Authenticity is then
   end-to-end and independent of how many fabric hops the answer crossed.
3. Reference the reserved shape from [ADR-0043](ADR-0043-reserved-seam-register.md) so v0.5.0's
   LLM-backed agents *compose* it rather than introduce a wire change.
4. Document at each relay (TRD-002 R5) that origin is hop-by-hop and does not survive a relay.

## Consequences

- The anti-forgery invariant (`bus.rs:83-91`) is preserved; no creature can fake origin.
- End-to-end authenticity becomes a property of the *message*, not the *transport path* — the correct
  grain for multi-hop cross-Realm dialogue and for audit.
- v0.5.0 adds signing/verification *inside the agents*, with **no substrate wire churn** — exactly the
  convergence goal.
- Slightly more work for an agent author (sign/verify the body), but it is the only sound option for
  multi-hop attribution.

## Implementation sketch

- **Files:** `cosmos/seer/src/lib.rs` — the `pub mod dialogue` block (L987); its `AnswerBody`
  (L1003, today just `pub reply: String`) gains optional `signer_pubkey` + `signature` fields,
  `#[serde(default, skip_serializing_if = "Option::is_none")]` (there is **no** `cosmos/seer/src/topics/`
  directory — every SEER topic body is an inline module in `lib.rs`);
  `cosmos/creatures/prototypes/dialogue/dialogue-responder` (sign the answer) +
  `dialogue-initiator` (verify on relay, surface a verdict). Reserve-only in v0.4.3 if signing the
  reference echo agent is out of scope — but at minimum land the *fields* + the doc + one verify test.
- **Wire-additivity:** **Additive** — new optional, serde-elided fields on the `Dialogue` body (schema
  stays `"seer"`); absent fields are wire-identical to today. No signed-manifest field touched.
- **Test:** a unit/integration test that a `Dialogue` answer carrying a valid body signature verifies,
  and a tampered reply fails verification — proving content authenticity survives a relay that strips/
  changes transport origin.

## Related

ADR-0043 (reserved-seam register lists this provenance shape); TRD-002; the v0.5.0 dialogue headline.

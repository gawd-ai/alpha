# ADR-0042 — Escape-hatch policy for `with_max_*(0) = unbounded`

- **Status:** Implemented (v0.4.3)
- **Drives:** [TRD-001](../trd/TRD-001-substrate-resource-safety.md) R6
- **Date:** 2026-06-16

## Context

Several reference creatures expose a `with_max_*(0) = unbounded` opt-out that disables an otherwise-default
cap:

- `registry-mem`: `with_max_entries(0)` (`cosmos/creatures/registry-mem/src/lib.rs:56,204-210`).
- `embodiment-advertiser`: `with_max_offers(0)` (`cosmos/creatures/embodiment-advertiser/src/lib.rs:50-51`).
- `realm-gateway`: `with_many_and_limit(.., 0)` (`cosmos/creatures/prototypes/gateways/realm-gateway/src/lib.rs:89-91`).

Each is intentional (lab/demo workloads) and documented locally, but the phrasing, naming, and framing
differ across the three, and the "0 disables the safety" idea sits uneasily next to TRD-001's
"never unbounded by default." The question for convergence: keep, remove, or standardize?

## Decision

**Keep the opt-out, but make it one uniform, clearly-labelled "lab posture."**

1. Treat `0 = unbounded` as a sanctioned pattern across the spine (including the new
   [ADR-0037](ADR-0037-bound-topic-subscription-table.md) topic cap), so operators learn one rule.
2. Standardize the doc-comment wording on every such knob: *"`0` selects the explicit unbounded opt-out
   (lab/demo workloads only); production deployments MUST set a finite cap."*
3. Default every cap to a finite value; `0` is never the default and must be selected explicitly.
4. Add a single short subsection in `CONTRIBUTING.md` (or `docs/design/substrate.md`) naming the pattern,
   so a new creature author reaches for the same convention instead of inventing another.
5. Do **not** remove the opt-out: the demos and test fixtures rely on it knowingly, and removing it would
   trade a documented, opt-in escape hatch for friction with no safety gain (the default is already
   finite).

## Consequences

- One mental model for unbounded opt-outs across every creature and the kernel.
- Production misuse is harder to do by accident (finite defaults) and easy to spot in review (one phrase
  to grep for).
- The lab/demo ergonomics that rely on unbounded growth keep working.

## Implementation sketch

- **Files:** the three creature builders above + `Router` (ADR-0037); a `CONTRIBUTING.md` /
  `docs/design/substrate.md` subsection. Align the doc-strings to the canonical phrasing.
- **Wire-additivity:** **None** (constructor docs + one new kernel default).
- **Test:** no new behavior test required beyond ADR-0037's; a grep/doc check that all `with_max_*`
  knobs share the canonical phrasing serves as the acceptance gate.

## Related

ADR-0037 (reuses this convention); TRD-001 (resource-safety ledger).

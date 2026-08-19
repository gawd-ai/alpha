# Technical Requirements Documents (TRDs)

A **TRD** states *what must be true* for one subsystem — requirements (MUST), acceptance criteria, and
the tests that prove them — independent of the specific code that satisfies them. Where a TRD requires a
**decision**, that decision is recorded as an [ADR](../adr/README.md) and linked from the TRD.

TRD-001–005 were authored for the **v0.4.3 convergence pass**. v0.4.2 shipped the cross-mesh *rails* for
the v0.5.0 headline (AIs interacting across the meshed Ω). v0.4.3's bar is **convergence, not features**:
make the current surface genuinely *work* and *make sense*, close bug/security/resource holes, tie loose
ends, and remove needless complexity — so that **before v0.5.0 the system is already a stable AI-OS / ASI
fabric**, and v0.5.0 lands as *composition* (swap reference agents for LLM-backed ones), not a rewrite.

**TRD-006 starts the v0.4.4 series.** It is intentionally an additive application/foundation contract
before v0.5.0: the creature ABI, Envelope, and three-job Kernel remain unchanged. It is `Met`: every
acceptance item is Green through the explicitly suite-compositional local, store, surface,
same-process, and real-process proofs recorded in the TRD.

**TRD-007 defines the v0.5.0 product composition.** It is `Accepted`, not yet `Met`: three distinct
live-model/signing agents—a Builder, Reviewer, and Contract Tester—must make one exact four-turn
causal decision chain across two in-process Kernel nodes/Realms over authenticated TCP. Their approved
result is a fresh bounded `affine_i32_v1` data program; trusted host validation/lowering produces
daemon, beast, and critter source, three signed/recovered artifacts, three distinct immutable
`FunctionId`s, and six tester-selected local/cross-Realm Job results. The clean exact-commit run must
retain seven provider calls/receipts and all signed/build/execution proof under a verified evidence
index plus an external operator seal. The frozen commit must first pass the exhaustive local
`tools/local-validation.sh` gate and produce its report plus copied-binary handoff. The unchanged
exact commit must then pass the short hosted sanity gate without exposing provider/operator keys or
raw evidence. The local `tools/v05-live-acceptance.sh` ceremony consumes the handoff, runs the exact
packaged binary's offline `dialogue verify-live` path, encrypts raw evidence, and produces the
disclosure-safe pack containing the validation report, exact binary, signed seal/index, acceptance
manifest, six-field verifier report, README, and hashes. Before tagging, the operator moves those
exact objects directly to immutable supported-lifetime storage, then appends the accepted novelty and
artifact identities to the external signed, append-only registry. The fixture run is regression only.
This is constrained typed synthesis, not arbitrary code, general agency, a generic group protocol,
or three-process deployment evidence, and no wire or creature-ABI shape changes.

## The convergence bar

> By the end of v0.4.3, every load-bearing surface of Alpha is **bounded, attributable, coherent, and
> documented**: no unbounded growth a peer or creature can drive; cross-node integrity specified and
> tested; one verb contract uniform across REPL / MCP / HTTP; every reserved seam classified with the
> v0.5.0 consumer that fills it; and no needless complexity left undocumented. **v0.5.0 introduces no
> wire-format churn.**

## Index

| TRD | Title | Theme | Spawns ADRs | Status |
|---|---|---|---|---|
| [TRD-001](TRD-001-substrate-resource-safety.md) | Substrate resource-safety & DoS bounds | Hardening | 0037, 0042 | Met (v0.4.3) |
| [TRD-002](TRD-002-cross-node-relay-integrity.md) | Cross-node origin & relay integrity | Hardening | 0038, 0039, 0040, 0041 | Met (v0.4.3) |
| [TRD-003](TRD-003-app-surface-coherence.md) | App-surface coherence | Convergence | 0045 | Met (v0.4.3) |
| [TRD-004](TRD-004-reserved-seam-discipline.md) | Reserved-seam & embryo discipline | Anti-churn | 0043 | Met (v0.4.3) |
| [TRD-005](TRD-005-hygiene-and-complexity.md) | Hygiene & complexity reduction | Hygiene | 0044 | Met (v0.4.3) |
| [TRD-006](TRD-006-typed-functions-and-durable-jobs.md) | Typed functions, durable Jobs, and portable home custody | Function foundation | 0046, 0047, 0048 | Met (v0.4.4) |
| [TRD-007](TRD-007-cross-mesh-model-collaboration.md) | Cross-mesh model collaboration to an all-tier typed capability | Product composition | 0049 | Accepted (v0.5.0) |

## How to read a TRD here

- **Requirements (Rn)** are testable MUST/SHOULD statements, each citing the `file:line` it ranges over.
- **Findings register** records the verification status of every candidate finding the TRD rests on:
  *Verified* (confirmed against code), *Needs-verify* (chase before relying on it), or *Down-ranked*
  (a candidate that did not survive scrutiny — kept so the reasoning isn't re-litigated).
- **Acceptance** lists the concrete tests/checks that close the TRD.

## Status lifecycle

`Draft` → `Accepted` (the requirements are agreed) → `Met` (implementation lands and acceptance passes).
The index above is authoritative per document: TRD-001–005 are Met for v0.4.3, TRD-006 is Met for
v0.4.4, and TRD-007 is Accepted for v0.5.0 but is not Met until the exact commit passes exhaustive
local validation, hosted sanity, a fresh retained operator-sealed local live proof, immutable
retention, and the external signed acceptance record. A TRD can be Met before its release heading is
cut;
release/version state is tracked in the workspace manifests and changelog rather than inferred from
this lifecycle.

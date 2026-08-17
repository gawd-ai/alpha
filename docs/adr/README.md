# Architecture Decision Records (ADRs)

An **ADR** records one architectural decision: its context, the decision, the consequences, and — for
this corpus — a concrete **implementation sketch** (files/seams touched, a wire-additivity note, the
test to add) so the decision can be executed without re-discovery.

ADR numbering is a single continuous series across GAWD's design history. The v0.4.3 convergence pass
opens at **ADR-0037** (the prior series runs through the cosmology/cohesion baseline to ~ADR-0036; those
records predate this public tree's `docs/` and live in project history). Each ADR below is paired with
the [TRD](../trd/README.md) whose requirements motivate it.

The v0.4.4 function foundation continues at ADR-0046. Those decisions are **Implemented**, and their
suite-compositional acceptance evidence is indexed by
[TRD-006](../trd/TRD-006-typed-functions-and-durable-jobs.md).

## Index

| ADR | Title | Decision in one line | Drives | Status |
|---|---|---|---|---|
| [ADR-0037](ADR-0037-bound-topic-subscription-table.md) | Bound the topic-subscription table | Cap + dedup `Router::topics`; host-only ⇒ defense-in-depth, not a live DoS | TRD-001 | Implemented |
| [ADR-0038](ADR-0038-origin-stays-hop-by-hop.md) | Origin stays hop-by-hop; agent identity is app-signed | Do **not** add a creature-settable origin (it would be forgeable); spec signed dialogue provenance instead | TRD-002 | Implemented |
| [ADR-0039](ADR-0039-nested-reply-to-rewrite.md) | Nested `reply_to` rewrite for Realm/Omega grain | Recursively rewrite the boxed inner target at the transport boundary | TRD-002 | Implemented |
| [ADR-0040](ADR-0040-replay-guard-reconnect.md) | Replay guard across reconnect | Accept session-scoped guard; document idempotency-via-`corr` as the cross-session contract | TRD-002 | Implemented |
| [ADR-0041](ADR-0041-origin-verdict-posture.md) | Origin-verdict enforcement posture | Router stays non-enforcing (R5); recommend a `policy-origin` subscriber and warn when no origin defense is wired | TRD-002 | Implemented |
| [ADR-0042](ADR-0042-escape-hatch-policy.md) | Escape-hatch policy for `with_max_*(0)` | Keep the unbounded opt-out, but unify naming + a single documented "lab posture" | TRD-001 | Implemented |
| [ADR-0043](ADR-0043-reserved-seam-register.md) | Reserved-seam disposition register | Classify every reserved seam: keep-reserved / realize-now / realize-v0.5.0, each with its consumer | TRD-004 | Accepted |
| [ADR-0044](ADR-0044-omni-control-plane-dry.md) | `omni` shared control-plane composition | Hoist the duplicated alpha/omega control-plane boot into one `omni` recipe | TRD-005 | Implemented |
| [ADR-0045](ADR-0045-demo-registry-coherence.md) | Demo-registry coherence (the `cluster` demo) | Teach `demos.json`/`alpha demo` about manual runbooks so `alpha demo list` is authoritative | TRD-003 | Implemented |
| [ADR-0046](ADR-0046-functions-are-typed-creature-entrypoints.md) | Functions are typed creature entrypoints | Add an optional structured entrypoint contract and dispatch over existing `handle`; no fourth tier/ABI | TRD-006 | Implemented |
| [ADR-0047](ADR-0047-jobs-have-home-and-execution-ledgers.md) | Jobs have home and execution ledgers | Abode home owns intent/control; Realm executor owns durable claim/facts; delivery mode is explicit | TRD-006 | Implemented |
| [ADR-0048](ADR-0048-home-authority-moves-by-fenced-handoff.md) | Home authority moves by fenced handoff | Freeze+fsync source before destination activation; separate root, epoch, and data keys | TRD-006 | Implemented |

## Status lifecycle

`Proposed` → `Accepted` (decision agreed) → `Implemented` (lands in code, with the test from its sketch).
TRD acceptance may compose several such tests; an ADR's `Implemented` status does not imply one test
alone proves an entire TRD.

## ADR shape used here

Context · Decision · Consequences · Implementation sketch (files · wire-additivity · test) · Related.
The **wire-additivity note** is mandatory: Alpha's invariant is *additive wire only (zero-retrofit)*, so
every ADR states explicitly whether it touches the signed/serialized wire and, if so, how it stays
backward-compatible.

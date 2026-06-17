# ADR-0037 — Bound the topic-subscription table

- **Status:** Implemented (v0.4.3)
- **Drives:** [TRD-001](../trd/TRD-001-substrate-resource-safety.md) R1
- **Date:** 2026-06-16

## Context

`Router::topics: RwLock<HashMap<Topic, Vec<CreatureId>>>` (`cosmos/aether/src/router.rs:86`) has no cap
on the number of distinct topics, and `Router::subscribe` (`router.rs:193`) appends to the per-topic
`Vec<CreatureId>` without deduping. The cross-board audit flagged this as a **BLOCKER** unbounded-growth
DoS. Verification down-ranks it: `subscribe` is reachable only through `Kernel::subscribe`
(`cosmos/sanctum/src/lib.rs:609`), called by trusted composition roots (`alpha/src/node.rs:512`,
`omega/src/serve.rs:510`, `cosmos/omni/src/lib.rs:2128`). The `Bus`/`BusHandle` a creature is handed
(`cosmos/aether/src/bus.rs`) exposes only `send` / `id` / `may_attest` / backpressure — **no
`subscribe`**. A hostile creature therefore cannot grow this map. The remaining risk is (a) a buggy host
loop and (b) duplicate subscribers from repeated bind cycles inflating fan-out — i.e. defense-in-depth +
hygiene, not an exploit.

## Decision

Bound the table and dedup subscribers, consistent with the rest of the spine's R9 discipline:

1. Add a `max_topics` cap (mirroring `inbox_capacity` / `journal_cap`) to `Router`, set at construction.
   When the table is at the cap, a `subscribe` to a **new** topic is refused (logged, no-op) — existing
   topics still accept subscribers.
2. Dedup within a topic: `subscribe(topic, id)` is idempotent — a repeat `(topic, id)` does not grow the
   `Vec`.
3. Follow the unified escape-hatch policy ([ADR-0042](ADR-0042-escape-hatch-policy.md)): `0 = unbounded`,
   selected explicitly, documented as the lab/demo posture. Default to a generous finite cap.
4. Record in the doc-comment that `subscribe` is host-only, so this cap is defense-in-depth (prevents a
   composition-root bug from unbounded growth), **not** a creature-facing DoS mitigation.

## Consequences

- A misbehaving host can no longer grow the topic table without bound; duplicate subscriptions can no
  longer inflate fan-out cost.
- No behavior change for correct callers (they subscribe a small fixed set of topics once).
- One more constructor parameter / builder default to thread through `Router::new`.

## Implementation sketch

- **Files:** `cosmos/aether/src/router.rs` — add `max_topics: usize` field + `Router::new` arg (or a
  `with_max_topics` builder to avoid churning every `Router::new` call site; prefer the builder if call
  sites are many), cap check + dedup in `subscribe`. Thread the default from the same place
  `inbox_capacity` is chosen.
- **Wire-additivity:** **None** — this is in-memory kernel state, no serialized/signed wire touched.
- **Test:** `cosmos/aether` unit test — subscribing past `max_topics` distinct topics refuses the
  surplus; a repeated `(topic, id)` leaves the subscriber `Vec` length unchanged.

## Related

ADR-0042 (escape-hatch policy, the `0 = unbounded` convention this reuses); TRD-001 (the resource-safety
ledger).

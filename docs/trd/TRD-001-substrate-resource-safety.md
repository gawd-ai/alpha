# TRD-001 — Substrate resource-safety & DoS bounds

- **Status:** Met (v0.4.3)
- **Theme:** Hardening
- **Spawns:** [ADR-0037](../adr/ADR-0037-bound-topic-subscription-table.md) (topic-table bound),
  [ADR-0042](../adr/ADR-0042-escape-hatch-policy.md) (escape-hatch policy)
- **Invariant in play:** R9 — *never OOM*; the kernel bounds the table, not the traffic.

## Scope

Every in-memory surface in the spine that can grow at runtime MUST be bounded, or be an *explicitly
selected, documented* unbounded opt-out. "Bounded" means a fixed cap with a defined drop/refuse/evict
behavior and a test. This TRD enumerates each surface, states who can drive its growth (a hostile
*creature*, a hostile *peer*, or only the *trusted host*), and locks the wins already in place so a
later change can't silently regress them.

## Requirements

- **R1 — Topic-subscription table is bounded.** `Router::topics` (`cosmos/aether/src/router.rs:86`)
  MUST gain a cap on the number of distinct topics and MUST dedup subscribers within a topic. See
  ADR-0037. *Driver:* trusted host only — `Router::subscribe` (`router.rs:193`) is reachable solely via
  `Kernel::subscribe` (`cosmos/sanctum/src/lib.rs:609`) from composition roots (`alpha/src/node.rs:512`,
  `omega/src/serve.rs:510`, `cosmos/omni/src/lib.rs:2128`); the `Bus`/`BusHandle` a creature holds
  (`cosmos/aether/src/bus.rs`) exposes only `send`/`id`/`may_attest`/backpressure — **no `subscribe`**.
  Therefore this is **defense-in-depth + dedup hygiene, not a live exploit** (the audit's "BLOCKER" was
  overstated). The cap follows the escape-hatch policy of R6.
- **R2 — Advisory payload caps are either enforced or documented as advisory.** `MAX_SENSE_EVENT_BYTES`
  (`cosmos/aether/src/lib.rs:53`) is documented as a cap but is not enforced on the bus. v0.4.3 MUST
  either (a) enforce a size check at the observer/policy ingestion boundary, or (b) re-document it
  unambiguously as an application-side hint with the rationale that observers are trusted and must
  size-check their own inputs. The decision and its placement MUST be recorded.
- **R3 — No new unbounded surface ships unbounded by default.** Any new runtime-growing collection
  added in v0.4.3 (or by a creature's reference impl) MUST have a default cap. The `0 = unbounded`
  opt-out is permitted only under the unified policy of R6.
- **R4 — The "already met" ledger is locked by tests.** The bounds already in place (R5 below) MUST each
  retain a regression test so convergence work cannot quietly remove them.
- **R5 — Already-met bounds (verified; lock, don't reopen):**
  - History journal — bounded ring, drop-oldest at `DEFAULT_JOURNAL_CAP = 65_536`
    (`cosmos/aether/src/router.rs:18,24,87`).
  - Per-creature inbox — bounded `SyncSender`, backpressure (never OOM); `inbox_capacity.max(1)`
    (`router.rs:106-107,122`).
  - Transport frame size — capped before parse (≈128 MB) in `transport-tcp`.
  - Engine metering — beast (fuel/mem/wall via wasmtime + `ExtendBudget`) and critter
    (fuel/wall + persistent-KV caps `MAX_PERSIST_ENTRIES=256` / `MAX_PERSIST_KEY_BYTES=256`,
    `cosmos/anima/src/script.rs`).
  - Registry/bestiary stores — entry cap (default 1024 refuse-new) + artifact/op byte caps + injected
    `EvictionPolicy` (`cosmos/creatures/registry-mem/src/lib.rs`, `cosmos/bestiary/src/store.rs`).
  - No cross-node kernel control — `Address::Kernel` delivery refused at the wire boundary.
  - Signing-payload tripwire — `signing_payload_hash_is_locked_to_a_known_fixture` guards field order.
- **R6 — Unbounded opt-outs are uniform and documented.** Every `with_max_*(0) = unbounded` knob MUST
  follow one policy (naming, doc phrasing, and a single "lab/demo posture" framing). See ADR-0042.

## Findings register

| Finding | Status | Evidence |
|---|---|---|
| `Router::topics` has no cap and no subscriber dedup | **Verified** | `router.rs:86`; `subscribe` `router.rs:193` |
| `subscribe` is host-only; not creature-reachable | **Verified** | `BusHandle` API `bus.rs`; callers all composition roots |
| "Unbounded subscription DoS = BLOCKER" | **Down-ranked** → defense-in-depth | hostile creature has no `subscribe` path |
| `MAX_SENSE_EVENT_BYTES` advisory, not enforced on bus | **Verified** | `lib.rs:53` doc vs no route-side check |
| `with_max_*(0)` unbounded opt-outs (registry-mem, embodiment-advertiser, realm-gateway) | **Verified** | see TRD/ADR-0042 |
| Journal / inbox / frame / engine / store bounds in place | **Verified** | citations in R5 |

## Acceptance

- A unit test proves `Router::topics` refuses growth past the cap and dedups a repeat `subscribe`.
- The `MAX_SENSE_EVENT_BYTES` decision (enforce vs advisory) is implemented and has a test or a doc
  change with rationale.
- Every R5 bound has a live regression test (audit confirms presence; add any missing).
- A grep-level check (or doc table) shows every `with_max_*(0)` knob shares the ADR-0042 phrasing.

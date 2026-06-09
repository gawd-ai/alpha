# Alpha — Topics & SEER reference

The substrate's **publish/subscribe and consult contract**: what a creature may listen to and what
it may emit. This is the surface a creature-authoring agent builds against. Everything here is a
*wire* commitment — a creature that binds these shapes today sees the same shapes as richer bodies
land.

Source of truth in code: [`aether::Topic`](../cosmos/aether/src/address.rs) (broadcast topics),
[`seer`](../cosmos/seer/src/lib.rs) (consult topics), [`aether::Role`](../cosmos/aether/src/address.rs)
(capability sockets). Browse the rendered API with `cargo doc -p aether --open`.

---

## Orientation — three ways to address (don't confuse them)

Alpha has one envelope and three kinds of destination ([`aether::Address`](../cosmos/aether/src/address.rs)):

| Kind | Address form | What it means | This doc |
|---|---|---|---|
| **Identity** | `Creature(id)` / `Node(node,id)` / `Kernel` | "talk to *this* creature/node" | — |
| **Topic** (pub/sub) | `Topic(name)` | "fan out to every subscriber of this channel" | **§1 below** |
| **Capability** (IoC) | `Role(name)` / `Intent{…}` | "route to *whoever* fills this socket" | **§3 + CONCEPTS** |

A **topic** is a fan-out channel you subscribe to. A **role** is an inversion-of-control socket you
*bind a creature into* (the substrate ships the socket; you inject the model). The **SEER topics**
(§2) are a layer *on top of* the envelope — a typed conversation protocol that rides identity or
topic delivery. Keep the three straight and the rest follows.

---

## 1. Broadcast bus topics

Fan-out channels published by the kernel. Subscribe with `Kernel::subscribe(Topic::new(name), endpoint)`.
The substrate publishes; what the signal *means for action* is the subscribing creature's model.

| Topic | Const | Meaning | Publisher | Typical subscribers | Payload |
|---|---|---|---|---|---|
| `proprioception` | `Topic::PROPRIOCEPTION` | Liveness / sense stream — Loops **1** (Sense) & **4** (Defend) | kernel, on creature **load / unload / leak**, plus the `BudgetSignalEvent` | [`cosmos/creatures/immune-response`](../cosmos/creatures/immune-response) (senses faults), [`cosmos/creatures/prototypes/monitor`](../cosmos/creatures/prototypes/monitor) (the nervous-system observer) | kernel sense events; `BudgetSignalEvent` |
| `fitness` | `Topic::FITNESS` | Outcome stream — Loop **2** (Select). Kernel emits `Fitness{module, ok}` after **every** handle (`module` is the creature id field) | kernel (only when a subscriber exists — no-listener short-circuit) | **passive observers only** — [`cosmos/creatures/prototypes/monitor`](../cosmos/creatures/prototypes/monitor); and a passive relay → [`cosmos/creatures/fitness-selector`](../cosmos/creatures/fitness-selector) (see note) | `{ module, ok }`, schema `"fitness"` |

Sense-topic consumers bound JSON parsing with `aether::MAX_SENSE_EVENT_BYTES` (1 MiB) before
decoding `proprioception`, `fitness`, or `budget_signal` payloads.
The reference `fitness-selector` also bounds selector control payloads, its distinct watch map, and
its observed-module tally by default; operators can explicitly opt out of retained-state caps with
`with_max_watched_modules(0)` / `with_max_obs(0)` for unbounded replay or lab workloads.
The reference `immune-response` bounds its control payloads, watch map, retained watch fields,
quarantine reasons, and inbound notice peer lists before writing registry/federation markers.
Registry fillings and the Omega federator also reject oversized quarantine keys/reasons/peer lists
at the shared `QuarantineNotice` wire shape, so malformed defense markers are not retained just
because they bypassed the reference immune-response creature.
The reference `policy-budget` bounds its tracked-module grace/decision state by default; operators can
explicitly opt out with `with_max_tracked_modules(0)`.

> **The `fitness` anti-feedback rule.** The kernel publishes a fitness event after *every* handle —
> *including the selector's own handles*. A drain-thread creature that subscribed directly to
> `fitness` would feed on its own events (a 1-in-1-out livelock). So the `fitness-selector` is fed by
> **direct addressing**, never a topic subscription; an operator who wants automatic feeding wires a
> *passive relay* (a no-drain-thread endpoint that subscribes to `fitness` and re-addresses each
> *watched* creature's event to the selector). See the `fitness-selector` crate docs for the full
> rationale. The selector also drops any fitness event for its own `CreatureId` as defense-in-depth.

---

## 2. SEER consult topics

SEER is the substrate-wide **consult-and-reconcile** protocol: "ask N somethings, reconcile
by my own model." Every SEER message — across every topic — is a single
[`SeerEnvelope`](../cosmos/seer/src/lib.rs) riding an `aether::Envelope` whose `header.schema` is the one
constant string **`"seer"`** (`seer::SCHEMA`). There is **no new wire format per topic**: the
topic and the conversation move live in the payload.

### The conversation moves (`SeerKind`)

| Move | Direction | Fields | Use |
|---|---|---|---|
| `Query` | initiator → | `query_id, body` | ask; `query_id` disambiguates multiple outstanding queries per `corr` |
| `Answer` | → initiator | `query_id, body` | reply, matched to its `Query` by `(corr, query_id)` |
| `Steer` | inbound | `kind, payload` | mid-flight intervention; `kind` ∈ `"abort"`/`"amend"`/`"info"` **by convention** |
| `Progress` | outbound | `stage, fraction?, note?` | observable trajectory (optional fields elide from the wire) |
| `Thought` | outbound | `channel, content` | observable reasoning (`channel` = `"internal"`/`"external"`) |

### The topics (`SeerTopic`)

All seven are reserved at the substrate level so a consumer can never widen the wire later. Status is
**live** (a shipped consumer) or **reserved/draft** (the shape compiles; bodies may still change
before a consumer pins them).

| Topic | Status | Conversation | Initiator → Responder | Typed body (`aether::seer::topics::*`) |
|---|---|---|---|---|
| `authoring` | **live** | author a creature from intent | orchestrator → [`agent-curious`](../cosmos/creatures/agent-curious) / [`agent-templated`](../cosmos/creatures/agent-templated) | `authoring::{QueryBody, AnswerBody}` |
| `placement` | **live** | "who can run this work?" | [`distributor-requirements`](../cosmos/creatures/distributor-requirements) → [`embodiment-advertiser`](../cosmos/creatures/embodiment-advertiser) | `placement::{QueryBody, AnswerBody, Predicate, Embodiment, EmbodimentOffer}` |
| `consensus` | **live** | weighted vote / VRF / quorum | [`omega-federator`](../cosmos/creatures/omega-federator) (signed reputation deltas) | `consensus::{QueryBody, AnswerBody}` (federator carries its own signed body) |
| `policy` | reserved/draft | richer admission consult | — (live path: mechanically-applied policy creatures) | `policy::{QueryBody, AnswerBody}` |
| `budget` | reserved/draft | grace request | — (live path: `proprioception` + `KernelControl::ExtendBudget`) | `budget::{QueryBody, AnswerBody}` |
| `fitness` | reserved/draft | fitness-score consult across raters | — (live path: injected `FitnessScorer` + registry promotion) | `fitness::{QueryBody, AnswerBody}` |
| `curation` | reserved/draft | durable Bestiary curation consult | — (live path: in-process `bestiary::AICurator`) | `curation::{QueryBody, AnswerBody}` |

> Note: a SEER **`fitness` consult topic** (ask N raters to score) is distinct from the **`fitness`
> broadcast topic** in §1 (the kernel's per-handle outcome stream). Same word, two layers.

### Wire guarantees you can rely on

- **One schema.** The router sees no new contract per topic — every SEER envelope is `schema = "seer"`.
- **Reduction theorem.** A creature that answers *immediately* (one terminal `Answer`, no `Query`
  precursor — `query_id = 0` by convention) is byte-equivalent to a plain single-shot responder.
  Richer conversations are *admitted*, never *required*.
- **Topic isolation by discrimination.** Delivery is by address; the consumer checks
  `seer.topic` and drops envelopes whose topic doesn't match its binding. No router-level topic
  enforcement, by design.
- **Bounded hostile-input parsing.** Live consumers use `SeerEnvelope::parse_bounded`, whose default
  cap is `seer::MAX_SEER_ENVELOPE_BYTES` (1 MiB), before decoding the opaque JSON body.
- **Bounded parked state is a consumer floor.** Reference consumers that park SEER exchanges, such
  as `agent-curious`, cap their pending tables by default and refuse a duplicate live `corr` rather
  than overwrite the parked exchange; `0` is an explicit lab/demo opt-out for the count cap.
- **`Steer` is generic** and **time is injected.** Whether a creature honors a steer is its model;
  `deadline_ms` (where a body has it) is **advisory** — the substrate ships no clock and enforces no
  timeout.

### Minimal consumer shape

```rust
use aether::seer::{SeerEnvelope, SeerKind, SeerTopic, SCHEMA};

fn on_envelope(env: &aether::Envelope) {
    if env.header.schema != SCHEMA { return; }                 // not a SEER message
    let seer = match SeerEnvelope::parse_bounded(&env.payload) { Ok(s) => s, Err(_) => return };
    if seer.topic != SeerTopic::Placement { return; }          // topic isolation: not mine
    if let SeerKind::Query { query_id, body } = seer.kind {
        // decode `body` against placement::QueryBody, reconcile by *your* model, then:
        // reply with SeerEnvelope::answer(SeerTopic::Placement, seer.corr, query_id, &answer_body)
    }
}
```

---

## 3. Capability sockets (roles) — the companion surface

Topics are *pub/sub*; **roles** are *inversion-of-control sockets* a creature binds into to fill a
substrate concern. They are the other half of "what can I plug into." The full set lives on
[`aether::Role`](../cosmos/aether/src/address.rs) (each with doc + the reference example that fills it):
`distributor`, `transport`, `policy`, `registry`, `authoring`, `build`, `realm-gateway`,
`omega-gateway`, `abode-migrator`, `fitness-selector`, `immune-response`, `abode-reconciler`.

For the role → loop → reference-creature mapping, see [CONCEPTS.md](CONCEPTS.md) (the five governing
loops table) and the [`cosmos/creatures/prototypes/` legend](../cosmos/creatures/prototypes/README.md).

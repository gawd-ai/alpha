# Alpha — Roadmap Toward GAWD

This is direction, not schedule: where Alpha's substrate goes next on the way to GAWD, and the
invariants that constrain how it gets there. For what ships today, see
[`CONCEPTS.md`](CONCEPTS.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), and the design notes under
[`design/`](design/).

## The baseline

An AI authors a creature and the substrate runs its whole life: it builds and signs the creature
across three tiers (native `daemon`, WASM `beast`, Rhai `critter`); places it on a node whose
embodiment satisfies the creature's declared requirements; quarantines it on a sensed fault and
promotes a fit one; migrates its **Abode** — identity and state — to another node as a single active
fork, reconciling divergent copies on an injected lattice; and federates, sanctums forming a **Realm**
and Realms meeting at **Omega** to exchange signed reputation by pull anti-entropy. The five
anti-entropy loops — sense→act, author→select→promote, distribute, defend, acculturate — are live end
to end.

The operator surface is one binary, `alpha`: a node daemon, an MCP control-hub, and an HTTP/WS plane,
each a thin host over the same `Role::CONTROL` bus contract. A node joins a gossip mesh from a seed,
and an AI drives any node it is allowed to. Its dual, the **Ω server** `omega serve`, boots a dedicated
federation/gateway Sanctum (`omega-federator` on `Role::OMEGA_GATEWAY`) — both poles compose the same
kernel and control core; they differ in posture, not mechanism.

The **v0.4.3 convergence pass** hardened that baseline so it is a stable floor for v0.5.0, not a
moving target: every load-bearing surface is now bounded, attributable, coherent, and documented —
cross-node origin is hop-by-hop with **app-signed dialogue provenance** for end-to-end agent identity,
the topic table and every retained collection are finite-by-default, the control vocabulary is uniform
across REPL/MCP/HTTP, and both poles share one node-boot recipe. The design corpus is `docs/trd/`
(five TRDs) + `docs/adr/` (ADRs 0037–0045). Crucially, **v0.5.0 introduces no wire-format churn** — it
lands as composition on top of this floor.

## Where it goes next

- **Transport** — a UDP transport beside the authenticated TCP one, for lossy and intermittent links,
  with richer partition tolerance.
- **Interaction across the mesh (the v0.5.0 headline)** — AIs genuinely interacting across Realms and
  Sanctums: two (or more) model-backed agents collaborating or conversing. v0.4.2 laid every rail —
  application traffic crosses a Realm boundary (the `omega-federator` forwards arbitrary envelopes, not
  just registry state), agents are *placed* across Realms (below), and a reserved SEER `Dialogue` topic
  plus the reference `dialogue-initiator` / `dialogue-responder` pair carry a multi-turn agent-to-agent
  conversation (`alpha demo dialogue` runs two agents talking across a Realm boundary). v0.5.0 swaps the
  reference agents for LLM-backed ones — the same wire, no refactor.
- **Placement** — cross-Realm placement now lands: a distributor fans placement Queries to peer-Realm
  advertisers through the Omega gateway and routes a chosen offer via `Address::Omega` (offers carry an
  optional `realm`, queries an optional `target_realm`; both elide from the wire when absent). What
  remains is *dynamic* discovery — the peer-Realm advertisers are still configured, like the scheduler's
  targets — and richer cross-Realm matching.
- **Federation** — Omega discovery and production realm/omega gateway creatures. (The Ω pole now has a
  body — `omega serve` runs a federation/gateway Sanctum — that **reconciles itself**: the
  `federation-scheduler` companion pokes the federator's anti-entropy on an injected cadence
  (`omega serve --pull-interval`), so cross-Realm pulls no longer wait for an operator. A durable,
  federated Bestiary beyond the in-memory seed ships as `bestiary-daemon`. What remains is peer
  discovery — the scheduler's targets are still configured, not discovered — and quorum: a pull is
  still one peer at a time, not a quorum'd read.)
- **Trust** — more of the proof-of-trust surface made live: weighted and consensus picks, and
  additional verifiable-randomness schemes. (Reference standing SEER consumers for the policy, budget,
  fitness, and curation topics now ship under `creatures/prototypes/responders/`; consensus already had
  the federator.)
- **Budgets** — extend live budget enforcement to the trusted-by-admission **native** tier (CPU,
  memory, and wall-clock are OS-level there, so every dimension reports `Unenforceable` today) and lift
  the **critter** tier's memory cap live (its structural caps are fixed at load). (The **beast** tier
  already lifts fuel, memory, and wall-clock live via `ExtendBudget` and traps a `wall_ms` *cap* via
  wasmtime epoch interruption; the **critter** tier enforces and lifts fuel + wall-clock, and now also
  carries a bounded **persistent memory** across `handle()` calls. The registry's store limiter gained
  an injected **eviction policy** — a bounded catalog that keeps accepting fresh artifacts under a fixed
  cap instead of refusing at it.)
- **Scenarios** — declarative runbooks the control plane replays as verbs over the bus, so a demo or
  an operator can drive a live remote node instead of building its own topology in code.

## Invariants

These hold across every release.

- **Fabric, not model.** The substrate ships sockets and mechanism; strategies — placement, policy,
  scoring, merge, consensus — are injected creatures. If a planned change would force a new substrate
  primitive, that is the signal it was mis-placed: the mechanism belongs in the fabric, the choice in
  a creature.
- **No second-class primitive.** Lifecycle, authoring, transport, and containment are co-designed.
  The signed manifest carries, up front, every field each depends on — version and ABI tag,
  provenance, declared capabilities, execution tier, entrypoints, content address, embodiment
  requirements — so none has to reopen it. A change that needs a new manifest field is a design smell;
  fold it in rather than retrofit.
- **Containment is opt-in.** Strong sandboxing is available and effective — sandboxable beast and
  critter tiers, declared capabilities, signing, budgets — but freedom is the default and defense is a
  chosen responsibility, not a cage imposed on every creature. Defense that proves out is promoted
  into shared instinct by the collective, not hard-wired by the kernel.
- **Verifiable, not opaque.** Where a choice must be random — a fair pick, a tie-break, a nonce — it
  uses a committed, signed value over the `commitment` slot, never an opaque RNG.
- **Take no side on order.** The substrate holds order against disorder and doses disorder on purpose
  (variation, diversity, verifiable randomness), bounded only by a thin life-safety floor. No
  wall-clock assumption and no one-node-one-vote assumption is baked in: time is a change of state,
  and consensus may be weighted.

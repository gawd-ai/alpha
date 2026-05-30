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
and an AI drives any node it is allowed to.

## Where it goes next

- **Transport** — a UDP transport beside the authenticated TCP one, for lossy and intermittent links,
  with richer partition tolerance.
- **Placement** — cross-Realm placement: a creature's requirements matched against embodiment beyond
  the local Realm, not only within it.
- **Federation** — Omega discovery and production realm/omega gateway creatures; a durable registry
  beyond the in-memory Bestiary.
- **Trust** — more of the proof-of-trust surface made live: weighted and consensus picks, additional
  verifiable-randomness schemes, and standing SEER consumers for the policy, budget, fitness, and
  consensus topics.
- **Budgets** — the limit-as-gradient enforced on memory and wall-clock, not only fuel; a live store
  limiter for the native tier's deployment seam.
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

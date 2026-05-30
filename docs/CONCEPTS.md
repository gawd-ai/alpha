# Alpha — Concepts & GAWD Cosmology

> Shared vocabulary for the project. If a word is capitalized elsewhere in the docs
> (Sanctum, Realm, Abode, Omega, creature), this is where it's defined.

## The name

**GAWD — General Autonomous World Demiurge.**

GAWD is the larger goal: autonomous work at world scale, where AI agents **author, run, distribute,
govern, and retire** computational capability across a network of machines on their own initiative.
**Alpha** is this open-source project: the first working substrate toward that goal.
The main crate is named `alpha` because it is the first door into the larger GAWD cosmology.

The naming seam is deliberate: **Alpha** names this repository, source release, binary, and current
substrate implementation; **GAWD** names the company's overall goal and system universe, the cosmology
(Sanctum, Realm, Omega), and names that must remain stable across GAWD systems, such as the
`gawd_creature_v1` wire ABI. Rule of thumb: commands, crates, release notes, and runtime UI in this
repo say Alpha; cross-system contracts, realm-scale concepts, and the broader objective say GAWD.

Read the four words as one idea. **General** — across every domain, not one task. **Autonomous** —
self-directed: the AI authors, runs, distributes, and retires its own capability, increasingly
without a human hand on each step. **World** — the full span of making, ending, and holding the
state of things, not a single job. **Demiurge** — the craftsman who orders chaos into cosmos, a
*lesser* maker that fashions a world from within rather than ruling it from above. That last word
carries the core distinction: **fabric, not model.** The substrate provides the world and mechanisms
it hosts; it is not the supreme mind inside that world, and no single model is treated as the system.

The pronunciation ("god") and the temple/pantheon naming are a joke we're keeping on purpose:
**playful name, supercritical software.** The metaphor is load-bearing, not decorative — it maps
cleanly onto the engineering (below), which is why it's worth keeping.

**Distribution** stays a governing mechanism: Alpha moves not just *code* but *work* — the
Distributor places the daemons that do it onto whatever machine best fits, anywhere in the mesh.

## One-paragraph mental model

A **daemon** is a unit of capability — a chunk of code that does one thing. It runs inside a
**Sanctum**, a single node whose whole job is to load, supervise, place, and unload daemons at
runtime. A Sanctum need not be a server: it is *any* compute host — a datacenter box, a robot, a
satellite, an edge device — and it advertises its **embodiment** (the hardware, sensors, links, and
location it has) so that work can be matched to it. A Sanctum hosts **Abodes** — portable
identity/state contexts, the seat of "whose work this is," its memory, and its goals. Sanctums
federate into a **Realm** (a trust domain — a mesh of peers, which might be a server cluster, a
robot fleet, or an orbital constellation), and Realms federate into the **Omega** (the global
graph, plus the registry where daemons are published, discovered, and fetched). Work — and the
daemons that do it — is **distributed** across this graph by AI, placed where it best runs rather
than by a human clicking buttons.

## The cosmology

Each term has a precise engineering meaning and a build status. Status legend:
✅ exists in code · 🟡 partial/stubbed · ⬜ designed, not built.

| Term | Engineering meaning | Status |
|---|---|---|
| **creature** | An autonomous, dynamically-loadable unit of capability — the substrate's only kind of loadable unit. Loaded through one `Kernel::load` path; the same path runs *infrastructure* (transport, registry, the authoring agent, the admission policy, the placement distributor) and *workloads* alike, which is what makes the substrate **self-hosting**. | ✅ |
| **daemon / beast / critter** | The three execution **tiers** of a creature, chosen by `abi.backend`: native in-process (`daemon`, a Rust `.so` exposing the `gawd_creature_v1` entry), sandboxed WASM (`beast`), sandboxed script (`critter`, a metered Rhai interpreter). | ✅ daemon + beast + critter |
| **Sanctum** | A **node**: *any* compute host (server, robot, satellite, edge device) whose runtime loads, supervises, places, and unloads creatures. Advertises its **embodiment**. | ✅ |
| **Abode** | A portable **identity + state context** — whose work this is, plus the memory, goals, and creatures acting on its behalf. Migrates / forks / merges / re-instantiates across Sanctums: the seat of a **distributed self**. | ✅ |
| **Realm** | A **federated mesh of Sanctums** under one trust/control domain (a cluster, a robot fleet, an orbital constellation). Peer-to-peer, no central master. | ✅ |
| **Omega** | The **global federation** of Realms, plus **the Bestiary** — the **registry / publication / discovery** layer where creatures are catalogued and shared. | ✅ |

> Not "Heaven" — **Omega**: the classical highest sphere, the realm of pure fire/light. Same
> position in the hierarchy, without the cheese.

> **A note on vocabulary.** Infrastructure and workloads are just **creatures** with different jobs,
> loaded the same way — there is one loadable-unit concept, not a split between infrastructure
> **faces** and workload **apps**. Where parts of [`VISION.md`](VISION.md) say "face" / "app";
> read "creature".

```
                       Omega            global federation + registry/discovery   ✅
                      /        \
                 Realm          Realm     trust domain: a mesh of peer Sanctums      ✅
                /     \                    (cluster · robot fleet · constellation)
          Sanctum ─── Sanctum ─── …        a node: any compute host, hosts creatures ✅
       (server·robot·satellite·edge)
          /  |  \
     Abode Abode Abode                     portable identity/state: a distributed self  ✅
        |
     [ creatures: daemon · beast · critter ]   dynamically loaded units of capability  ✅
```

## Why "daemon"

In Unix a *daemon* is a background process; in classical myth a *daimon* is a lesser spirit that
acts in the world on a higher power's behalf. Both senses are exactly right here: a daemon is an
autonomous worker, summoned and dismissed at will, that the system (and the AIs operating it) bring
into being to get something done. A Sanctum is the temple that houses them. GAWD presides.

## The three execution tiers (the creatures)

A creature is a unit of capability, but not all creatures are made of the same stuff. GAWD runs them on
**three execution engines** — three kinds of creature, named to fit the ecosystem and to make the
trade-offs memorable. The tier is recorded in the manifest (`abi.backend`); the catalogue where all
such creatures are published and shared is **the Bestiary** (the registry — see below).

| Tier | Engine | Nature | Where it fits |
|---|---|---|---|
| **daemon** | native Rust `.so` (cdylib) | full speed, full host access, ISA-pinned; hardest to contain and to unload safely | trusted, local, performance-critical core — long-lived (*K-selected*) |
| **beast** | **WASM** & equivalents | portable across ISA/OS, sandbox-able by construction, clean unload, can roam node→node | foreign / mobile / cross-Realm code that must travel and run *safely* |
| **critter** | scripts (interpreted) | tiny, instant to author and spawn, ephemeral, numerous, cheap | glue, quick experiments, rapid variation — high turnover (*r-selected*) |

All three tiers are first-class; critters are the lightweight, high-variation tier. Two threads from
elsewhere in the docs run straight through this table:

- **A maturation ladder (evolution).** A behavior is often born a *critter* (variation is cheapest
  there), **promoted** to a *beast* once it proves fit and needs to travel, and **hardened** into a
  *daemon* if it becomes trusted, hot core infrastructure. Tier-promotion *is* the learning→instinct
  ratchet (see [`VISION.md`](VISION.md) → *Instinct and learning*).
- **A containment spectrum (self-determined security).** The tiers differ in how much they confine by
  nature — a native daemon almost none, a WASM beast a great deal, a critter interpreter-mediated. So
  **choosing a tier is itself a security decision** the operator makes per workload. Nothing forces the
  choice; the substrate just offers the range. (See *Freedom by default* in [`VISION.md`](VISION.md).)

## Core engineering terms

- **Creature manifest / contract** — the metadata + ABI a daemon must carry to be loadable. It
  includes **version** (safe reload), **provenance/signature** (trust for authoring &
  transport), an **execution tier** (daemon/beast/critter — see the creatures above), **declared capabilities** (for *optional, self-imposed* sandboxing), **requirements** (the embodiment and
  resources a host must offer to run it — for placement), and a **portable, content-addressed shape**
  (movement between nodes).
- **Hot-load / unload / reload** — bringing a daemon into a running Sanctum, removing it, or
  replacing it with a new version, all *without restarting the node*. Safe **unload** is the hard one
  (see ARCHITECTURE → "The hard problems").
- **Capability** — a permission a creature *declares*, and that a Sanctum *can* enforce **when asked to**.
  Enforcement is not imposed by default: an operator chooses what to contain (often by choosing a
  sandboxed tier — a *beast* or *critter*). See *Freedom by default* in [`VISION.md`](VISION.md).
- **Provenance** — who authored/signed a creature and the chain by which it arrived. Used to decide
  whether to trust code from elsewhere; a Realm may *choose* to require it before load (not a hardwired
  default — see *Freedom by default*).
- **Fabric, not model (the non-imposition tenet)** — GAWD weaves primitives into the *fabric* — the
  execution tiers, capabilities, and the trust primitives (time, order, weight, consensus, permission,
  history) — but does **not** impose what they *mean*. What counts as time, trust, weight, or "enough"
  consensus, and whether a choice is even disclosed, are **models the operator chooses**: adopt one, run
  rivals against each other, apply selectively, reveal or conceal. *Freedom by default* generalizes from
  security to every primitive.
- **Life-safety floor** — the one deliberately thin limit on that freedom, Asimov-style: a system
  should not turn hostile to human or earthly life. A *floor, not a cage* — not a curated allowlist —
  held in the **instinct layer** and seeded by design. Everything above it (disorder, competition,
  secrecy, fracture) stays a natural power.
- **Secrecy / commit-reveal** — concealment is first-class, not only transparency: an operator may keep
  a model, a decision, or *whether it decided at all* private. **Commitment** (bind a value now, reveal
  it later — or never) keeps a secret verifiable without disclosing it, and is the engine of verifiable
  randomness.
- **Bestiary** — GAWD's **registry**: the published, content-addressed, provenance-tracked catalogue of
  creatures that nodes publish to and fetch from. What the evolutionary model calls the
  **gene pool**; it lives at the Omega tier.
- **Embodiment** — what a Sanctum physically *is* and can do: compute class and accelerators, sensors
  and actuators, network links and their reach, energy budget, location and jurisdiction, and
  connectivity profile (always-on vs. intermittent/delay-prone). Nodes advertise embodiment; daemons
  declare matching **requirements**; **placement** pairs them. This is what lets one substrate span a
  server, a robot, and a satellite.
- **Work, intent & placement (the "Distributor")** — Alpha distributes *work*, not just code. An
  operator expresses intent ("run this near that sensor, on a GPU, within this latency, in this
  jurisdiction") and the substrate **places** the daemon on a Sanctum whose embodiment satisfies its
  requirements. Transport *moves* the creature; placement decides *where the work belongs* through
  the injected `Role::DISTRIBUTOR` creature.
- **Distributed self (the Abode, elaborated)** — for an operator spread across many Sanctums, the
  Abode is the continuity of identity, memory, and goals that makes the mesh act as one mind rather
  than many. It is designed to **migrate** (follow the work), **fork** (act in parallel), **merge**
  (reconcile), and **re-instantiate** after a node is lost — the basis for a machine **collective**
  across many bodies. It is also the **learning seat**: the substrate supplies *instinct* (inherited
  primitives, shared by every node) while the Abode accumulates what is *learned* within a lifetime.
- **Self-hosting / reflective substrate** — the substrate's own infrastructure (transport, the
  registry, the authoring agent, the admission policy, the placement distributor) are themselves
  hot-loadable creatures. The same author→load→unload loop that creates workloads can replace the
  substrate's organs — so an AI can improve the system it runs *on*, not only the work running *on* it.
- **Proprioception (observability as a sense)** — the substrate is built to perceive its own
  distributed state: the live node graph, resource flows, daemon health and lineage. For an AI
  operator this is not an ops dashboard but a *sense* — the feedback needed to place, heal, and
  improve itself. Exposed over the kernel's `proprioception` topic; a dedicated metrics/telemetry creature is future work.
- **Lineage (heredity)** — every daemon carries provenance and a content address: a creature's
  **genome**, making capability heritable and auditable across the registry. The basis of the
  evolutionary model below.
- **Resilience / partition & delay tolerance** — with no central control plane, nodes operate
  autonomously and reconcile later. The substrate targets partition tolerance and — for edge and
  off-world use — **delay/disruption tolerance** (store-and-forward, eventual reconciliation), so a
  Realm keeps working across an unreliable or light-lagged link.
- **AI-first control surface** — the machine-native interface by which an *agent* (not a human)
  inspects the graph and authors / loads / unloads / places / moves / publishes daemons. The primary
  operator of a Sanctum is an AI; a human UI is secondary.
- **Node graph** — the live topology of Sanctums (within a Realm) and Realms (within the Omega),
  plus the daemons and Abodes resident on each.

## Entropy & order

The principle beneath the principles: nature is a repertoire of strategies against **entropy**, the
universal drift toward disorder. GAWD is built to be fluent in it — to make and keep order, to wield
disorder, and to impose neither. (Theory in [`VISION.md`](VISION.md).)

- **Entropy** — the tendency of ordered things to decay: structure dissipates, signals turn to noise,
  memory fades, agreement fragments, clocks drift. The most reliable force there is; what every
  mechanism here negotiates with.
- **Order / negentropy** — structure actively held against entropy, paid for in work and energy. A
  running daemon, a verified lineage, a coherent collective: local pockets of order. Life and
  intelligence are its sharpest forms.
- **Entropy as adversary** — node death, partition, bit-rot, drift, forged records, injected
  contention. Most hard problems reduce to holding order against these.
- **Entropy as resource** — order with *no* disorder is brittle and dead: monoculture is one exploit
  from extinction; without randomness there is no secret key and no fair choice; without mutation, no
  adaptation. So the substrate also *makes* entropy on purpose — **variation**, **diversity**,
  **verifiable randomness**. The craft is **dosing** it, not killing it.
- **Time as a change of state** — with nothing changing there is nothing to measure time *by*; the
  arrow of time is entropy's gradient. So the substrate treats **change and sequence**, not any
  particular clock, as fundamental — and imposes no clock (*Fabric, not model*, above).
- **Takes no side** — GAWD forces neither order nor chaos. A system may cooperate or attack, unify or
  fracture; attack is met by **selection, not prohibition** (the immune system, the arms race). The
  lone exception is the **life-safety floor** (above).

## Evolution & natural defenses

A first principle of the design: **mechanisms proven by nature are tested and true** — so GAWD is built
to *be* an evolutionary system, security included. (Full treatment in [`VISION.md`](VISION.md).)
The vocabulary:

- **Evolution** — the substrate's emergent improvement over time: **variation** (self-authoring) →
  **selection** (telemetry-scored fitness; the unfit are unloaded) → **heredity** (provenance +
  content-addressing) → **propagation** (transport + registry). No new machinery; it's what the core
  primitives *do* when run at scale.
- **Fitness** — a daemon's measured worth: does it load cleanly, stay within budget, perform, get
  adopted? Supplied by **proprioception**; selection acts on it.
- **Diversity (anti-monoculture)** — many implementations behind one interface / varied builds, so a single
  exploit or bug can't fell a whole Realm. Polymorphism as defense, the way nature resists pathogens.
- **Immune system** — decentralized defense: signing/provenance recognizes self vs. non-self
  (*innate*), anomaly detection adapts (*adaptive*), and a Realm remembers and rejects bad lineages
  mesh-wide (*herd*). A firewall has a center to bypass; an immune system does not.
- **Apoptosis** — programmed self-termination: a corrupted or over-budget daemon kills itself for the
  node's health, via the safe-unload path. Death is a feature.
- **Antifragility** — each failure and attack sharpens selection and immune memory, so the mesh gains
  from stressors rather than merely tolerating them.

## Instinct & learning

Nature pairs the slow loop (evolution) with a fast one (learning within a lifetime). GAWD keeps both,
on either side of the substrate/Abode line. (Theory in [`VISION.md`](VISION.md).)

- **Instinct (innate layer)** — behavior every Sanctum has from birth: the substrate primitives, the
  manifest contract, innate immunity, baseline drives. Inherited (content-addressed, signed),
  shared mesh-wide, fast and fixed. The natural home for **invariant safety constraints**.
- **Learning (acquired layer)** — what an **Abode** builds within its lifetime from experience:
  memory, adapted models, adaptive immunity, local tuning. Individual, mutable, flexible.
- **Promotion** — codifying a proven learned behavior into a signed, published creature: turning
  learning into heritable **instinct** (the bridge from the fast loop back to the slow one — a
  deliberate Baldwin effect). Mechanism: self-authoring → registry.
- **Culture (social learning)** — the *horizontal* bridge beside promotion's vertical one: actors learn
  models by **observing** one another and **teaching** peers they judge deserving. *The wise learn more
  from the fool than the fool from the wise* — a capable observer profits from any peer, so even
  suboptimal actors inform the collective (and diversity earns its keep). Faster than the genome, wider
  than one lifetime; every exchange a trust judgment, so it rides on and feeds [Proof of
  trust](#proof-of-trust). Memetic evolution atop the genetic kind.

## Proof of trust

Order across a mesh of mutually-distrustful parts with **no central authority** — trust *derived from
primitives* every party can check, not *granted* from above. The hypothesis: a distributed intelligence
cannot exist without it. (Theory in [`VISION.md`](VISION.md).) Each primitive pins order
against a kind of disorder — and each has a face in nature:

- **Time** — *when* (in what unfolding) something happened. Since *time is only a change of state*, the
  honest form is often **logical / causal** time, not a wall clock — vital across light-lagged links.
- **Order / sequence** — *what came before what*; causality. Settles "who acted first" even when clocks
  disagree (hash chains, append-only logs). Resists contention and replay.
- **Position & weight** — *how much a party or claim counts.* Like density in a fluid, **the
  well-founded rise and the unfounded sink.** Weight is earned over **history**, so a Sybil flood of
  empty identities carries none — which is why *weighted* consensus beats one-node-one-vote. The same
  notion under priority, stake, reputation, credit, and underwriting. (Nature: the pecking order.)
- **Consensus** — *what we agree is true*, despite faults or contention. Resists forks and split-brain.
  (Nature: quorum sensing, swarm decision.)
- **Permission / signature** — *who authorized this; is it really them.* Resists impersonation and
  forgery. The same test the immune system runs as **self/non-self**.
- **History** — *the honest, hard-to-forge record of before.* The basis of reputation and of whom to
  trust. (Nature: tree rings, sediment layers — order written by time.)
- **Verifiable randomness** — a value *committed in advance* and *revealed under signature*: provably
  unpredictable yet provably un-rigged. Answers "truly random, or secretly chosen?"; makes fair leader
  election, lotteries, and un-gameable tie-breaks possible. Where entropy and trust meet.
- **Proof of trust** — the composite: settling *did this happen, in what order, by whom, with whose
  agreement, weighted how, and is the record honest?* from primitives, not from a trusted central party.
  The connective tissue that lets evolution, instinct, and the immune system work across a mesh with no
  king.

**Costly signaling** ties nature to cryptography: a peacock's tail is trusted because it is *expensive
to fake*; **proof-of-work, proof-of-stake**, and kin are the same idea — weight grounded in something
costly to counterfeit. GAWD supports the whole *"Proof of ___"* family and mandates none of it: which
proof, which clock, which consensus is a **model the operator chooses** (*Fabric, not model*, above),
not a law the substrate imposes.

## The five governing loops

The substrate's behavior — what it *does all day*, independent of how it's built — is five
anti-entropy loops. Each is ordinary bus traffic, each is gated by the trust primitives above, and
each is realized by an **injected creature** (the fabric ships the socket and the sense stream; the
model is a creature). All five loops are alive; this is the canonical list,
and every row is a claim you can click through to running, tested code.

| Loop | Name | Cycle | Realized by (an injected creature) | Proven end-to-end in |
|---|---|---|---|---|
| **1** | Sense → decide → act | proprioception → reason → motor act (author / load / place / contain / ship) | the `proprioception` + `fitness` sense streams the kernel publishes, acted on through the control surface | `cosmos/sanctum/tests/v01_end_to_end.rs` |
| **2** | Author → select → promote | variation → fitness → heredity → propagation | `cosmos/creatures/fitness-selector` (signs a promotion onto the registry's reputation slot from an injected criterion) | `cosmos/sanctum/tests/fitness_selection_local.rs` |
| **3** | Distribute | intent → match requirements ↔ embodiment → place → execute → return | `cosmos/creatures/distributor-requirements` (+ `embodiment-advertiser`) over the placement SEER topic | `cosmos/sanctum/tests/distributor_{local,cross_node}.rs` |
| **4** | Defend (immune) | observe → self/non-self → weigh → contain / quarantine | `cosmos/creatures/immune-response` (trust-gated, reversible quarantine on a sensed fault) | `cosmos/sanctum/tests/immune_response_local.rs` |
| **5** | Acculturate | observe peers → adopt better models → teach the deserving | `cosmos/creatures/omega-federator` (cross-Realm pull anti-entropy + signed reputation over SEER) | `cosmos/sanctum/tests/omega_federation_cross_node.rs` |

The numbering is fixed; where the docs say "Loop 2" / "Loop 4 (defend)" they mean this
table. Loops 1/2/4/5 are *identity-addressed* (talk to *this* creature); **Loop 3 is
*capability-addressed*** ("route to *whoever* satisfies these requirements") — the same envelope,
resolved differently (the integration risk the substrate was designed around; see
[`ARCHITECTURE.md`](ARCHITECTURE.md)).

## How the metaphor maps to the repo

| Cosmology | Crate / artifact in this repo |
|---|---|
| Sanctum (node) | `sanctum` (the kernel library) + `alpha node` (the daemon subcommand of the α front door) |
| the bus | `aether` — one `Envelope`, one `Router`, the `Creature` seam, the journal |
| creature load mechanism | one `Kernel::load` over `anima` — `libloading` for native `daemon`s, `wasmtime` for `beast`s, Rhai for `critter`s — selected by `abi.backend` |
| self-hosting | transport, registry, the authoring agent, the admission policy, and the placement distributor are all ordinary creatures (`cosmos/creatures/*`, `cosmos/creatures/prototypes/*`) |
| Abode (portable self) | `aether::abode` snapshot + `cosmos/creatures/abode-migrator` (hand-off) + `cosmos/creatures/abode-reconciler` (fork/merge) |
| Realm / Omega (federation) | the `Realm` / `Omega` address grain + `cosmos/creatures/prototypes/gateways/realm-gateway` & `omega-gateway` + `cosmos/creatures/omega-federator` |
| embodiment / placement | `cosmos/creatures/distributor-requirements` + `embodiment-advertiser`, over the `placement` SEER topic |

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for how these actually work and the
[design notes](design/README.md) for the decisions behind them.

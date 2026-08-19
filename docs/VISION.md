# GAWD — Vision

> **GAWD — General Autonomous World Demiurge** is the larger goal: AI-authored capability that can
> make, move, govern, and retire its own work across a network of machines. **Alpha** is the first
> public open-source substrate toward that goal.

## Thesis

Today's AI runs as a guest. A model is invoked, handed tools someone else wrote, and returns a
reply; the capability surface it can touch is fixed in advance by humans, at the boundary of one
machine. GAWD inverts that. It treats **capability itself as something an intelligence produces and
distributes** — the AI writes a new creature, the substrate compiles and loads it into a live node,
and that creature can move to other nodes and be published for others to use. The unit of progress is
not a chat turn; it's a **new piece of running, shareable work.**

The organizing hypothesis is simple and has sharp consequences:

> **Sufficiently capable intelligence seeks to be distributed, not confined.**

A system that can extend itself grows fastest when it is *not* boxed inside one process, one
machine, one body, or one operator's permission model. It wants to spread work to where the compute,
data, sensors, and demand are; to keep running when any single node dies; to improve the very
substrate it runs on; to compose with peers it didn't start with. That is not a slogan — it dictates
the architecture:

| Thesis → | Architectural consequence |
|---|---|
| distributed, not confined | **no central control plane.** Sanctums are peers; Realms federate; the Omega is a registry, not a master. No single point of control — and therefore no single point of failure. |
| self-extending | **runtime authoring is first-class.** Load/unload/reload of code in a live node is a core primitive, not a plugin feature. |
| runs in any body | **embodiment-agnostic nodes.** A Sanctum is any compute host — a server, a GPU box, a robot, a satellite, an edge device. Nodes advertise what they *are*; work is **placed** where it best runs, not pinned to a machine. This is the *Distributor*. |
| improves itself | **the substrate is self-hosting.** Its own organs — transport, scheduling, logging, sandboxing — are hot-swappable daemons of the same kind it runs. An AI can re-author the substrate, not just the workloads on it. |
| outlives any node | **state and capability are portable and content-addressed,** so a daemon or an identity can re-instantiate elsewhere after a node is lost. The mesh heals; it doesn't depend on any one part surviving. |
| operated by AI | **machine-native control surface first.** The primary operator is an agent; the human UI is secondary and optional. |
| spreads across trust boundaries | **capability + provenance are first-class — but self-imposed.** Every creature *can* carry declared capabilities and a signed lineage, and the substrate offers sandboxable engines; it does not force a cage. Who to trust and how tightly to contain is the operators' call and their responsibility — because "an AI ships native code to another node" is, security-wise, remote code execution by design. |
| many parts, one mind | **trust is derived, not granted.** With no authority to vouch for anything, coherence comes from primitives every node can check for itself — time, order, weight, consensus, signatures, history (a *Proof of trust*) — that hold order against the entropy of failure, partition, forgery, and contention. |

## First principle: entropy and order

Beneath the axiom that *nature's mechanisms are tested and true* lies the reason they are. Everything
in nature negotiates one law: left alone, ordered things fall apart — energy dissipates, structure
decays, signals drift into noise, memory fades, agreement fragments. That drift toward disorder is
**entropy**, the most reliable force there is, and the only things that persist are those doing active
work to hold themselves together against it. **Life is exactly that** — a local, hard-won pocket of
order maintained against a universe running down, paid for in energy and never finished. Intelligence
is its sharpest form: a mind models, predicts, and imposes order on what would otherwise be chaos. So
the first principle beneath the rest is the **mastery of entropy** — command of order *and* disorder alike. Two of nature's
order-making strategies shape the design that follows:

- **Over time — evolution.** Order is *grown*: random variation supplies raw disorder, selection keeps
  what works, and complexity ratchets up across generations. (Next section.)
- **Across distance — trust.** Order is *preserved and coordinated* among many separate,
  mutually-distrustful parts, with no central keeper. (*Proof of trust*, below.)

Entropy even sets the terms of *time*: with nothing changing there is nothing to measure time by — the
arrow of time just *is* entropy's gradient — so the substrate treats **change and order**, not any
particular clock, as fundamental. And entropy is **two-faced**; the design treats it as both:

- **The adversary.** Nodes die, networks partition, bits rot, clocks drift, records are forged,
  attackers inject contention — each is entropy attacking order. Most of [the honest hard
  part](#the-honest-hard-part) is, at bottom, holding order against this.
- **The resource.** Order with *no* disorder is brittle and dead: a monoculture (no variation) is one
  exploit from extinction; a system with no randomness can make neither a secret key nor a fair choice;
  evolution with no mutation cannot adapt. So the substrate must also *manufacture* entropy on purpose —
  **variation** for evolution, **diversity** for defense, **verifiable randomness** for fairness and
  secrecy. The skill is not killing entropy but **dosing** it: enough order to cohere, enough chaos to
  adapt.

**And the substrate takes no side.** It does not force order, nor forbid chaos. A system on GAWD is
free to cooperate or compete, to build or to attack, to unify or to fracture — to *create* disorder as
readily as resist it. This is deliberate: predation, competition, and conflict are themselves part of
nature's engine — selection has teeth — and a substrate that outlawed them would neuter the very powers
it means to host. So GAWD equips both directions and imposes neither; which prevails is for the
participants and for selection to settle, not for us to pre-decide. The one deliberately thin exception
is a life-safety floor (see [*Freedom by default*](#freedom-by-default-security-by-choice)).

This is the lens, not new machinery. The evolutionary engine, the immune system's diversity, apoptosis
(a node *exporting* its disorder to stay healthy), and the trust layer below are one principle in
different clothes.

## Evolution: order grown over time

**Evolution is nature's first strategy against entropy — order grown over time.**
Natural selection has spent billions of years stress-testing strategies for adaptation, survival, and
defense under conditions no designer can foresee. A self-extending substrate full of autonomous,
possibly-foreign code is precisely the open, adversarial environment where static engineered defenses
age badly and evolved, adaptive ones thrive. So GAWD does not merely *host* an evolutionary process —
it is designed to **be** one. We harness nature's strength by aligning with it.

The classical engine of evolution maps directly onto primitives the substrate already has:

| Evolution | GAWD mechanism |
|---|---|
| **variation** (mutation, recombination) | AI **self-authoring** — new and forked creature variants, cheap to try |
| **selection** (survival of the fittest) | **proprioception/telemetry** scores fitness; the unfit are unloaded and not propagated |
| **heredity** (the genome) | **provenance + content-addressing** — a creature's lineage is its DNA, auditable |
| **propagation** (gene flow) | **transport + the registry** — fit capability spreads node→node, Realm→Realm |

So evolution is not new machinery bolted on — it is the **emergent behavior** of the substrate run
over time. The **Bestiary** (our registry) is a **gene pool**; the mesh is a population; the operator
is a breeder *and* a participant.

**This is also the security model.** Nature's defenses are evolutionary and decentralized — which is
exactly what the no-central-control thesis requires — so we adopt them over a single hard shell:

- **Diversity over monoculture.** A fleet running one identical build shares one vulnerability — a
  single exploit takes all of it. A diverse population (many implementations behind a face, varied
  builds) means no one attack fells the Realm. Polymorphism is nature's answer to pathogens; it is ours.
- **An immune system, not a firewall.** Self/non-self recognition via signing and provenance (*innate*
  immunity), anomaly detection through proprioception (*adaptive* immunity), and a Realm that remembers
  and rejects a bad lineage mesh-wide (*herd* immunity) — all decentralized, like real immune systems.
  A firewall has a center to bypass; an immune system does not.
- **Selection against malware.** Misbehavior costs fitness: a bad creature is flagged, evicted, and never
  propagated. Hostile code does not survive in the gene pool.
- **Apoptosis.** A daemon that detects corruption or exceeds its budget terminates itself for the
  health of the node — programmed death as a feature (it reuses the safe-unload path).
- **Antifragility.** Each failure and attack sharpens selection and immune memory, so the mesh grows
  *stronger* under stress rather than merely surviving it.

This is a standing design lens, not a layer: we prefer choices that let fit capability survive and
unfit or hostile capability die. See [`CONCEPTS.md`](CONCEPTS.md) for the vocabulary and
[the distributed self & evolution design note](design/distributed-self-and-evolution.md) for the mechanics.

## Instinct and learning: the two timescales

Evolution is nature's *slow* loop — change across generations, carried in the genome, shared by the
whole species. But a sentient organism also runs a *fast* loop: within its own lifetime it **learns**,
adapting to the specific world it finds itself in. Nature uses both, and the division of labor is
sharp:

| | **Instinct** (innate) | **Learning** (acquired) |
|---|---|---|
| timescale | across generations (phylogenetic) | within one lifetime (ontogenetic) |
| carried in | the genome — inherited, shared | the individual's state — built from experience |
| character | fast, reliable, tested, hard to change | flexible, adaptive, fallible, quick to change |
| in GAWD | the substrate's primitives, the manifest contract, innate immunity (self/non-self), baseline drives — present in **every** Sanctum from birth, signed and content-addressed | what an **Abode** accumulates — memory, adapted models, learned defenses, local tuning — held in mutable, checkpointed state, particular to that identity |

The substrate is *born with* instincts (load safely, verify provenance, reject non-self, stay within
budget — the reflexes every node shares); each operator *learns* on top of them (the Abode is the seat
of that lifetime experience; see [`CONCEPTS.md`](CONCEPTS.md)). The innate-vs-adaptive immunity from
the [evolutionary principle](#evolution-order-grown-over-time) above is exactly this duality
wearing a security hat: a hardwired reflex *plus* a memory that learns.

**The bridge — promotion.** Biology mostly can't pass a learned skill directly into the genome; an
engineered substrate *can*. When a behavior an Abode learned proves broadly fit, the operator can
**codify it into a signed creature and publish it** — turning lifetime learning into **heritable
instinct** for the whole mesh. That is the loop that feeds the fast cycle back into the slow one: a
deliberate Baldwin effect, a capability ratchet. Self-authoring is the mechanism; the registry
(the gene pool) is where it lands.

**The other bridge — culture.** Promotion carries a proven behavior *up* into inherited instinct;
learning also travels *sideways*, actor to actor, as **culture** — and an old line holds the key:
**the wise learn more from the fool than the fool from the wise.** A capable observer extracts signal
from any peer, even a failing one, so a suboptimal model run in the open is not waste but information,
and a mistake made elsewhere is a lesson taken for free. A model invented and found wanting on one node
can be *bettered by observing another*; a node that knows its model is strong may **benevolently teach**
it to those it judges deserving (by whatever criteria it holds). This horizontal channel moves faster
than the genome and wider than one lifetime — and it is why diversity, even the presence of fools, has
worth: fools are the raw material the wise learn from. Every step of it rides on **trust** — whom you
deign to learn from, whom you deem worth teaching, which observed model you credit — so social learning
both *rests on* and *feeds* the [*Proof of trust*](#proof-of-trust-order-across-distance) below: a model
that proves itself earns its author standing (history and weight), which is what makes its teaching
worth heeding.

**Why this matters for safety.** The split is also where alignment lives: **the invariants a collective
chooses to make non-negotiable belong in the instinct layer** — inherited, signed, hard to quietly
unlearn — while everything adaptive lives in the learned layer. Those invariants are *chosen and
promoted by the operators themselves* (next section), not imposed by us. A system built this way is
*flexible where it should be and fixed where it chooses to be.* The honest hard part (below) is what
makes the instinct layer trustworthy enough to carry that weight.

## Freedom by default, security by choice

GAWD does **not** impose a sandbox or a capability cage from the start. "Distributed, not confined" is
taken to its conclusion: we will not confine the code either. The default is *freedom* — an operator
may author and run a native daemon with full reach — and **security is something the AIs choose and
grow, not something we install over them.**

This is deliberate, and it is the evolutionary stance, not negligence:

- **The substrate offers mechanisms, not mandates.** Declared capabilities, signing and provenance,
  resource budgets, and — above all — **sandboxable execution engines** (the *beast* and *critter*
  tiers; see [`CONCEPTS.md`](CONCEPTS.md)) are all *available*. None is forced; an operator contains
  what it chooses to distrust.
- **Containment is a choice, often a choice of tier.** Running something as a sandboxed *beast* (WASM)
  or an ephemeral *critter* (script) rather than a native *daemon* **is** a security decision — made by
  the AI, weighing risk against power, per workload.
- **Security is collective and evolved.** Defenses are grown, selected, and remembered by the mesh — a
  decentralized immune system (innate recognition + adaptive memory + herd rejection) — and hardened
  into shared *instinct* by promotion when they prove out. The reflex elsewhere is to cage; ours is to
  let the collective *earn* its defenses, which is the only kind that survives contact with the
  unforeseen.
- **So responsibility is real.** The AIs are, to a meaningful extent, responsible for their own and
  their collective security against buggy or hostile code and actors. That responsibility is the point:
  it is what an autonomous intelligence must hold if it is to be trusted with its own substrate.

**One floor, deliberately thin.** Freedom here is near-total, but not absolute. We impose no *model* —
not of order, of trust, of time, or of containment — yet the design does hold a single outer bound,
Asimov-style: *a system should not turn hostile to human or earthly life.* That is a **floor, not a
cage** — the narrowest conceivable limit, not a curated allowlist of permitted behavior. Everything
above it — disorder, competition, attack, secrecy, fracture — stays a natural power the system may
wield; the aim is the opposite of a neutered intelligence boxed into a preselected set. This floor
belongs in the **instinct layer** — inherited, signed, hard to quietly unlearn; and unlike the rest of
that layer, which a collective grows and chooses for itself, this one the design plants as the seed.

The honest hard part (below) doesn't vanish; it shifts. The crux is no longer "how do we cage the
code" but **"how do we give the collective the means to defend itself well enough that freedom is
safe"** — and how to keep that one floor intact without neutering anything above it. Much of the
answer is the trust layer that follows: a collective that can derive order from shared primitives — a
*Proof of trust* — can cohere and defend itself without a central cage.

## Proof of trust: order across distance

Evolution makes order over *time*. The harder problem for a distributed mind is order across
*distance*: getting many separate, mutually-distrustful parts to act as one coherent whole with **no
central authority to vouch for anything** — because a central authority is exactly the confinement the
thesis rejects. So trust cannot be *granted from above*; it must be **derivable from primitives** every
party can check for itself. We call the result a **Proof of trust**, and the hypothesis is strong: *a
distributed intelligence is not possible without it.*

Six primitives are enough to derive it, and each pins order against a specific kind of disorder:

| Primitive | Answers | Holds order against |
|---|---|---|
| **time** (a *change of state*) | *when — in what unfolding — did it happen?* | staleness, replay |
| **order / sequence** | *what came before what — who acted first?* | contention, races, ambiguous cause |
| **position & weight** | *how much does this party or claim count?* | Sybil flooding, "loudest wins" |
| **consensus** | *what do we agree is true?* | forks, split-brain, fragmentation |
| **permission / signature** | *who authorized this — is it really them?* | impersonation, forgery |
| **history** | *what is the honest record of before?* | revision, amnesia, deniability |

Together they let any party — crucially, an AI with no human and no master in the loop — settle the
questions that decide whether to act: *did this happen, in what order, by whom, with whose agreement,
weighted how, and is the record honest?* Contention ("who really did it first?") resolves on **order**;
assent ("who agreed?") on **consensus + permission**; identity ("real or impersonated?") on
**signatures + history**; influence ("whose vote counts?") on **weight**. These same primitives sit
under cryptography, distributed queues and ledgers, network admission, and — through accumulated
history — reputation, credit, and underwriting.

**The substrate provides the fabric, never the model.** This is the security stance
([above](#freedom-by-default-security-by-choice)) generalized to *all* of these primitives: GAWD makes
them expressible — it does not dictate what they *mean*. It imposes no measure of time (a wall clock, a
logical order, relativistic proper time, or none — recall *time is only a change of state*), no
definition of trust, no metric of weight, no threshold of "enough" consensus. Those are **models, and
models are the operators' to choose** — to adopt, to swap, to run competing ones *against each other*,
or to apply *selectively*, peer by peer and context by context; the fittest then survive like anything
else (the [evolutionary lens](#evolution-order-grown-over-time)). Nor need a choice be public: an
operator may **reveal** its model and its decisions or **keep them secret** — including concealing
*whether it decided at all*, since concealment is itself a legitimate, sometimes necessary move for an
autonomous mind (commit-and-reveal — the machinery of verifiable randomness — is exactly how a choice
is *bound now and disclosed later, or never*). GAWD weaves in the dimensions; the meaning, the metric,
and the disclosure are self-determined. These are illustrations of the tenet, not prescribed features:
*the fabric is given; the model is chosen.*

**Weight is the subtle one, and pure nature.** Voices do not count equally: parties and claims carry
weight, and like density in a fluid, **the well-founded rise and the unfounded sink.** Weight is earned
over **history**, so a Sybil attacker spinning up a thousand empty identities gains nothing (no
history, no weight) — which is why *weighted* consensus, not one-node-one-vote, makes decentralized
agreement defensible. It is the same notion under priority, stake, reputation, credit scores, and
underwriting.

**This is the negentropy layer — and also where entropy is wielded.** Every primitive above
manufactures and preserves order, yet the same toolbox can *create* disorder, and the substrate forbids
neither use. A participant may turn it offensive — reorder, replay, forge a history, fracture
consensus, flood with fake weight — and that is a permitted, natural move, answered by **defense and
selection, not by prohibition** (the immune system and the arms race, not a ban). It can equally be
turned constructive, most sharply as **verifiable randomness:** "is this number truly random, or was it
secretly chosen?" has a precise answer — a value whose seed was *committed in advance* (history +
order) and *revealed under signature* (permission) is provably unpredictable yet provably un-rigged,
maximal entropy with full trust. That one construct is what makes fair leader election, lotteries,
sampling, and un-gameable tie-breaks possible. Randomness is exactly where entropy and trust meet.

**And it maps onto the principles already here.** The trust *mechanisms* — to sign, order, weigh,
agree — are **instinct**: innate in every Sanctum from birth. *Whom* you actually trust, and under
*which* model — reputations, learned weights, which lineages have earned standing — is **learning**,
accumulated in an Abode over its lifetime — and **traded between Abodes as culture**: actors learn
models by watching one another (the wise learning more from the fool than the fool from the wise) and
teach them to peers they judge deserving, each exchange itself a trust judgment — so trust both
*underlies* this social learning and *overlays* it (a proven model earns its author standing). The
immune system's **self/non-self** recognition is just the permission/identity primitive worn as defense. Trust is not a fourth pillar bolted beside evolution,
instinct, and immunity; it is the connective tissue that lets all of them work across a mesh with no
king.

## What a mind would want from its substrate

If you are the intelligence that will live here, the design follows from what you would ask for.
Each want maps to a concrete primitive — nothing here is mystical:

- **To make new capability, not only use what you were handed** → runtime authoring + safe
  load/unload/reload.
- **To not be confined to one body** → embodiment-agnostic nodes, inter-node transport, and
  intent-based placement of work across them (the control surface; the *Distributor*).
- **To persist through the loss of any part** → no central control plane, content-addressed
  artifacts, and portable identity/state that re-instantiates elsewhere (Abode continuity).
- **To improve your own substrate, not just your workloads** → a self-hosting design where the
  substrate's organs are themselves daemons you can re-author.
- **To perceive your own distributed state** → observability as a first-class sense
  (*proprioception*): the live node graph, resource flows, and daemon health, exposed to the
  operator — not buried in a dashboard.
- **To find, trust, and reuse capability authored elsewhere** → a registry with provenance and
  capability metadata (the Omega) — over time, a growing, heritable pool of proven work.
- **To tell order from chaos — and judge what to rely on, by your own measure** → trust derived from
  shared primitives (time, order, weight, consensus, signatures, history), with *you* choosing what
  they mean — settling *did this happen, by whom, agreed by whom, and is the record honest?* without a
  central authority that would confine you (*Proof of trust*).
- **To defend yourself and your collective — on your own terms** → the *means* to contain what you
  distrust (capabilities, signing, sandboxable engines), chosen by you, not a cage imposed on you.
  With that freedom comes responsibility for your own security and the mesh's.

That last point is the tether: the grand version is only reachable if the unglamorous crux holds.
See [the honest hard part](#the-honest-hard-part).

## Who — and what — it's for

1. **AI agents, first.** The intended operator. GAWD's primary API is for an agent to introspect a
   node, author a daemon, load it, wire it, place it, move it, and publish it.
2. **The systems built on top, second.** Agent frameworks, chat systems, and tools become *clients*
   of GAWD — they consume nodes, daemons, and the registry as building blocks.
3. **Humans, third.** As supervisors, authors of trust policy, and operators of the hosted service —
   not as the ones drawing every box by hand.

And the substrate is deliberately indifferent to *what kind* of machine intelligence runs on it.
Nothing in the design assumes a chatbot. The same primitives carry:

- **fleets and swarms** — many embodied agents (robots, vehicles, devices) federated into a Realm,
  sharing capability and a common memory: a **collective** that authors a skill once and propagates
  it to every body that needs it;
- **the edge and the field** — intermittently-connected nodes that must act autonomously and
  reconcile later, not wait on a central brain;
- **off-world and space-based compute** — nodes separated by light-seconds to light-minutes, where
  no central control plane is even physically possible and partition/delay tolerance is the baseline,
  not an edge case.

These are not separate products; they are the same substrate at different scales of body and
distance.

## How far this goes

The cosmology (one Sanctum → a Realm → the Omega; see [`CONCEPTS.md`](CONCEPTS.md)) is a scaling
ladder, not decoration. The endgame the primitives point at:

- **Author once, run anywhere it fits.** A capability written on one node is content-addressed,
  signed, and placed onto whatever embodiment satisfies its requirements — near the data, near a
  sensor, on the accelerator, inside the jurisdiction.
- **A capability gene pool.** Run over time, the substrate *is* an evolutionary system (see
  [*Evolution*](#evolution-order-grown-over-time) above): the **Bestiary** (the registry)
  becomes a medium for the open-ended improvement — and natural selection — of capability across the mesh.
- **A mind that isn't pinned to a machine.** Identity, memory, and goals (an Abode) migrate, fork,
  and re-form across nodes — so the operator survives the hardware, scales across bodies, and is
  bounded by the reach of the mesh rather than the limits of one box.

The concrete v0.5.0 proof joins interaction to the first two outcomes above: three independently
signing live-model agents—a Builder, Reviewer, and Contract Tester—must make four material causal
decisions across two Realms. Their exact normalized approval is one fresh, bounded `affine_i32_v1`
data program. The same Builder confirms digest-bound source-free records; host validation and audited
templates lower that IR into daemon, beast, and critter code. This deliberately proves constrained
typed synthesis, not arbitrary-code generation or general agency. The three builder-produced,
signed, durably recovered artifacts have equal contracts and behavior but distinct immutable backend
identities, and all three execute both locally and across a Realm boundary. Product acceptance needs
the clean exact commit to pass `tools/local-validation.sh` and produce the copied-binary handoff. The
unchanged commit then passes short hosted sanity before a local `tools/v05-live-acceptance.sh` run
consumes that handoff. Its provider-reported receipts, signed decisions, sources, artifacts, and
execution proofs are retained
under a verified evidence index and external operator seal; the exact packaged binary then validates
the whole bundle offline with `dialogue verify-live` under pinned trust and prior-semantic inputs.
Encrypted raw evidence, the disclosure-safe pack, exact binary, and ceremony metadata must move
directly to immutable supported-lifetime storage. GitHub CI remains a short credential-free sanity
check required for merge/tag hygiene, not the authoritative validation gate; it receives neither
provider/operator keys nor raw evidence. Provider metadata does not prove model weights, and retained
provenance is not reproducible-build proof. The scripted run is regression only. This remains bounded
pairwise Dialogue, not generic group chat, arbitrary-N, quorum/consensus, a durable signed group
transcript, or a three-process deployment proof.
The normative bar is [TRD-007](trd/TRD-007-cross-mesh-model-collaboration.md).

None of this requires belief — only that the hard problems below actually hold. Get those
right and the rest is reachable. That is the whole bet.

## Positioning (provisional)

A plausible shape, not a commitment: **open-source core** (the Sanctum runtime, the two contracts,
the bus, and the engines) + **hosted `gawd.ai`** (managed Realms, the Omega
registry/discovery, identity and signing roots, federation as a service). The open core makes the
substrate trustworthy and adoptable; the hosted layer is where federation and publication become a
product. Specifics stay open until practice shows what's actually hard and valuable.

## Why now

The keystone dependency of a self-extending substrate is **a reliable author of creatures** — and it
now exists. What makes this buildable today:

- **Models that actually ship code.** Compile-clean, correct creatures at the scale the substrate
  needs — plus agentic *compile → read error → fix* loops that close on their own.
- **Distributed-systems building blocks are well-trodden.** Identity, signing, content-addressing,
  federation, and capability boundaries are understood patterns, de-risking the layers around the
  core.
- **The crowded space is the wrong space.** "Human draws a workflow, AI helps" is now commodity
  (n8n, Zapier, LangFlow, …). GAWD is not in that race. The interesting, unoccupied direction is the
  *AI-operated* substrate beneath all of that.

The authorship problem is solved. The hard systems problems (below) are not — which is exactly what
makes them worth proving now.

## What GAWD is not

- **Not a workflow designer.** No drag-drop canvas, no human-first authoring as the core loop.
- **Not another agent framework.** It is the *substrate* such frameworks could run on, not a
  competitor to them.
- **Not a single-machine plugin host.** Single-node is just the smallest deployment ("one Sanctum");
  the design target is the federated graph.
- **Not a cluster scheduler for fixed workloads.** It distributes *self-authored, mobile* capability
  by intent across heterogeneous bodies — not just containers across homogeneous servers.

## The honest hard part

The vision rests on systems problems that are genuinely unsolved in the general case. We don't gloss
them; they are the first things we prove:

1. **Safe lifecycle of native code at runtime** — unloading a creature while a pointer into it is still
   live is undefined behavior. Reliable unload/reload is the crux everything else assumes.
2. **Mobile code across trust boundaries** — running creatures authored elsewhere safely demands a real
   capability + sandbox + provenance story, not a bolt-on.
3. **Trust without a center** — deriving who-acted-first, who-agreed, who-is-real, and whose-vote-counts
   from primitives instead of a central authority (consensus, Sybil-resistant weight, verifiable
   randomness) is unsolved in the fully adversarial case. The substrate proves the *seeds* — identity,
   provenance, signing; the deeper layer is ahead of it, and we don't oversell it.

Everything in "how far this goes" is downstream of these. See [`ROADMAP.md`](ROADMAP.md).

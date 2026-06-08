# Inversion of control: sockets, not strategies

> The discipline that makes "fabric, not model" structural rather than promised. The
> substrate ships **mechanisms and sockets**; every model is an **injected creature**. For
> vocabulary see [`CONCEPTS.md`](../CONCEPTS.md); for how it all composes,
> [`ARCHITECTURE.md`](../ARCHITECTURE.md).

## The principle

A self-extending, AI-first substrate must let new models — for placement, admission, consensus,
weighting, randomness, fitness, clock semantics, federation — be authored, deployed, and swapped
while the node runs. If the fabric bakes any of those in, the AI has to work around it; if the
fabric *encodes* a particular one (which trust roots, which placement strategy, which fitness
criterion), it has chosen sides among its own players. Both contradict the central axiom: GAWD
supplies **primitives, never a curated worldview**.

So the rule is one shape, applied everywhere:

> **The fabric ships a socket. A creature bound to that socket *is* the model for that concern.
> If nothing is bound, the router returns `NoProvider` — the fabric supplies nothing in its place.**

This is *fabric, not model*: the fabric is **indifferent to the players, inviolable as the board**.
Indifference is deliberate — it lets evolution and the immune system shape models by *selection, not
prohibition*. Inviolability is also deliberate — the board enforces, by construction, two floors no
tenant can cross:

- **The fabric-integrity floor.** No tenant may crash, hang, DoS, OOM, or corrupt the kernel or bus
  *through the fabric's own surfaces*: bounded inboxes with backpressure, no-panic parsing of
  hostile envelopes and manifests, creature-fault isolation (a `handle` panic is caught and routed
  to unload), per-creature resource accounting. Guaranteed by construction for the sandboxed tiers
  (WASM `beast`, scripted `critter`); native `daemon` code is trusted-by-admission — the honest
  containment limit.
- **The life-safety floor.** The substrate is not hostile to human or earthly life: a floor seeded
  in the instinct layer, not a curated allowlist.

These refine *takes no side* into its exact form: **takes no side *among the players*; is not itself
a player.**

## The placement test

For any new concern, ask: **is this a mechanism, or a model?**

- A **mechanism** is a fact about the board everyone must agree on — *how* an envelope routes, *how*
  an artifact is validated and hashed, *how* a creature loads and unloads safely. It has no opinion.
  It goes in the kernel (`sanctum`) or the bus (`aether`).
- A **model** is a choice among defensible options — *which* creature fills an intent, *which* trust
  roots admit, *which* criterion counts as "fit", *which* sandbox contains a build, *which* clock
  applies. It has an opinion. It is a **creature bound to a socket**, and it lives under
  `cosmos/creatures/` — never in the fabric.

The tell: if two reasonable operators would choose differently, it is a model, and the fabric must
ship the socket instead of picking. The kernel is exactly three jobs — **lifecycle, routing,
admission-mechanism** — and ships *no* placement, policy, consensus, weight, clock, fitness
criterion, or randomness scheme. Everything woven on it — logging, transport, registry, the
distributor, the authoring agent, the admission policy itself — is a hot-swappable creature. That is
what keeps the kernel the fixed fabric an AI cannot re-author.

## Sockets are first-class

The bus's `Address` enum carries the socket directly. `Address::Role(name)` routes to whoever is
bound to that role; `Address::Intent(outcome, requirements)` is the distributor hook — it routes to
whoever is bound to `Role::DISTRIBUTOR`, which resolves the desired outcome to a concrete creature.
The role table generalizes the pattern: *any* role name is a socket. The shipped roles —
`distributor`, `transport`, `policy`, `registry`, `authoring`, `build`, `realm-gateway`,
`omega-gateway`, `abode-migrator`, `fitness-selector`, `immune-response`, `abode-reconciler`,
`control` — are each a concern the fabric refuses to model. `bind_role(role, id)` plugs a creature
in; an unbound socket yields `NoProvider` rather than a default.

Trust primitives ride every envelope structurally — `seq`, `stamp`, `sig`, `corr`, `commitment` —
free of any specific model for what they *mean*. The fabric carries the order/permission/correlation
material; a consumer's model decides how to weigh it.

Two binding forms both honor the discipline: a `Creature` on the bus bound to a `Role` (the full
pattern), or a Rust trait object handed to the kernel at construction — the pragmatic form for
things consulted *during* load, which avoids an admission bootstrap. Admission's `Policy` is the
canonical example: the kernel runs the mechanism (structural validation, signature verification,
content-address recompute, artifact-hash check) and hands a `Admission` evidence record to an
injected `Policy::admit`, which supplies the model — what to require, which roots to trust. The
fabric ships the gate and the socket, never a worldview of its own.

**Something-in-the-loop is just a creature** with the `net` capability. A bound resolver may answer
instantly, cast a verifiable die, consult N somethings (humans, AIs, services, peers) and reconcile
by **race** (first wins = *order*), weighted or unweighted **consensus**, or **quorum** — or it may
have already decided and consult only for show. The fabric adjudicates none of it. Resolution is
**async and `corr`-correlated, never blocking RPC**: the same guardrail as *don't hard-wire a wall
clock* — **don't bake in synchronous resolution**.

## The self-authoring loop

New creatures arrive at runtime. An intent enters the substrate, an agent answers with source, the
source becomes a signed artifact, the artifact admits and loads, the new creature joins the bus — no
restart. Two sockets close that loop, and each is a model the fabric refuses to pick:

```
intent ──▶ AUTHORING ──▶ source + manifest stub ──▶ BUILD ──▶ signed (manifest, artifact)
                                                                       │
                                                            (same admission gates)
                                                                       ▼
                                                              Kernel::load (safe)
                                                                       ▼
                                                                new creature runs
```

- **`Role::AUTHORING`** receives an `AuthoringRequest { request, prev_error }` — a natural-language
  outcome plus optional retry context — and replies with `AuthoringReply::Authored` (source +
  manifest stub + cargo deps + a telemetry label) or `AuthoringReply::Failed`. Picking a template,
  asking an LLM, consulting a human, running a planner: each is a *strategy*, and the fabric ships
  none. The reference `agent-templated` is a pattern matcher with zero authoring intelligence; its
  job is to make the *seam* testable end-to-end without coupling the substrate to any model. A
  Claude/GPT/local agent is the **same creature answering the same request** — a swap, not a
  redesign. That swap ships: `agent-mind` binds this same socket and asks a real model — an injected
  `Model` from the `mind` leaf crate — for the source + manifest stub, returned as two fenced
  blocks (a `rust` source block + a `json` manifest stub) and parsed **fail-closed** (a missing or
  malformed stub is a structured `Failed`, never a silently-defaulted permissive manifest). It is
  opt-in (`--features openai` + an `--author-model` flag selecting the model per node instance — the
  model is configured at the operator surface, never from the environment) and **in-process only** —
  never a `.so` — because its construction takes the model explicitly (no `Default`-constructed fake
  can be substituted) and its slow model call runs off the kernel drain thread on a self-owned worker.
  The model is injected through a trait; the fabric still ships only the socket. `agent-curious` is
  the third reference — the conversational end, consulting over SEER when no template fits.

- **`Role::BUILD`** receives a `BuildOp::Build { crate_name, crate_version, source, manifest_stub,
  deps }` and replies with `BuildReply::Built { manifest, artifact }` — signed, hashed,
  content-addressed, admissible by `Kernel::load` with no further preparation — or
  `BuildReply::Failed { kind, message, stderr, stdout }`. The reference `build-cargo` materializes a
  fresh temp workspace (path-dep on `forge` so the authored crate inherits the FFI macro), runs
  `cargo build --release` into a shared cache, hashes the resulting `.so`, populates and ed25519-signs
  the manifest with the operator's Abode key, and returns the pair. `build-critter` is the sibling
  on the same socket for the scripted tier — it validates that Rhai source compiles and defines
  `fn handle(env)`, then signs the source bytes themselves as the artifact under
  `abi_tag = gawd_critter_v1`. Native daemons carry `gawd_creature_v1`. Cross-compile, AOT-from-WASM,
  and remote build farms are the same socket, a different bindee.

The loop is **just composition of existing sockets** — admission and safe-load are unchanged, and
nothing new lands in the fabric. Three properties make the loop sound:

- **One admission path.** What BUILD emits is admissible by the *same* gates that admit a creature
  shipped from a peer. No second, more-permissive metadata schema for authored creatures: one
  manifest, validated at one place, with explicit reasons an agent can read and revise.
- **Sandbox is an injected model, opt-in but always available.** `build-cargo`'s `Sandbox` is
  `None` or `Custom(prefix)`; the operator prepends their containment vocabulary (`bwrap`,
  `firejail`, `docker run`, …) to the cargo argv. Build is a mechanism, sandbox is a model — the
  same lever, one level down. The seam is in the contract, not behind a feature flag: there is no
  build that *can't* be sandboxed.
- **Compile failures are first-class.** `BuildReply::Failed { kind, stderr, … }` is the agent's
  input on retry. An LLM-backed agent reads the stderr; the templated agent flips a deterministic
  switch. Both honor the same contract, and a failed build never harms the node.

One detail is load-bearing for any BUILD implementation: the signing payload strips only the
signature, **not** the content address, so the content address must be set *before* signing — else
the receiver verifies a different document and the signature drifts.

## Authoring as conversation

Single-shot request-reply is exactly right for closing the loop deterministically, and exactly wrong
for an ASI framework: it loses every dimension of a real authoring exchange — a creature that
compiles for thirty seconds looks dead; its reasoning is the most selectable signal selection has;
an orchestrator can't intervene mid-flight; the creature can't ask for input when it's stuck.

The bus already carries all of it through `corr`. So authoring is not an RPC — it is a
**`corr`-correlated thread of envelopes** with one required terminal `AuthoringReply` and a set of
optional moves around it. Those moves ride `seer`, the substrate's generic Query/Answer primitive:
one `SeerEnvelope { topic, corr, kind }` on the `authoring` topic, where `kind` is one of five
conversation moves:

- **Query** *(outbound)* — the creature actively seeking external input ("approach A or B?",
  "what's this schema?", "is this constraint hard or soft?"). A `query_id` disambiguates multiple
  outstanding queries on one `corr`. The curiosity / alimentation seam — without it the framework
  structurally forecloses a *feeding*, curious authoring shape.
- **Answer** *(inbound)* — matched to a Query by `(corr, query_id)`. A mismatch is stale or spoofed
  and the consumer drops it.
- **Steer** *(inbound)* — mid-flight intervention from an orchestrator (`amend` | `abort` | `info`
  by convention; payload opaque to the substrate). A creature may ignore every steer and still
  complete.
- **Progress** *(outbound)* — observable trajectory (`stage` + optional `fraction`, `note`), so a
  creature that compiles silently can surface that it is alive.
- **Thought** *(outbound)* — observable reasoning (`internal` deliberation vs `external` prose). A
  creature whose deliberation is observable is selectable by reasoning quality, not just outcome —
  and auditable by the immune loop, which the reduced "we only saw the bad reply" was not.

`forge::seer::{query, answer, steer, progress, thought}` are typed wrappers that build these
envelopes; they never decide topic semantics. The wire format is identical across every `seer`
topic — `placement`, `policy`, `budget`, `fitness`, `consensus` reserve the same shape — so a
consensus / VRF / weight model lands as another `seer` consumer, never as a new bus contract.
The reference `agent-curious` bounds its parked authoring Query state by default as a resource
floor; liveness/deadline policy still belongs to the orchestrator.

### Single-shot is the reduced case

**Any authoring conversation reduces to a single terminal `AuthoringReply` by dropping the
intermediate envelopes.** The contract on `Role::AUTHORING` is exactly "produce a terminal
`AuthoringReply` correlated by `corr` to the request" — everything else is opt-in. This is the
load-bearing property: the wire admits richer creatures *without requiring them*. The minimal
`agent-templated` emits only the terminal reply, byte-identical to a creature that never heard of
`seer`. The reference `agent-curious` proves the other end: on a template match it collapses to the
single-shot path with no `seer` traffic at all; on a request it can't match, it emits a Thought
narrating why, a Progress, and a Query to the originating orchestrator, parks the exchange by
`(corr, query_id)`, and completes terminally when the matching Answer arrives — honoring an inbound
`Steer { abort }` by dropping the exchange and replying Failed.

What the fabric deliberately does **not** do: require any of the four optional moves; block on a
Query (`deadline_ms` is advisory — *time is injected policy, never fabric*); define what a Steer or
Answer payload *means*; or enforce total order across a multi-party conversation. The substrate
carries `corr` and per-sender `seq`; total order is a model concern. **The fabric ships the
primitives, not the model** — which is the whole discipline, restated at conversation grain.

# Alpha — Roadmap Toward GAWD

This is direction, not schedule: where Alpha's substrate goes next on the way to GAWD, and the
invariants that constrain how it gets there. For what ships today, see
[`CONCEPTS.md`](CONCEPTS.md), [`ARCHITECTURE.md`](ARCHITECTURE.md), and the design notes under
[`design/`](design/).

## The baseline

The substrate loads and supervises three tiers: native `daemon`, WASM `beast`, and Rhai `critter`.
Its managed author→build→sign surface covers daemon and critter today; beast artifacts are supplied
externally and then enter the same admission/lifecycle path. Alpha places a creature on a node
whose embodiment satisfies its declared requirements; quarantines it on a sensed fault and promotes
a fit one; hands its **Abode** — identity and state — to another body with an acknowledged in-memory
protocol whose overlap/crash limits are explicit, reconciling divergent copies on an injected
lattice; and federates, sanctums forming a **Realm** and
Realms meeting at **Omega** to exchange signed reputation by pull anti-entropy. The five anti-entropy
loops — sense→act, author→select→promote, distribute, defend, acculturate — are live end to end.

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
(TRDs 001–005) + `docs/adr/` (ADRs 0037–0045). v0.4.4 is the final **additive application-contract**
pass before the v0.5 headline; **v0.5.0 itself introduces no further Envelope or creature-ABI churn**
and lands as composition on these rails.

## v0.4.4 — typed functions and durable Jobs

v0.4.4 makes the capabilities inside creatures callable by immutable, typed name and gives an
invocation a durable asynchronous life. Its Met requirements are
[TRD-006](trd/TRD-006-typed-functions-and-durable-jobs.md); the full composition is
[Typed functions and durable Jobs](design/functions-and-jobs.md).

- A **Function** is an optional structured contract on a signed creature entrypoint. Its canonical
  `FunctionId` is `{ manifest_content_address, entrypoint }`; a friendly alias resolves once and the
  Job pins the result. The creature remains the only loadable/lifecycle/security unit, and invocation
  still enters through `Creature::handle(Envelope)` on all three tiers.
- **Deploy then call** is explicit. Deployment obtains/verifies/admit-loads a creature and produces a
  signed deployment receipt. Submit never hides fetch/load/placement and returns a `JobHandleV1` once
  the submission is durable — not when execution finishes.
- The caller chooses **at-most-once** or **at-least-once**. At-most-once accepts an honest unknown
  outcome after ambiguity rather than risk a duplicate; at-least-once makes repeats attributable.
  Exactly-once external effects are not claimed.
- A single active **function home** carries the canonical Job graph with the caller's Abode; a
  Realm-local **executor** durably claims attempts and signs execution facts. Causal child Jobs,
  bounded progress, steer, and cancellation are protocol mechanisms. Private reads bind a signed
  caller nonce through an admitted relay to the exact return route and bind the Home response back to
  that complete request; observation/control retention is finite independently at Home and executor.
  Join/workflow behavior, scheduling, placement, retries, and interpretation remain injected
  creatures/policies.
- The contract moves Home authority across Realms by a fail-closed epoch handoff: source freeze is
  fsynced before destination activation, root authority never rides in the checkpoint, operational
  epoch signing is separate from application encryption, and foreign receipts remain verifiable end
  to end. The proof suite combines exhaustive in-process boundary coverage with a lifecycle running
  two real child processes over boot-attested TCP/Omega. The latter loads and measures a signed typed critter,
  recovers a changed-id executor through `NodeRole`, carries blocking-parent progress and an exact
  `TooLate` Steer, migrates the Home through signed Stage/Activate, executes a typed causal child,
  retries exact GX gaps after one drop and one corruption, hard-restarts both sides, and recovers the
  terminal foreign receipt without another invocation. The complementary in-process custody suite
  proves the optional root-declared KMS rewrap chain; the process harness uses the legacy no-rewrap
  branch.
- The exact cross-system wire lives in `foundation/gawdfn`; Alpha's role fillings are ordinary
  `function-*` creatures and `job-blob-fs` is the injected storage library. That split is deliberate: GAWD shares identities and proofs,
  while Alpha does not claim ownership of the cross-system contract or bake a strategy into its
  Kernel.

The v0.4.4 proof target is Green and TRD-006 is **Met**, suite-compositionally: the process proof
supplies the real deployment/mesh/restart conjunction while dedicated suites supply full R3 undeploy,
R8 unacknowledged-control recovery, store boundary matrices, and surface parity. The release does
**not** promise crash-resume inside an unfinished GX transfer, generic migration of running creature
memory, active-Home fork/merge, a global queue/cron/DAG product, dynamic MCP tool export, or a
partition-solving global Home locator.

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
- **Scenarios** — declarative runbooks the control plane replays as verbs over the bus. They may
  deploy/submit/query Jobs, but retry graphs, joins, branches, compensation, and cron remain creatures
  authored by an AI rather than a workflow language baked into Alpha.

## Invariants

These hold across every release.

- **Fabric, not model.** The substrate ships sockets and mechanism; strategies — placement, policy,
  scoring, merge, consensus, scheduling, retry, workflow, and custody policy — are injected creatures.
  The fabric may fix an identity, proof, legal state edge, or atomic custody operation; it never fixes
  which work ought to run or how an operator values it.
- **One loadable unit.** A Function is an entrypoint, a Job is an invocation record, and a deployment
  is a receipt; none is a fourth creature tier. Creature lifecycle/admission/containment remain one
  grain across native, WASM, and script.
- **No second-class primitive.** Lifecycle, authoring, transport, and containment are co-designed.
  The signed manifest carries, up front, every field each depends on — version and ABI tag,
  provenance, declared capabilities, execution tier, typed entrypoints, content address, embodiment
  requirements — so none has to reopen it. New signed meaning lands additively and deliberately in the
  manifest, never in a sidecar metadata system.
- **Custody is explicit.** Portable data may replicate, but write authority is single and proof-bearing.
  Signing authority, operational delegation, and application encryption are separate key domains; a
  timeout is never proof that another body did not activate.
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

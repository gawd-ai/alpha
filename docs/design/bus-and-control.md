# The bus, SEER, and the control plane

Alpha implements GAWD's rule: *one bus, two contracts, AI drives the mesh*. Every
interaction in the system — a creature talking to the kernel, a node talking to a
peer, an author loop, a control command — is the same object on the same fabric:
a signed, ordered `Envelope` carried by `aether`. This document describes that
fabric, the SEER conversation primitive that rides it, and the control plane —
which is not an exception to the rule but its sharpest demonstration: node
control is plain bus traffic.

## The aether bus

`aether` is the substrate spine. It ships the routing fabric and nothing a model
should own: creature inboxes, the inversion-of-control role-binding table, topic
fan-out, and an append-only history journal. It carries the trust primitives
*structurally* — they ride on every envelope, so no later layer exists "before"
them — and it decides no policy.

### The Envelope

One typed object carries every interaction. The header is the trust + routing
contract:

- `from` / `to` — sender and destination, two addresses.
- `reply_to` — where a reply is addressed, **preserved across relays** so the
  final responder answers the *original* requester directly. Fire-and-correlate,
  never proxying. `None` means "reply to `from`".
- `seq` — a per-sender monotone counter. Order, not a global total order.
- `causal` — happens-before links, empty unless a creature asserts causality.
- `stamp` — a node-logical tick, **never a wall clock**. *Time is a change of
  state*: every routed envelope advances the node's logical clock, and the
  router assigns the stamp after signing.
- `sig` — a permission token, present on **every** envelope. Whether it is
  *required* is injected policy; that it is present is fabric.
- `corr` — the correlation id that matches a reply to its request across
  arbitrary async, human, or external delay. The spine is message-passing, never
  blocking RPC.
- `commitment` — a commit-and-reveal slot for verifiable randomness or a
  concealed decision. The scheme is injected; the slot is fabric.
- `schema` — the payload's content-type, so typed send/recv survives the dynamic
  boundary.

The payload is opaque bytes — the *same type* local and remote, so a sandboxed
native creature is a natural bus citizen rather than a special case. On the wire
the payload serializes as a hex string, not a JSON array of numbers, which keeps
an 8 MB shipped artifact a single fast-parsing token. Header metadata has a
separate serialized-byte cap before signing, routing, journaling, or remote
gateway use; payload-sized domains keep their own caps. `Envelope::parse`,
`BusHandle::send`, and `Router::route` share the same hostile-input gates: no
panic on malformed bytes, reject oversized headers, and reject a pathologically
deep federation-grain address before any gateway tries to unwrap it.

### Identity is fabric-set: the reseal of `from`

A creature never writes its own `from`. It emits a `Dispatch` — a destination, a
payload, and the sender-controlled header fields (`reply_to`, `corr`,
`commitment`, `schema`) — and the `BusHandle` seals identity, order, and
permission into the envelope: `from` becomes the creature's own `CreatureId`,
`seq` is the next per-sender counter, and `sig` is the signer's signature over
the canonical signing payload. The router then stamps logical time. The
*fabric-set* fields (`from`, `seq`, `sig`, `stamp`) cannot be forged by a
creature, because the creature never touches them.

This reseal is what makes cross-node identity sound. When a `transport` creature
receives a frame from a peer and re-routes it onto the local bus, the local bus
reseals `from` to the transport creature's own id — a remote peer cannot spoof a
local identity, because the only `from` a local recipient ever sees is one the
local bus assigned. The transport rewrites `reply_to` to
`Address::Node(peer, original_sender)` so the eventual reply travels back across
the wire to the true requester, while `corr`, `schema`, and `commitment` ride
through unchanged. The wire boundary is the one place the off-node origin is
still known, which is exactly where the kernel's local-only control inbox is
defended: an inbound frame addressed to the reserved kernel id is refused there,
because admitted peers route *data* across the mesh, never drive a peer's kernel.

### Addressing

Two addressing modes, the *same* envelope, resolved differently by the router:

- **Identity** — `Creature`, `Node`, `Kernel`, `Topic`: talk to *this*
  creature, node, or channel.
- **Capability** — `Role`, `Intent`: route to *whoever* is bound to fill the
  concern. This is the inversion-of-control socket; the fabric ships the socket,
  never the model.

Federation composes by depth: `Realm` and `Omega` wrap an inner target and
resolve through a bound gateway creature — the same IoC discipline as
`Intent → distributor` and `Node → transport`, not a parallel routing system.

### Roles, topics, and PROPRIOCEPTION

A `Role` is an IoC socket name: `"distributor"`, `"transport"`, `"policy"`,
`"control"`, and the rest. A creature bound to a role *is* the model for that
concern. Role bindings are single-occupant, last-write-wins, so re-binding a
socket hot-swaps the whole model behind it.

A `Topic` is a publish/subscribe channel for fan-out. Two are substrate-named:

- `PROPRIOCEPTION` — the liveness sense stream. The kernel publishes here on
  creature load, unload, and resource leak, and a budget signal lands here when
  an engine surfaces one. This is the sense channel the immune loop watches.
- `FITNESS` — the outcome stream, published per handled envelope: the selection
  signal the fitness loop aggregates.

Fan-out is best-effort and bounded: a slow or absent subscriber never blocks the
publisher. Every inbox is a bounded ring that *sheds* on overflow rather than
block the router or grow without limit. Backpressure is an observable, typed
result a creature can react to, distinct from "no such creature" or "no provider
bound".

### The journal

The router appends every routed envelope to an in-memory, append-only history
journal — `from`, `to`, `seq`, `stamp`, `corr` — bounded as a drop-oldest ring.
It is an audit and proprioception *window*, never durable storage, so a
long-lived node's journal memory stays O(cap), not O(envelopes-ever-routed);
the header-byte cap also prevents one row from carrying unbounded routing
metadata.
Because control, authoring, sense, and federation are *all* bus traffic, the
journal is one stream where the whole node's behavior is legible — and a
`corr`-correlated conversation can be reconstructed from it after the fact.

### Take no side

`aether` forces neither order nor chaos. It ships a fabric-integrity floor —
bounded queues, no-panic hostile-input parsing, creature-fault isolation — and a
life-safety floor seeded in the instinct layer, and then it *takes no side*
among the players on top. Attack is answered by selection, not prohibition: the
immune loop is a creature, defense is something a mesh earns. Entropy is
two-faced — adversary (node death, partition, drift, forgery) and resource
(variation, diversity, verifiable randomness) — and the craft is *dosing*
disorder, not killing it. So the substrate keeps the means of dosed disorder
structural — the `commitment` slot for verifiable randomness, monotone-but-not-
total order, change-of-state time — and ships none of the strategies that *use*
them. Those are injected models.

## SEER

Many sockets in the operating model ask-N-somethings-and-reconcile: authoring
(an agent unsure how to proceed), placement (the distributor consulting
candidates), policy admission, budget negotiation, fitness scoring, consensus.
Rather than let each grow its own divergent Query/Answer schema, the substrate
defines the conversation primitive **once**, in the `seer` crate.

SEER is a payload schema, not a new bus contract. A `SeerEnvelope` is carried as
the JSON payload of an ordinary `Envelope` whose `header.schema` is `"seer"`. It
discriminates by **typed topic**, never by per-role schema string:

```rust
pub enum SeerTopic { Authoring, Placement, Policy, Budget, Fitness, Consensus, Curation }

pub enum SeerKind {
    Query    { query_id, body },   // the initiator asks
    Answer   { query_id, body },   // the respondent answers, matched by (corr, query_id)
    Steer    { kind, payload },     // inbound mid-flight intervention
    Progress { stage, fraction, note },  // outbound observable trajectory
    Thought  { channel, content },       // outbound observable reasoning
}

pub struct SeerEnvelope { topic: SeerTopic, corr: u64, kind: SeerKind }
```

`corr` threads the conversation across arbitrary delay; `query_id` is local to a
thread so a creature with several outstanding queries matches each answer to the
right one.

Live SEER consumers parse with `SeerEnvelope::parse_bounded`, capped by default at
1 MiB (`seer::MAX_SEER_ENVELOPE_BYTES`), before decoding the opaque JSON body.
That keeps high-volume consult/sense traffic inside the hostile-input floor
without adding a router-level topic table.

**Reserved topics.** `Authoring` (the curiosity seam) and `Placement` (the
distributor consult) have live consumers; `Consensus` carries signed reputation
deltas for cross-Realm federation. `Policy`, `Budget`, `Fitness`, and `Curation`
are reserved topics with draft typed bodies — their sockets exist, awaiting a
concrete consumer to pin the exact payload. `Curation` is the durable Bestiary's
seam for an *external* curator creature (an in-process curator already runs over
the injected `mind::Model`; the topic reserves the off-process form). Reserving
them means a new mechanism lands as a topic *consumer*, never as a widening of
the wire.

**Topic isolation is a consumer concern, by design.** The substrate has no
router-level topic concept; SEER envelopes route by address like any envelope. A
creature bound to topic A reads a `SeerEnvelope`, sees a foreign topic, and drops
it *silently* — no Failed reply, because that would make the substrate
adjudicate a cross-topic dispute through the creature. The router stays the
three-job fabric (inboxes, IoC binding, fan-out) and never grows a topic table.

**The reduction theorem holds per topic.** A creature that answers a topic
immediately — one terminal envelope, no intermediate Query — is wire-equivalent
to a single-shot responder; the terminal convention is `Answer { query_id: 0 }`,
where `query_id = 0` signals "no precursor Query". The shape *admits* a richer
conversation; it never *requires* one. Synchronous Query is rejected: SEER is
fire-and-correlate, the substrate never blocks, and where a topic body carries a
deadline it is advisory — *time is injected policy, never fabric*.

**Steer is substrate-wide.** A Steer (`"abort"` / `"amend"` / `"info"`) works on
any topic; a creature may ignore every steer and the original exchange still
completes on its terminal envelope. The `payload` is opaque — two creatures
sharing a `(kind, payload)` meaning is their contract, not the substrate's.

Because `Thought` and `Progress` are observable, a creature whose reasoning rides
SEER is selectable by reasoning quality on that topic, not only by outcome — the
SEER stream is per-topic selection and audit material for the fitness and immune
loops.

## Control as a bus contract

The control plane is the one place a substrate that claims "one bus" is most
tempted to cheat — to put node commands behind a private REST hop. GAWD does
not. **Node control is an injected creature on `Role::CONTROL`**, and a command
is an ordinary `Envelope`.

### omni and ControlCore

The spine-only `omni` crate ("control core") owns the command vocabulary,
independent of any transport (no `tokio`, no `axum`, no HTTP): the `Verb` enum,
the `VerbResult` it returns, the `VerbCtx` it runs against, the shared
`AiControl` gate, the `run_verb` core, and the boot helpers. Every surface links
`omni`, so the REPL, the HTTP/WS plane, and the MCP hub speak one vocabulary.

`run_verb(verb, ctx, progress) -> VerbResult` is the single place a command
becomes a kernel effect. A `VerbResult` carries both a machine-readable `json`
(what a surface serializes) and a `human` string (what the REPL prints), so one
core feeds every surface with no divergence.

`ControlCore` is the node's co-located, privileged control organ. Bound to
`Role::CONTROL`, it receives a `control_verb` envelope whose payload is a
serialized `Verb`, runs it against the live node via the shared `run_verb`, and
replies with a `control_result` envelope correlated by `corr` — the same relay
discipline a gateway uses. A `Verb` and a `VerbResult` are plain bus payloads,
so a control command is plain bus traffic between a surface and `ControlCore`.
`control_verb` payloads are bounded before decode; the HTTP and MCP surfaces use
the same cap before they park a corr or emit the envelope, while `ControlCore`
repeats the check for remote or non-standard senders. `control_result` payloads
are capped before emission; an oversized result is replaced with a small
structured error instead of crossing the bus and failing only at a surface.
Public `bind` verbs also shape-check the role name as a bounded ASCII socket
token before inserting it into the router's retained role table; in-process boot
composition can still bind richer internal roles directly.
Re-binding the socket swaps the whole control core.

It holds a `Weak<Kernel>`, not an `Arc` — so the control organ, which lives
inside the kernel's loaded-creature map, forms no strong cycle that would defeat
its own teardown. It is co-located *because* control cannot be decomposed
remotely: you cannot turn `author` into role-addressed sub-requests sent from
afar — the node that authors must resolve `authoring` and `build` locally — so
the control core always sits on the kernel it drives and calls it directly. The
IoC win is at the *interface*: control is bus traffic, surfaces hold no kernel,
and a peer cannot drive this node except by sending a `Verb` envelope this node's
own `ControlCore` chooses to honor.

### Two lanes, so reads never block a build

A cold `author` is a real `cargo build` — tens of seconds. If every verb queued
behind one responder, a build would head-of-line-block a `status`. So the
control core runs on two lanes:

- **Fast, probe-free verbs** (`status`, `list`, `journal`, `bind`, `unload`,
  `load`, `allow-ai`, `ai-status`, `watch`) run **inline on the kernel's drain
  thread** — microseconds — and reply directly.
- **Request/reply orchestration** (`author`, `author --critter`, `registry
  publish`, `registry fetch`, `registry list`, `bestiary prove`, `send`,
  `intent`, `cluster`, `cluster join`) is forwarded to a **single worker
  thread** that owns its own probe endpoint and `corr` space and emits the reply
  itself — these verbs round-trip a `RegistryOp` / `BestiaryOp` to the bound
  `Role::REGISTRY` and need a probe to await the reply. A build in the worker
  never stalls an inline `status`.

Long-running progress (an `author`'s "compiling…") rides a SEER topic, a
`control_progress` frame correlated by the command `corr`, so any surface that
wants to stream it subscribes — fan-out, not request/reply.

### Registry and Bestiary verbs

Four verbs let a surface drive the bound registry without holding it. `registry
publish` reads a manifest and an artifact **from node-local paths** (the same
operator caveat as `load`: these are files on the node, not a client upload),
parses and ships them as a `RegistryOp::Publish`; `registry fetch` returns the
entry's *metadata* (name, version, content address, artifact length) rather than
inlining the bytes, using the byte-light `RegistryOp::FetchMetadata` /
`FetchMetadataInRealm` path; `registry list` enumerates a Realm's catalogue via
the byte-light `RegistryOp::ListMetadata` path. Full `RegistryOp::ListEntries`
remains the anti-entropy wire for federation pulls because it intentionally
carries artifact bytes. The control core therefore parses `registry fetch` and
`registry list` replies under metadata-sized caps; only artifact-producing build
and anti-entropy paths use artifact-sized caps. Each carries an optional `realm`
(omitted → the local Realm). `bestiary prove` rides the additive `bestiary.op`
schema and asks for a verifiable `EntryProof` — only a durable `bestiary-daemon`
answers it; the in-memory stub returns a structured error. `registry publish` is
the only mutating one of the four and is gated like every other mutation; the
three reads are not.

### Remote control is free

Because a `Verb` is a bus address away from anything, remote control is the
*same* envelope addressed to `Address::Node(peer, control_id)` instead of the
local role. It crosses the authenticated mesh to the peer's own `ControlCore`,
which resolves the verb against its *own* node; the reply rides the transport's
`reply_to` rewrite back to the caller. There is no second control transport to
secure.

## Control surfaces are creatures

A control surface is anything that owns an external boundary and translates it to
and from `Role::CONTROL`. Every surface is a **loadable creature** that holds no
kernel: it emits a `control_verb` envelope under its own id with `reply_to`
itself, and matches the `control_result` reply by `corr`. The pattern is the one
the `transport` creature already proves — own a listener, bridge it to the bus,
tear it down cleanly on shutdown.

This makes the control plane composable. A node loads only the surfaces it wants;
a node with no surface loaded has *no external control attack surface at all*.
The most privileged surface — one that can author and hot-load native code —
can be summoned for a task and dismissed the moment it is done, so a permanently
listening privileged plane becomes a transient, human-gated one. And because a
surface is a creature, it is subject to every loop: it can be quarantined by the
immune loop and hot-swapped mid-flight. The substrate can defend against its own
control plane.

The `alpha` (α) front door is the surfaces' host. `alpha node` boots a sanctum
with an optional HTTP/WS surface; `alpha http` serves a headless node plus the
HTTP surface; `alpha mcp` boots the MCP control-hub. Loading a privileged surface
is itself a privileged act — the bootstrap is the trusted REPL seat or boot
config, never a restricted remote caller. Local text inputs that the front door
ingests before control dispatch are bounded too: interactive `alpha node` REPL
lines, `alpha node --script`, and the external `alpha demo` registry manifest
are capped at 1 MiB, while `--author-api-key-file` is capped at 8 KiB before
UTF-8, JSON, or verb parsing. Control composition also probes ancestor
`Cargo.toml` files under a 1 MiB cap when locating the workspace root for build
path dependencies.

### surface-http — the HTTP/WS plane

`surface-http` owns an Axum/tokio runtime. Its `bind` spawns a multi-thread
runtime racing the server against a shutdown signal; `shutdown` fires the signal,
joins the runtime thread, and drops the listener so the port is freed and a
re-load on the same port succeeds. REST endpoints map one-to-one to verbs —
`/api/status|creatures|journal` and `GET /api/registry/fetch|list` +
`/api/bestiary/prove` read, `/api/author|author/critter|load|send|intent|bind|
unload|cluster|cluster/connect` + `POST /api/registry/publish` mutating,
`/api/ai/status`. Every endpoint except `GET /api/health` is auth-guarded by a
**Bearer key** compared in
constant time; `GET /api/ws` is authenticated by `?token=` because a browser
WebSocket upgrade cannot set an `Authorization` header. The WebSocket streams the
high-volume sense topics — PROPRIOCEPTION, FITNESS, SEER — through a **separate,
drain-less** sense endpoint kept off the surface's own inbox, so a fitness burst
can never shed a control reply under backpressure. (Separately — and not a surface
property — the sense-topic *consumer creatures* such as `immune-response`,
`monitor`, and `fitness-selector` cap their own JSON parsing at 1 MiB
(`aether::MAX_SENSE_EVENT_BYTES`) before decoding a topic body.) Progress frames preserve the
originating command `corr`, so clients can attach `"compiling…"` to the right request. The surface holds no kernel:
HTTP JSON bodies and protected raw query strings are capped before typed
extraction, and body/query string fields are byte-capped before `Verb`
construction, so one request cannot turn into oversized retained command
metadata. The public WebSocket upgrade scans only a bounded raw `token` query.
Every verb, including reads, is a `Role::CONTROL` round-trip, answered inline by
the co-located `ControlCore`. Its pending `corr → oneshot` table is bounded too:
if too many HTTP requests are already waiting on control replies, the surface
returns `503` with `surface-busy` instead of allocating another parked request
until a timeout drains.

### surface-mcp and the MCP control-hub

The thing an MCP host spawns is itself a **headless Alpha Sanctum** participating
in the GAWD fabric, in an MCP control-hub profile — `alpha mcp`. There is no shim
process: the `surface-mcp` creature owns the process stdin/stdout directly,
terminates newline-delimited JSON-RPC 2.0 (tools-only, protocol `2025-11-25`),
and turns each tool call into a `Verb` envelope on the node's own bus. The MCP
server *is* a bus citizen, not an HTTP client. Like the HTTP surface, it bounds
its parked `corr → reply` table and returns a structured `surface-busy` result
inside the tool response instead of allocating unbounded waiters.
Tool-call arguments are validated against the advertised schema before `Verb`
construction, with byte caps on string fields and bounded previews for unknown
method/tool/parameter names, so a hostile stdio peer cannot turn one line into
retained command metadata or an attacker-sized error response. The initialize
handshake also caps any client-supplied `protocolVersion` before reflecting it.
On shutdown it asks the stdio loop to stop, joins it if stdin has reached EOF, and
otherwise detaches the still-blocked reader rather than hanging node teardown on
an uninterruptible `read_line`.

The server id is `alpha-mcp` and the tool verbs are `alpha_*` —
`alpha_status` / `alpha_list` / `alpha_journal` / `alpha_watch` /
`alpha_cluster` / `alpha_registry_fetch` / `alpha_registry_list` /
`alpha_bestiary_prove` read-only (carrying `readOnlyHint`), and `alpha_author` /
`alpha_author_critter` / `alpha_load` / `alpha_registry_publish` / `alpha_send` /
`alpha_intent` / `alpha_bind` / `alpha_unload` / `alpha_cluster_connect`
mutating, plus the `alpha_ai_status` announcement. One binary, two profiles, one
`ControlTarget`:

- **Local (default)** — the hub boots its own `authoring` / `build` /
  critter-builder organs and a `ControlCore`, and the surface targets
  `ControlTarget::Local`: a self-contained MCP server that authors, loads, and
  runs on itself. `--minimal` skips the organs for a bare control-only plane.
- **Remote (`--target <node-id@control-id>` + `--seed …`)** — the hub joins the
  mesh and targets `ControlTarget::Node`; the verb crosses to the peer's own
  `ControlCore`, which resolves `authoring` and `build` *there*. No local organs.

Because the hub joins the mesh as a node, "reach a remote sanctum" is the
authenticated mesh, not a new problem. Mesh-peer trust only *delivers* the
control envelope to the target's `Role::CONTROL`; the target node's own allow-AI
gate, admission policy, and the control responder's capability scope still decide
whether to *act* — defense in depth. The real security surface is provisioning:
which identity key the hub carries and which realm(s) it may join. MCP stays the
world's protocol, terminated at the boundary, never absorbed into the cosmology.

## Human and AI share one node

A human at the REPL and an AI over MCP co-drive the *same* live node, safely and
visibly. The node-level `AiControl` is a shared allow-AI gate plus an AI activity
status. The gate defaults **off**:

- The **local REPL is never gated** — the terminal is the trusted human seat, so
  it drives `run_verb` directly, ungated.
- A **gated (remote) front-end** — the HTTP plane, the MCP hub, any control over
  the bus — may not run a *mutating* verb until a human grants access (`allow-ai
  on` at the REPL, or `--allow-ai` at boot). A blocked mutation returns a clear
  `ai-not-allowed` error (HTTP 403). The gate is checked inside `run_verb`
  itself, exactly once, the single home for the decision.
- **Read-only verbs are never blocked by allow-AI** — HTTP reads still require
  the Bearer key; MCP reads require access to the spawned hub and, in remote mode,
  its mesh identity. An AI can always observe once it has reached the control
  surface, but it only acts under grant.

`ControlCore` runs gated, because control over the bus is a remote front-end; the
mutating verbs (`author`, `author --critter`, `load`, `registry publish`, `send`,
`intent`, `bind`, `unload`, `cluster join`) are exactly the ones the gate guards.
`allow-ai` itself
is REPL-only — a gated caller cannot flip its own gate. The AI announces what it
is doing through `alpha_ai_status`, surfaced live on the operator's tape and the
WebSocket stream, so a human can watch the AI work and revoke mid-flight. The
activity/message text is stripped of terminal control characters and bounded in
the shared `omni` state, so HTTP, MCP, and direct bus control all store and
display the same safe text.

The allow-AI gate and a surface's capability scope are two independent levers.
Each surface emits under its own id, so the router's `calls` allowlist — the
unchanged choke point that gates every dispatch — bounds what a surface may
address. A capability scope says *what a surface can touch*; the human-held
allow-AI gate says *whether an AI may act at all right now*. Control rides
capability and identity, never around them.

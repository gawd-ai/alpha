# Identity, transport, and clustering

How two Sanctums learn to trust each other, carry envelopes between them, and assemble into a
self-forming mesh. This is the seam where a single node becomes a Realm: a daemon authored on one
Sanctum runs on another only after the two nodes have authenticated, so identity comes first,
transport second, clustering third.

The whole subsystem is **fabric, not model**: the substrate ships the mechanism — ed25519 sign and
verify, an authenticated link, gossip membership — and never decides *which* keys are trust roots.
That decision is injected policy. The kernel ships sockets, not opinions about who to trust.

## Node identity

Each Sanctum carries one **node key**: an ed25519 keypair, held in `sigil` as
`Ed25519KeyMaterial`. It is derived from a 32-byte seed, and the seed (not the unwrapped private
key) is what persists — so the same value drives a reproducible test fixture and a production
identity alike. An operator generates a seed once, persists it, and the node's public identity is
stable across restarts (ed25519 derivation and signing are deterministic; the same seed always
yields the same public key and the same signature for a payload).

Keys and signatures are lowercase hex everywhere they touch the wire, a manifest, or a config line,
so identity survives JSON, command-line args, and human eyeballs with no binary handling.

The node key is one of three distinct identities, kept separate on purpose:

| Identity | Lives | Authenticates |
|---|---|---|
| **Node key** (ed25519) | per-Sanctum keystore | the *peer*, on every connection |
| **Abode key** (ed25519) | per-Abode (the distributed self) | the *author* of a creature, in `manifest.provenance.signature` |
| **Verifier** | `sigil::Ed25519Verifier` | nothing — it is the mechanism, root-blind by design |

The verifier answers exactly one question — *is this signature valid for this public key over this
payload?* — and never decides which keys count. Which node keys are admitted is the transport's
allowlist; which Abode keys are trusted authors is the admission policy. Two questions, two seams,
never conflated: one proves the peer, the other proves the artifact's authorship and integrity.

## Authenticated transport

`transport-tcp` is the creature bound to `Role::TRANSPORT`. The router sends every
`Address::Node(_, _)` envelope to whoever fills that role, so "route off-node" is one more delivery
case, not a separate subsystem. An operator who wants a different topology — a hub broker, a routed
overlay — ships their own creature for the role; the fabric picks no network model.

The link is **TCP** (loopback by default, any `host:port` by config). TCP carries the data plane
because it already gives reliable, ordered, backpressured delivery; carrying envelopes over UDP
would mean reinventing exactly that. **UDP transport is out of scope** — for the data plane it is a
rewrite of the stack, and as a discovery base it cannot be relied on (multicast/mDNS is routinely
blocked on cloud VPCs and absent across WANs). Seed-plus-gossip over TCP works on any network that
can open a connection.

### The handshake

Before any envelope crosses, both sides run a **mutual ed25519 challenge-response**:

1. Each side sends its public key and a fresh 32-byte nonce (from the OS RNG; the handshake
   **fails closed** if the RNG is unavailable rather than proceed with a weak nonce).
2. The dialer first checks the listener's offered public key is the one it meant to dial.
3. The listener looks up the dialer's public key in its allowlist; an unknown key is refused
   (`peer_auth_failed:unknown_pubkey`).
4. Each side signs the **transcript** of the exchange and the other verifies it.

The transcript is `b"GAWD-NODE-AUTH-v1:" ‖ peer_nonce ‖ owner_pubkey ‖ peer_pubkey`. Three
properties hold it together:

- **Domain-separated** — the `GAWD-NODE-AUTH-v1:` prefix means a handshake signature is never valid
  in any other ed25519 context the substrate uses (a manifest provenance signature, a commitment).
- **Nonce-bound** — each side signs over the *peer's* fresh nonce, so a transcript captured on one
  connection cannot be replayed on another.
- **Direction-bound** — the pubkeys enter the transcript in a fixed order (owner first, the side
  that minted the nonce), so the dialer's signature and the listener's signature are over different
  bytes and neither can be reused as the other.

A peer that cannot sign with an allowlisted key cannot establish a session. The allowlist is the
trust gate; the ed25519 proof is what binds a connection to an allowlisted identity.

### Frames and bounds

After the handshake, the connection carries length-prefixed frames: a 4-byte little-endian length
followed by a JSON `WireFrame` — either a routed `Envelope` or a membership `Gossip` push, tagged
so both share the one authenticated socket. The bounds keep a hostile or buggy peer from exhausting
the node:

- A frame's length prefix is capped at **128 MB**; an over-cap prefix tears the connection down
  rather than allocating. (128 MB is roomy for shipping a real artifact envelope, tight enough to
  refuse a billion-byte-prefix attack.)
- A single gossip frame is capped at **1024 members** and rejected whole if it exceeds that — a
  ceiling on how many dialer threads one message can spawn, not a topology limit.
- Each admitted cluster member is shape-checked before retention or allowlisting: node ids are
  bounded printable routing tokens (256 bytes, `[A-Za-z0-9._-]`), pubkeys must decode to a 32-byte
  ed25519 key and are stored as canonical lowercase hex, and dial addresses are bounded IP socket
  addresses (`127.0.0.1:9001`, `[::1]:9001`).
- An explicit gossip advertise address is run through that same dial-address shape check before it
  can enter this node's self gossip entry; a bad override is ignored and the listener address
  remains the advertised default. The effective advertise address is checked too — if it would be
  refused by receiving peers (a hostname listener, say), the node says so at boot rather than
  implying the fallback propagates.
- `transport.ctl` request payloads are capped at **64 KiB** before JSON decode, and typed replies
  are capped at **1 MiB** before callers decode them. The control contract only carries `Members` or
  one `Connect` member, and the `Connect` fields still pass through the member shape checks above
  before retention.
- Per-peer outbound queues are bounded and **shed on overflow** (`try_send`), and an outbound frame
  that exceeds the 128 MiB wire cap is refused before it can sit in a peer queue. A slow peer applies
  backpressure instead of growing memory without bound. A shed frame is surfaced as a
  `peer_send_dropped` event rather than vanishing silently. Because envelope payloads serialize as
  hex (2x expansion), the frame cap means an artifact over roughly half the 128 MiB artifact ceiling
  cannot cross the wire in one envelope today — cross-node shipping of larger artifacts needs a
  chunked path, and the sender now sheds such a frame loudly instead of letting the receiver
  tear the link down.

Malformed bytes are dropped quietly — hostile input never panics a transport thread.

### Re-addressing across the wire

When an `Address::Node(peer, mid)` envelope reaches the transport, the local sender addressed a
creature `mid` on `peer`; the transport frames it and ships it. On the receiving node the inbound
frame names `Node(receiver, mid)`, which the transport unwraps to a local `Creature(mid)`
delivery. Two header rewrites make a reply find its way home:

- **`reply_to` is resealed.** A `reply_to: Creature(x)` from the peer means "creature `x` on the
  peer node" from the receiver's vantage, so it is rewritten to `Node(peer, x)` — the eventual
  reply routes back across the same link to the original requester.
- **`from` is resealed by the local bus** to the transport creature's own id. The original
  cross-hop sender identity is carried by the (rewritten) `reply_to`, not by `from`.

`corr`, `schema`, and `commitment` ride through untouched: `corr`/`schema` are what match a reply
to its request across the boundary, and `commitment` is the commit-and-reveal slot a receiving
Realm may need to verify — dropping it would silently defeat cross-node commit-and-reveal.

### Kernel control is local-only

The reserved `KERNEL_ID` inbox drives `KernelControl` — unloading a creature, extending a budget.
A remote peer must never reach it. The transport **refuses any inbound frame addressed to the local
`KERNEL_ID`** at the wire boundary, which is the one place the off-node origin is still visible (the
bus reseals `from` before any local listener sees the envelope). Admitted peers are trusted to route
*data* across the mesh; they are never trusted to drive a peer node's kernel. The trust granted by
admission and the trust required to command a kernel are different trusts, and this boundary keeps
them apart.

## Dynamic clustering

A static O(N²) peer config on every node is not a cluster. A node joins a **many-to-many mesh
dynamically** from one or more seeds, membership **propagates by gossip** over the same
ed25519-authenticated link, and the resulting graph is **observable**.

Clustering is the existing transport creature plus gossip — no new substrate primitive, no new
socket, no new dependency. Membership is bus traffic and wire frames, observable on the same sense
stream everything else uses.

### Joining a mesh

`alpha node --cluster-listen <addr> --node-id <id>` boots the transport in gossip mode, bound to
`Role::TRANSPORT`. With no key it mints a fresh node key and prints the seed and public key so they
can be persisted (and reused via `--cluster-key <hex>`); it prints the join line peers use to reach
it. Each `--seed <id@host:port#pubkey>` is a bootstrap peer the node dials at boot.

A joining node dials a seed; the seed's allowlist is mutable, so once the seed has admitted the
newcomer (the first admission of a node is an operator/AI action — `cluster join
<id@host:port#pubkey>` at the REPL, or the allow-AI-gated control surface), the handshake succeeds
and gossip takes over from there.

### Gossip membership

On every successful connection a node pushes its **full member view** to the new peer as a `Gossip`
frame. On receiving gossip a node admits and dials any member it does not already know (skipping
itself and peers it is already connected to or dialing); if it learned anything new it re-broadcasts,
so a fresh member floods to the rest of the mesh. The mesh **self-completes from a single
introduction** — one seed is enough for the graph to close.

Gossip is event-driven: pushed on connect, re-flooded only when membership changes. It is
best-effort — there is no periodic re-gossip, and a gossip frame is shed if a peer's send queue is
saturated. For the tens-of-nodes range this converges reliably (queues are idle at join time). The
mesh is a **full mesh** — every node dials every member it learns — which fits the tens-of-nodes
range; a partial-mesh overlay is a different shape this release does not ship.

### Trust model

The handshake mechanism is untouched: every link is still mutually ed25519-proven against the
allowlist in force at that instant. What gossip changes is *who is in the allowlist*. ed25519 proves
**identity**; admission grants **routing**. The first introduction of any node is gated at the
control surface (an operator or an allow-AI-gated AI). From there, gossip propagates that membership
**transitively** across the authenticated mesh: **you route data with whomever your already-trusted
peers vouch for.**

That transitivity is the model's boundary. The first admission is gated, but gossip propagation is
not signed — a compromised member can gossip a bogus member, and its already-admitted peers will
dial it. Admitted peers are trusted to route data, nothing more: they cannot reach a peer's kernel
(the `KERNEL_ID` refusal above), and the *artifact* trust gate is separate — a creature still has to
pass the receiving node's admission policy (signed manifest, known author, intact bytes) before any
foreign code runs. Network admission and code admission are two gates; clearing one never clears the
other.

### Observing the graph

The graph is two things, both already on the bus:

- **The member view** — `cluster` at the REPL (or the control surface's cluster query) asks the
  transport for its `Members`: this node, every known member, and which are presently connected.
- **The change stream** — the transport publishes `peer_event` (connected, disconnected,
  auth-failed, admitted) on `Topic::PROPRIOCEPTION`, which the monitor renders and the WebSocket
  surface streams. Subscribing to topology changes is free; it is the same nervous system every
  other sense rides.

### Cross-node send

`send <node-id>:<id> <text>` addresses creature `id` on node `node-id` — it builds an
`Address::Node`, which the router hands to the transport, which ships it to the peer and reseals the
reply path so the answer routes back. A bare `send <id>` stays local. The cross-node form waits
longer for a reply than the local form, because a healthy-but-distant peer is a full mesh round-trip
plus the peer's own handling away.

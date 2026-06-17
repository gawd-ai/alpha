# TRD-002 — Cross-node origin & relay integrity

- **Status:** Met (v0.4.3)
- **Theme:** Hardening (load-bearing for the v0.5.0 cross-mesh headline)
- **Spawns:** [ADR-0038](../adr/ADR-0038-origin-stays-hop-by-hop.md) (origin stays hop-by-hop),
  [ADR-0039](../adr/ADR-0039-nested-reply-to-rewrite.md) (nested `reply_to`),
  [ADR-0040](../adr/ADR-0040-replay-guard-reconnect.md) (replay across reconnect),
  [ADR-0041](../adr/ADR-0041-origin-verdict-posture.md) (verdict enforcement posture).
- **Why now:** v0.5.0 puts model-backed agents in genuine cross-Realm conversation. The substrate that
  carries those envelopes must be *attributable, correctly routed, and replay-defined* **before** the
  agents arrive — otherwise v0.5.0 inherits subtle wire bugs disguised as agent bugs.

## Scope

Specify the integrity properties of a cross-node envelope from the moment a peer's frame is verified at
the transport boundary, through any in-fabric **relay** (gateway / federator / dialogue creature), to
final delivery and reply. Three properties: **attribution** (who really sent it), **routing**
(`reply_to` resolves across grain), and **replay** (a frame is not delivered twice).

## Ground truth (verified)

- Inbound cross-node frames **are** origin-attested by the transport:
  `bus.emit_attested(dispatch, Origin::node(peer))` (`cosmos/creatures/transport-tcp/src/lib.rs:1514`),
  gated by `may_attest`. A non-attesting transport relays with no origin (`:1483-1492`).
- `Origin`-sealing is a **boot-only kernel grant** (`may_attest`), conferred by *how the kernel loads*
  the creature, never declared by an artifact, *"so a signed/authored creature can never grant itself
  the power to forge a cross-node origin"* (`cosmos/aether/src/bus.rs:83-91`).
- A creature **can read** inbound origin: `Envelope.header.origin: Option<Origin>`
  (`cosmos/aether/src/envelope.rs:74`). A creature **cannot set** origin on what it emits: `Dispatch`
  has no origin field (`cosmos/aether/src/instance.rs:16-24`); only `emit_attested` seals it
  (`bus.rs:244-253`).
- `reply_to` rewrite at the boundary handles only `Creature → Node`; `Realm`/`Omega` fall through
  unrewritten: `Address::Creature(mid) => Node(peer, mid), other => other`
  (`transport-tcp/src/lib.rs:1463-1466`).
- Replay guard is a per-`(peer, sender)` high-water mark (`is_replayed_seq`, `:1525-1535`) **reset on
  reconnect** (`reset_origin_watermarks`, `:1539-1541`) — intentional, to admit a fresh session's
  restarted `seq`.

## Requirements

- **R1 — Origin is hop-by-hop and unforgeable; end-to-end agent identity is application-signed.** v0.4.3
  MUST NOT add a creature-settable origin field (it would be forgeable, breaking `bus.rs:83-91`). The
  transport `Origin::node(peer)` correctly attributes the *immediate* peer and MUST remain so. For the
  v0.5.0 requirement "the original requester knows which agent answered," v0.4.3 MUST **specify** an
  application-layer signed-provenance shape carried *inside* the dialogue body (the responder signs its
  answer), so authenticity is end-to-end and independent of hop-by-hop transport origin. See ADR-0038.
- **R2 — Nested `reply_to` resolves across federation grain.** A reply addressed
  `reply_to = Realm{realm, Creature(mid)}` or `Omega{realm, Creature(mid)}` MUST route back correctly
  across the node boundary. The transport rewrite MUST recurse into the boxed inner target rather than
  passing nested grain through unchanged. See ADR-0039.
- **R3 — Replay semantics are defined and tested.** The session-scoped guard is acceptable, but the
  cross-session behavior (reconnect resets the watermark ⇒ a crashed-and-restarted peer could re-present
  an old-session frame) MUST be **explicitly specified**: the bus does not promise exactly-once across
  sessions; applications that need it use `corr` + idempotency. A reconnect-replay test MUST pin the
  chosen behavior. See ADR-0040.
- **R4 — `BadSig` posture is explicit and operator-visible.** The router is correctly non-enforcing
  (R5-style): a `BadSig` verdict is *published*, not *dropped* (`transport-tcp/src/lib.rs:1502-1512`).
  v0.4.3 MUST make the consequence operator-visible — a recommended default immune-response binding
  and/or a `SECURITY.md` warning that, absent a bound `Role::IMMUNE_RESPONSE` acting on
  `OriginVerdict::BadSig`, forged-signature frames are admitted. See ADR-0041.
- **R5 — Relay attribution is documented end-to-end.** Each in-fabric relay path
  (`omega-federator`, `realm-gateway`, `dialogue-initiator`) MUST have a one-paragraph doc stating what
  it preserves (`reply_to`, `corr`, `commitment`, payload bytes) and what it does *not* (origin —
  hop-by-hop only), so v0.5.0 authors don't assume transport origin survives a relay.

## Findings register

| Finding | Status | Evidence |
|---|---|---|
| Inbound frames are origin-attested at transport | **Verified** | `transport-tcp:1514` |
| Creature can read but not set origin (anti-forgery by design) | **Verified** | `envelope.rs:74`, `instance.rs:16`, `bus.rs:83-91` |
| "Add `Dispatch.origin` to fix relay attribution" | **Down-ranked** | would be forgeable; replaced by R1 app-signing |
| `reply_to` nested grain not rewritten | **Verified** | `transport-tcp:1463-1466` |
| Replay watermark resets on reconnect | **Verified** | `transport-tcp:1525-1541` |
| `BadSig` is published, not enforced | **Verified** | `transport-tcp:1502-1512` |

## Acceptance

- ADR-0038 lands the signed-dialogue-provenance *spec* (reserved shape + doc), with a test that a
  relayed answer's *content* authenticity is verifiable independent of transport origin.
- A cross-node integration test sends a request with `reply_to = Realm{…, Creature(mid)}` and asserts the
  reply arrives at the right creature on the right node (ADR-0039).
- A reconnect-replay test pins the ADR-0040 behavior.
- `SECURITY.md` documents the `BadSig`-admission consequence; composition roots show the recommended
  immune binding (ADR-0041).
- Each relay creature's module doc states its preserve/not-preserve contract (R5).

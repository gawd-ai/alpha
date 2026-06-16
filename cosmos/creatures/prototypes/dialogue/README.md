# `dialogue/` — the agent-to-agent dialogue seam (SEER `dialogue` topic)

Every other SEER consumer answers *upward* — back to whoever asked it. A **dialogue** is the
exception: one agent opens a conversation by sending a turn to a **named peer**, the peer answers, and
the `(corr, query_id)` thread carries a back-and-forth of any length. This is the seam the v0.5.0
headline rides — two model-backed agents conversing across the mesh — and the reference pair here is
its reduced, runnable form.

| Crate | Role | The injected part |
|---|---|---|
| [`dialogue-initiator`](dialogue-initiator) | opens a conversation: sends a turn to a peer named by a plain `aether::Address` (local `Creature`, cross-node `Node`, or cross-Realm `Omega`), parks the requester by `corr`, relays the peer's reply back | the **peer address** (constructor) — point it at `Omega{realm, …}` and the conversation crosses a Realm boundary with no other change |
| [`dialogue-responder`](dialogue-responder) | the peer half: answers a turn with an injected `Responder` model (the reference `EchoResponder` echoes the prompt) over the shared [`seer::responder`] skeleton | the **`Responder`** — fork it into an LLM call |

Both build on the same primitives as the other seams: the initiator reuses `seer::responder::classify`
as its inbound gate (it's a SEER consumer of the `Answer` that also handles a non-SEER trigger), and
the responder reuses `seer::responder::respond_query`. Because the peer is a plain `Address` and
replies ride `reply_to` (rewritten by transport on the cross-node path), the *same* two creatures work
in-process, across nodes, and across Realms.

See it run end to end: `cargo run -p dialogue` (or `alpha demo dialogue`) stands up two Realms over
real TCP and has an initiator on one hold a multi-turn conversation with a stateful agent on the other,
through the Omega gateway.

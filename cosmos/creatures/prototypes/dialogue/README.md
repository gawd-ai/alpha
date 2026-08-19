# `dialogue/` — the agent-to-agent dialogue seam (SEER `dialogue` topic)

Every other SEER consumer answers *upward* — back to whoever asked it. A **dialogue** is the
exception: one agent opens a conversation by sending a turn to a **named peer**, the peer answers, and
the `(corr, query_id)` thread binds that exact turn. A composition can causally chain bounded turns
without introducing a transcript protocol. This is the seam the v0.5.0 headline rides—three
model-backed minds causally fanning exact contributions out and in through ordinary pairwise
turns—and the reference pair here is its reduced, runnable mechanism.

| Crate | Role | The injected part |
|---|---|---|
| [`dialogue-initiator`](dialogue-initiator) | opens a conversation: sends a turn to a peer named by a plain `aether::Address` (local `Creature`, cross-node `Node`, or cross-Realm `Omega`), parks the requester by `corr`, and relays the peer's reply back; when a peer key is pinned, both answers and aborts are authenticated before the parked turn is consumed | the **peer address** (constructor), plus optional verifier and expected signer — point the address at `Omega{realm, …}` and the conversation crosses a Realm boundary with no other change |
| [`dialogue-responder`](dialogue-responder) | the peer half: the legacy immediate path answers through an injected `Responder` (`EchoResponder` is the reference); additive `DialogueMind` runs a blocking `mind::Model` in a bounded off-drain worker and signs the existing `AnswerBody` for both successful answers and terminal abort reasons | choose the immediate **`Responder`** or inject a **`mind::Model` + signer** into `DialogueMind` |

Both build on the same primitives as the other seams: the initiator reuses `seer::responder::classify`
as its inbound gate (it's a SEER consumer of the `Answer` that also handles a non-SEER trigger), and
the immediate responder reuses `seer::responder::respond_query`; `DialogueMind` keeps the same gate
and wire while moving blocking model work off the drain thread. Because the peer is a plain `Address` and
replies ride `reply_to` (rewritten by transport on the cross-node path), the *same* two creatures work
in-process, across nodes, and across Realms. A `DialogueMind` abort reuses `AnswerBody` provenance:
its signature binds `(corr, prompt, reason)`, so a signer-pinned initiator rejects unsigned or
wrong-key terminal moves without evicting pending state. The legacy plain-string abort remains
accepted only when no peer signer is pinned.

See it run end to end:
`CARGO_BUILD_JOBS=1 CARGO_INCREMENTAL=0 nice -n 10 cargo run --locked -p dialogue`
(or `alpha demo dialogue`) stands up two in-process Kernel nodes in two Realms over authenticated
TCP and runs a strict four-turn Builder / Reviewer / Contract Tester collaboration through the Omega
gateway. Each signer-verified answer is decoded into a bounded causal decision; the final Builder
approval is the exact projection of the draft, materially narrowing review, and tester-selected
cases. The accepted value is a source-free `affine_i32_v1` profile. The same Builder Model injection
confirms three digest-bound implementation records, and trusted host templates lower them into Rust,
no-import WAT, and Rhai before the tier builders sign. A durable Bestiary recovers the outputs, and
three distinct `FunctionId`s each execute one local and one cross-Realm Job.

Default/`--fixture` uses strict scripted Models and is credential-free regression only. v0.5 product
acceptance requires the demo README's fresh exact-commit `--live` run, retained provider receipts and
proof bundle, verified evidence index, and external operator-signed seal. Neither posture adds a
broadcast/group-chat protocol or durable group transcript, and neither proves arbitrary code,
general agency, provider weights, or a three-process Sanctum deployment. The composition performs one
bounded native Cargo compile; beast/critter builds invoke no Cargo.

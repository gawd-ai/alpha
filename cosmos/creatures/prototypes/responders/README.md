# responders — reference standing SEER consumers (NOT substrate)

Reference creatures that **stand** on a SEER topic: bind one topic, answer every `Query` on it. SEER
([`cosmos/seer`](../../../seer)) ships a closed set of topics, each with a typed `Query`/`Answer`
body. Several topics shipped a body but no creature to consult — these fill that gap so the reserved
topics are demonstrably stand-on-able, not just declared.

Each binds one topic and routes through the shared [`seer::responder::respond_query`](../../../seer/src/responder.rs)
skeleton (schema check → bounded parse → topic isolation → `Query`-only → typed decode → shape check →
decide → reply on `reply_to`). The **decision** is the only part each crate writes; it is the
operator-replaceable model. Real deployments fork the decision and keep the skeleton.

| Crate | SEER topic | Decides |
|---|---|---|
| `responder-policy` | `policy` | admit a manifest whose hash is allow-listed (or admit-all in the explicit dev posture) |
| `responder-budget` | `budget` | grant up to a per-request ceiling, optionally from a finite depleting pool (the stateful exemplar) |
| `responder-fitness` | `fitness` | score a content-addressed candidate via an injected `Rater`; clamp `[0,1]`, non-finite folds to `0` (fail-closed) |
| `responder-curation` | `curation` | answer `keep` / `gc` / `quarantine` for a Bestiary entry from configured lists (default `keep`) |

The other SEER topics already have live consumers: `placement` (`embodiment-advertiser` +
`distributor-requirements`), `authoring` (`agent-curious` / `agent-templated`), and `consensus`
(`omega-federator`, with its own signed-reputation body).

The substrate ships none of these decisions — it ships the topic and the responder skeleton. See each
crate's `lib.rs` header and [`CONTRIBUTING.md`](../../../../CONTRIBUTING.md).

# prototypes — injected reference models (NOT substrate)

GAWD's substrate ships **sockets**; operators inject **models**. Everything in this tree is a
*reference* implementation of one such injected seam — the minimal, readable version that proves the
socket and shows the shape an operator's real model takes. **None of it is substrate**; every
deployment binds its own. These are reference *strategies*, not disposable demo material.

These sit in the middle of a **reduction gradient**: production organs above, prototypes
here, the most-reduced test specimens nested below.

- The production-capable reference **organs** live one level up in [the reference organs](..).
- The **test-only** creatures (fault specimens + walking skeleton) live in [`fixtures/`](fixtures) —
  the most reduced prototype. The nesting is the rule: don't make a fixture where a prototype would do.

Organized by the seam each fills — `ls` this directory and you are reading GAWD's extension points:

| Folder | Seam (the socket it fills) | Reference models |
|---|---|---|
| [`critters/`](critters) | Rhai **script-tier creatures** | `echo-critter`, `uppercase`, `rot13`, `contains`, `kv-extract`, `route-by-prefix`, `typed-add-one` |
| [`policies/`](policies) | admission `Policy`, `RestorePolicy`, `QuarantineTrust`, budget policy, Function placement/retry policy | `policy-dev / -signed / -budget / -abode-allowlist / -prefer-promoted / -quarantine-{aware,trust-all,trust-realm} / policy-job-basic` |
| [`scorers/`](scorers) | `FitnessScorer` for `fitness-selector` | `scorer-success-rate / -latency / -roundrobin` |
| [`distributors/`](distributors) | placement `PickModel` for `Role::DISTRIBUTOR` | `distributor-roundrobin` |
| [`reputation/`](reputation) | `ReputationWeigher` for `omega-federator` | `reputation-roundrobin` |
| [`merge/`](merge) | CRDT `MergeModel` for `abode-reconciler` | `merge-lww-map` |
| [`gateways/`](gateways) | federation gateways for the `Realm` / `Omega` grain | `realm-gateway`, `omega-gateway` |
| [`responders/`](responders) | **standing SEER consumers** for the reserved topics (the decision is the injected model) | `responder-policy / -budget / -fitness / -curation` |
| [`dialogue/`](dialogue) | the **agent-to-agent dialogue** pair on the SEER `dialogue` topic — an initiator that names a peer (local / cross-node / cross-Realm `Omega`) + a responder over an injected model | `dialogue-initiator`, `dialogue-responder` |
| [`monitor/`](monitor) | a sense-stream reader (PROPRIOCEPTION + FITNESS) | `monitor` |

Each folder carries a short README naming its socket and its reference(s). Several seams ship one
reference today — the folder marks the seam, which is *meant* to grow. To write your own: copy the
nearest reference, swap the model, bind it into the socket (see [`CONTRIBUTING.md`](../../../CONTRIBUTING.md)).

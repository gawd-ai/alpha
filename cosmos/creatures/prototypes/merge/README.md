# merge — injected CRDT `MergeModel` (NOT substrate)

Reference conflict-free merge lattices for [`creatures/abode-reconciler`](../../../creatures/abode-reconciler).
The reconciler takes two divergent signed snapshots of the *same* Abode and merges
them into one re-signed snapshot; the merge **semantics** are an injected model — the substrate ships
the reconciler socket + the verify/sign primitives, not the lattice.

| Crate | Lattice |
|---|---|
| `merge-lww-map` | Last-Writer-Wins Element-Map over a JSON object `{key: {v, ts}}` — commutative, associative, idempotent, so it converges regardless of order |

Operators write their own (OR-Set, RGA, domain-specific).

# distributors — injected placement `PickModel` (NOT substrate)

Reference placement creatures bound to `Role::DISTRIBUTOR` (the `Intent` socket) — they take an Intent
and pick which creature serves it.

| Crate | Strategy |
|---|---|
| `distributor-roundrobin` | a minimal round-robin reference over the Intent/IoC socket |

The full, requirements-aware Distributor is the organ
[`creatures/distributor-requirements`](../../../creatures/distributor-requirements) (consults SEER on
the `placement` topic). Both are creatures that fill the same socket — two can coexist and the operator
binds one. Write your own `PickModel` and bind it the same way.

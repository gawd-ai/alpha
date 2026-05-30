# reputation — injected `ReputationWeigher` (NOT substrate)

Reference reputation-weight models for [`creatures/omega-federator`](../../../creatures/omega-federator).
The federator propagates signed reputation across Realms; how much each attestation *weighs*
is an **injected** model, not a substrate rule.

| Crate | Weighs |
|---|---|
| `reputation-roundrobin` | every signed attestation weighs 1.0 (the bare-minimum reference) |

Operators write their own (EWMA over recent attestations, realm-allowlist, VRF-weighted, …).

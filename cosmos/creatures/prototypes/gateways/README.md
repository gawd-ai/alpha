# gateways — injected federation gateways (NOT substrate)

Reference gateway creatures for the `Realm` / `Omega` address grain. They route the cross-Realm /
cross-Omega address cases; the substrate ships the address grain, operators bind the routing.

| Crate | Routes |
|---|---|
| `realm-gateway` | `Address::Realm` envelopes to the configured peer for the named Realm (single-peer-per-Realm reference) |
| `omega-gateway` | a minimal Omega seam — replies `omega.deferred`, the structured commitment that the Omega dispatch arrived; operators bind a real federator for the mechanism |

The full cross-Realm federation organ is
[`creatures/omega-federator`](../../../creatures/omega-federator).

(For the address grain, the Distributor, and federation see
[the addressing/placement/federation design note](../../../../docs/design/addressing-placement-federation.md).)

# Design notes

How Alpha works, by subsystem. Each note describes what ships — the mechanism, and the reasoning that
shapes it. For the cosmology and vocabulary, start with [CONCEPTS](../CONCEPTS.md); for the structure
and layout, [ARCHITECTURE](../ARCHITECTURE.md).

- [The substrate: creatures, the ABI, and the tiers](substrate.md) — the three execution tiers, the
  `gawd_creature_v1` ABI, the signed manifest, safe unload, and the capability model.
- [Inversion of control: sockets, not strategies](inversion-of-control.md) — fabric vs. model, the
  role sockets, the self-authoring loop, and authoring as a conversation.
- [The bus, SEER, and the control plane](bus-and-control.md) — the `aether` bus, the SEER
  Query/Answer primitive, and control as bus traffic over loadable surfaces.
- [Identity, transport, and clustering](identity-transport-clustering.md) — node identity, the
  authenticated transport, and the self-forming gossip mesh.
- [Addressing, placement, and federation](addressing-placement-federation.md) — the address grain,
  the registry, the Distributor, Realm and Omega, and verifiable randomness.
- [The distributed self and evolution](distributed-self-and-evolution.md) — the Abode, migration and
  fork/merge, the evolutionary loops, and limits as gradients.

# ADR-0040 — Replay guard across reconnect

- **Status:** Implemented (v0.4.3)
- **Drives:** [TRD-002](../trd/TRD-002-cross-node-relay-integrity.md) R3
- **Date:** 2026-06-16

## Context

The transport's replay guard tracks a per-`(peer, sender)` high-water mark and drops any frame whose
`seq` does not advance it:

```rust
// cosmos/creatures/transport-tcp/src/lib.rs:1525-1535
fn is_replayed_seq(state, peer, sender, seq) -> bool {
    match wm.get(&(peer, sender)) { Some(&last) if seq <= last => true, _ => { wm.insert(..); false } }
}
```

On a fresh handshake the watermarks for that peer are wiped (`reset_origin_watermarks`, `:1539-1541`),
so the new session's restarted `seq` stream is not mistaken for a replay. This is intentional and correct
*within* a session. The consequence: a peer that crashes and reconnects can re-present a frame from the
*previous* session with a `seq` the cleared map no longer remembers — i.e. the guard is **session-scoped,
not cross-session**. The bus has never promised exactly-once delivery, so this is a *specification gap*,
not a regression — but it must be pinned before v0.5.0 leans on cross-node dialogue.

## Decision

**Accept the session-scoped guard and specify the contract**, rather than add persistence/generation
tokens:

1. Document that the replay guard is **session-scoped**: it prevents intra-session replay and is reset by
   a fresh authenticated handshake. The bus does **not** guarantee exactly-once across sessions.
2. State the application-level contract: components that require exactly-once across reconnects use `corr`
   + idempotent handling (the dialogue/SEER reduction theorem already keys on `corr`).
3. Keep the door open: note generation-token / persisted-watermark as the future option if a concrete
   need arises (out of v0.4.3 scope — it adds durable state to a transport that is otherwise
   memory-only).

Rationale: persisting watermarks introduces durable per-peer state and a new failure mode (stale marks
across restarts) for a guarantee the architecture deliberately pushes to the application layer (R5 / "take
no side on order"). The cheap, honest move is to *specify* the boundary and test it.

## Consequences

- No new durable state; the transport stays memory-only and simple.
- The exactly-once expectation is explicit, so v0.5.0 agent authors key on `corr` rather than assuming
  transport dedup.
- A reconnect-replay remains *possible*; a test pins it as known/accepted, not surprising.

## Implementation sketch

- **Files:** `cosmos/creatures/transport-tcp/src/lib.rs` — doc-comment on `is_replayed_seq` /
  `reset_origin_watermarks` stating session-scope; a line in `SECURITY.md` / TRD-002.
- **Wire-additivity:** **None.**
- **Test:** an integration test that simulates session A (frames `seq 1..N`), a reconnect (watermark
  reset), then re-presents an old-session frame and asserts current behavior (delivered), documenting it
  as the accepted contract; plus the existing intra-session replay-drop test stays green.

## Related

TRD-002; ADR-0041 (verdict posture — same "publish/specify, don't silently enforce" philosophy).

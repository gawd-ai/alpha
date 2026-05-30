//! Loopback transport gateway — proves **R4** by genuinely crossing a byte boundary.
//!
//! When the kernel routes a `Node`-addressed envelope, the router delivers it to whoever is bound
//! to [`Role::TRANSPORT`](aether::Role::TRANSPORT). This in-process creature is the stand-in for
//! a real peer link: it serializes the envelope to bytes, writes them to one end of a Unix
//! `socketpair`, reads them back from the other end, deserializes, and re-routes to the inner
//! `Creature(target)` — preserving `reply_to` / `corr` / `schema` so the eventual reply finds the
//! original requester directly. `transport-tcp` swaps the socketpair for an authenticated peer channel.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use aether::{Address, Creature, CreatureCtx, Dispatch, Envelope, Outcome};

pub struct LoopbackGateway {
    write_end: UnixStream,
    read_end: UnixStream,
}

impl LoopbackGateway {
    pub fn new() -> std::io::Result<Self> {
        let (a, b) = UnixStream::pair()?;
        Ok(LoopbackGateway { write_end: a, read_end: b })
    }
}

impl Creature for LoopbackGateway {
    fn bind(&mut self, _ctx: CreatureCtx) {}

    fn handle(&mut self, env: Envelope) -> Outcome {
        let target = match &env.header.to {
            Address::Node(_, m) => *m,
            // Anything else is not for the transport (defensive — the router should not deliver
            // non-`Node` envelopes here).
            _ => return Outcome::none(),
        };

        // Serialize and physically push bytes through the socket — *that* is the boundary proof.
        let bytes = env.to_bytes();
        let len = (bytes.len() as u32).to_le_bytes();
        if self.write_end.write_all(&len).is_err() || self.write_end.write_all(&bytes).is_err() {
            return Outcome::none();
        }

        // Read them back from the paired socket and reconstruct the envelope.
        let mut len_buf = [0u8; 4];
        if self.read_end.read_exact(&mut len_buf).is_err() {
            return Outcome::none();
        }
        let n = u32::from_le_bytes(len_buf) as usize;
        let mut buf = vec![0u8; n];
        if self.read_end.read_exact(&mut buf).is_err() {
            return Outcome::none();
        }
        let restored = match Envelope::parse(&buf) {
            Ok(e) => e,
            Err(_) => return Outcome::none(),
        };

        // Re-address to the local target creature, **preserving the trust + reply fields** so the
        // eventual reply finds the *original* requester directly (R8 reply_to discipline).
        let mut d = Dispatch::to(Address::Creature(target), restored.payload)
            .with_schema(restored.header.schema);
        if let Some(rt) = restored.header.reply_to {
            d = d.with_reply_to(rt);
        }
        if let Some(corr) = restored.header.corr {
            d = d.with_corr(corr);
        }
        Outcome::send(d)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aether::{CreatureId, Header, NodeId};

    fn node_env(
        target: CreatureId,
        payload: &[u8],
        from: CreatureId,
        reply_to: Option<CreatureId>,
    ) -> Envelope {
        Envelope {
            header: Header {
                from: Address::Creature(from),
                to: Address::Node(NodeId("self".into()), target),
                reply_to: reply_to.map(Address::Creature),
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: Some(7),
                commitment: None,
                schema: "text".into(),
            },
            payload: payload.to_vec(),
        }
    }

    #[test]
    fn round_trips_a_node_envelope_through_the_socketpair() {
        let mut g = LoopbackGateway::new().unwrap();
        let out = g.handle(node_env(CreatureId(42), b"hello", CreatureId(1), Some(CreatureId(99))));
        assert_eq!(out.dispatches.len(), 1);
        let d = &out.dispatches[0];
        // Re-addressed locally to the inner Creature(target).
        assert_eq!(d.to, Address::Creature(CreatureId(42)));
        // reply_to preserved → reply goes to the *original* requester, not the gateway.
        assert_eq!(d.reply_to, Some(Address::Creature(CreatureId(99))));
        // corr preserved → fire-and-correlate across the byte boundary.
        assert_eq!(d.corr, Some(7));
        // Payload survives the real byte round-trip.
        assert_eq!(d.payload, b"hello");
    }

    #[test]
    fn non_node_envelopes_are_a_quiet_no_op() {
        let mut g = LoopbackGateway::new().unwrap();
        let env = Envelope {
            header: Header {
                from: Address::Creature(CreatureId(1)),
                to: Address::Creature(CreatureId(2)),
                reply_to: None,
                seq: 0,
                causal: vec![],
                stamp: 0,
                sig: String::new(),
                corr: None,
                commitment: None,
                schema: "".into(),
            },
            payload: b"x".to_vec(),
        };
        assert!(g.handle(env).dispatches.is_empty());
    }
}

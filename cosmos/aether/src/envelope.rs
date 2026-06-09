//! The envelope — the contract *in motion*. One typed, signed, ordered object carries every
//! interaction. The Proof-of-trust primitives ride **structurally and model-free**,
//! so no later layer exists "before" them.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sigil::crypto::{hex_decode, hex_encode};

use crate::address::Address;

/// Maximum serialized bytes in an envelope header.
///
/// Payload bytes carry the bulk data and are governed by domain-specific caps. Header fields are
/// routing/control metadata (`Address`, `schema`, `commitment`, etc.) and are cloned into the
/// bounded journal and signed on every send, so they need their own resource floor.
pub const MAX_ENVELOPE_HEADER_BYTES: usize = 128 * 1024;

/// The trust + routing header. The *fabric-set* fields (`from`, `seq`, `sig`, `stamp`) cannot be
/// forged by a creature — creatures emit a [`Dispatch`](crate::Dispatch) and the bus seals these in.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Header {
    /// Sender identity. Sealed by the bus (`BusHandle`).
    pub from: Address,
    /// Destination. Chosen by the sender.
    pub to: Address,
    /// Where a reply should be addressed, **preserved across relays** (resolver, gateway) so the
    /// final responder answers the *original* requester directly — fire-and-correlate without
    /// proxying. `None` → reply to `from` (the immediate sender). Set by the requester, copied by
    /// relays. Part of the signed payload (sender-controlled), unlike `stamp`.
    #[serde(default)]
    pub reply_to: Option<Address>,
    /// Per-sender monotone counter — *order*. Sealed by the bus. No global total order is imposed.
    pub seq: u64,
    /// Happens-before links (causal order). Empty unless a creature asserts causality.
    #[serde(default)]
    pub causal: Vec<u64>,
    /// *Time = a change of state*: a node-logical tick, **never a wall clock**. Sealed by the
    /// router (each routed envelope advances it). Excluded from [`Envelope::signing_payload`]
    /// because it is assigned *after* signing.
    pub stamp: u64,
    /// Permission. Present on every envelope (**R5**); whether it is *required* is injected policy.
    pub sig: String,
    /// Correlation id: matches a reply to its request across arbitrary async / human / external
    /// delay. The spine is message-passing, never blocking RPC.
    #[serde(default)]
    pub corr: Option<u64>,
    /// Commit-and-reveal slot for verifiable randomness / a concealed decision. Scheme is injected.
    #[serde(default)]
    pub commitment: Option<String>,
    /// Schema / content-type of the payload, for typed send/recv across the dynamic boundary.
    #[serde(default)]
    pub schema: String,
}

/// A message in motion: header + opaque payload bytes.
///
/// The payload rides as owned bytes — the **same type local and remote**, so a creature sees
/// only envelopes and a sandboxed beast is a natural citizen (**R4**). A by-reference local fast
/// path (`Arc<dyn Any>`) is a later *additive* optimization that does not touch this shape.
///
/// **The payload serializes as a hex string in JSON, not the default array-of-numbers**
/// (transport efficiency). serde_json renders `Vec<u8>` as `[123, 8, 7, ...]` by default —
/// 3-4 bytes of JSON per byte of payload, plus a `Number` token per byte for the parser to
/// chew through. On an 8 MB shipped artifact that's hundreds of milliseconds of parse time and
/// ~30 MB of wire. Hex is a single `String` token, parses in microseconds, costs 2× wire. The
/// signing-payload path is unaffected — `signing_payload()` appends raw bytes, not JSON-encoded
/// bytes — so this change is wire-format-only and doesn't touch the trust fields.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Envelope {
    pub header: Header,
    #[serde(
        serialize_with = "serialize_payload_as_hex",
        deserialize_with = "deserialize_payload_from_hex"
    )]
    pub payload: Vec<u8>,
}

fn serialize_payload_as_hex<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&hex_encode(bytes))
}

fn deserialize_payload_from_hex<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(d)?;
    hex_decode(&s).ok_or_else(|| serde::de::Error::custom("invalid hex in envelope payload"))
}

impl Envelope {
    /// Deserialize from wire bytes. **Never panics** on hostile input (**R9**).
    ///
    /// Rejects a pathologically deep federation-grain address: `serde_json` already
    /// caps parse recursion at 128 (so this never stack-overflows), but the *semantic* nesting
    /// ceiling belongs to the substrate, not the JSON parser. Both endpoints are checked — `from`
    /// arrives attacker-controlled over transport just as `to` does — and the check happens before
    /// any gateway tries to unwrap the address.
    pub fn parse(bytes: &[u8]) -> Result<Envelope, EnvelopeError> {
        let env: Envelope =
            serde_json::from_slice(bytes).map_err(|e| EnvelopeError::Parse(e.to_string()))?;
        if let Some((len, limit)) = header_size_error(&env.header) {
            return Err(EnvelopeError::HeaderTooLarge { len, limit });
        }
        let depth = env.header.to.nesting_depth().max(env.header.from.nesting_depth());
        if depth > crate::address::MAX_ADDRESS_NESTING_DEPTH {
            return Err(EnvelopeError::TooDeep {
                depth,
                max: crate::address::MAX_ADDRESS_NESTING_DEPTH,
            });
        }
        Ok(env)
    }

    /// Serialize to wire bytes — used only at a real boundary (off-node, into a sandbox). A
    /// well-formed envelope of plain data cannot fail to serialize; [`crate::wire::to_bytes`]
    /// `debug_assert!`s the impossible failure and degrades to empty in release.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::wire::to_bytes(self)
    }

    /// The **raw canonical bytes** a signature commits to: the header with `sig` and `stamp`
    /// cleared (both are fabric-assigned — `stamp` *after* signing), concatenated with the payload.
    /// Returns raw bytes (not a hash) for symmetry with
    /// [`Manifest::signing_payload`](sigil::Manifest::signing_payload) — the signer
    /// hashes internally (`ed25519` hashes the message itself; the `StubSigner` hashes
    /// `key || payload` with SHA-256). Determinism of these bytes is guarded by tests that lock a
    /// known fixture to a known hex digest — any future field change that breaks byte-stability
    /// fails CI loudly rather than silently breaking signatures.
    pub fn signing_payload(&self) -> Vec<u8> {
        // Serialize a *borrowing* view of the header with `sig`/`stamp` zeroed, rather than cloning
        // the whole `Header` (its addresses, strings, and the `causal` Vec) only to null two fields
        // and throw the clone away. This runs on the universal hot path — once per `send` (signing)
        // and once per `route` (verify) — so the per-envelope allocations matter. The view's field
        // set / order / values match `Header`'s derived `Serialize` exactly, so the bytes are
        // identical to the old clone-and-clear form; the
        // `envelope_signing_payload_hash_is_locked_to_a_known_fixture` tripwire fails loudly in CI if
        // that ever drifts.
        #[derive(Serialize)]
        struct SigningHeader<'a> {
            from: &'a Address,
            to: &'a Address,
            reply_to: &'a Option<Address>,
            seq: u64,
            causal: &'a Vec<u64>,
            stamp: u64,
            sig: &'static str,
            corr: &'a Option<u64>,
            commitment: &'a Option<String>,
            schema: &'a str,
        }
        let h = &self.header;
        let view = SigningHeader {
            from: &h.from,
            to: &h.to,
            reply_to: &h.reply_to,
            seq: h.seq,
            causal: &h.causal,
            stamp: 0,
            sig: "",
            corr: &h.corr,
            commitment: &h.commitment,
            schema: &h.schema,
        };
        let mut out = crate::wire::to_bytes(&view);
        out.extend_from_slice(&self.payload);
        out
    }

    /// The address a reply to this envelope should go to: its `reply_to` if set (the original
    /// requester, preserved across relays so the final responder answers the requester directly),
    /// else its immediate `from`. The single home for the resolution
    /// — [`Dispatch::reply_to_env`](crate::Dispatch::reply_to_env) and
    /// [`Outcome::reply`](crate::Outcome::reply) both build on it.
    pub fn reply_target(&self) -> Address {
        self.header.reply_to.clone().unwrap_or_else(|| self.header.from.clone())
    }
}

pub(crate) fn header_size_error(header: &Header) -> Option<(usize, usize)> {
    let len = serde_json::to_vec(header)
        .map(|bytes| bytes.len())
        .unwrap_or(MAX_ENVELOPE_HEADER_BYTES + 1);
    (len > MAX_ENVELOPE_HEADER_BYTES).then_some((len, MAX_ENVELOPE_HEADER_BYTES))
}

#[derive(Debug, thiserror::Error)]
pub enum EnvelopeError {
    #[error("envelope parse error: {0}")]
    Parse(String),
    /// The serialized header exceeded [`MAX_ENVELOPE_HEADER_BYTES`].
    #[error("envelope header is {len} bytes, exceeds {limit} byte limit")]
    HeaderTooLarge { len: usize, limit: usize },
    /// The address nesting depth exceeded [`MAX_ADDRESS_NESTING_DEPTH`](crate::MAX_ADDRESS_NESTING_DEPTH)
    /// — a pathological `Realm`/`Omega` wrapper chain rejected before any gateway unwraps it (R9).
    #[error("envelope address nesting depth {depth} exceeds max {max} (R9 federation-grain cap)")]
    TooDeep { depth: usize, max: usize },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::{Address, CreatureId, RealmId, MAX_ADDRESS_NESTING_DEPTH};

    fn header_to(to: Address) -> Header {
        Header {
            from: Address::Kernel,
            to,
            reply_to: None,
            seq: 0,
            causal: vec![],
            stamp: 0,
            sig: String::new(),
            corr: None,
            commitment: None,
            schema: String::new(),
        }
    }

    fn nested_realm(layers: usize) -> Address {
        let mut a = Address::Creature(CreatureId(1));
        for _ in 0..layers {
            a = Address::Realm { realm: RealmId::local(), target: Box::new(a) };
        }
        a
    }

    #[test]
    fn parse_accepts_addresses_at_the_nesting_ceiling() {
        let env = Envelope {
            header: header_to(nested_realm(MAX_ADDRESS_NESTING_DEPTH)),
            payload: vec![],
        };
        let bytes = env.to_bytes();
        assert!(Envelope::parse(&bytes).is_ok(), "exactly at the ceiling must parse");
    }

    #[test]
    fn parse_rejects_over_deep_federation_nesting_without_panicking() {
        let env = Envelope {
            header: header_to(nested_realm(MAX_ADDRESS_NESTING_DEPTH + 1)),
            payload: vec![],
        };
        let bytes = env.to_bytes();
        match Envelope::parse(&bytes) {
            Err(EnvelopeError::TooDeep { depth, max }) => {
                assert_eq!(depth, MAX_ADDRESS_NESTING_DEPTH + 1);
                assert_eq!(max, MAX_ADDRESS_NESTING_DEPTH);
            }
            other => panic!("expected TooDeep, got {other:?}"),
        }
    }

    #[test]
    fn parse_rejects_oversized_headers_before_gateway_use() {
        let mut header = header_to(Address::Kernel);
        header.schema = "x".repeat(MAX_ENVELOPE_HEADER_BYTES + 1);
        let bytes = Envelope { header, payload: vec![] }.to_bytes();

        match Envelope::parse(&bytes) {
            Err(EnvelopeError::HeaderTooLarge { len, limit }) => {
                assert!(len > MAX_ENVELOPE_HEADER_BYTES);
                assert_eq!(limit, MAX_ENVELOPE_HEADER_BYTES);
            }
            other => panic!("expected HeaderTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn parse_also_guards_the_from_endpoint() {
        // `from` arrives attacker-controlled over transport; a deep `from` is rejected too.
        let mut header = header_to(Address::Kernel);
        header.from = nested_realm(MAX_ADDRESS_NESTING_DEPTH + 1);
        let bytes = Envelope { header, payload: vec![] }.to_bytes();
        assert!(matches!(Envelope::parse(&bytes), Err(EnvelopeError::TooDeep { .. })));
    }
}

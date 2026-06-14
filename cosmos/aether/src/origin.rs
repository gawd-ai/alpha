//! Cross-node sender attribution — *who really sent a cross-node envelope*.
//!
//! A node has one cryptographic identity: its ed25519 key. It signs its bus envelopes with the
//! same key it authenticates transport links with (the handshake). So a peer that authenticated
//! node A at the handshake can verify any envelope A's fabric signed. The receiving transport, at
//! the wire boundary — where the inbound frame is still un-rewritten and the peer's pubkey is
//! known — verifies that signature and stamps the proven [`NodeId`] into [`Header::origin`], a
//! field only the transport can write (the privileged [`emit_attested`](crate::Bus::emit_attested)
//! path) and that rides inside the signed bytes. The judgement of that check is an [`OriginVerdict`],
//! published as a non-enforcing diagnostic; *acting* on it is an injected policy creature's job.

use serde::{Deserialize, Serialize};

use crate::address::{CreatureId, NodeId};

/// Schema tag for an [`OriginEvent`] published on [`Topic::PROPRIOCEPTION`](crate::Topic::PROPRIOCEPTION).
pub const ORIGIN_EVENT_SCHEMA: &str = "origin_verdict";

/// The authenticated origin of a cross-node envelope: the node it entered this bus from.
///
/// Sealed by the transport from the handshake-authenticated peer (never the frame's own claim),
/// signed into [`signing_payload`](crate::Envelope::signing_payload), and unreachable by an
/// ordinary creature (which cannot express it on a [`Dispatch`](crate::Dispatch) and whose ordinary
/// sends always seal `None`). Shaped to take a future per-creature attribution field additively.
#[derive(Clone, Default, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Origin {
    /// The peer node this envelope was authenticated as coming from.
    pub node: NodeId,
}

impl Origin {
    /// The origin of an envelope authenticated as coming from `node`.
    pub fn node(node: NodeId) -> Self {
        Origin { node }
    }
}

/// The transport's judgement about a cross-node envelope's origin. **Diagnostic, not enforcement** —
/// the spine never rejects on it; an injected policy creature decides what a non-`Verified` verdict
/// earns. (The replay guard is the one wire-integrity exception, like the `KERNEL_ID` refusal.)
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum OriginVerdict {
    /// Same-node traffic: no origin stamp. Consumers infer this from `Header.origin == None`; the
    /// transport never emits it (it only sees cross-node frames).
    Local,
    /// The peer's node key signed this exact content — verified under the pubkey the handshake
    /// authenticated. Survives tampering of the plaintext channel after the handshake.
    Verified,
    /// The origin is stamped, but the peer's pubkey could not be resolved to run the content check.
    /// For an authenticated link this should be unreachable — its appearance is itself an alarm.
    Unresolved,
    /// The signature did not verify under the peer's node key: tampered content, a key mismatch, or
    /// a sender that isn't signing with its node identity.
    BadSig,
}

/// A non-enforcing diagnostic the transport publishes on
/// [`Topic::PROPRIOCEPTION`](crate::Topic::PROPRIOCEPTION) for each cross-node frame, carrying enough
/// for an injected policy creature to attribute and act: which node, which local target, the
/// correlation id, and the verdict.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct OriginEvent {
    /// The authenticated peer node the frame entered from.
    pub origin_node: NodeId,
    /// The local creature the frame was delivered to.
    pub target: CreatureId,
    /// The frame's correlation id, if any — lets a policy tie a verdict to a request/reply thread.
    #[serde(default)]
    pub corr: Option<u64>,
    /// The origin check's verdict.
    pub verdict: OriginVerdict,
}

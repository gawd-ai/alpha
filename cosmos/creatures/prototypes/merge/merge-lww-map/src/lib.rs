//! `LwwMapMerge` — a **reference** injected [`MergeModel`] for `abode-reconciler`: a Last-Writer-Wins
//! Element-Map CRDT over a JSON object.
//!
//! The Abode state is a JSON object mapping each key to a timestamped register:
//! `{ "key": { "v": <any json>, "ts": <u64> }, ... }`. Merging two divergent forks is the **union**
//! of their keys; where both forks hold a key, the register with the higher `ts` wins (ties broken
//! deterministically by the serialized value, so the merge is total-order-driven). This is a textbook
//! **LWW-Element-Map**, and it is a CRDT — the three laws `abode-reconciler` needs hold:
//!
//! - **Commutative** — `merge(a, b) == merge(b, a)`: per key the winner is the max under a fixed
//!   total order on `(ts, serialized value)`, which doesn't depend on argument order.
//! - **Associative** — `merge(merge(a, b), c) == merge(a, merge(b, c))`: max over a total order is
//!   associative.
//! - **Idempotent** — `merge(a, a) == a`.
//!
//! So an Abode that forked across a partition and rejoined converges to the same merged state no
//! matter the order or number of reconciliations. The substrate ships none of this — it's the
//! operator's lattice; a different domain wants OR-Set (add/remove sets), RGA (collaborative text),
//! or a bespoke join-semilattice, each a different `MergeModel` on the same socket.

use std::collections::BTreeMap;

use abode_reconciler::MergeModel;
use serde::{Deserialize, Serialize};

/// A timestamped register: a value plus the logical time it was written. `ts` is a logical clock the
/// operator advances (time is *a change of state*, never a wall clock the substrate reads).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Lww {
    pub v: serde_json::Value,
    pub ts: u64,
}

/// The LWW-Element-Map merge model. Stateless; the state lives in the snapshots it merges.
pub struct LwwMapMerge;

impl LwwMapMerge {
    /// The per-key winner under the fixed total order `(ts, serialized value)`. Higher `ts` wins;
    /// on a tie, the lexicographically-greater serialized value wins — a deterministic tiebreak so
    /// the merge is commutative even when two forks wrote the same key at the same logical time.
    fn pick(a: Lww, b: Lww) -> Lww {
        match a.ts.cmp(&b.ts) {
            std::cmp::Ordering::Greater => a,
            std::cmp::Ordering::Less => b,
            std::cmp::Ordering::Equal => {
                // Tiebreak on the canonical serialization of the value (stable, total).
                let sa = serde_json::to_string(&a.v).unwrap_or_default();
                let sb = serde_json::to_string(&b.v).unwrap_or_default();
                if sa >= sb {
                    a
                } else {
                    b
                }
            }
        }
    }
}

impl MergeModel for LwwMapMerge {
    fn merge(&self, a: &[u8], b: &[u8]) -> Result<Vec<u8>, String> {
        // A `BTreeMap` parse gives stable key ordering, so the serialized merge is byte-deterministic
        // (the same property the reconciler's re-hash relies on).
        let map_a: BTreeMap<String, Lww> =
            serde_json::from_slice(a).map_err(|e| format!("fork_a is not an LWW map: {e}"))?;
        let mut merged: BTreeMap<String, Lww> =
            serde_json::from_slice(b).map_err(|e| format!("fork_b is not an LWW map: {e}"))?;
        for (k, va) in map_a {
            let winner = match merged.remove(&k) {
                Some(vb) => Self::pick(va, vb),
                None => va,
            };
            merged.insert(k, winner);
        }
        serde_json::to_vec(&merged).map_err(|e| format!("serialize merged map: {e}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(entries: &[(&str, serde_json::Value, u64)]) -> Vec<u8> {
        let map: BTreeMap<String, Lww> = entries
            .iter()
            .map(|(k, v, ts)| (k.to_string(), Lww { v: v.clone(), ts: *ts }))
            .collect();
        serde_json::to_vec(&map).unwrap()
    }

    fn parse(bytes: &[u8]) -> BTreeMap<String, Lww> {
        serde_json::from_slice(bytes).unwrap()
    }

    #[test]
    fn union_of_keys_with_higher_ts_winning() {
        let a = state(&[
            ("name", serde_json::json!("alice"), 1),
            ("color", serde_json::json!("red"), 5),
        ]);
        let b = state(&[
            ("name", serde_json::json!("bob"), 3),
            ("city", serde_json::json!("paris"), 2),
        ]);
        let merged = parse(&LwwMapMerge.merge(&a, &b).unwrap());
        assert_eq!(merged["name"].v, serde_json::json!("bob"), "ts 3 > 1 → bob wins");
        assert_eq!(merged["color"].v, serde_json::json!("red"), "only in a → kept");
        assert_eq!(merged["city"].v, serde_json::json!("paris"), "only in b → kept");
        assert_eq!(merged.len(), 3, "union of keys");
    }

    #[test]
    fn merge_is_commutative() {
        let a = state(&[("k", serde_json::json!(1), 7), ("x", serde_json::json!("a"), 2)]);
        let b = state(&[("k", serde_json::json!(2), 4), ("y", serde_json::json!("b"), 9)]);
        assert_eq!(
            LwwMapMerge.merge(&a, &b).unwrap(),
            LwwMapMerge.merge(&b, &a).unwrap(),
            "merge(a,b) == merge(b,a)"
        );
    }

    #[test]
    fn merge_is_associative() {
        // Exercises ALL three dimensions a CRDT bug could hide in (a single-key
        // strictly-increasing-ts case is a trivial `max`): disjoint-key union (x/y/z), an
        // overlapping key with distinct ts, AND an overlapping key with an EQUAL-ts tiebreak (`t`).
        let a = state(&[
            ("x", serde_json::json!("a"), 1),
            ("k", serde_json::json!("ka"), 2),
            ("t", serde_json::json!("ta"), 9),
        ]);
        let b = state(&[
            ("y", serde_json::json!("b"), 2),
            ("k", serde_json::json!("kb"), 5),
            ("t", serde_json::json!("tb"), 9),
        ]);
        let c = state(&[
            ("z", serde_json::json!("c"), 3),
            ("k", serde_json::json!("kc"), 4),
            ("t", serde_json::json!("tc"), 9),
        ]);
        let ab_c = LwwMapMerge.merge(&LwwMapMerge.merge(&a, &b).unwrap(), &c).unwrap();
        let a_bc = LwwMapMerge.merge(&a, &LwwMapMerge.merge(&b, &c).unwrap()).unwrap();
        assert_eq!(
            ab_c, a_bc,
            "merge(merge(a,b),c) == merge(a,merge(b,c)) over union + distinct-ts + equal-ts"
        );
        // Sanity: `k` resolves to the higher ts (kb@5), `t` to the equal-ts tiebreak winner.
        let m = parse(&ab_c);
        assert_eq!(m["k"].v, serde_json::json!("kb"), "k: ts 5 wins");
        assert_eq!(m.len(), 5, "x,y,z,k,t");
    }

    #[test]
    fn merge_output_is_byte_deterministic_regardless_of_object_value_key_order() {
        // The equal-ts tiebreak compares serde_json::to_string of the
        // Value, which is only stable because the workspace builds serde_json WITHOUT `preserve_order`
        // (so Value::Object is BTreeMap-backed → sorted-key serialization). This regression test
        // asserts that property directly: two object values with the SAME keys inserted in DIFFERENT
        // orders must serialize identically, so the tiebreak (and thus the whole merge) stays
        // commutative. If a future feature-unification flips `preserve_order` on, THIS breaks loudly
        // rather than the merge silently going non-commutative in production.
        let v1: serde_json::Value = serde_json::from_str(r#"{"a":1,"b":2,"c":3}"#).unwrap();
        let v2: serde_json::Value = serde_json::from_str(r#"{"c":3,"b":2,"a":1}"#).unwrap();
        assert_eq!(
            serde_json::to_string(&v1).unwrap(),
            serde_json::to_string(&v2).unwrap(),
            "object values serialize key-order-independently (serde_json preserve_order is OFF) — the \
             LWW tiebreak depends on this; if it ever fails, pin serde_json default-features=false"
        );
        // And the merge that relies on it is itself order-independent for equal-ts object values:
        let a = state(&[("k", v1, 7)]);
        let b = state(&[("k", v2, 7)]);
        assert_eq!(LwwMapMerge.merge(&a, &b).unwrap(), LwwMapMerge.merge(&b, &a).unwrap());
    }

    #[test]
    fn merge_is_idempotent() {
        let a = state(&[("k", serde_json::json!("v"), 1), ("j", serde_json::json!(2), 5)]);
        assert_eq!(LwwMapMerge.merge(&a, &a).unwrap(), a, "merge(a,a) == a");
    }

    #[test]
    fn equal_ts_breaks_ties_deterministically_and_commutatively() {
        let a = state(&[("k", serde_json::json!("alpha"), 4)]);
        let b = state(&[("k", serde_json::json!("zeta"), 4)]); // same ts, different value
        let ab = LwwMapMerge.merge(&a, &b).unwrap();
        let ba = LwwMapMerge.merge(&b, &a).unwrap();
        assert_eq!(ab, ba, "tie broken identically regardless of order");
        assert_eq!(
            parse(&ab)["k"].v,
            serde_json::json!("zeta"),
            "higher serialized value wins the tie"
        );
    }

    #[test]
    fn malformed_state_is_a_structured_error_not_a_panic() {
        assert!(LwwMapMerge.merge(b"{not json", b"{}").is_err());
        assert!(LwwMapMerge.merge(b"{}", b"[1,2,3]").is_err());
    }
}

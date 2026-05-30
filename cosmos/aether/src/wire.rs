//! Wire-serialization helpers shared by every creature that puts a typed message on the bus.
//!
//! Every GAWD wire type is a plain serde struct/enum. `serde_json` serializes such a type
//! **infallibly**: it renders a non-finite float (`NaN` / `±∞`) as `null` and an integer map key
//! as a string rather than erroring, and none of our wire types use the two shapes it *does*
//! reject (a map keyed by a non-string/non-integer type, or a `Serialize` impl that itself
//! errors). So a failure on this path is a **bug** — a future field of an un-serializable shape —
//! not a runtime condition a peer can trigger.
//!
//! These helpers encode that invariant. A `debug_assert!` surfaces the impossible case loudly in
//! dev/test builds; release builds degrade to an empty `Vec` / [`serde_json::Value::Null`] — the
//! receiver then drops the payload as malformed (R9: the serialize path never panics a creature).
//! This is the **single disposition** for the
//! `serde_json::to_vec(..).unwrap_or_default()` / `to_value(..).unwrap_or(Value::Null)` sites,
//! which would otherwise swallow the (cannot-happen-for-these-types) error with no diagnostic at all.

use serde::Serialize;

/// Serialize a wire message to JSON bytes. See the [module docs](self) for why a failure is a bug
/// (caught by `debug_assert!`) rather than a peer-triggerable runtime condition.
pub fn to_bytes<T: ?Sized + Serialize>(value: &T) -> Vec<u8> {
    match serde_json::to_vec(value) {
        Ok(bytes) => bytes,
        Err(e) => {
            debug_assert!(
                false,
                "wire serialize must not fail (a non-string-keyed map or an erroring Serialize \
                 impl reached the bus?): {e}"
            );
            Vec::new()
        }
    }
}

/// Serialize a typed body to a [`serde_json::Value`] — the form a
/// `seer::SeerEnvelope` body rides in (the `seer` crate depends on this helper). Same invariant as [`to_bytes`];
/// degrades to [`serde_json::Value::Null`], which a consumer reads as "empty body."
pub fn to_value<T: ?Sized + Serialize>(value: &T) -> serde_json::Value {
    match serde_json::to_value(value) {
        Ok(v) => v,
        Err(e) => {
            debug_assert!(false, "wire to_value must not fail: {e}");
            serde_json::Value::Null
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;

    #[derive(Serialize)]
    struct Plain {
        n: u64,
        s: String,
        // A non-finite float still serializes (serde_json renders it as JSON `null`), so even this
        // does NOT trip the debug_assert — proving the guard only fires on a genuinely
        // un-serializable shape, never on attacker-supplied numeric values (the federation ingest
        // guards own that concern).
        f: f64,
    }

    #[test]
    fn to_bytes_roundtrips_a_plain_type() {
        let v = Plain { n: 7, s: "hi".into(), f: 1.5 };
        let bytes = to_bytes(&v);
        assert_eq!(bytes, serde_json::to_vec(&v).unwrap());
    }

    #[test]
    fn non_finite_float_serializes_as_null_without_tripping_the_guard() {
        // If this fired the debug_assert it would panic the test. It does not — serde_json maps
        // NaN/∞ to `null`. This is what keeps the federation/fitness/immune NaN guards safe.
        let v = Plain { n: 1, s: String::new(), f: f64::NAN };
        let bytes = to_bytes(&v);
        assert!(std::str::from_utf8(&bytes).unwrap().contains("null"));
        let val = to_value(&v);
        assert_eq!(val["f"], serde_json::Value::Null);
    }
}

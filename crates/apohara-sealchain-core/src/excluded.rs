//! Volatile-key exclusion.
//!
//! Mirrors the Python reference `excluded.py`: a fixed set of keys that carry
//! observability / runtime noise are stripped recursively from the payload
//! before the preimage is built, so the seal stays stable across replays.

use serde_json::{Map, Value};

/// Keys removed from every object in the payload tree before canonicalization.
pub const EXCLUDED_KEYS: [&str; 6] = [
    "kg_status",
    "kg_latency_ms",
    "surface_status",
    "truncated",
    "charsSeen",
    "lowConfidenceTier",
];

fn is_excluded(key: &str) -> bool {
    EXCLUDED_KEYS.contains(&key)
}

/// Return a deep copy of `v` with all [`EXCLUDED_KEYS`] removed from every
/// nested object. Arrays are traversed element-wise; scalars pass through
/// unchanged.
pub fn strip_excluded(v: &Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = Map::with_capacity(map.len());
            for (k, val) in map {
                if is_excluded(k) {
                    continue;
                }
                out.insert(k.clone(), strip_excluded(val));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(strip_excluded).collect()),
        other => other.clone(),
    }
}

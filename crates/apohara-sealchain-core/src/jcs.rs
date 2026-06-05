//! RFC 8785 JSON Canonicalization Scheme.
//!
//! Backed by the `serde_jcs` crate (which uses `ryu-js` for ES6/RFC 8785
//! number formatting). Validated byte-for-byte against the conformance
//! vectors — including the `-0.0` → `0` collapse (`vec_06`) and astral /
//! CJK unicode round-tripping (`vec_05`).

use crate::error::SealError;
use serde_json::Value;

/// Canonicalize a JSON value into its RFC 8785 byte representation (UTF-8).
///
/// Object keys are sorted lexicographically by UTF-16 code units, numbers use
/// the ECMAScript `Number.prototype.toString` algorithm, and strings carry the
/// minimal JSON escaping mandated by the spec.
pub fn canonicalize(v: &Value) -> Result<Vec<u8>, SealError> {
    serde_jcs::to_vec(v).map_err(|e| SealError::Canonicalization(e.to_string()))
}

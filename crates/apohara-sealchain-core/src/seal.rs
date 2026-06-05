//! Deterministic seal construction.
//!
//! Builds the canonical preimage and assembles a [`SealBlock`] /
//! [`SealedRecord`] in the exact wire shape of the conformance vectors. With
//! the fixed test keys this reproduces the stored seal blocks byte-for-byte:
//! HMAC is deterministic by construction and Ed25519 is deterministic by
//! RFC 8032.

use ed25519_dalek::SigningKey;
use serde_json::{json, Value};

use crate::error::SealError;
use crate::excluded::strip_excluded;
use crate::jcs;
use crate::layers::{ed25519, hmac};
use crate::schema::{Ed25519Layer, HmacLayer, SealBlock, SealedRecord};
use crate::METHOD_V1;

/// Hex-encode bytes with the `0x` prefix used throughout the wire format.
fn hex0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    s.push_str(&hex::encode(bytes));
    s
}

/// Build the canonical preimage bytes for `payload` at `sealed_at`.
///
/// The preimage object is `{method, sealedAt, payload}` with the payload's
/// volatile keys stripped; JCS then sorts keys lexicographically (yielding
/// `method`, `payload`, `sealedAt`) and serializes deterministically.
pub fn build_preimage(payload: &Value, sealed_at: &str) -> Result<Vec<u8>, SealError> {
    let stripped = strip_excluded(payload);
    let envelope = json!({
        "method": METHOD_V1,
        "sealedAt": sealed_at,
        "payload": stripped,
    });
    jcs::canonicalize(&envelope)
}

/// Deterministically seal `payload` and return the full record.
///
/// Always produces the HMAC layer. If `ed` is supplied, also produces the
/// Ed25519 layer. The resulting [`SealBlock`] matches the vector wire shape:
/// `0x`-hex preimage and signatures, fixed key ids.
pub fn seal_deterministic(
    payload: &Value,
    key_hmac: &[u8],
    ed: Option<&SigningKey>,
    sealed_at: &str,
) -> Result<SealedRecord, SealError> {
    let preimage = build_preimage(payload, sealed_at)?;

    let hmac_sig = hmac::sign(&preimage, key_hmac)?;
    let hmac_layer = HmacLayer {
        alg: hmac::ALG.to_string(),
        key_id: "hmac-default".to_string(),
        sig: hex0x(&hmac_sig),
    };

    let ed25519_layer = ed.map(|key| {
        let sig = ed25519::sign(&preimage, key);
        Ed25519Layer {
            key_id: "default".to_string(),
            sig: hex0x(&sig),
        }
    });

    let seal = SealBlock {
        method: METHOD_V1.to_string(),
        sealed_at: sealed_at.to_string(),
        preimage: hex0x(&preimage),
        hmac: hmac_layer,
        ed25519: ed25519_layer,
        ed25519_public_key: None,
        tsa: None,
        rekor_anchor: None,
        c2pa_manifest: None,
        c2pa_embedded: None,
    };

    Ok(SealedRecord {
        payload: payload.clone(),
        seal,
    })
}

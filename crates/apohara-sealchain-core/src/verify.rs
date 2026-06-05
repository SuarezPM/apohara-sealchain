//! Verification with strict error/mismatch separation.
//!
//! Contract:
//! * **Structural** problems — not an object, missing required fields, bad
//!   schema, legacy v3 — return [`SealError`].
//! * **Content / signature mismatch** (tamper) is *not* an error: it returns
//!   `Ok(false)`.
//! * When every layer that is *present* verifies, the result is `Ok(true)`.
//!
//! Verification is **present-layers-only**: an HMAC-only record (no Ed25519)
//! is valid as long as the recomputed preimage matches the stored one and the
//! HMAC checks out. If an Ed25519 layer is present, a public key is required
//! and must validate it.
//!
//! Scope: this function is the **conformance-vector path** — it covers HMAC and
//! Ed25519, the two layers exercised by the deterministic v1 vectors. The TSA,
//! Rekor and C2PA layers are verified by [`crate::artifact::verify_artifact_bytes`]
//! (and the per-layer modules in [`crate::layers`]), not here.

use serde_json::Value;

use crate::error::SealError;
use crate::layers::{ed25519, hmac};
use crate::schema::{detect_schema, SealBlock};
use crate::seal::build_preimage;

/// Decode a `0x`-prefixed (prefix optional) hex string.
fn decode_hex0x(s: &str, what: &str) -> Result<Vec<u8>, String> {
    let body = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(body).map_err(|e| format!("{what}: {e}"))
}

/// Verify a sealed record.
///
/// `record` is the raw `{payload, seal}` value. `key_hmac` is the shared HMAC
/// key. `pubkey_pem` is the Ed25519 SPKI public key PEM, required only if the
/// record carries an Ed25519 layer. When `pubkey_pem` is `None` and the seal
/// block embeds an `ed25519PublicKey` field, that embedded key is used — this
/// makes artifact receipts self-contained while keeping the conformance
/// vectors (which embed no key and pass the pubkey explicitly) working.
pub fn verify(
    record: &Value,
    key_hmac: &[u8],
    pubkey_pem: Option<&str>,
) -> Result<bool, SealError> {
    // Structural: schema gate (also rejects legacy v3).
    detect_schema(record)?;

    // Structural: the seal block must deserialize into the known shape.
    let seal_value = record
        .get("seal")
        .ok_or_else(|| SealError::Malformed("missing seal block".into()))?;
    let seal: SealBlock = serde_json::from_value(seal_value.clone())
        .map_err(|e| SealError::Malformed(format!("invalid seal block: {e}")))?;

    // Fall back to the seal block's embedded public key when no key is passed.
    let embedded_pubkey = seal_value
        .get("ed25519PublicKey")
        .and_then(Value::as_str)
        .map(str::to_string);
    let pubkey_pem = pubkey_pem.or(embedded_pubkey.as_deref());

    // Structural: payload must be present.
    let payload = record
        .get("payload")
        .ok_or_else(|| SealError::Malformed("missing payload".into()))?;

    // Recompute the canonical preimage from the (stripped) payload.
    let computed = build_preimage(payload, &seal.sealed_at)?;

    // Structural: the stored preimage must be decodable hex.
    let stored = decode_hex0x(&seal.preimage, "preimage").map_err(SealError::InvalidPreimage)?;

    // Mismatch (tamper): recomputed preimage differs from the stored one.
    if computed != stored {
        return Ok(false);
    }

    // HMAC layer (mandatory). A malformed hex signature is treated as a
    // mismatch, not a structural error: the record is simply not valid.
    let hmac_sig = match decode_hex0x(&seal.hmac.sig, "hmac.sig") {
        Ok(s) => s,
        Err(_) => return Ok(false),
    };
    if !hmac::verify(&computed, &hmac_sig, key_hmac) {
        return Ok(false);
    }

    // Ed25519 layer (present-only). Missing public key is structural.
    if let Some(ed_layer) = seal.ed25519.as_ref() {
        let pem = pubkey_pem.ok_or(SealError::MissingPublicKey)?;
        let key = ed25519::verifying_key_from_pem(pem)?;
        let ed_sig = match decode_hex0x(&ed_layer.sig, "ed25519.sig") {
            Ok(s) => s,
            Err(_) => return Ok(false),
        };
        if !ed25519::verify(&computed, &ed_sig, &key) {
            return Ok(false);
        }
    }

    Ok(true)
}

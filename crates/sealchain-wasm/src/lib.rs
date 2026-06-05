//! Offline in-browser receipt verifier (wasm-bindgen).
//!
//! This crate exposes a single entry point, [`verify_receipt`], that the static
//! web page calls with the raw artifact bytes and the `<artifact>.seal.json`
//! text. It runs **entirely offline** in the browser: no network, no
//! filesystem. It calls into `apohara-sealchain-core`'s verify-only path
//! ([`apohara_sealchain_core::verify_artifact_bytes`]) for the layers that are
//! self-contained and reports the rest honestly.
//!
//! ## What verifies in the browser, and what does not
//!
//! * **content** — `sha256(file) == payload.artifactSha256`. Fully verifiable.
//! * **ed25519** — checked against the receipt's embedded `ed25519PublicKey`.
//!   Self-contained, fully verifiable.
//! * **c2pa** — the JUMBF sidecar is parsed by the real `c2pa::Reader` and the
//!   bound payload hash is checked. Fully verifiable offline.
//! * **hmac** — HMAC is *symmetric*: the secret key is NOT in the receipt and is
//!   never shipped to the browser. We therefore CANNOT verify the MAC here, and
//!   we say so plainly (`ok: false`, "hmac key not available in browser"). We do
//!   not claim a pass we did not earn.
//! * **tsa / rekor** — when present, reported as present-but-unverified (their
//!   network-layer verification needs the bundled sigstore keys, a future item).
//!
//! The honest HMAC reason is enforced here: the core's `verify_artifact_bytes`,
//! when called with `key_hmac = None`, reports the HMAC layer as preimage-integrity
//! only — which is true but easy to misread in a browser. We rewrite that single
//! layer to the unambiguous "no key in browser" message before returning.

use serde::Serialize;
use wasm_bindgen::prelude::*;

use apohara_sealchain_core::{verify_artifact_bytes, SealedRecord};

/// One verified layer, as returned to JavaScript.
#[derive(Serialize)]
struct LayerOut {
    /// Layer name: `content`, `hmac`, `ed25519`, `c2pa`, `tsa`, `rekor`.
    name: String,
    /// Whether this layer verified in the browser.
    ok: bool,
    /// Honest, human-readable explanation.
    reason: String,
}

/// The full verification result returned to JavaScript.
#[derive(Serialize)]
struct VerifyOut {
    /// Overall offline verdict: every *browser-verifiable* layer passed.
    ///
    /// The HMAC layer is excluded from this verdict because it is unknowable in
    /// the browser (symmetric secret not present); it is reported individually.
    ok: bool,
    /// Per-layer results, in chain order.
    layers: Vec<LayerOut>,
    /// Set when verification could not be performed at all (structural error,
    /// e.g. malformed JSON or missing required fields). `null` on success.
    error: Option<String>,
}

/// Install the panic hook so a Rust panic surfaces as a readable console error
/// instead of an opaque `unreachable`. Safe to call more than once.
#[wasm_bindgen(start)]
pub fn init() {
    console_error_panic_hook::set_once();
}

/// Verify `file_bytes` against `receipt_json` fully offline, returning
/// `{ ok, layers: [{ name, ok, reason }], error }` as a JS value.
///
/// `file_bytes` is the raw artifact; `receipt_json` is the text of the
/// `<artifact>.seal.json` file. No network or filesystem access occurs.
#[wasm_bindgen]
pub fn verify_receipt(file_bytes: &[u8], receipt_json: &str) -> JsValue {
    let out = verify_inner(file_bytes, receipt_json);
    serde_wasm_bindgen::to_value(&out).unwrap_or(JsValue::NULL)
}

/// Core logic, factored out so the native smoke tests can exercise the exact
/// same path the wasm export uses.
fn verify_inner(file_bytes: &[u8], receipt_json: &str) -> VerifyOut {
    let record: SealedRecord = match serde_json::from_str(receipt_json) {
        Ok(r) => r,
        Err(e) => {
            return VerifyOut {
                ok: false,
                layers: Vec::new(),
                error: Some(format!("invalid receipt JSON: {e}")),
            }
        }
    };

    // No HMAC key in the browser (symmetric secret, never shipped): pass `None`.
    let results = match verify_artifact_bytes(file_bytes, &record, None) {
        Ok(r) => r,
        Err(e) => {
            return VerifyOut {
                ok: false,
                layers: Vec::new(),
                error: Some(format!("verification could not be performed: {e}")),
            }
        }
    };

    let mut layers = Vec::with_capacity(results.len());
    for r in results {
        if r.name == "hmac" {
            // Honest override: HMAC cannot be verified without the secret key,
            // which is never present in the browser. Do not imply a pass.
            layers.push(LayerOut {
                name: "hmac".to_string(),
                ok: false,
                reason:
                    "hmac key not available in browser (offline public verify); HMAC is symmetric \
                     and the secret is never shipped"
                        .to_string(),
            });
        } else {
            layers.push(LayerOut {
                name: r.name,
                ok: r.ok,
                reason: r.reason,
            });
        }
    }

    // Overall verdict ignores the (unknowable) HMAC layer: it is true when every
    // browser-verifiable layer passed.
    let ok = layers.iter().filter(|l| l.name != "hmac").all(|l| l.ok);

    VerifyOut {
        ok,
        layers,
        error: None,
    }
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use apohara_sealchain_core::{load_or_generate, seal_artifact};

    /// Seal a real artifact (content + HMAC + Ed25519 + C2PA) and verify it
    /// through the same offline path the wasm export uses. Content, Ed25519 and
    /// C2PA must pass; HMAC is honestly reported as unverifiable in-browser.
    #[test]
    fn good_receipt_verifies_content_ed25519_c2pa() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.txt");
        std::fs::write(&artifact, b"apohara-sealchain wasm verifier test bytes").expect("write");

        // c2pa = true so the receipt carries a real JUMBF sidecar.
        let record = seal_artifact(&artifact, &keys, None, true, false, None, None).expect("seal");
        let receipt_json = serde_json::to_string(&record).expect("serialize receipt");
        let file_bytes = std::fs::read(&artifact).expect("read artifact");

        let out = verify_inner(&file_bytes, &receipt_json);
        assert!(out.error.is_none(), "no structural error: {:?}", out.error);
        assert!(out.ok, "overall (browser-verifiable layers) must pass");

        let layer = |name: &str| out.layers.iter().find(|l| l.name == name).expect("layer");
        assert!(layer("content").ok, "content must verify");
        assert!(layer("ed25519").ok, "ed25519 must verify");
        assert!(
            layer("c2pa").ok,
            "c2pa must verify: {}",
            layer("c2pa").reason
        );

        // HMAC must be honestly reported as unverifiable in the browser.
        assert!(!layer("hmac").ok, "hmac must NOT claim a pass in-browser");
        assert!(
            layer("hmac")
                .reason
                .contains("hmac key not available in browser"),
            "hmac reason must be honest: {}",
            layer("hmac").reason
        );
    }

    /// A tampered artifact (one byte flipped) must trip the content layer and
    /// flip the overall verdict to false.
    #[test]
    fn tampered_file_fails_content() {
        let dir = tempfile::tempdir().expect("tempdir");
        let keys = load_or_generate(Some(dir.path())).expect("keys");
        let artifact = dir.path().join("data.bin");
        std::fs::write(&artifact, b"original-bytes").expect("write");

        let record = seal_artifact(&artifact, &keys, None, true, false, None, None).expect("seal");
        let receipt_json = serde_json::to_string(&record).expect("serialize receipt");

        // Verify against DIFFERENT bytes than were sealed (a tampered artifact).
        let tampered = b"Original-bytes";
        let out = verify_inner(tampered, &receipt_json);

        assert!(out.error.is_none(), "tamper is not a structural error");
        assert!(!out.ok, "overall verdict must be false on tamper");
        let content = out
            .layers
            .iter()
            .find(|l| l.name == "content")
            .expect("content");
        assert!(!content.ok, "content layer must fail: {}", content.reason);
    }

    /// Malformed receipt JSON is a structural error, reported via `error`.
    #[test]
    fn malformed_receipt_json_is_error() {
        let out = verify_inner(b"anything", "{ not valid json");
        assert!(!out.ok);
        assert!(out.error.is_some(), "malformed JSON must set error");
        assert!(out.layers.is_empty());
    }
}

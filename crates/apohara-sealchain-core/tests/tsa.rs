//! RFC 3161 TSA layer tests (story R-002).
//!
//! Three honest tiers:
//!
//! * **Tier-C LIVE** (`live_token_from_default_tsa_verifies`, `#[ignore]`):
//!   requests a *real* token from the default public TSA over a fixed
//!   `to_stamp`, asserts the DER parses and the imprint verifies, and that
//!   `issuedAt` is populated. Marked `#[ignore]` so CI without network stays
//!   green; run it with `cargo test -p apohara-sealchain-core --test tsa -- --ignored`.
//!   Setting `SEALCHAIN_TSA_CAPTURE=1` additionally freezes the captured token
//!   into the offline vector (used once to mint `tests/vectors/tsa/*.json`).
//!
//! * **Offline** (`frozen_vector_*`, NOT ignored): replays a committed real
//!   token. The imprint verifies against the stored `to_stamp` (`ok:true`); a
//!   flipped `to_stamp` fails (`ok:false`). This is the deterministic CI gate.
//!
//! * **Structural** (`garbage_der_*`): a corrupted DER is `ok:false`, never a
//!   panic.

use apohara_sealchain_core::layers::tsa::{request_token, verify_token, DEFAULT_TSA_URL};
use apohara_sealchain_core::{load_or_generate, verify_artifact, SealedRecord};
use serde_json::{json, Value};

/// The fixed canonical binding used by the live + frozen tests: stand-in raw
/// bytes for `hmac.sig || ed25519.sig`. The TSA stamps `sha256(to_stamp)`.
const TO_STAMP: &[u8] = b"apohara-sealchain-tsa-R002-binding: hmac.sig||ed25519.sig";

const FROZEN_VECTOR: &str = include_str!("vectors/tsa/sigstore_token.json");

/// Path to the frozen offline vector, for the optional capture step.
fn vector_path() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/tsa/sigstore_token.json")
}

fn frozen_der() -> Vec<u8> {
    let v: Value = serde_json::from_str(FROZEN_VECTOR).expect("frozen vector parses");
    let der_hex = v["der"].as_str().expect("der field");
    let body = der_hex.strip_prefix("0x").unwrap_or(der_hex);
    hex::decode(body).expect("der hex decodes")
}

fn frozen_to_stamp() -> Vec<u8> {
    let v: Value = serde_json::from_str(FROZEN_VECTOR).expect("frozen vector parses");
    let hex_str = v["toStamp"].as_str().expect("toStamp field");
    let body = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    hex::decode(body).expect("toStamp hex decodes")
}

/// Tier-C LIVE: request a real token from the default TSA and verify it.
#[test]
#[ignore = "live network: requests a real RFC 3161 token from the public TSA"]
fn live_token_from_default_tsa_verifies() {
    let token = request_token(TO_STAMP, DEFAULT_TSA_URL).expect("live TSA request");

    assert!(!token.der.is_empty(), "DER token must be non-empty");
    assert!(!token.issued_at.is_empty(), "issuedAt must be set");
    assert_eq!(token.authority, "sigstore", "default authority label");

    // The token's imprint must bind our exact to_stamp.
    let result = verify_token(&token.der, TO_STAMP, None);
    assert!(
        result.ok,
        "live token must verify its imprint: {}",
        result.reason
    );

    // A flipped binding must fail the imprint pass bar.
    let mut wrong = TO_STAMP.to_vec();
    wrong[0] ^= 0xff;
    let bad = verify_token(&token.der, &wrong, None);
    assert!(!bad.ok, "flipped to_stamp must fail the imprint");

    // Optional: freeze the captured token as the offline vector.
    if std::env::var("SEALCHAIN_TSA_CAPTURE").is_ok() {
        let vector = serde_json::json!({
            "authority": token.authority,
            "issuedAt": token.issued_at,
            "toStamp": format!("0x{}", hex::encode(TO_STAMP)),
            "der": format!("0x{}", hex::encode(&token.der)),
        });
        let path = vector_path();
        std::fs::create_dir_all(path.parent().unwrap()).expect("create vectors/tsa dir");
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&vector).expect("serialize vector"),
        )
        .expect("write frozen vector");
        eprintln!("captured frozen TSA vector -> {}", path.display());
    }
}

/// Offline gate: the frozen real token verifies its imprint against the stored
/// `to_stamp` (`ok:true`).
#[test]
fn frozen_vector_imprint_verifies() {
    let der = frozen_der();
    let to_stamp = frozen_to_stamp();
    let result = verify_token(&der, &to_stamp, None);
    assert_eq!(result.name, "tsa");
    assert!(
        result.ok,
        "frozen token must verify its imprint: {}",
        result.reason
    );
    assert!(
        result.reason.contains("imprint ok"),
        "reason should note imprint ok: {}",
        result.reason
    );
}

/// Offline gate: a flipped `to_stamp` fails the imprint pass bar (`ok:false`).
#[test]
fn frozen_vector_flipped_to_stamp_fails() {
    let der = frozen_der();
    let mut to_stamp = frozen_to_stamp();
    to_stamp[0] ^= 0xff;
    let result = verify_token(&der, &to_stamp, None);
    assert!(!result.ok, "flipped to_stamp must not verify");
    assert_eq!(result.reason, "tsa imprint mismatch");
}

/// Structural: a corrupted DER is handled (`ok:false`), never a panic.
#[test]
fn garbage_der_is_ok_false() {
    let result = verify_token(b"\x30\x82garbage-not-a-token", b"whatever", None);
    assert!(!result.ok, "garbage DER must not verify");
}

/// Frozen value for the orchestrator wiring test.
fn frozen_issued_at() -> String {
    let v: Value = serde_json::from_str(FROZEN_VECTOR).expect("frozen vector parses");
    v["issuedAt"].as_str().expect("issuedAt").to_string()
}

/// Orchestrator wiring (offline): a receipt carrying `seal.tsa` makes
/// `verify_artifact` append a `tsa` LayerResult whose imprint binds the
/// reconstructed `hmac.sig || ed25519.sig`. The frozen real token's `to_stamp`
/// is split across the seal's two signature fields so the orchestrator's
/// `tsa_to_stamp` reconstructs it exactly — no network needed. The other layers
/// (content/hmac/ed25519) are not the subject here; only the `tsa` entry is
/// asserted, which isolates the TSA wiring.
#[test]
fn verify_artifact_appends_tsa_layer_from_seal() {
    let dir = tempfile::tempdir().expect("tempdir");
    let keys = load_or_generate(Some(dir.path())).expect("keys");
    let artifact = dir.path().join("data.txt");
    std::fs::write(&artifact, b"tsa wiring artifact").expect("write artifact");

    // A minimal real receipt; the payload hash is irrelevant to the tsa layer.
    let record_value = serde_json::to_value(
        apohara_sealchain_core::seal_deterministic(
            &json!({ "artifactSha256": "00", "path": "data.txt", "size": 0u64, "mime": "x" }),
            &keys.hmac,
            Some(&keys.ed25519),
            "2026-01-01T00:00:00+00:00",
        )
        .expect("seal_deterministic"),
    )
    .expect("to_value");
    let mut record: SealedRecord = serde_json::from_value(record_value).expect("from_value");
    // Embed the public key so the ed25519 layer is self-verifiable (mirrors what
    // `seal_artifact` does); without it `verify_artifact` is a structural error.
    record.seal.ed25519_public_key = Some(keys.ed25519_public_pem.clone());

    // Overwrite the two sig fields so hmac.sig || ed25519.sig == frozen to_stamp.
    let to_stamp = frozen_to_stamp();
    let (hmac_part, ed_part) = to_stamp.split_at(32);
    record.seal.hmac.sig = format!("0x{}", hex::encode(hmac_part));
    record.seal.ed25519.as_mut().unwrap().sig = format!("0x{}", hex::encode(ed_part));
    record.seal.tsa = Some(json!({
        "authority": "sigstore",
        "issuedAt": frozen_issued_at(),
        "der": format!("0x{}", hex::encode(frozen_der())),
    }));

    let results = verify_artifact(&artifact, &record, Some(&keys.hmac)).expect("verify");
    let tsa = results
        .iter()
        .find(|r| r.name == "tsa")
        .expect("tsa layer present");
    assert!(tsa.ok, "tsa layer must verify its imprint: {}", tsa.reason);

    // Tamper a stamped sig byte: the reconstructed binding no longer matches the
    // token's imprint, so the tsa layer trips (ok:false), proving the binding.
    let mut tampered = record.clone();
    let mut bytes = hex::decode(tampered.seal.hmac.sig.trim_start_matches("0x")).unwrap();
    bytes[0] ^= 0xff;
    tampered.seal.hmac.sig = format!("0x{}", hex::encode(bytes));
    let results = verify_artifact(&artifact, &tampered, Some(&keys.hmac)).expect("verify");
    let tsa = results.iter().find(|r| r.name == "tsa").expect("tsa layer");
    assert!(!tsa.ok, "tampered binding must trip the tsa imprint");
    assert_eq!(tsa.reason, "tsa imprint mismatch");
}

#![no_main]
//! Fuzz the untrusted-input surface of `verify`.
//!
//! An attacker fully controls the receipt bytes (and the artifact bytes). The
//! contract — stated in `docs/ASSURANCE.md` §4 — is that neither parsing nor
//! verification may ever panic: structural problems are typed errors, tamper is
//! a measured `ok:false`, and malformed hex/base64, bad proof indices, and
//! unknown schema versions are all handled explicitly. This harness exercises
//! exactly that path so a regression that reintroduces a panic is caught.
use apohara_sealchain_core::{detect_schema, verify_artifact_bytes, SealedRecord};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Schema detection over arbitrary JSON must not panic.
    if let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = detect_schema(&value);
    }

    // A parseable receipt must verify without panicking against arbitrary
    // artifact bytes, both without and with an HMAC key (the two branches of
    // the HMAC layer). The result is intentionally ignored: we assert only the
    // absence of panics/UB (ASan catches memory issues in the C2PA/JUMBF path).
    if let Ok(record) = serde_json::from_slice::<SealedRecord>(data) {
        let _ = verify_artifact_bytes(data, &record, None);
        let _ = verify_artifact_bytes(b"", &record, Some(b"fuzz-key"));
    }
});

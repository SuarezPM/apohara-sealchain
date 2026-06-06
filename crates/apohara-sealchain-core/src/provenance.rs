//! in-toto/SLSA-style provenance for sealed artifacts.
//!
//! [`provenance_statement`] maps a [`SealedRecord`] onto an **in-toto
//! Statement v1** envelope so a sealed receipt can be consumed by the wider
//! supply-chain tooling that already speaks in-toto/SLSA (`cosign`, policy
//! engines, attestation stores).
//!
//! ## Honest scope of the predicate
//!
//! The `predicateType` is **`https://apohara.dev/sealchain/provenance/v1`** — a
//! apohara-sealchain-specific attestation predicate, *not* `slsa.dev/provenance`. This is
//! deliberate: SLSA Build provenance attests how a build system produced an
//! artifact (builder identity, build steps, materials). apohara-sealchain is **not** a
//! build system: it does not run or observe a build. What it attests is that a
//! given artifact (by sha256) was **sealed** — bound to an Ed25519 key, optionally
//! timestamped, logged in a transparency log, and given a C2PA manifest. Claiming
//! `slsa.dev/provenance` would mis-state what we can prove, so we use the in-toto
//! Statement *envelope* (the SLSA-style shape) with our own predicate type and
//! say plainly which attestations are independently verifiable offline.
//!
//! Everything in the predicate is read from the record's own fields — no value is
//! invented. The output is **deterministic** given a record (no `now()`): the only
//! time it reports is the receipt's own `seal.sealedAt`.

use serde_json::{json, Value};

use crate::schema::SealedRecord;

/// The in-toto Statement type URI (in-toto attestation framework v1).
pub const STATEMENT_TYPE_V1: &str = "https://in-toto.io/Statement/v1";

/// The apohara-sealchain provenance predicate type. SLSA-style (in-toto envelope) but
/// **not** `slsa.dev/provenance`: apohara-sealchain seals artifacts, it does not run
/// builds, so it does not claim SLSA Build semantics. See the module docs.
pub const PREDICATE_TYPE_V1: &str = "https://apohara.dev/sealchain/provenance/v1";

/// The model-transparency / OpenSSF Model Signing predicate type emitted by
/// [`model_signing_statement`] for ML-ecosystem interop. Pinned to interoperate
/// with sigstore/model-transparency (subjects = (path, sha256) pairs); the vendored
/// shape + provenance live in `packaging/model-signing-schema.json`.
pub const MODEL_SIGNING_PREDICATE_TYPE_V1: &str = "https://model_signing/signature/v1.0";

/// The in-toto Statement subject for `record`: a single `(name, {sha256})` pair.
/// The name is the artifact's recorded path, falling back to the digest so the
/// subject is never anonymous. Shared by both statement shapes.
fn subject_for(record: &SealedRecord) -> Value {
    let artifact_sha256 = record
        .payload
        .get("artifactSha256")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let subject_name = record
        .payload
        .get("path")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or(artifact_sha256);
    json!([{ "name": subject_name, "digest": { "sha256": artifact_sha256 } }])
}

/// Build an in-toto Statement v1 attesting the seal of `record`'s artifact.
///
/// Shape:
/// ```jsonc
/// {
///   "_type": "https://in-toto.io/Statement/v1",
///   "subject": [{ "name": <payload.path>, "digest": { "sha256": <payload.artifactSha256> } }],
///   "predicateType": "https://apohara.dev/sealchain/provenance/v1",
///   "predicate": { /* the receipt's real attestations */ }
/// }
/// ```
///
/// The subject digest is the receipt's `payload.artifactSha256`, so a tampered or
/// re-sealed record (whose payload hash differs) yields a different subject digest.
/// The predicate reflects only the layers actually present in the record (hmac is
/// always there; ed25519/tsa/rekor/c2pa appear only when the receipt carries them),
/// and notes which are independently verifiable offline. Deterministic: the only
/// timestamp is the record's own `seal.sealedAt`.
pub fn provenance_statement(record: &SealedRecord) -> Value {
    json!({
        "_type": STATEMENT_TYPE_V1,
        "subject": subject_for(record),
        "predicateType": PREDICATE_TYPE_V1,
        "predicate": build_predicate(record),
    })
}

/// Build an in-toto Statement in the **model-transparency / OpenSSF Model Signing**
/// shape ([`MODEL_SIGNING_PREDICATE_TYPE_V1`]) for interop with the ML-signing
/// ecosystem (sigstore/model-transparency consumers).
///
/// Same in-toto envelope and the same `(name, sha256)` subject as
/// [`provenance_statement`] — so a model-signing verifier can match the artifact
/// digest — but with the model-signing `predicateType`. The predicate cross-links
/// back to apohara's native attestation (it does **not** restate or replace it):
/// it records the seal method, the receipt's `sealedAt`, and the native
/// [`PREDICATE_TYPE_V1`] so a consumer can fetch the full apohara provenance. No
/// value is invented; deterministic given a record.
pub fn model_signing_statement(record: &SealedRecord) -> Value {
    json!({
        "_type": STATEMENT_TYPE_V1,
        "subject": subject_for(record),
        "predicateType": MODEL_SIGNING_PREDICATE_TYPE_V1,
        "predicate": {
            "sealedBy": "apohara-sealchain",
            "method": record.seal.method,
            "sealedAt": record.seal.sealed_at,
            // Cross-link, not a copy: the authoritative apohara provenance is its
            // own predicate type, emitted by `provenance_statement`.
            "sealchainPredicateType": PREDICATE_TYPE_V1,
        },
    })
}

/// Build the `predicate` body: the seal method, its timestamp, and one entry per
/// attestation actually present in the record. Each entry carries the real field
/// values from the receipt plus an honest `offlineVerifiable` flag stating whether
/// that attestation can be checked without a network round-trip.
fn build_predicate(record: &SealedRecord) -> Value {
    let seal = &record.seal;

    // Attestations, in chain order. HMAC is always present; the rest are gated on
    // the record carrying them, so the predicate never claims a layer we don't have.
    let mut attestations: Vec<Value> = Vec::new();

    // HMAC: symmetric local-integrity tag. NOT offline-verifiable by a third party
    // (the secret never appears in the receipt), and never a public-authorship claim.
    attestations.push(json!({
        "type": "hmac",
        "alg": seal.hmac.alg,
        "keyId": seal.hmac.key_id,
        "offlineVerifiable": false,
        "note": "symmetric integrity tag; the secret is not in the receipt, so only \
                 the key holder can re-check it. Not a public-authorship claim.",
    }));

    // Ed25519: authorship. The public key travels in the receipt, so anyone can
    // verify the signature offline.
    if let Some(ed) = seal.ed25519.as_ref() {
        let mut entry = json!({
            "type": "ed25519",
            "keyId": ed.key_id,
            "offlineVerifiable": true,
            "note": "signature over the canonical preimage; proves the key holder \
                     sealed this artifact (authorship), checkable offline.",
        });
        // Embed the public key when present so the predicate is self-contained.
        if let Some(pem) = seal.ed25519_public_key.as_ref() {
            entry["publicKey"] = json!(pem);
        }
        attestations.push(entry);
    }

    // C2PA: real provenance manifest (sidecar JUMBF or in-file embedded). Offline.
    if seal.c2pa_embedded == Some(true) {
        attestations.push(json!({
            "type": "c2pa",
            "mode": "embedded",
            "offlineVerifiable": true,
            "note": "in-file C2PA manifest (hard binding); verified offline.",
        }));
    } else if seal.c2pa_manifest.is_some() {
        attestations.push(json!({
            "type": "c2pa",
            "mode": "sidecar",
            "offlineVerifiable": true,
            "note": "sidecar JUMBF manifest binding the payload hash; verified offline.",
        }));
    }

    // TSA (RFC 3161): the seal existed before a point in time. Present-only; the
    // authority and issuance time are read straight from the record.
    if let Some(tsa) = seal.tsa.as_ref() {
        attestations.push(json!({
            "type": "tsa",
            "authority": tsa.get("authority").and_then(Value::as_str),
            "issuedAt": tsa.get("issuedAt").and_then(Value::as_str),
            "offlineVerifiable": true,
            "note": "RFC 3161 timestamp over hmac.sig || ed25519.sig; the token \
                     verifies offline by message imprint.",
        }));
    }

    // Rekor v2: recorded in a public transparency log. Present-only; logIndex and
    // logId are read straight from the record.
    if let Some(rekor) = seal.rekor_anchor.as_ref() {
        attestations.push(json!({
            "type": "rekor",
            "logIndex": rekor.get("logIndex").and_then(Value::as_i64),
            "logId": rekor.get("logId").and_then(Value::as_str),
            "offlineVerifiable": true,
            "note": "Sigstore Rekor v2 DSSE anchor; RFC 6962 inclusion + checkpoint \
                     signature verify offline against the pinned shard key.",
        }));
    }

    json!({
        "method": seal.method,
        "sealedAt": seal.sealed_at,
        "attestations": attestations,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::SealedRecord;

    /// A minimal hand-built record exercising the always-present layers.
    fn base_record() -> SealedRecord {
        let json = serde_json::json!({
            "payload": {
                "artifactSha256": "0daed7749b4f02b8f76240d5deadbeef",
                "path": "config.json",
                "size": 665,
                "mime": "application/json"
            },
            "seal": {
                "method": "apohara-seal-v1",
                "sealedAt": "2026-06-05T17:17:23+00:00",
                "preimage": "0x7b226d6574686f64223a22",
                "hmac": { "alg": "HMAC-SHA256", "keyId": "hmac-default", "sig": "0xaa" },
                "ed25519": { "keyId": "default", "sig": "0xbb" },
                "ed25519PublicKey": "-----BEGIN PUBLIC KEY-----\nMCowBQ==\n-----END PUBLIC KEY-----\n"
            }
        });
        serde_json::from_value(json).expect("valid record")
    }

    #[test]
    fn statement_has_in_toto_shape() {
        let record = base_record();
        let stmt = provenance_statement(&record);

        assert_eq!(stmt["_type"], STATEMENT_TYPE_V1);
        assert_eq!(stmt["predicateType"], PREDICATE_TYPE_V1);
        // Subject digest is the record's artifactSha256.
        assert_eq!(
            stmt["subject"][0]["digest"]["sha256"],
            "0daed7749b4f02b8f76240d5deadbeef"
        );
        assert_eq!(stmt["subject"][0]["name"], "config.json");
        // Predicate is non-empty and carries the real sealedAt.
        assert_eq!(stmt["predicate"]["sealedAt"], "2026-06-05T17:17:23+00:00");
        assert_eq!(stmt["predicate"]["method"], "apohara-seal-v1");
        assert!(stmt["predicate"]["attestations"].is_array());
    }

    #[test]
    fn predicate_is_honest_not_slsa_build() {
        // The predicate type must NOT claim slsa.dev build provenance.
        assert!(!PREDICATE_TYPE_V1.contains("slsa.dev"));
        assert!(PREDICATE_TYPE_V1.starts_with("https://apohara.dev/sealchain/provenance"));
    }

    #[test]
    fn present_layers_are_reflected() {
        let record = base_record();
        let stmt = provenance_statement(&record);
        let types: Vec<&str> = stmt["predicate"]["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| a["type"].as_str().unwrap())
            .collect();
        // hmac is always present; ed25519 is present in the base record.
        assert!(types.contains(&"hmac"));
        assert!(types.contains(&"ed25519"));
        // No tsa/rekor/c2pa in the base record -> not reflected.
        assert!(!types.contains(&"tsa"));
        assert!(!types.contains(&"rekor"));
        assert!(!types.contains(&"c2pa"));

        // HMAC is honestly marked NOT offline-verifiable; ed25519 IS.
        let hmac = find(&stmt, "hmac");
        assert_eq!(hmac["offlineVerifiable"], false);
        let ed = find(&stmt, "ed25519");
        assert_eq!(ed["offlineVerifiable"], true);
        // The embedded public key is carried through.
        assert!(ed["publicKey"]
            .as_str()
            .unwrap()
            .contains("BEGIN PUBLIC KEY"));
    }

    #[test]
    fn optional_layers_reflected_when_present() {
        let mut record = base_record();
        record.seal.c2pa_manifest = Some("0x0000".to_string());
        record.seal.tsa = Some(serde_json::json!({
            "authority": "http://tsa.example/tsr",
            "issuedAt": "2026-06-05T17:17:24+00:00",
            "der": "0xdead"
        }));
        record.seal.rekor_anchor = Some(serde_json::json!({
            "logIndex": 42,
            "logId": "abc123"
        }));

        let stmt = provenance_statement(&record);
        let c2pa = find(&stmt, "c2pa");
        assert_eq!(c2pa["mode"], "sidecar");
        let tsa = find(&stmt, "tsa");
        assert_eq!(tsa["authority"], "http://tsa.example/tsr");
        assert_eq!(tsa["issuedAt"], "2026-06-05T17:17:24+00:00");
        let rekor = find(&stmt, "rekor");
        assert_eq!(rekor["logIndex"], 42);
        assert_eq!(rekor["logId"], "abc123");
    }

    #[test]
    fn embedded_c2pa_mode_reflected() {
        let mut record = base_record();
        record.seal.c2pa_embedded = Some(true);
        let stmt = provenance_statement(&record);
        assert_eq!(find(&stmt, "c2pa")["mode"], "embedded");
    }

    #[test]
    fn tampered_payload_changes_subject_digest() {
        let record = base_record();
        let before = provenance_statement(&record);

        let mut tampered = base_record();
        tampered.payload["artifactSha256"] =
            serde_json::Value::String("ffffffffffffffffffffffffffffffff".to_string());
        let after = provenance_statement(&tampered);

        assert_ne!(
            before["subject"][0]["digest"]["sha256"], after["subject"][0]["digest"]["sha256"],
            "editing the payload hash must change the subject digest"
        );
        assert_eq!(
            after["subject"][0]["digest"]["sha256"],
            "ffffffffffffffffffffffffffffffff"
        );
    }

    #[test]
    fn deterministic_for_a_given_record() {
        let record = base_record();
        // No now(): two calls on the same record produce byte-identical output.
        assert_eq!(provenance_statement(&record), provenance_statement(&record));
    }

    #[test]
    fn model_signing_statement_matches_vendored_shape() {
        // Publish-safe: the vendored descriptor lives in packaging/ (not in the
        // crate package), so skip if absent — `cargo publish` is unaffected.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../packaging/model-signing-schema.json");
        let Ok(text) = std::fs::read_to_string(&path) else {
            return;
        };
        let schema: Value = serde_json::from_str(&text).expect("descriptor parses");

        let stmt = model_signing_statement(&base_record());

        assert_eq!(stmt["_type"], schema["statementType"]);
        assert_eq!(stmt["predicateType"], schema["predicateType"]);
        assert_eq!(stmt["predicateType"], MODEL_SIGNING_PREDICATE_TYPE_V1);
        for k in schema["requiredStatementKeys"].as_array().unwrap() {
            let key = k.as_str().unwrap();
            assert!(stmt.get(key).is_some(), "missing statement key {key}");
        }
        let subj = &stmt["subject"][0];
        for k in schema["requiredSubjectKeys"].as_array().unwrap() {
            let key = k.as_str().unwrap();
            assert!(subj.get(key).is_some(), "missing subject key {key}");
        }
        // The subject digest equals the record's artifactSha256, so a model-signing
        // verifier can match it against a hash of the artifact.
        assert!(subj["digest"]["sha256"].is_string());
        assert_eq!(subj["digest"]["sha256"], "0daed7749b4f02b8f76240d5deadbeef");
    }

    #[test]
    fn model_signing_keeps_native_predicate_distinct() {
        let r = base_record();
        // Interop export uses the model-signing predicate; the native export keeps
        // apohara's own. Neither claims slsa.dev.
        assert_eq!(
            model_signing_statement(&r)["predicateType"],
            MODEL_SIGNING_PREDICATE_TYPE_V1
        );
        assert_eq!(provenance_statement(&r)["predicateType"], PREDICATE_TYPE_V1);
        assert!(!MODEL_SIGNING_PREDICATE_TYPE_V1.contains("slsa.dev"));
    }

    /// Find the attestation entry of the given `type` in a Statement.
    fn find<'a>(stmt: &'a Value, ty: &str) -> &'a Value {
        stmt["predicate"]["attestations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|a| a["type"] == ty)
            .unwrap_or_else(|| panic!("missing attestation: {ty}"))
    }
}

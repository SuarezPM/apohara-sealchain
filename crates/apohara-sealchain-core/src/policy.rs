//! Attestation policy engine.
//!
//! A *policy* declares the bar a receipt must clear to be acceptable for a given
//! use — e.g. "must carry a verified Ed25519 signature AND a public Rekor entry",
//! or "must be timestamped by a qualified eIDAS QTSP and be less than a year old".
//! Policies are evaluated **after** cryptographic verification and never replace
//! it: a tampered receipt fails verification (exit 1) regardless of any policy.
//!
//! Two ways to get a [`Policy`]:
//! * [`Policy::from_toml_str`] parses a declarative TOML file (`verify --policy`);
//! * [`Policy::from_profile`] derives one from a named profile in the canonical
//!   [trust profile](mod@crate::trust_profile) (`verify --profile legal-grade`).
//!
//! ## Honesty (rule #1)
//!
//! `evaluate` counts a layer as satisfied **only if it is present in the
//! receipt AND its verification [`LayerResult`] is `ok`** — a present-but-failed
//! layer never satisfies a requirement. `require_qualified_tsa` is a **host
//! allowlist** match (the recorded `seal.tsa.authority` against
//! [`crate::trust_profile::known_qualified_tsa_hosts`] or the policy's own
//! `require_tsa_authority_in`); it does **not** cryptographically prove eIDAS
//! qualification, and the violation message says so. This module is native-only:
//! the wasm verify-only build does not enforce policies.

use serde::Deserialize;

use crate::artifact::LayerResult;
use crate::error::SealError;
use crate::schema::SealedRecord;
use crate::trust_profile::{known_qualified_tsa_hosts, named_profile};

/// A declarative attestation policy.
///
/// All fields are optional; an empty policy passes every receipt. Unknown keys
/// are rejected (`deny_unknown_fields`) so a typo in a policy file is a loud
/// error, not a silently-ignored requirement.
#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// Layers that must be present AND verified, e.g. `["ed25519", "rekor"]`.
    #[serde(default)]
    pub require_layers: Vec<String>,
    /// Layers that must NOT be present at all.
    #[serde(default)]
    pub forbid_layers: Vec<String>,
    /// Minimum number of present-and-verified attestation layers (hmac counts).
    #[serde(default)]
    pub min_layers: Option<usize>,
    /// Require the TSA layer's authority host to be a known qualified eIDAS QTSP.
    /// This is a host-allowlist match, NOT cryptographic proof of qualification.
    #[serde(default)]
    pub require_qualified_tsa: bool,
    /// Maximum age, in days, between `seal.sealedAt` and the verify time.
    #[serde(default)]
    pub max_age_days: Option<i64>,
    /// Explicit TSA-authority host allowlist. When set, it overrides the canonical
    /// `known_qualified_tsa_hosts` for the `require_qualified_tsa` check (point it
    /// at your own QTSP host).
    #[serde(default)]
    pub require_tsa_authority_in: Option<Vec<String>>,
}

/// The outcome of evaluating a [`Policy`] against a receipt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReport {
    /// True when there are no violations.
    pub passed: bool,
    /// One human-readable line per failed requirement (empty when `passed`).
    pub violations: Vec<String>,
    /// The named profile this policy came from, if any (set by the caller).
    pub profile: Option<String>,
}

impl Policy {
    /// Parse a policy from declarative TOML. A typo'd key is a hard error.
    pub fn from_toml_str(s: &str) -> Result<Self, SealError> {
        toml::from_str(s).map_err(|e| SealError::Malformed(format!("invalid policy TOML: {e}")))
    }

    /// Derive a policy from a named profile in the canonical trust profile
    /// (e.g. `offline-basic`, `transparency`, `legal-grade`, `full`). Returns
    /// `None` if no profile by that name exists.
    pub fn from_profile(name: &str) -> Option<Self> {
        let p = named_profile(name)?;
        Some(Policy {
            require_layers: p.require_layers.clone(),
            forbid_layers: Vec::new(),
            min_layers: p.min_layers,
            require_qualified_tsa: p.require_qualified_tsa,
            max_age_days: None,
            require_tsa_authority_in: None,
        })
    }
}

/// Evaluate `policy` against a receipt and its verification results.
///
/// `layer_results` is the output of [`crate::verify_artifact`] /
/// [`crate::verify_artifact_bytes`]; `now` is the reference time for
/// `max_age_days`. A requirement is satisfied only with positive evidence (a
/// present layer whose [`LayerResult`] is `ok`).
pub fn evaluate(
    policy: &Policy,
    record: &SealedRecord,
    layer_results: &[LayerResult],
    now: chrono::DateTime<chrono::Utc>,
) -> PolicyReport {
    let mut violations = Vec::new();

    // Layers present in the receipt (chain order: hmac, ed25519, c2pa, tsa, rekor)
    // and the subset that verified ok in this run.
    let present = crate::index::present_layers(record);
    let verified_ok: std::collections::BTreeSet<&str> = layer_results
        .iter()
        .filter(|r| r.ok)
        .map(|r| r.name.as_str())
        .collect();
    let is_present = |layer: &str| present.iter().any(|p| p == layer);

    // require_layers: present AND verified.
    for layer in &policy.require_layers {
        if !is_present(layer) {
            violations.push(format!("missing required layer: {layer}"));
        } else if !verified_ok.contains(layer.as_str()) {
            violations.push(format!("required layer present but not verified: {layer}"));
        }
    }

    // forbid_layers: must be absent.
    for layer in &policy.forbid_layers {
        if is_present(layer) {
            violations.push(format!("forbidden layer present: {layer}"));
        }
    }

    // min_layers: count present-and-verified attestation layers.
    if let Some(min) = policy.min_layers {
        let count = present
            .iter()
            .filter(|p| verified_ok.contains(p.as_str()))
            .count();
        if count < min {
            violations.push(format!(
                "too few verified layers: {count} verified, policy requires at least {min}"
            ));
        }
    }

    // require_qualified_tsa: host-allowlist match on the recorded authority.
    if policy.require_qualified_tsa {
        check_qualified_tsa(policy, record, &mut violations);
    }

    // max_age_days: sealedAt within `now - max` .. now.
    if let Some(max) = policy.max_age_days {
        check_max_age(record, max, now, &mut violations);
    }

    PolicyReport {
        passed: violations.is_empty(),
        violations,
        profile: None,
    }
}

/// Convenience over `evaluate` that uses the current UTC time for
/// `max_age_days`. Used by the CLI and MCP surfaces (which evaluate against
/// "now"); tests call `evaluate` directly with a fixed time.
pub fn evaluate_now(
    policy: &Policy,
    record: &SealedRecord,
    layer_results: &[LayerResult],
) -> PolicyReport {
    evaluate(policy, record, layer_results, chrono::Utc::now())
}

/// Check that the receipt's TSA authority host is on the qualified-QTSP allowlist
/// (the policy's `require_tsa_authority_in`, else the canonical trust-profile
/// list). A measured, honest check — not a proof of eIDAS qualification.
fn check_qualified_tsa(policy: &Policy, record: &SealedRecord, violations: &mut Vec<String>) {
    let Some(tsa) = record.seal.tsa.as_ref() else {
        violations.push(
            "require_qualified_tsa: no TSA layer present (a qualified timestamp is required)"
                .to_string(),
        );
        return;
    };
    let authority = tsa
        .get("authority")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let allow: Vec<String> = match &policy.require_tsa_authority_in {
        Some(list) => list.clone(),
        None => known_qualified_tsa_hosts().to_vec(),
    };
    let host_ok = allow.iter().any(|h| h.eq_ignore_ascii_case(&authority));
    if !host_ok {
        violations.push(format!(
            "require_qualified_tsa: TSA authority '{authority}' is not in the qualified-QTSP host \
             allowlist (this matches the recorded authority host against a known-QTSP list; it does \
             NOT cryptographically prove eIDAS qualification)"
        ));
    }
}

/// Check that `seal.sealedAt` is no more than `max_days` before `now`.
fn check_max_age(
    record: &SealedRecord,
    max_days: i64,
    now: chrono::DateTime<chrono::Utc>,
    violations: &mut Vec<String>,
) {
    let sealed_at = &record.seal.sealed_at;
    match chrono::DateTime::parse_from_rfc3339(sealed_at) {
        Ok(dt) => {
            let age_days = now
                .signed_duration_since(dt.with_timezone(&chrono::Utc))
                .num_days();
            if age_days > max_days {
                violations.push(format!(
                    "receipt too old: sealed {age_days} days ago, policy allows at most {max_days}"
                ));
            } else if age_days < 0 {
                // A seal dated more than a day in the future is not "fresh" — it
                // points at clock skew or a forged timestamp. `num_days` truncates
                // toward zero, so minor skew (< 24h) does not trip this.
                violations.push(format!(
                    "receipt sealedAt is in the future ({sealed_at}): clock skew or a forged timestamp"
                ));
            }
        }
        Err(e) => violations.push(format!("cannot parse sealedAt '{sealed_at}': {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{HmacLayer, SealBlock};
    use serde_json::{json, Value};

    /// Build a minimal sealed record with the requested sibling layers present.
    /// The payload/preimage/hmac are placeholders — policy evaluation reads only
    /// the seal's present-layer shape and `sealedAt`, plus the supplied results.
    fn record(
        sealed_at: &str,
        ed25519: bool,
        c2pa: bool,
        tsa_authority: Option<&str>,
        rekor: bool,
    ) -> SealedRecord {
        let seal = SealBlock {
            method: "apohara-seal-v1".to_string(),
            sealed_at: sealed_at.to_string(),
            preimage: "0x00".to_string(),
            hmac: HmacLayer {
                alg: "HMAC-SHA256".to_string(),
                key_id: "test".to_string(),
                sig: "0x00".to_string(),
            },
            ed25519: ed25519.then(|| crate::schema::Ed25519Layer {
                key_id: "test".to_string(),
                sig: "0x00".to_string(),
            }),
            ed25519_public_key: None,
            tsa: tsa_authority.map(|a| json!({ "authority": a })),
            rekor_anchor: rekor.then(|| json!({ "logIndex": 1 })),
            c2pa_manifest: c2pa.then(|| "0x00".to_string()),
            c2pa_embedded: None,
        };
        SealedRecord {
            payload: Value::Null,
            seal,
        }
    }

    /// LayerResults marking the named layers as ok (plus content+hmac always ok).
    fn ok_results(names: &[&str]) -> Vec<LayerResult> {
        let mut all = vec!["content", "hmac"];
        all.extend_from_slice(names);
        all.iter()
            .map(|n| LayerResult {
                name: n.to_string(),
                ok: true,
                reason: String::new(),
            })
            .collect()
    }

    fn now() -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339("2026-06-05T00:00:00+00:00")
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn require_layers_pass_and_fail() {
        let rec = record("2026-06-01T00:00:00+00:00", true, false, None, true);
        let results = ok_results(&["ed25519", "rekor"]);
        let policy = Policy {
            require_layers: vec!["ed25519".into(), "rekor".into()],
            ..Default::default()
        };
        assert!(evaluate(&policy, &rec, &results, now()).passed);

        // rekor required but absent from the receipt.
        let rec2 = record("2026-06-01T00:00:00+00:00", true, false, None, false);
        let report = evaluate(&policy, &rec2, &ok_results(&["ed25519"]), now());
        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|v| v.contains("missing required layer: rekor")));
    }

    #[test]
    fn require_layer_present_but_not_verified_fails() {
        // rekor is present in the receipt but its verify result is ok:false.
        let rec = record("2026-06-01T00:00:00+00:00", true, false, None, true);
        let results = vec![
            LayerResult {
                name: "content".into(),
                ok: true,
                reason: String::new(),
            },
            LayerResult {
                name: "hmac".into(),
                ok: true,
                reason: String::new(),
            },
            LayerResult {
                name: "ed25519".into(),
                ok: true,
                reason: String::new(),
            },
            LayerResult {
                name: "rekor".into(),
                ok: false,
                reason: "bad proof".into(),
            },
        ];
        let policy = Policy {
            require_layers: vec!["rekor".into()],
            ..Default::default()
        };
        let report = evaluate(&policy, &rec, &results, now());
        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|v| v.contains("present but not verified: rekor")));
    }

    #[test]
    fn forbid_layers_fails_when_present() {
        let rec = record(
            "2026-06-01T00:00:00+00:00",
            true,
            false,
            Some("freetsa.org"),
            false,
        );
        let policy = Policy {
            forbid_layers: vec!["tsa".into()],
            ..Default::default()
        };
        let report = evaluate(&policy, &rec, &ok_results(&["ed25519", "tsa"]), now());
        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|v| v.contains("forbidden layer present: tsa")));
    }

    #[test]
    fn min_layers_counts_only_verified() {
        let rec = record("2026-06-01T00:00:00+00:00", true, true, None, false);
        // present: hmac, ed25519, c2pa. All verified -> 3.
        let policy = Policy {
            min_layers: Some(3),
            ..Default::default()
        };
        assert!(evaluate(&policy, &rec, &ok_results(&["ed25519", "c2pa"]), now()).passed);

        // c2pa present but NOT verified -> only hmac+ed25519 = 2 < 3.
        let results = vec![
            LayerResult {
                name: "content".into(),
                ok: true,
                reason: String::new(),
            },
            LayerResult {
                name: "hmac".into(),
                ok: true,
                reason: String::new(),
            },
            LayerResult {
                name: "ed25519".into(),
                ok: true,
                reason: String::new(),
            },
            LayerResult {
                name: "c2pa".into(),
                ok: false,
                reason: "mismatch".into(),
            },
        ];
        assert!(!evaluate(&policy, &rec, &results, now()).passed);
    }

    #[test]
    fn require_qualified_tsa_allowlist() {
        // Non-qualified authority fails against the default trust-profile list.
        let rec = record(
            "2026-06-01T00:00:00+00:00",
            true,
            false,
            Some("freetsa.org"),
            false,
        );
        let policy = Policy {
            require_layers: vec!["ed25519".into(), "tsa".into()],
            require_qualified_tsa: true,
            ..Default::default()
        };
        let report = evaluate(&policy, &rec, &ok_results(&["ed25519", "tsa"]), now());
        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|v| v.contains("not in the qualified-QTSP host allowlist")));

        // A QTSP host on the seeded allowlist passes.
        let rec2 = record(
            "2026-06-01T00:00:00+00:00",
            true,
            false,
            Some("timestamp.actalis.it"),
            false,
        );
        assert!(evaluate(&policy, &rec2, &ok_results(&["ed25519", "tsa"]), now()).passed);

        // An explicit per-policy authority allowlist overrides the default list.
        let policy2 = Policy {
            require_layers: vec!["ed25519".into(), "tsa".into()],
            require_qualified_tsa: true,
            require_tsa_authority_in: Some(vec!["freetsa.org".into()]),
            ..Default::default()
        };
        assert!(evaluate(&policy2, &rec, &ok_results(&["ed25519", "tsa"]), now()).passed);
    }

    #[test]
    fn max_age_days() {
        let policy = Policy {
            max_age_days: Some(30),
            ..Default::default()
        };
        // Sealed 4 days before `now` -> within 30.
        let fresh = record("2026-06-01T00:00:00+00:00", true, false, None, false);
        assert!(evaluate(&policy, &fresh, &ok_results(&["ed25519"]), now()).passed);
        // Sealed ~157 days before `now` -> too old.
        let stale = record("2025-12-30T00:00:00+00:00", true, false, None, false);
        let report = evaluate(&policy, &stale, &ok_results(&["ed25519"]), now());
        assert!(!report.passed);
        assert!(report.violations.iter().any(|v| v.contains("too old")));

        // Sealed well in the future (negative age) -> rejected as not fresh.
        let future = record("2026-09-01T00:00:00+00:00", true, false, None, false);
        let report = evaluate(&policy, &future, &ok_results(&["ed25519"]), now());
        assert!(!report.passed);
        assert!(report
            .violations
            .iter()
            .any(|v| v.contains("in the future")));
    }

    #[test]
    fn from_profile_maps_named_profile() {
        let legal = Policy::from_profile("legal-grade").expect("profile exists");
        assert!(legal.require_qualified_tsa);
        assert!(legal.require_layers.contains(&"tsa".to_string()));
        assert!(Policy::from_profile("does-not-exist").is_none());
    }

    #[test]
    fn from_toml_round_trip_and_rejects_unknown_keys() {
        let toml = r#"
            require_layers = ["ed25519", "rekor"]
            min_layers = 2
            max_age_days = 365
        "#;
        let p = Policy::from_toml_str(toml).expect("valid policy");
        assert_eq!(p.require_layers, vec!["ed25519", "rekor"]);
        assert_eq!(p.min_layers, Some(2));
        assert_eq!(p.max_age_days, Some(365));

        // A typo'd key must be rejected (deny_unknown_fields), not ignored.
        let bad = "require_layer = [\"ed25519\"]";
        assert!(Policy::from_toml_str(bad).is_err());
    }
}

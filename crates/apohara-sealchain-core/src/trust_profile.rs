//! Canonical machine-readable Trust Profile.
//!
//! This module embeds [`packaging/trust-profile.json`](../../../packaging/trust-profile.json)
//! (via an identical crate-local copy, see below) and parses it into typed
//! structures. It is the **single source of truth** for three things consumed
//! across the tool:
//!
//! * the **proof matrix** — what each layer/combination proves and does not
//!   prove (the machine-readable form of `docs/TRUST-PROFILE.md`);
//! * the **named profiles** (`offline-basic`, `transparency`, `legal-grade`,
//!   `full`) the attestation policy engine ([`crate::policy`]) and the
//!   transparency dashboard ([`crate::dashboard`]) reference;
//! * the **qualified-TSA host allowlist** the `require_qualified_tsa` policy
//!   check matches against — honestly a host allowlist, NOT cryptographic proof
//!   of eIDAS qualification (see `qualifiedTsaHonesty` in the JSON).
//!
//! The crate ships its own copy at `crates/apohara-sealchain-core/trust-profile.json`
//! (so `include_str!` works and the file travels inside the published crate),
//! mirroring the `rekor-shards.json` precedent. The published, user-facing
//! canonical copy lives at `packaging/trust-profile.json`; a dev-only test
//! (`packaging_mirror_matches_embedded_when_present`) asserts the two stay
//! byte-identical whenever the `packaging/` copy is reachable.
//!
//! Pure `serde`/`serde_json` over an embedded constant: no filesystem and no
//! network, so this module is available in BOTH the native and the wasm
//! `verify-only` builds.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use serde::Deserialize;

/// The embedded canonical trust profile (single source of truth for the binary).
const TRUST_PROFILE_JSON: &str = include_str!("../trust-profile.json");

/// The parsed canonical trust profile.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustProfile {
    /// Schema tag, currently `apohara-trust-profile-v1`.
    pub schema_version: String,
    /// Human-readable summary of what this document is.
    #[serde(default)]
    pub description: String,
    /// One-liner per layer: the narrow question that layer answers.
    #[serde(default)]
    pub layers: BTreeMap<String, String>,
    /// Named attestation profiles, keyed by profile name.
    pub profiles: BTreeMap<String, NamedProfile>,
    /// The proof matrix: one row per layer combination.
    #[serde(default)]
    pub matrix: Vec<MatrixRow>,
    /// Non-exhaustive allowlist of qualified-TSA hostnames (see
    /// [`Self::qualified_tsa_honesty`]).
    #[serde(default)]
    pub known_qualified_tsa_hosts: Vec<String>,
    /// The candid caveat on what matching `known_qualified_tsa_hosts` proves.
    #[serde(default)]
    pub qualified_tsa_honesty: String,
}

/// A named attestation profile: the requirements a receipt must meet to be
/// considered to satisfy this profile. Maps directly onto a [`crate::policy::Policy`].
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NamedProfile {
    /// Short display title.
    pub title: String,
    /// What the profile is for.
    #[serde(default)]
    pub description: String,
    /// Layers that must be present AND verified for the profile to hold.
    #[serde(default)]
    pub require_layers: Vec<String>,
    /// Minimum number of present-and-verified attestation layers, if any.
    #[serde(default)]
    pub min_layers: Option<usize>,
    /// Whether the TSA layer must be a qualified eIDAS QTSP (host-allowlist check).
    #[serde(default)]
    pub require_qualified_tsa: bool,
}

/// One row of the proof matrix: a layer combination and its narrow claims.
#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixRow {
    /// The layer combination, e.g. `hmac+ed25519+rekor`.
    pub combination: String,
    /// What the combination proves (stated narrowly).
    pub proves: String,
    /// What it explicitly does NOT prove.
    pub does_not_prove: String,
    /// The trust anchor the combination depends on.
    pub trust_anchor: String,
}

/// Parse and cache the embedded trust profile.
///
/// The embedded JSON is a compile-time constant guarded by the
/// `embedded_trust_profile_parses` unit test, so a parse failure is a build bug,
/// not runtime input — we surface it as a clear panic rather than threading a
/// `Result` through every caller.
pub fn trust_profile() -> &'static TrustProfile {
    static CACHE: OnceLock<TrustProfile> = OnceLock::new();
    CACHE.get_or_init(|| {
        serde_json::from_str(TRUST_PROFILE_JSON)
            .expect("embedded trust-profile.json is malformed (guarded by a unit test)")
    })
}

/// Look up a named profile (e.g. `legal-grade`) by name.
pub fn named_profile(name: &str) -> Option<&'static NamedProfile> {
    trust_profile().profiles.get(name)
}

/// The names of every defined profile, sorted (BTreeMap order).
pub fn profile_names() -> Vec<&'static str> {
    trust_profile()
        .profiles
        .keys()
        .map(String::as_str)
        .collect()
}

/// The canonical, non-exhaustive allowlist of qualified-TSA hostnames. Matching
/// it does NOT cryptographically prove eIDAS qualification — see
/// [`TrustProfile::qualified_tsa_honesty`].
pub fn known_qualified_tsa_hosts() -> &'static [String] {
    &trust_profile().known_qualified_tsa_hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_trust_profile_parses() {
        let tp = trust_profile();
        assert_eq!(tp.schema_version, "apohara-trust-profile-v1");
        assert!(!tp.profiles.is_empty(), "profiles must be non-empty");
        assert!(!tp.matrix.is_empty(), "matrix must be non-empty");
        for (name, p) in &tp.profiles {
            assert!(!p.title.is_empty(), "profile {name} has empty title");
        }
        // The four named profiles the policy engine + dashboard rely on.
        for name in ["offline-basic", "transparency", "legal-grade", "full"] {
            assert!(named_profile(name).is_some(), "missing profile: {name}");
        }
        // legal-grade is the one that requires a qualified TSA.
        assert!(named_profile("legal-grade").unwrap().require_qualified_tsa);
        // The allowlist is seeded (non-empty) and documented.
        assert!(!known_qualified_tsa_hosts().is_empty());
        assert!(!tp.qualified_tsa_honesty.is_empty());
    }

    #[test]
    fn packaging_mirror_matches_embedded_when_present() {
        // Dev/CI only: packaging/trust-profile.json must be byte-identical to the
        // crate-local embedded copy. Skips silently when packaging/ is absent
        // (e.g. inside a published crate), so `cargo publish` is unaffected.
        let manifest = env!("CARGO_MANIFEST_DIR"); // crates/apohara-sealchain-core
        let mirror = std::path::Path::new(manifest).join("../../packaging/trust-profile.json");
        if let Ok(text) = std::fs::read_to_string(&mirror) {
            assert_eq!(
                text, TRUST_PROFILE_JSON,
                "packaging/trust-profile.json drifted from the embedded crate copy"
            );
        }
    }
}

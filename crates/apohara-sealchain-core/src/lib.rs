//! apohara-sealchain-core — the `apohara-seal-v1` receipt engine.
//!
//! Native Rust reimplementation of the Python `core/seal` reference. This
//! crate is **sync**; network-backed layers (TSA, Rekor) own a private
//! runtime internally so the public API stays runtime-agnostic.
//!
//! Where the Python reference is internally inconsistent (the C2PA hash
//! input and the Rekor signed-checkpoint verification), this crate defines
//! the canonical behavior and documents the divergence.

/// The seal method identifier for the v1 (a.k.a. v4 / apohara) schema.
pub const METHOD_V1: &str = "apohara-seal-v1";

pub mod artifact;
/// Transparency dashboard: render a self-contained, offline HTML report from a
/// set of receipts. Native-only (it reuses the native verify path + policy).
#[cfg(feature = "native")]
pub mod dashboard;
pub mod error;
pub mod excluded;
/// Local receipt index (sqlite). Native-only convenience/discovery layer —
/// rebuildable from receipts, never a source of truth.
#[cfg(feature = "native")]
pub mod index;
pub mod jcs;
#[cfg(feature = "native")]
pub mod keystore;
pub mod layers;
/// Attestation policy engine: evaluate a receipt against required layers, a
/// minimum layer count, qualified-TSA, and a maximum age. Native-only — the wasm
/// verify-only build does not enforce policies.
#[cfg(feature = "native")]
pub mod policy;
/// in-toto/SLSA-style provenance predicate for sealed artifacts. Pure
/// `serde_json` mapping, available in both the native and wasm verify-only
/// builds (it never touches the network or filesystem).
pub mod provenance;
pub mod schema;
pub mod seal;
/// Canonical machine-readable Trust Profile (named profiles + proof matrix +
/// qualified-TSA allowlist). Pure serde over an embedded constant, so it is
/// available in both the native and wasm verify-only builds.
pub mod trust_profile;
pub mod verify;

// Always available (native + wasm verify-only): the per-layer verify types and
// the in-memory verify entry point used by the browser verifier.
pub use artifact::{render_chain, verify_artifact_bytes, LayerResult};
// Native-only: filesystem seal/verify orchestration and the receipt-path helper.
#[cfg(feature = "native")]
pub use artifact::{default_receipt_path, seal_artifact, verify_artifact};
#[cfg(feature = "native")]
pub use dashboard::{
    generated_at_now, render_html as render_dashboard, DashboardEntry, VerifyStatus,
};
pub use error::SealError;
pub use excluded::strip_excluded;
#[cfg(feature = "native")]
pub use index::{
    index_find, index_insert, index_list, present_layers, rebuild as index_rebuild, scan_receipts,
    IndexRecord,
};
pub use jcs::canonicalize;
#[cfg(feature = "native")]
pub use keystore::{
    decrypt_keystore, encrypt_keystore, from_overrides, info as keystore_info, load_or_generate,
    load_or_generate_with_passphrase, rotate as rotate_keystore, ArchivedKey, Keys, KeystoreInfo,
};
#[cfg(feature = "native")]
pub use layers::rekor::{
    check_shard_active, classify_shard, load_shards as load_rekor_shards,
    resolve_shard as resolve_rekor_shard, submit as submit_rekor_anchor,
    verify_anchor as verify_rekor_anchor, RekorAnchor, ShardActiveness, ShardKey,
    DEFAULT_REKOR_V2_URL,
};
#[cfg(feature = "native")]
pub use layers::tsa::{
    request_token as request_tsa_token, verify_token as verify_tsa_token, TsaToken, DEFAULT_TSA_URL,
};
#[cfg(feature = "native")]
pub use policy::{
    evaluate as evaluate_policy, evaluate_now as evaluate_policy_now, Policy, PolicyReport,
};
pub use provenance::{
    model_signing_statement, provenance_statement, MODEL_SIGNING_PREDICATE_TYPE_V1,
    PREDICATE_TYPE_V1, STATEMENT_TYPE_V1,
};
pub use schema::{detect_schema, SchemaVersion, SealBlock, SealedRecord};
pub use seal::{build_preimage, seal_deterministic};
pub use trust_profile::{
    known_qualified_tsa_hosts, named_profile, profile_names, trust_profile, MatrixRow,
    NamedProfile, TrustProfile,
};
pub use verify::verify;
